"""
agents/system_agent/permission_guard.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Local permission guard for System Agent risky actions before Security Agent.

This module provides a production-ready, import-safe permission guard used by
the System Agent before performing risky local/system-level operations such as:

    - OS commands
    - File operations
    - App control
    - Device controls
    - Automation tasks
    - Notification/message/call actions
    - Desktop/system interactions

Architecture Compatibility:
    - Master Agent routing
    - BaseAgent-compatible result format
    - Agent Registry / Agent Loader safe import
    - Security Agent approval flow
    - Verification Agent payload preparation
    - Memory Agent payload compatibility
    - Dashboard/API audit logging
    - SaaS user/workspace isolation

Important:
    This guard does NOT execute real system actions.
    It only evaluates permissions, risk, policy, and approval requirements.
"""

from __future__ import annotations

import enum
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Union


# -------------------------------------------------------------------------
# Safe optional imports for William/Jarvis architecture compatibility
# -------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # fallback stub
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe if the William base agent file
        has not been generated yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)


try:
    from core.context import AgentContext  # type: ignore
except Exception:  # pragma: no cover
    class AgentContext:  # fallback stub
        """
        Fallback AgentContext stub.

        The real AgentContext should provide user_id, workspace_id,
        task_id, role, permissions, and metadata.
        """

        def __init__(self, **kwargs: Any) -> None:
            self.__dict__.update(kwargs)


try:
    from core.config import settings  # type: ignore
except Exception:  # pragma: no cover
    class _FallbackSettings:
        SYSTEM_AGENT_PERMISSION_STRICT_MODE = True
        SYSTEM_AGENT_ALLOW_UNKNOWN_ACTIONS = False
        SYSTEM_AGENT_DEFAULT_REQUIRE_SECURITY = True
        SYSTEM_AGENT_AUDIT_ENABLED = True
        SYSTEM_AGENT_MEMORY_ENABLED = True
        SYSTEM_AGENT_VERIFICATION_ENABLED = True

    settings = _FallbackSettings()


# -------------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------------

logger = logging.getLogger("william.system_agent.permission_guard")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# -------------------------------------------------------------------------
# Enums and constants
# -------------------------------------------------------------------------

class PermissionDecision(str, enum.Enum):
    """
    Permission decision returned by the local guard.
    """

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_SECURITY_APPROVAL = "require_security_approval"
    REQUIRE_USER_CONFIRMATION = "require_user_confirmation"
    REQUIRE_ADMIN_APPROVAL = "require_admin_approval"
    REQUIRE_WORKSPACE_OWNER_APPROVAL = "require_workspace_owner_approval"
    UNKNOWN = "unknown"


class RiskLevel(str, enum.Enum):
    """
    Risk level used to classify local System Agent actions.
    """

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    DESTRUCTIVE = "destructive"
    UNKNOWN = "unknown"


class ActionCategory(str, enum.Enum):
    """
    Categories understood by the System Agent permission guard.
    """

    OS_COMMAND = "os_command"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    FILE_MOVE = "file_move"
    FILE_PERMISSION = "file_permission"
    APP_CONTROL = "app_control"
    DEVICE_CONTROL = "device_control"
    AUTOMATION = "automation"
    NOTIFICATION_READ = "notification_read"
    MESSAGE_SEND = "message_send"
    CALL_ACTION = "call_action"
    BROWSER_ACTION = "browser_action"
    CLIPBOARD = "clipboard"
    SCREEN_CAPTURE = "screen_capture"
    DESKTOP_VISION = "desktop_vision"
    GESTURE_CONTROL = "gesture_control"
    NETWORK = "network"
    SECURITY = "security"
    CONFIGURATION = "configuration"
    SYSTEM_MEMORY = "system_memory"
    UNKNOWN = "unknown"


class ApprovalType(str, enum.Enum):
    """
    Approval mechanism requested before risky actions.
    """

    NONE = "none"
    SECURITY_AGENT = "security_agent"
    USER_CONFIRMATION = "user_confirmation"
    ADMIN = "admin"
    WORKSPACE_OWNER = "workspace_owner"
    MULTI_STEP = "multi_step"


DEFAULT_DENIED_COMMAND_KEYWORDS: Set[str] = {
    "rm -rf /",
    "format",
    "mkfs",
    "dd if=",
    "shutdown",
    "reboot",
    "poweroff",
    "halt",
    "del /s",
    "rd /s",
    "cipher /w",
    "diskpart",
    "reg delete",
    "net user",
    "chmod 777",
    "chown -R",
    "sudo su",
    "passwd",
    "userdel",
    "groupdel",
    "iptables",
    "ufw disable",
    "firewall-cmd",
    "curl | bash",
    "wget | bash",
    "Invoke-WebRequest",
    "Set-ExecutionPolicy Unrestricted",
}

DEFAULT_SENSITIVE_PATH_FRAGMENTS: Set[str] = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/boot",
    "/root",
    "/var/log/auth",
    "/var/lib",
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64",
    "C:\\Windows\\Registry",
    "AppData\\Local",
    "AppData\\Roaming",
    ".ssh",
    ".env",
    "id_rsa",
    "private_key",
    "secrets",
    "credentials",
    "token",
}

DEFAULT_SAFE_READ_EXTENSIONS: Set[str] = {
    ".txt",
    ".md",
    ".json",
    ".csv",
    ".yaml",
    ".yml",
    ".log",
    ".ini",
    ".toml",
}

DEFAULT_HIGH_RISK_EXTENSIONS: Set[str] = {
    ".exe",
    ".bat",
    ".cmd",
    ".ps1",
    ".sh",
    ".bash",
    ".zsh",
    ".dll",
    ".so",
    ".dylib",
    ".reg",
    ".msi",
    ".apk",
    ".jar",
}

DEFAULT_ADMIN_ROLES: Set[str] = {
    "owner",
    "admin",
    "workspace_owner",
    "super_admin",
}


# -------------------------------------------------------------------------
# Data structures
# -------------------------------------------------------------------------

@dataclass
class PermissionRule:
    """
    Defines one local permission rule for a category/action.

    Attributes:
        name:
            Human-readable rule name.
        category:
            Action category this rule applies to.
        allowed_roles:
            Roles that may pass local permission checks.
        denied_roles:
            Roles explicitly denied.
        risk_level:
            Risk assigned when this rule matches.
        requires_security:
            Whether the action must be sent to Security Agent.
        requires_user_confirmation:
            Whether the user must confirm before execution.
        requires_admin:
            Whether admin/workspace owner approval is required.
        blocked:
            Whether this action is always blocked locally.
        description:
            Clear explanation for audit/dashboard.
    """

    name: str
    category: ActionCategory
    allowed_roles: Set[str] = field(default_factory=set)
    denied_roles: Set[str] = field(default_factory=set)
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    requires_security: bool = True
    requires_user_confirmation: bool = False
    requires_admin: bool = False
    blocked: bool = False
    description: str = ""


@dataclass
class PermissionRequest:
    """
    Normalized local permission request.

    This object is used internally before converting to structured dict result.
    """

    action: str
    category: ActionCategory = ActionCategory.UNKNOWN
    user_id: Optional[Union[str, int]] = None
    workspace_id: Optional[Union[str, int]] = None
    role: Optional[str] = None
    task_id: Optional[str] = None
    agent_name: str = "SystemAgent"
    resource: Optional[str] = None
    command: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    requested_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class PermissionEvaluation:
    """
    Evaluation result before final structured response.
    """

    request_id: str
    decision: PermissionDecision
    risk_level: RiskLevel
    approval_type: ApprovalType
    message: str
    allowed: bool = False
    requires_security: bool = False
    reasons: List[str] = field(default_factory=list)
    violations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    matched_rules: List[str] = field(default_factory=list)
    security_payload: Optional[Dict[str, Any]] = None
    verification_payload: Optional[Dict[str, Any]] = None
    memory_payload: Optional[Dict[str, Any]] = None
    audit_event: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# -------------------------------------------------------------------------
# SystemPermissionGuard
# -------------------------------------------------------------------------

class SystemPermissionGuard(BaseAgent):
    """
    Local permission guard for risky System Agent actions.

    Responsibilities:
        1. Validate SaaS context with user_id and workspace_id.
        2. Classify system-level action risk.
        3. Apply local permissions before Security Agent.
        4. Block clearly unsafe/destructive operations.
        5. Prepare Security Agent approval payload.
        6. Prepare Verification Agent payload.
        7. Prepare Memory Agent payload.
        8. Emit agent events and audit logs.
        9. Return structured JSON-style result.

    This class does not execute actions. It only evaluates permission.
    """

    agent_name = "SystemPermissionGuard"
    agent_module = "System Agent"
    version = "1.0.0"

    def __init__(
        self,
        *,
        strict_mode: Optional[bool] = None,
        allow_unknown_actions: Optional[bool] = None,
        audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        security_requester: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        rules: Optional[List[PermissionRule]] = None,
    ) -> None:
        """
        Initialize the SystemPermissionGuard.

        Args:
            strict_mode:
                If True, missing SaaS context or unknown actions are denied.
            allow_unknown_actions:
                If True, unknown actions may continue with security approval.
            audit_sink:
                Optional callable for dashboard/API audit logging.
            event_sink:
                Optional callable for agent events.
            security_requester:
                Optional callable that sends approval request to Security Agent.
            rules:
                Optional custom permission rules.
        """

        super().__init__(agent_name=self.agent_name)

        self.strict_mode = (
            bool(strict_mode)
            if strict_mode is not None
            else bool(getattr(settings, "SYSTEM_AGENT_PERMISSION_STRICT_MODE", True))
        )

        self.allow_unknown_actions = (
            bool(allow_unknown_actions)
            if allow_unknown_actions is not None
            else bool(getattr(settings, "SYSTEM_AGENT_ALLOW_UNKNOWN_ACTIONS", False))
        )

        self.audit_enabled = bool(
            getattr(settings, "SYSTEM_AGENT_AUDIT_ENABLED", True)
        )
        self.memory_enabled = bool(
            getattr(settings, "SYSTEM_AGENT_MEMORY_ENABLED", True)
        )
        self.verification_enabled = bool(
            getattr(settings, "SYSTEM_AGENT_VERIFICATION_ENABLED", True)
        )

        self.audit_sink = audit_sink
        self.event_sink = event_sink
        self.security_requester = security_requester

        self.rules: List[PermissionRule] = rules or self._default_rules()

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def check_permission(
        self,
        action: str,
        *,
        category: Optional[Union[str, ActionCategory]] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        task_id: Optional[str] = None,
        resource: Optional[str] = None,
        command: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        context: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Main public permission check method.

        Args:
            action:
                Action name requested by System Agent.
            category:
                Optional explicit category.
            user_id:
                SaaS user ID.
            workspace_id:
                SaaS workspace ID.
            role:
                User role in workspace.
            task_id:
                Optional task identifier from Master Agent/Task Manager.
            resource:
                Optional file path, app name, device ID, URL, etc.
            command:
                Optional OS command string.
            payload:
                Action payload.
            metadata:
                Additional context for audit/security/memory.
            context:
                Optional AgentContext or dict-like object.

        Returns:
            Structured dict with success, message, data, error, metadata.
        """

        started = time.time()
        request_id = self._new_request_id()

        try:
            normalized = self._build_permission_request(
                action=action,
                category=category,
                user_id=user_id,
                workspace_id=workspace_id,
                role=role,
                task_id=task_id,
                resource=resource,
                command=command,
                payload=payload or {},
                metadata=metadata or {},
                context=context,
            )

            validation = self._validate_task_context(normalized)
            if not validation["success"]:
                evaluation = PermissionEvaluation(
                    request_id=request_id,
                    decision=PermissionDecision.DENY,
                    risk_level=RiskLevel.UNKNOWN,
                    approval_type=ApprovalType.NONE,
                    allowed=False,
                    requires_security=False,
                    message=validation["message"],
                    violations=validation.get("data", {}).get("violations", []),
                    metadata={
                        "duration_ms": self._duration_ms(started),
                        "stage": "context_validation",
                    },
                )
                return self._finalize_evaluation(normalized, evaluation)

            evaluation = self._evaluate_request(normalized, request_id=request_id)
            evaluation.metadata["duration_ms"] = self._duration_ms(started)

            return self._finalize_evaluation(normalized, evaluation)

        except Exception as exc:
            logger.exception("Permission check failed unexpectedly.")
            return self._error_result(
                message="Permission guard failed unexpectedly.",
                error=str(exc),
                metadata={
                    "request_id": request_id,
                    "action": action,
                    "duration_ms": self._duration_ms(started),
                },
            )

    def can_execute(
        self,
        action: str,
        **kwargs: Any,
    ) -> bool:
        """
        Convenience boolean method.

        Returns True only when local guard allows execution without additional
        approval. If Security Agent approval is required, this returns False
        until approval is granted outside this method.
        """

        result = self.check_permission(action, **kwargs)
        data = result.get("data", {})
        return bool(
            result.get("success")
            and data.get("allowed") is True
            and data.get("decision") == PermissionDecision.ALLOW.value
        )

    def require_security_check(
        self,
        action: str,
        **kwargs: Any,
    ) -> bool:
        """
        Convenience method to determine whether Security Agent approval is needed.
        """

        result = self.check_permission(action, **kwargs)
        data = result.get("data", {})
        return bool(data.get("requires_security"))

    def register_rule(self, rule: PermissionRule) -> Dict[str, Any]:
        """
        Add a new local permission rule.

        This supports future plugin-style agents and dashboard-configurable rules.
        """

        if not isinstance(rule, PermissionRule):
            return self._error_result(
                message="Invalid permission rule.",
                error="rule must be a PermissionRule instance.",
            )

        self.rules.append(rule)
        self._emit_agent_event(
            event_type="permission_rule_registered",
            payload={"rule": asdict(rule)},
        )

        return self._safe_result(
            message="Permission rule registered successfully.",
            data={"rule": asdict(rule), "total_rules": len(self.rules)},
        )

    def list_rules(self) -> Dict[str, Any]:
        """
        List registered permission rules.
        """

        return self._safe_result(
            message="Permission rules loaded.",
            data={
                "rules": [self._serialize_rule(rule) for rule in self.rules],
                "total": len(self.rules),
            },
        )

    def classify_action(
        self,
        action: str,
        *,
        category: Optional[Union[str, ActionCategory]] = None,
        resource: Optional[str] = None,
        command: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Public action classification method.

        Useful for dashboard previews before the user presses Run/Start.
        """

        normalized_category = self._normalize_category(category)
        if normalized_category == ActionCategory.UNKNOWN:
            normalized_category = self._infer_category(action, payload or {})

        risk, reasons, warnings = self._classify_risk(
            action=action,
            category=normalized_category,
            resource=resource,
            command=command,
            payload=payload or {},
        )

        return self._safe_result(
            message="Action classified successfully.",
            data={
                "action": action,
                "category": normalized_category.value,
                "risk_level": risk.value,
                "reasons": reasons,
                "warnings": warnings,
            },
        )

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------

    def _build_permission_request(
        self,
        *,
        action: str,
        category: Optional[Union[str, ActionCategory]],
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        role: Optional[str],
        task_id: Optional[str],
        resource: Optional[str],
        command: Optional[str],
        payload: Dict[str, Any],
        metadata: Dict[str, Any],
        context: Optional[Any],
    ) -> PermissionRequest:
        """
        Normalize explicit arguments and optional AgentContext into one request.
        """

        context_values = self._extract_context(context)

        resolved_user_id = user_id if user_id is not None else context_values.get("user_id")
        resolved_workspace_id = (
            workspace_id
            if workspace_id is not None
            else context_values.get("workspace_id")
        )
        resolved_role = role if role is not None else context_values.get("role")
        resolved_task_id = task_id if task_id is not None else context_values.get("task_id")

        merged_metadata = {
            **context_values.get("metadata", {}),
            **metadata,
        }

        normalized_category = self._normalize_category(category)
        if normalized_category == ActionCategory.UNKNOWN:
            normalized_category = self._infer_category(action, payload)

        return PermissionRequest(
            action=str(action or "").strip(),
            category=normalized_category,
            user_id=resolved_user_id,
            workspace_id=resolved_workspace_id,
            role=str(resolved_role or "member").strip().lower(),
            task_id=str(resolved_task_id) if resolved_task_id else None,
            agent_name=str(context_values.get("agent_name") or "SystemAgent"),
            resource=resource or payload.get("resource") or payload.get("path"),
            command=command or payload.get("command"),
            payload=payload,
            metadata=merged_metadata,
        )

    def _evaluate_request(
        self,
        request: PermissionRequest,
        *,
        request_id: str,
    ) -> PermissionEvaluation:
        """
        Evaluate local permission rules and risk signals.
        """

        risk, risk_reasons, warnings = self._classify_risk(
            action=request.action,
            category=request.category,
            resource=request.resource,
            command=request.command,
            payload=request.payload,
        )

        matched_rules = self._match_rules(request)
        violations: List[str] = []
        reasons: List[str] = list(risk_reasons)

        blocked_by_rule = False
        requires_security = self._requires_security_check(request, risk)
        requires_user_confirmation = False
        requires_admin = False

        for rule in matched_rules:
            reasons.append(f"Matched rule: {rule.name}")
            if rule.description:
                reasons.append(rule.description)

            if rule.blocked:
                blocked_by_rule = True
                violations.append(f"Blocked by rule: {rule.name}")

            if request.role in rule.denied_roles:
                blocked_by_rule = True
                violations.append(
                    f"Role '{request.role}' is denied by rule: {rule.name}"
                )

            if rule.allowed_roles and request.role not in rule.allowed_roles:
                violations.append(
                    f"Role '{request.role}' is not in allowed roles for rule: {rule.name}"
                )
                if rule.requires_admin:
                    requires_admin = True
                else:
                    blocked_by_rule = True

            requires_security = requires_security or rule.requires_security
            requires_user_confirmation = (
                requires_user_confirmation or rule.requires_user_confirmation
            )
            requires_admin = requires_admin or rule.requires_admin

            risk = self._max_risk(risk, rule.risk_level)

        direct_violations = self._direct_safety_violations(request)
        violations.extend(direct_violations)

        if direct_violations:
            blocked_by_rule = True

        if risk in {RiskLevel.HIGH, RiskLevel.CRITICAL, RiskLevel.DESTRUCTIVE}:
            requires_security = True

        if risk in {RiskLevel.CRITICAL, RiskLevel.DESTRUCTIVE}:
            requires_user_confirmation = True

        if request.category == ActionCategory.UNKNOWN and not self.allow_unknown_actions:
            violations.append("Unknown action category is not allowed in current mode.")
            blocked_by_rule = True

        if request.category == ActionCategory.UNKNOWN and self.allow_unknown_actions:
            requires_security = True
            warnings.append("Unknown action allowed only with Security Agent approval.")

        if blocked_by_rule:
            return PermissionEvaluation(
                request_id=request_id,
                decision=PermissionDecision.DENY,
                risk_level=risk,
                approval_type=ApprovalType.NONE,
                allowed=False,
                requires_security=False,
                message="Permission denied by local System Agent guard.",
                reasons=reasons,
                violations=violations,
                warnings=warnings,
                matched_rules=[rule.name for rule in matched_rules],
                metadata={
                    "category": request.category.value,
                    "role": request.role,
                    "strict_mode": self.strict_mode,
                },
            )

        if requires_admin and not self._is_admin_role(request.role):
            return PermissionEvaluation(
                request_id=request_id,
                decision=PermissionDecision.REQUIRE_ADMIN_APPROVAL,
                risk_level=risk,
                approval_type=ApprovalType.ADMIN,
                allowed=False,
                requires_security=True,
                message="Admin approval is required before this System Agent action.",
                reasons=reasons,
                violations=violations,
                warnings=warnings,
                matched_rules=[rule.name for rule in matched_rules],
                metadata={
                    "category": request.category.value,
                    "role": request.role,
                    "strict_mode": self.strict_mode,
                },
            )

        if requires_security:
            security_payload = self._request_security_approval(request, risk, reasons)

            return PermissionEvaluation(
                request_id=request_id,
                decision=PermissionDecision.REQUIRE_SECURITY_APPROVAL,
                risk_level=risk,
                approval_type=ApprovalType.SECURITY_AGENT,
                allowed=False,
                requires_security=True,
                message="Security Agent approval is required before execution.",
                reasons=reasons,
                violations=violations,
                warnings=warnings,
                matched_rules=[rule.name for rule in matched_rules],
                security_payload=security_payload,
                metadata={
                    "category": request.category.value,
                    "role": request.role,
                    "strict_mode": self.strict_mode,
                },
            )

        if requires_user_confirmation:
            return PermissionEvaluation(
                request_id=request_id,
                decision=PermissionDecision.REQUIRE_USER_CONFIRMATION,
                risk_level=risk,
                approval_type=ApprovalType.USER_CONFIRMATION,
                allowed=False,
                requires_security=False,
                message="User confirmation is required before execution.",
                reasons=reasons,
                violations=violations,
                warnings=warnings,
                matched_rules=[rule.name for rule in matched_rules],
                metadata={
                    "category": request.category.value,
                    "role": request.role,
                    "strict_mode": self.strict_mode,
                },
            )

        return PermissionEvaluation(
            request_id=request_id,
            decision=PermissionDecision.ALLOW,
            risk_level=risk,
            approval_type=ApprovalType.NONE,
            allowed=True,
            requires_security=False,
            message="Permission granted by local System Agent guard.",
            reasons=reasons,
            violations=violations,
            warnings=warnings,
            matched_rules=[rule.name for rule in matched_rules],
            metadata={
                "category": request.category.value,
                "role": request.role,
                "strict_mode": self.strict_mode,
            },
        )

    def _finalize_evaluation(
        self,
        request: PermissionRequest,
        evaluation: PermissionEvaluation,
    ) -> Dict[str, Any]:
        """
        Add audit, memory, verification, events, and final structured response.
        """

        if self.verification_enabled:
            evaluation.verification_payload = self._prepare_verification_payload(
                request,
                evaluation,
            )

        if self.memory_enabled:
            evaluation.memory_payload = self._prepare_memory_payload(
                request,
                evaluation,
            )

        if self.audit_enabled:
            evaluation.audit_event = self._log_audit_event(request, evaluation)

        self._emit_agent_event(
            event_type="system_permission_evaluated",
            payload={
                "request_id": evaluation.request_id,
                "action": request.action,
                "category": request.category.value,
                "decision": evaluation.decision.value,
                "risk_level": evaluation.risk_level.value,
                "user_id": request.user_id,
                "workspace_id": request.workspace_id,
                "task_id": request.task_id,
            },
        )

        data = {
            "request_id": evaluation.request_id,
            "allowed": evaluation.allowed,
            "decision": evaluation.decision.value,
            "risk_level": evaluation.risk_level.value,
            "approval_type": evaluation.approval_type.value,
            "requires_security": evaluation.requires_security,
            "reasons": evaluation.reasons,
            "violations": evaluation.violations,
            "warnings": evaluation.warnings,
            "matched_rules": evaluation.matched_rules,
            "security_payload": evaluation.security_payload,
            "verification_payload": evaluation.verification_payload,
            "memory_payload": evaluation.memory_payload,
            "audit_event": evaluation.audit_event,
        }

        metadata = {
            **evaluation.metadata,
            "agent_name": self.agent_name,
            "agent_module": self.agent_module,
            "version": self.version,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "task_id": request.task_id,
        }

        success = evaluation.decision != PermissionDecision.DENY

        return self._safe_result(
            success=success,
            message=evaluation.message,
            data=data,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        request: PermissionRequest,
    ) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation context.

        Required by architecture:
            - Every user-specific action needs user_id.
            - Every workspace action needs workspace_id.
            - Missing context is denied in strict mode.
        """

        violations: List[str] = []

        if not request.action:
            violations.append("Missing action.")

        if request.user_id in (None, "", "None"):
            violations.append("Missing user_id.")

        if request.workspace_id in (None, "", "None"):
            violations.append("Missing workspace_id.")

        if not request.role:
            violations.append("Missing role.")

        if violations and self.strict_mode:
            return self._safe_result(
                success=False,
                message="Task context validation failed.",
                data={"violations": violations},
            )

        return self._safe_result(
            success=True,
            message="Task context validated successfully.",
            data={"violations": violations},
        )

    def _requires_security_check(
        self,
        request: PermissionRequest,
        risk_level: Optional[RiskLevel] = None,
    ) -> bool:
        """
        Decide whether this action must go through Security Agent.

        Required hook for Security Agent compatibility.
        """

        risk = risk_level or RiskLevel.UNKNOWN

        if request.category in {
            ActionCategory.OS_COMMAND,
            ActionCategory.FILE_DELETE,
            ActionCategory.FILE_PERMISSION,
            ActionCategory.DEVICE_CONTROL,
            ActionCategory.MESSAGE_SEND,
            ActionCategory.CALL_ACTION,
            ActionCategory.CONFIGURATION,
            ActionCategory.SECURITY,
            ActionCategory.GESTURE_CONTROL,
        }:
            return True

        if risk in {
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
            RiskLevel.DESTRUCTIVE,
            RiskLevel.UNKNOWN,
        }:
            return bool(
                getattr(settings, "SYSTEM_AGENT_DEFAULT_REQUIRE_SECURITY", True)
            )

        return False

    def _request_security_approval(
        self,
        request: PermissionRequest,
        risk_level: RiskLevel,
        reasons: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare or dispatch Security Agent approval payload.

        If a security_requester callable is provided, this method attempts to
        pass the payload to it safely. Otherwise, it returns a ready-to-send
        payload for Master Agent/Router/Security Agent.
        """

        payload = {
            "approval_request_id": self._new_request_id(prefix="sec"),
            "source_agent": self.agent_name,
            "target_agent": "SecurityAgent",
            "approval_type": ApprovalType.SECURITY_AGENT.value,
            "action": request.action,
            "category": request.category.value,
            "risk_level": risk_level.value,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "role": request.role,
            "task_id": request.task_id,
            "resource": self._redact_sensitive_value(request.resource),
            "command": self._redact_sensitive_value(request.command),
            "payload_summary": self._safe_payload_summary(request.payload),
            "reasons": reasons or [],
            "metadata": {
                "requested_at": datetime.now(timezone.utc).isoformat(),
                "system_permission_guard_version": self.version,
                "strict_mode": self.strict_mode,
            },
        }

        if self.security_requester:
            try:
                response = self.security_requester(payload)
                payload["security_agent_response"] = response
            except Exception as exc:
                logger.warning("Security requester callable failed: %s", exc)
                payload["security_agent_response_error"] = str(exc)

        return payload

    def _prepare_verification_payload(
        self,
        request: PermissionRequest,
        evaluation: PermissionEvaluation,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        The Verification Agent can use this after the requested system action
        completes to confirm whether the action matched the approved scope.
        """

        return {
            "verification_id": self._new_request_id(prefix="ver"),
            "source_agent": self.agent_name,
            "target_agent": "VerificationAgent",
            "action": request.action,
            "category": request.category.value,
            "decision": evaluation.decision.value,
            "allowed": evaluation.allowed,
            "risk_level": evaluation.risk_level.value,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "task_id": request.task_id,
            "resource": self._redact_sensitive_value(request.resource),
            "expected_result_contract": {
                "must_return_structured_result": True,
                "must_include_success": True,
                "must_include_message": True,
                "must_include_data_or_error": True,
                "must_preserve_user_workspace_isolation": True,
            },
            "metadata": {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "guard_request_id": evaluation.request_id,
            },
        }

    def _prepare_memory_payload(
        self,
        request: PermissionRequest,
        evaluation: PermissionEvaluation,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        This payload stores useful permission context without leaking secrets.
        """

        return {
            "memory_id": self._new_request_id(prefix="mem"),
            "source_agent": self.agent_name,
            "target_agent": "MemoryAgent",
            "memory_type": "system_permission_decision",
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "task_id": request.task_id,
            "content": {
                "action": request.action,
                "category": request.category.value,
                "decision": evaluation.decision.value,
                "risk_level": evaluation.risk_level.value,
                "approval_type": evaluation.approval_type.value,
                "reasons": evaluation.reasons[:10],
                "warnings": evaluation.warnings[:10],
            },
            "metadata": {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "safe_to_store": True,
                "contains_secret": False,
                "guard_request_id": evaluation.request_id,
            },
        }

    def _emit_agent_event(
        self,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Emit agent event for dashboard/API/task history.

        If an event sink exists, the event is sent there. Otherwise, it is logged.
        """

        event = {
            "event_id": self._new_request_id(prefix="evt"),
            "event_type": event_type,
            "source_agent": self.agent_name,
            "agent_module": self.agent_module,
            "payload": payload or {},
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        if self.event_sink:
            try:
                self.event_sink(event)
            except Exception as exc:
                logger.warning("Event sink failed: %s", exc)

        logger.debug("Agent event emitted: %s", event)
        return event

    def _log_audit_event(
        self,
        request: PermissionRequest,
        evaluation: PermissionEvaluation,
    ) -> Dict[str, Any]:
        """
        Create audit event for SaaS dashboard/API.

        This must never mix users/workspaces. The event always includes
        user_id and workspace_id.
        """

        audit_event = {
            "audit_id": self._new_request_id(prefix="aud"),
            "source_agent": self.agent_name,
            "agent_module": self.agent_module,
            "action": request.action,
            "category": request.category.value,
            "decision": evaluation.decision.value,
            "allowed": evaluation.allowed,
            "risk_level": evaluation.risk_level.value,
            "approval_type": evaluation.approval_type.value,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "role": request.role,
            "task_id": request.task_id,
            "resource": self._redact_sensitive_value(request.resource),
            "command": self._redact_sensitive_value(request.command),
            "violations": evaluation.violations,
            "warnings": evaluation.warnings,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "metadata": {
                "guard_request_id": evaluation.request_id,
                "strict_mode": self.strict_mode,
                "version": self.version,
            },
        }

        if self.audit_sink:
            try:
                self.audit_sink(audit_event)
            except Exception as exc:
                logger.warning("Audit sink failed: %s", exc)

        logger.info(
            "Audit permission event: action=%s decision=%s risk=%s user=%s workspace=%s",
            request.action,
            evaluation.decision.value,
            evaluation.risk_level.value,
            request.user_id,
            request.workspace_id,
        )

        return audit_event

    def _safe_result(
        self,
        *,
        success: bool = True,
        message: str = "Success.",
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis structured success result.
        """

        return {
            "success": success,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Optional[Any] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis structured error result.
        """

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    # ------------------------------------------------------------------
    # Risk classification and rules
    # ------------------------------------------------------------------

    def _classify_risk(
        self,
        *,
        action: str,
        category: ActionCategory,
        resource: Optional[str],
        command: Optional[str],
        payload: Dict[str, Any],
    ) -> Tuple[RiskLevel, List[str], List[str]]:
        """
        Classify action risk using local deterministic checks.
        """

        action_lower = str(action or "").lower()
        command_lower = str(command or "").lower()
        resource_lower = str(resource or "").lower()

        reasons: List[str] = []
        warnings: List[str] = []

        risk = RiskLevel.LOW

        if category == ActionCategory.UNKNOWN:
            risk = RiskLevel.UNKNOWN
            reasons.append("Action category is unknown.")

        category_risk = self._base_category_risk(category)
        risk = self._max_risk(risk, category_risk)
        reasons.append(f"Base category risk: {category_risk.value}")

        destructive_terms = {
            "delete",
            "remove",
            "wipe",
            "format",
            "kill",
            "terminate",
            "shutdown",
            "reboot",
            "reset",
            "factory",
            "erase",
            "purge",
        }

        if any(term in action_lower for term in destructive_terms):
            risk = self._max_risk(risk, RiskLevel.HIGH)
            reasons.append("Action name contains destructive/control keyword.")

        if command:
            command_risk = self._classify_command_risk(command_lower)
            risk = self._max_risk(risk, command_risk)
            reasons.append(f"Command risk: {command_risk.value}")

        if resource:
            resource_risk = self._classify_resource_risk(resource_lower)
            risk = self._max_risk(risk, resource_risk)
            reasons.append(f"Resource risk: {resource_risk.value}")

        if payload.get("requires_admin") is True:
            risk = self._max_risk(risk, RiskLevel.HIGH)
            reasons.append("Payload requested admin-level execution.")

        if payload.get("destructive") is True:
            risk = self._max_risk(risk, RiskLevel.DESTRUCTIVE)
            reasons.append("Payload explicitly marked destructive.")

        if payload.get("external_network") is True:
            risk = self._max_risk(risk, RiskLevel.MEDIUM)
            reasons.append("Payload includes external network interaction.")

        if payload.get("contains_user_data") is True:
            risk = self._max_risk(risk, RiskLevel.MEDIUM)
            warnings.append("Payload may contain user data.")

        if payload.get("contains_secret") is True:
            risk = self._max_risk(risk, RiskLevel.HIGH)
            warnings.append("Payload may contain secrets.")

        return risk, reasons, warnings

    def _base_category_risk(self, category: ActionCategory) -> RiskLevel:
        """
        Default risk assigned by category.
        """

        if category in {
            ActionCategory.FILE_READ,
            ActionCategory.NOTIFICATION_READ,
            ActionCategory.CLIPBOARD,
        }:
            return RiskLevel.LOW

        if category in {
            ActionCategory.FILE_WRITE,
            ActionCategory.FILE_MOVE,
            ActionCategory.APP_CONTROL,
            ActionCategory.AUTOMATION,
            ActionCategory.BROWSER_ACTION,
            ActionCategory.SCREEN_CAPTURE,
            ActionCategory.DESKTOP_VISION,
            ActionCategory.NETWORK,
            ActionCategory.SYSTEM_MEMORY,
        }:
            return RiskLevel.MEDIUM

        if category in {
            ActionCategory.OS_COMMAND,
            ActionCategory.DEVICE_CONTROL,
            ActionCategory.MESSAGE_SEND,
            ActionCategory.CALL_ACTION,
            ActionCategory.GESTURE_CONTROL,
            ActionCategory.CONFIGURATION,
            ActionCategory.SECURITY,
        }:
            return RiskLevel.HIGH

        if category in {
            ActionCategory.FILE_DELETE,
            ActionCategory.FILE_PERMISSION,
        }:
            return RiskLevel.CRITICAL

        return RiskLevel.UNKNOWN

    def _classify_command_risk(self, command_lower: str) -> RiskLevel:
        """
        Classify command string risk without executing it.
        """

        if not command_lower.strip():
            return RiskLevel.LOW

        if any(keyword.lower() in command_lower for keyword in DEFAULT_DENIED_COMMAND_KEYWORDS):
            return RiskLevel.DESTRUCTIVE

        risky_markers = [
            "sudo",
            "admin",
            "powershell",
            "cmd.exe",
            "bash -c",
            "sh -c",
            "curl",
            "wget",
            "chmod",
            "chown",
            "kill",
            "taskkill",
            "sc delete",
            "systemctl",
            "launchctl",
            "crontab",
            "schtasks",
        ]

        if any(marker in command_lower for marker in risky_markers):
            return RiskLevel.HIGH

        write_markers = [
            ">",
            ">>",
            "tee",
            "copy",
            "move",
            "mv ",
            "cp ",
            "mkdir",
            "touch",
            "echo ",
        ]

        if any(marker in command_lower for marker in write_markers):
            return RiskLevel.MEDIUM

        return RiskLevel.LOW

    def _classify_resource_risk(self, resource_lower: str) -> RiskLevel:
        """
        Classify file/app/device/network resource risk.
        """

        if not resource_lower.strip():
            return RiskLevel.LOW

        if any(fragment.lower() in resource_lower for fragment in DEFAULT_SENSITIVE_PATH_FRAGMENTS):
            return RiskLevel.HIGH

        if any(resource_lower.endswith(ext) for ext in DEFAULT_HIGH_RISK_EXTENSIONS):
            return RiskLevel.HIGH

        if resource_lower.startswith(("http://", "https://")):
            return RiskLevel.MEDIUM

        if any(resource_lower.endswith(ext) for ext in DEFAULT_SAFE_READ_EXTENSIONS):
            return RiskLevel.LOW

        return RiskLevel.MEDIUM

    def _direct_safety_violations(
        self,
        request: PermissionRequest,
    ) -> List[str]:
        """
        Hard-block known dangerous requests.
        """

        violations: List[str] = []
        command_lower = str(request.command or "").lower()
        resource_lower = str(request.resource or "").lower()

        for keyword in DEFAULT_DENIED_COMMAND_KEYWORDS:
            if keyword.lower() in command_lower:
                violations.append(
                    f"Command contains blocked dangerous keyword: {keyword}"
                )

        if request.category == ActionCategory.FILE_DELETE:
            if resource_lower in {"/", "/*", "c:\\", "c:\\*", "."}:
                violations.append("Refusing to delete root/current/global path.")

        if request.category == ActionCategory.FILE_PERMISSION:
            if "777" in command_lower or "everyone" in command_lower:
                violations.append("Unsafe broad permission change blocked.")

        if request.payload.get("bypass_security") is True:
            violations.append("Security bypass request is not allowed.")

        if request.payload.get("ignore_permissions") is True:
            violations.append("Permission bypass request is not allowed.")

        return violations

    def _match_rules(self, request: PermissionRequest) -> List[PermissionRule]:
        """
        Match local permission rules by category and action.
        """

        matched: List[PermissionRule] = []

        for rule in self.rules:
            if rule.category == request.category:
                matched.append(rule)

        return matched

    def _default_rules(self) -> List[PermissionRule]:
        """
        Default local permission rules for System Agent.
        """

        return [
            PermissionRule(
                name="safe_file_read",
                category=ActionCategory.FILE_READ,
                allowed_roles={"viewer", "member", "operator", "admin", "owner", "workspace_owner", "super_admin"},
                risk_level=RiskLevel.LOW,
                requires_security=False,
                requires_user_confirmation=False,
                requires_admin=False,
                description="Reading normal files is allowed locally when SaaS context is valid.",
            ),
            PermissionRule(
                name="file_write_requires_security",
                category=ActionCategory.FILE_WRITE,
                allowed_roles={"member", "operator", "admin", "owner", "workspace_owner", "super_admin"},
                risk_level=RiskLevel.MEDIUM,
                requires_security=True,
                requires_user_confirmation=False,
                requires_admin=False,
                description="Writing files requires Security Agent approval.",
            ),
            PermissionRule(
                name="file_delete_requires_security_and_confirmation",
                category=ActionCategory.FILE_DELETE,
                allowed_roles={"admin", "owner", "workspace_owner", "super_admin"},
                risk_level=RiskLevel.CRITICAL,
                requires_security=True,
                requires_user_confirmation=True,
                requires_admin=True,
                description="Deleting files requires admin role, Security Agent approval, and user confirmation.",
            ),
            PermissionRule(
                name="os_commands_high_risk",
                category=ActionCategory.OS_COMMAND,
                allowed_roles={"operator", "admin", "owner", "workspace_owner", "super_admin"},
                risk_level=RiskLevel.HIGH,
                requires_security=True,
                requires_user_confirmation=True,
                requires_admin=False,
                description="OS commands are high risk and must go through Security Agent.",
            ),
            PermissionRule(
                name="device_control_high_risk",
                category=ActionCategory.DEVICE_CONTROL,
                allowed_roles={"operator", "admin", "owner", "workspace_owner", "super_admin"},
                risk_level=RiskLevel.HIGH,
                requires_security=True,
                requires_user_confirmation=True,
                description="Device controls may affect user environment and require approval.",
            ),
            PermissionRule(
                name="automation_medium_risk",
                category=ActionCategory.AUTOMATION,
                allowed_roles={"member", "operator", "admin", "owner", "workspace_owner", "super_admin"},
                risk_level=RiskLevel.MEDIUM,
                requires_security=True,
                requires_user_confirmation=False,
                description="Automation tasks require Security Agent review before execution.",
            ),
            PermissionRule(
                name="message_send_requires_security",
                category=ActionCategory.MESSAGE_SEND,
                allowed_roles={"operator", "admin", "owner", "workspace_owner", "super_admin"},
                risk_level=RiskLevel.HIGH,
                requires_security=True,
                requires_user_confirmation=True,
                description="Sending messages requires approval to avoid unauthorized communication.",
            ),
            PermissionRule(
                name="call_action_requires_security",
                category=ActionCategory.CALL_ACTION,
                allowed_roles={"operator", "admin", "owner", "workspace_owner", "super_admin"},
                risk_level=RiskLevel.HIGH,
                requires_security=True,
                requires_user_confirmation=True,
                description="Call actions require approval to prevent unauthorized calls.",
            ),
            PermissionRule(
                name="screen_capture_privacy_review",
                category=ActionCategory.SCREEN_CAPTURE,
                allowed_roles={"member", "operator", "admin", "owner", "workspace_owner", "super_admin"},
                risk_level=RiskLevel.MEDIUM,
                requires_security=True,
                requires_user_confirmation=True,
                description="Screen capture can expose private data and requires review.",
            ),
            PermissionRule(
                name="configuration_admin_only",
                category=ActionCategory.CONFIGURATION,
                allowed_roles={"admin", "owner", "workspace_owner", "super_admin"},
                risk_level=RiskLevel.HIGH,
                requires_security=True,
                requires_user_confirmation=True,
                requires_admin=True,
                description="Configuration changes are admin-only and require Security Agent approval.",
            ),
            PermissionRule(
                name="security_actions_admin_only",
                category=ActionCategory.SECURITY,
                allowed_roles={"admin", "owner", "workspace_owner", "super_admin"},
                risk_level=RiskLevel.CRITICAL,
                requires_security=True,
                requires_user_confirmation=True,
                requires_admin=True,
                description="Security actions require privileged approval.",
            ),
        ]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _normalize_category(
        self,
        category: Optional[Union[str, ActionCategory]],
    ) -> ActionCategory:
        """
        Convert category string/enum to ActionCategory.
        """

        if isinstance(category, ActionCategory):
            return category

        if not category:
            return ActionCategory.UNKNOWN

        category_str = str(category).strip().lower()

        for item in ActionCategory:
            if item.value == category_str or item.name.lower() == category_str:
                return item

        return ActionCategory.UNKNOWN

    def _infer_category(
        self,
        action: str,
        payload: Dict[str, Any],
    ) -> ActionCategory:
        """
        Infer category from action name and payload.
        """

        text = f"{action} {' '.join(str(k) for k in payload.keys())}".lower()

        mapping: List[Tuple[ActionCategory, Iterable[str]]] = [
            (ActionCategory.OS_COMMAND, ["command", "shell", "terminal", "cmd", "powershell"]),
            (ActionCategory.FILE_DELETE, ["delete_file", "remove_file", "unlink", "delete path"]),
            (ActionCategory.FILE_WRITE, ["write_file", "save_file", "create_file", "append_file"]),
            (ActionCategory.FILE_READ, ["read_file", "open_file", "load_file"]),
            (ActionCategory.FILE_MOVE, ["move_file", "rename_file", "copy_file"]),
            (ActionCategory.FILE_PERMISSION, ["chmod", "permission", "chown", "access mode"]),
            (ActionCategory.APP_CONTROL, ["open_app", "close_app", "launch_app", "app_control"]),
            (ActionCategory.DEVICE_CONTROL, ["device", "volume", "brightness", "wifi", "bluetooth"]),
            (ActionCategory.AUTOMATION, ["automation", "schedule", "macro", "workflow"]),
            (ActionCategory.NOTIFICATION_READ, ["notification"]),
            (ActionCategory.MESSAGE_SEND, ["send_message", "sms", "email", "whatsapp", "telegram"]),
            (ActionCategory.CALL_ACTION, ["call", "dial", "phone"]),
            (ActionCategory.BROWSER_ACTION, ["browser", "tab", "url", "web"]),
            (ActionCategory.CLIPBOARD, ["clipboard", "copy", "paste"]),
            (ActionCategory.SCREEN_CAPTURE, ["screenshot", "screen_capture", "capture_screen"]),
            (ActionCategory.DESKTOP_VISION, ["desktop_vision", "vision", "ocr"]),
            (ActionCategory.GESTURE_CONTROL, ["gesture", "click", "tap", "swipe"]),
            (ActionCategory.NETWORK, ["network", "request", "download", "upload"]),
            (ActionCategory.SECURITY, ["security", "permission", "auth", "token"]),
            (ActionCategory.CONFIGURATION, ["config", "settings", "environment"]),
            (ActionCategory.SYSTEM_MEMORY, ["memory", "remember", "system_memory"]),
        ]

        for category, keywords in mapping:
            if any(keyword in text for keyword in keywords):
                return category

        return ActionCategory.UNKNOWN

    def _extract_context(self, context: Optional[Any]) -> Dict[str, Any]:
        """
        Extract context values from dict-like or object-like AgentContext.
        """

        if context is None:
            return {}

        if isinstance(context, dict):
            return {
                "user_id": context.get("user_id"),
                "workspace_id": context.get("workspace_id"),
                "role": context.get("role"),
                "task_id": context.get("task_id"),
                "agent_name": context.get("agent_name"),
                "metadata": context.get("metadata", {}) or {},
            }

        return {
            "user_id": getattr(context, "user_id", None),
            "workspace_id": getattr(context, "workspace_id", None),
            "role": getattr(context, "role", None),
            "task_id": getattr(context, "task_id", None),
            "agent_name": getattr(context, "agent_name", None),
            "metadata": getattr(context, "metadata", {}) or {},
        }

    def _serialize_rule(self, rule: PermissionRule) -> Dict[str, Any]:
        """
        Convert PermissionRule to JSON-safe dict.
        """

        return {
            "name": rule.name,
            "category": rule.category.value,
            "allowed_roles": sorted(rule.allowed_roles),
            "denied_roles": sorted(rule.denied_roles),
            "risk_level": rule.risk_level.value,
            "requires_security": rule.requires_security,
            "requires_user_confirmation": rule.requires_user_confirmation,
            "requires_admin": rule.requires_admin,
            "blocked": rule.blocked,
            "description": rule.description,
        }

    def _max_risk(self, left: RiskLevel, right: RiskLevel) -> RiskLevel:
        """
        Return the higher of two risk levels.
        """

        order = {
            RiskLevel.SAFE: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
            RiskLevel.DESTRUCTIVE: 5,
            RiskLevel.UNKNOWN: 3,
        }

        return left if order[left] >= order[right] else right

    def _is_admin_role(self, role: Optional[str]) -> bool:
        """
        Check if role is admin-like.
        """

        return str(role or "").strip().lower() in DEFAULT_ADMIN_ROLES

    def _safe_payload_summary(
        self,
        payload: Dict[str, Any],
        *,
        max_items: int = 30,
    ) -> Dict[str, Any]:
        """
        Create safe payload summary for Security Agent and audit.

        Secrets and long values are redacted/truncated.
        """

        summary: Dict[str, Any] = {}

        sensitive_keys = {
            "password",
            "secret",
            "token",
            "api_key",
            "private_key",
            "credential",
            "authorization",
            "cookie",
        }

        for index, (key, value) in enumerate(payload.items()):
            if index >= max_items:
                summary["_truncated"] = True
                break

            key_lower = str(key).lower()

            if any(sensitive in key_lower for sensitive in sensitive_keys):
                summary[key] = "[REDACTED]"
                continue

            summary[key] = self._redact_sensitive_value(value)

        return summary

    def _redact_sensitive_value(self, value: Any) -> Any:
        """
        Redact secrets and shorten long values.
        """

        if value is None:
            return None

        text = str(value)

        sensitive_markers = [
            "password=",
            "token=",
            "api_key=",
            "secret=",
            "authorization:",
            "bearer ",
            "private_key",
            "id_rsa",
        ]

        lowered = text.lower()

        if any(marker in lowered for marker in sensitive_markers):
            return "[REDACTED]"

        if len(text) > 300:
            return text[:300] + "...[TRUNCATED]"

        return value

    def _new_request_id(self, prefix: str = "perm") -> str:
        """
        Generate stable unique request ID.
        """

        return f"{prefix}_{uuid.uuid4().hex}"

    def _duration_ms(self, started: float) -> int:
        """
        Calculate duration in milliseconds.
        """

        return int((time.time() - started) * 1000)


# -------------------------------------------------------------------------
# Module-level convenience instance and functions
# -------------------------------------------------------------------------

_default_guard: Optional[SystemPermissionGuard] = None


def get_system_permission_guard() -> SystemPermissionGuard:
    """
    Return shared default SystemPermissionGuard instance.

    Useful for Agent Loader, Registry, Router, or FastAPI dependency injection.
    """

    global _default_guard

    if _default_guard is None:
        _default_guard = SystemPermissionGuard()

    return _default_guard


def check_system_permission(
    action: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Module-level helper for quick permission checks.

    Example:
        result = check_system_permission(
            "write_file",
            category="file_write",
            user_id=1,
            workspace_id=10,
            role="admin",
            resource="/tmp/test.txt",
        )
    """

    guard = get_system_permission_guard()
    return guard.check_permission(action, **kwargs)


__all__ = [
    "SystemPermissionGuard",
    "PermissionDecision",
    "RiskLevel",
    "ActionCategory",
    "ApprovalType",
    "PermissionRule",
    "PermissionRequest",
    "PermissionEvaluation",
    "get_system_permission_guard",
    "check_system_permission",
]


# -------------------------------------------------------------------------
# Safe manual test
# -------------------------------------------------------------------------

if __name__ == "__main__":
    guard = SystemPermissionGuard()

    demo_result = guard.check_permission(
        action="write_file",
        category="file_write",
        user_id="demo_user",
        workspace_id="demo_workspace",
        role="admin",
        resource="/tmp/demo.txt",
        payload={
            "resource": "/tmp/demo.txt",
            "contains_user_data": False,
        },
        metadata={
            "source": "manual_test",
        },
    )

    print(demo_result)