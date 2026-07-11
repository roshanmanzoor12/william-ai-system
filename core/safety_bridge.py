"""
core/safety_bridge.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Bridge that sends sensitive task payloads to Security Agent before execution.

This file is responsible for:
    - Detecting sensitive actions before execution
    - Preparing Security Agent approval requests
    - Enforcing SaaS user/workspace isolation
    - Creating structured permission/risk decisions
    - Returning safe dict/JSON style responses
    - Preparing Verification Agent payloads
    - Preparing Memory Agent payloads
    - Emitting agent/router/dashboard events
    - Logging audit-safe records
    - Remaining import-safe even if future William modules do not exist yet

Architecture Compatibility:
    - Master Agent
    - Router
    - Task Manager
    - Planner
    - Security Agent
    - Verification Agent
    - Memory Agent
    - Dashboard/API
    - Agent Registry
    - Agent Loader
    - BaseAgent compatibility
"""

from __future__ import annotations

import hashlib
import logging
import traceback
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger("william.core.safety_bridge")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# =============================================================================
# Safe Optional Imports
# =============================================================================

try:
    from core.context import TaskContext  # type: ignore
except Exception:  # pragma: no cover
    TaskContext = None  # type: ignore


try:
    from core.response_builder import ResponseBuilder  # type: ignore
except Exception:  # pragma: no cover
    ResponseBuilder = None  # type: ignore


try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover

    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent.

        Keeps this file import-safe until the real BaseAgent is generated.
        """

        agent_name = "safety_bridge"
        agent_type = "core_bridge"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.initialized_at = datetime.now(timezone.utc).isoformat()

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            logger.debug("Fallback emit_event: %s | %s", event_name, payload)

        def log_audit(self, payload: Dict[str, Any]) -> None:
            logger.info("Fallback audit log: %s", payload)


try:
    # Real path is agents.security_agent.security_agent -- this always
    # raised ImportError, so self.security_agent (see _init_security_agent
    # below) was always None regardless of anything MasterAgent did.
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


# =============================================================================
# Enums
# =============================================================================

class SafetyDecision(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"
    REVIEW = "review"
    ERROR = "error"


class RiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SensitiveActionType(str, Enum):
    SYSTEM = "system"
    FILE = "file"
    BROWSER = "browser"
    MESSAGE = "message"
    CALL = "call"
    FINANCE = "finance"
    MEMORY = "memory"
    SECURITY = "security"
    WORKFLOW = "workflow"
    USER_DATA = "user_data"
    API = "api"
    UNKNOWN = "unknown"


class SafetyStatus(str, Enum):
    SUCCESS = "success"
    ERROR = "error"
    BLOCKED = "blocked"
    APPROVAL_REQUIRED = "approval_required"
    APPROVED = "approved"
    DENIED = "denied"
    PENDING = "pending"


class AuditSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class SafetyMetadata:
    """
    Metadata attached to every safety decision.

    Keeps responses compatible with dashboard/API/task history.
    """

    user_id: Optional[Union[str, int]] = None
    workspace_id: Optional[Union[str, int]] = None
    task_id: Optional[str] = None
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    agent_name: str = "safety_bridge"
    module_name: str = "core"
    file_name: str = "safety_bridge.py"
    source: str = "SafetyBridge"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    version: str = "1.0.0"


@dataclass
class SafetyRule:
    """
    Represents a safety rule used by SafetyBridge before Security Agent approval.
    """

    rule_id: str
    name: str
    description: str
    keywords: List[str]
    action_type: str = SensitiveActionType.UNKNOWN.value
    risk_level: str = RiskLevel.MEDIUM.value
    require_approval: bool = True
    block_immediately: bool = False


@dataclass
class SafetyCheckResult:
    """
    Structured result of a local SafetyBridge check.
    """

    decision: str
    risk_level: str
    requires_security_agent: bool
    matched_rules: List[Dict[str, Any]] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    sanitized_payload: Dict[str, Any] = field(default_factory=dict)
    approval_payload: Optional[Dict[str, Any]] = None


@dataclass
class SecurityApprovalRequest:
    """
    Payload prepared for Security Agent.
    """

    approval_id: str
    user_id: Optional[Union[str, int]]
    workspace_id: Optional[Union[str, int]]
    task_id: Optional[str]
    action: str
    action_type: str
    risk_level: str
    payload_hash: str
    sanitized_payload: Dict[str, Any]
    matched_rules: List[Dict[str, Any]]
    reasons: List[str]
    requested_by: str = "safety_bridge"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = SafetyStatus.PENDING.value


# =============================================================================
# SafetyBridge
# =============================================================================

class SafetyBridge(BaseAgent):
    """
    SafetyBridge routes sensitive task payloads to the Security Agent
    before execution.

    It is designed to sit between:
        - Master Agent
        - Router
        - Planner
        - Task Manager
        - Individual agents

    and:

        - Security Agent

    Important:
        SafetyBridge does not execute dangerous actions.
        It only classifies, validates, sanitizes, approves, blocks,
        or prepares approval requests.
    """

    agent_name = "safety_bridge"
    agent_type = "core_bridge"
    module_name = "core"

    DEFAULT_COMPLETION_TRACKING = {
        "agent_module": "Core Master Control Files",
        "file_completed": "safety_bridge.py",
        "completion": 80.0,
        "completed_files": [
            "context.py",
            "config.py",
            "master_agent.py",
            "planner.py",
            "router.py",
            "task_manager.py",
            "response_builder.py",
            "safety_bridge.py",
        ],
        "remaining_files": [
            "verification_bridge.py",
            "memory_bridge.py",
        ],
        "next_recommended_file": "core/verification_bridge.py",
    }

    SENSITIVE_KEYS = {
        "password",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "private_key",
        "credential",
        "authorization",
        "cookie",
        "session",
        "otp",
        "pin",
        "card_number",
        "cvv",
        "bank_account",
    }

    def __init__(
        self,
        security_agent: Optional[Any] = None,
        strict_saas_isolation: bool = True,
        enable_audit_log: bool = True,
        enable_memory_payload: bool = True,
        enable_verification_payload: bool = True,
        default_block_unknown_critical: bool = True,
    ) -> None:
        super().__init__()

        self.strict_saas_isolation = strict_saas_isolation
        self.enable_audit_log = enable_audit_log
        self.enable_memory_payload = enable_memory_payload
        self.enable_verification_payload = enable_verification_payload
        self.default_block_unknown_critical = default_block_unknown_critical

        self.security_agent = security_agent or self._init_security_agent()
        self.response_builder = self._init_response_builder()

        self.created_at = datetime.now(timezone.utc).isoformat()
        self.rules = self._build_default_rules()

    # =========================================================================
    # Public API
    # =========================================================================

    def inspect_task(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
        context: Optional[Any] = None,
        force_security_check: bool = False,
    ) -> Dict[str, Any]:
        """
        Inspect a task before execution.

        Returns:
            Structured dict with decision:
                - allow
                - require_approval
                - block
                - review
                - error
        """

        valid, validation_error = self._validate_task_context(context)

        if not valid:
            return self._error_result(
                message="Task context validation failed.",
                error_code="CONTEXT_VALIDATION_FAILED",
                details=validation_error,
                context=context,
            )

        payload = payload or {}

        check = self._local_safety_check(
            action=action,
            payload=payload,
            context=context,
            force_security_check=force_security_check,
        )

        result_data = {
            "decision": check.decision,
            "risk_level": check.risk_level,
            "requires_security_agent": check.requires_security_agent,
            "matched_rules": check.matched_rules,
            "reasons": check.reasons,
            "sanitized_payload": check.sanitized_payload,
            "approval_payload": check.approval_payload,
        }

        if check.decision == SafetyDecision.BLOCK.value:
            result = self._error_result(
                message="Task blocked by SafetyBridge before execution.",
                error_code="TASK_BLOCKED_BY_SAFETY_BRIDGE",
                details=result_data,
                data=result_data,
                context=context,
            )
        elif check.decision == SafetyDecision.REQUIRE_APPROVAL.value:
            result = self._safe_result(
                message="Security Agent approval is required before execution.",
                data=result_data,
                context=context,
                status=SafetyStatus.APPROVAL_REQUIRED.value,
            )
        elif check.decision == SafetyDecision.ALLOW.value:
            result = self._safe_result(
                message="Task passed SafetyBridge inspection.",
                data=result_data,
                context=context,
                status=SafetyStatus.SUCCESS.value,
            )
        else:
            result = self._safe_result(
                message="Task requires manual review before execution.",
                data=result_data,
                context=context,
                status=SafetyStatus.PENDING.value,
            )

        self._emit_agent_event(
            event_name="safety.task.inspected",
            payload=result,
            context=context,
        )

        self._log_audit_event(
            action="inspect_task",
            context=context,
            payload=result,
            severity=self._risk_to_audit_severity(check.risk_level),
        )

        return result

    def guard_task(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
        context: Optional[Any] = None,
        executor: Optional[Callable[..., Any]] = None,
        executor_kwargs: Optional[Dict[str, Any]] = None,
        force_security_check: bool = False,
    ) -> Dict[str, Any]:
        """
        Guard a task before execution.

        If executor is provided:
            - It executes only when the task is allowed.
            - It does not execute when approval is required or blocked.

        This protects sensitive actions from direct execution.
        """

        inspection = self.inspect_task(
            action=action,
            payload=payload,
            context=context,
            force_security_check=force_security_check,
        )

        decision = inspection.get("data", {}).get("decision")

        if decision == SafetyDecision.BLOCK.value:
            return inspection

        if decision == SafetyDecision.REQUIRE_APPROVAL.value:
            return inspection

        if decision not in {SafetyDecision.ALLOW.value, None}:
            return inspection

        if executor is None:
            return self._safe_result(
                message="Task is safe to execute. No executor was provided.",
                data={
                    "decision": SafetyDecision.ALLOW.value,
                    "inspection": inspection.get("data", {}),
                },
                context=context,
            )

        try:
            execution_result = executor(**(executor_kwargs or {}))

            result = self._safe_result(
                message="Task executed after passing SafetyBridge.",
                data={
                    "decision": SafetyDecision.ALLOW.value,
                    "execution_result": execution_result,
                    "inspection": inspection.get("data", {}),
                    "verification_payload": self._prepare_verification_payload(
                        context=context,
                        action=action,
                        decision=SafetyDecision.ALLOW.value,
                        execution_result=execution_result,
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        context=context,
                        action=action,
                        decision=SafetyDecision.ALLOW.value,
                        payload=payload or {},
                    ),
                },
                context=context,
            )

            self._emit_agent_event(
                event_name="safety.task.executed",
                payload=result,
                context=context,
            )

            self._log_audit_event(
                action="guard_task_execute",
                context=context,
                payload=result,
                severity=AuditSeverity.LOW.value,
            )

            return result

        except Exception as exc:
            return self._error_result(
                message="Task execution failed after safety approval.",
                error_code="GUARDED_EXECUTION_FAILED",
                details={
                    "exception_type": exc.__class__.__name__,
                    "exception_message": str(exc),
                    "traceback": traceback.format_exc(),
                },
                context=context,
            )

    def request_security_approval(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
        context: Optional[Any] = None,
        reason: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Explicitly create and send an approval request to Security Agent.

        If real Security Agent is unavailable, returns a pending approval payload
        safely instead of crashing.
        """

        valid, validation_error = self._validate_task_context(context)

        if not valid:
            return self._error_result(
                message="Task context validation failed.",
                error_code="CONTEXT_VALIDATION_FAILED",
                details=validation_error,
                context=context,
            )

        payload = payload or {}
        sanitized_payload = self._sanitize_payload(payload)
        action_type = self.classify_action_type(action, sanitized_payload)
        calculated_risk = risk_level or self.calculate_risk_level(action, sanitized_payload)

        approval_request = self._build_approval_request(
            action=action,
            action_type=action_type,
            risk_level=calculated_risk,
            payload=sanitized_payload,
            context=context,
            matched_rules=[],
            reasons=[reason or "Explicit security approval requested."],
        )

        security_response = self._send_to_security_agent(approval_request)

        result = self._safe_result(
            message="Security approval request prepared.",
            data={
                "approval_request": asdict(approval_request),
                "security_response": security_response,
                "decision": SafetyDecision.REQUIRE_APPROVAL.value,
            },
            context=context,
            status=SafetyStatus.APPROVAL_REQUIRED.value,
        )

        self._emit_agent_event(
            event_name="safety.security_approval.requested",
            payload=result,
            context=context,
        )

        self._log_audit_event(
            action="request_security_approval",
            context=context,
            payload=result,
            severity=self._risk_to_audit_severity(calculated_risk),
        )

        return result

    def approve_or_block_from_security_response(
        self,
        security_response: Dict[str, Any],
        context: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Normalize a Security Agent response into SafetyBridge decision format.
        """

        approved = bool(
            security_response.get("approved")
            or security_response.get("success") is True
            and security_response.get("data", {}).get("approved") is True
        )

        denied = bool(
            security_response.get("denied")
            or security_response.get("blocked")
            or security_response.get("data", {}).get("denied")
            or security_response.get("data", {}).get("blocked")
        )

        if approved and not denied:
            decision = SafetyDecision.ALLOW.value
            status = SafetyStatus.APPROVED.value
            message = "Security Agent approved the task."
        elif denied:
            decision = SafetyDecision.BLOCK.value
            status = SafetyStatus.DENIED.value
            message = "Security Agent denied or blocked the task."
        else:
            decision = SafetyDecision.REVIEW.value
            status = SafetyStatus.PENDING.value
            message = "Security Agent response requires review."

        result = self._safe_result(
            message=message,
            data={
                "decision": decision,
                "status": status,
                "security_response": self._sanitize_payload(security_response),
            },
            context=context,
            status=status,
        )

        self._emit_agent_event(
            event_name="safety.security_response.normalized",
            payload=result,
            context=context,
        )

        return result

    def classify_action_type(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Classify the action category for Security Agent routing.
        """

        text = f"{action} {payload or {}}".lower()

        mapping = {
            SensitiveActionType.SYSTEM.value: [
                "system",
                "terminal",
                "shell",
                "cmd",
                "powershell",
                "bash",
                "sudo",
                "install",
                "process",
                "kill",
                "restart",
                "shutdown",
            ],
            SensitiveActionType.FILE.value: [
                "file",
                "delete",
                "remove",
                "write",
                "overwrite",
                "upload",
                "download",
                "folder",
                "directory",
                "path",
            ],
            SensitiveActionType.BROWSER.value: [
                "browser",
                "click",
                "open_url",
                "visit",
                "scrape",
                "crawl",
                "serp",
                "ads",
                "login",
            ],
            SensitiveActionType.MESSAGE.value: [
                "email",
                "sms",
                "message",
                "send",
                "reply",
                "forward",
                "whatsapp",
                "telegram",
            ],
            SensitiveActionType.CALL.value: [
                "call",
                "dial",
                "phone",
                "voice",
                "record",
                "transcribe",
            ],
            SensitiveActionType.FINANCE.value: [
                "payment",
                "invoice",
                "bank",
                "charge",
                "refund",
                "transfer",
                "subscription",
                "billing",
                "card",
            ],
            SensitiveActionType.MEMORY.value: [
                "memory",
                "remember",
                "forget",
                "profile",
                "personal_context",
            ],
            SensitiveActionType.SECURITY.value: [
                "permission",
                "role",
                "admin",
                "security",
                "audit",
                "policy",
                "auth",
                "oauth",
                "token",
            ],
            SensitiveActionType.USER_DATA.value: [
                "user_data",
                "customer",
                "lead",
                "contact",
                "personal",
                "private",
                "workspace",
            ],
            SensitiveActionType.API.value: [
                "api",
                "webhook",
                "endpoint",
                "request",
                "headers",
                "bearer",
            ],
        }

        for action_type, keywords in mapping.items():
            if any(keyword in text for keyword in keywords):
                return action_type

        return SensitiveActionType.UNKNOWN.value

    def calculate_risk_level(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Calculate local risk level before Security Agent review.
        """

        payload = payload or {}
        text = f"{action} {payload}".lower()

        critical_terms = [
            "delete database",
            "drop table",
            "wipe",
            "format disk",
            "transfer money",
            "send payment",
            "private_key",
            "access_token",
            "refresh_token",
            "mass email",
            "send all",
            "root access",
            "sudo rm",
        ]

        high_terms = [
            "delete",
            "remove",
            "payment",
            "bank",
            "card",
            "call",
            "send email",
            "send sms",
            "oauth",
            "token",
            "password",
            "credential",
            "admin",
            "role",
            "permission",
            "personal data",
            "customer data",
        ]

        medium_terms = [
            "browser",
            "login",
            "scrape",
            "download",
            "upload",
            "file write",
            "api request",
            "webhook",
            "memory",
            "remember",
            "forget",
        ]

        if any(term in text for term in critical_terms):
            return RiskLevel.CRITICAL.value

        if any(term in text for term in high_terms):
            return RiskLevel.HIGH.value

        if any(term in text for term in medium_terms):
            return RiskLevel.MEDIUM.value

        if self._contains_sensitive_keys(payload):
            return RiskLevel.HIGH.value

        return RiskLevel.LOW.value

    def is_sensitive_task(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Public helper to check whether a task is sensitive.
        """

        return self._requires_security_check(action=action, payload=payload or {})

    def build_module_completion_response(
        self,
        context: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Build required module completion tracking response.
        """

        tracking = dict(self.DEFAULT_COMPLETION_TRACKING)

        message = (
            f"Agent/Module: {tracking['agent_module']}\n"
            f"File Completed: {tracking['file_completed']}\n"
            f"Completion: {tracking['completion']}%\n"
            f"Completed Files: {tracking['completed_files']}\n"
            f"Remaining Files: {tracking['remaining_files']}\n"
            f"Next Recommended File: {tracking['next_recommended_file']}"
        )

        return self._safe_result(
            message=message,
            data={
                "completion_tracking": tracking,
                "formatted_completion": message,
            },
            context=context,
        )

    # =========================================================================
    # Local Safety Logic
    # =========================================================================

    def _local_safety_check(
        self,
        action: str,
        payload: Dict[str, Any],
        context: Optional[Any],
        force_security_check: bool = False,
    ) -> SafetyCheckResult:
        """
        Perform local SafetyBridge checks before Security Agent review.
        """

        sanitized_payload = self._sanitize_payload(payload)
        matched_rules = self._match_rules(action, sanitized_payload)
        action_type = self.classify_action_type(action, sanitized_payload)
        risk_level = self.calculate_risk_level(action, sanitized_payload)

        reasons: List[str] = []

        if force_security_check:
            reasons.append("Security check was forced by caller.")

        for rule in matched_rules:
            reasons.append(rule.get("description", "Matched safety rule."))

        requires_security = (
            force_security_check
            or self._requires_security_check(action, sanitized_payload)
            or any(rule.get("require_approval") for rule in matched_rules)
        )

        block_immediately = any(rule.get("block_immediately") for rule in matched_rules)

        if risk_level == RiskLevel.CRITICAL.value and self.default_block_unknown_critical:
            if action_type == SensitiveActionType.UNKNOWN.value:
                block_immediately = True
                reasons.append("Unknown critical-risk action blocked by default.")

        if block_immediately:
            return SafetyCheckResult(
                decision=SafetyDecision.BLOCK.value,
                risk_level=risk_level,
                requires_security_agent=False,
                matched_rules=matched_rules,
                reasons=reasons or ["Task was blocked by local safety policy."],
                sanitized_payload=sanitized_payload,
            )

        if requires_security:
            approval_request = self._build_approval_request(
                action=action,
                action_type=action_type,
                risk_level=risk_level,
                payload=sanitized_payload,
                context=context,
                matched_rules=matched_rules,
                reasons=reasons or ["Sensitive task requires Security Agent approval."],
            )

            security_response = self._send_to_security_agent(approval_request)

            approval_payload = {
                "approval_request": asdict(approval_request),
                "security_response": security_response,
            }

            normalized_security = self.approve_or_block_from_security_response(
                security_response=security_response,
                context=context,
            )

            normalized_decision = normalized_security.get("data", {}).get("decision")

            if normalized_decision == SafetyDecision.ALLOW.value:
                return SafetyCheckResult(
                    decision=SafetyDecision.ALLOW.value,
                    risk_level=risk_level,
                    requires_security_agent=True,
                    matched_rules=matched_rules,
                    reasons=reasons or ["Security Agent approved the task."],
                    sanitized_payload=sanitized_payload,
                    approval_payload=approval_payload,
                )

            if normalized_decision == SafetyDecision.BLOCK.value:
                return SafetyCheckResult(
                    decision=SafetyDecision.BLOCK.value,
                    risk_level=risk_level,
                    requires_security_agent=True,
                    matched_rules=matched_rules,
                    reasons=reasons or ["Security Agent blocked the task."],
                    sanitized_payload=sanitized_payload,
                    approval_payload=approval_payload,
                )

            return SafetyCheckResult(
                decision=SafetyDecision.REQUIRE_APPROVAL.value,
                risk_level=risk_level,
                requires_security_agent=True,
                matched_rules=matched_rules,
                reasons=reasons or ["Security Agent approval is pending or unavailable."],
                sanitized_payload=sanitized_payload,
                approval_payload=approval_payload,
            )

        return SafetyCheckResult(
            decision=SafetyDecision.ALLOW.value,
            risk_level=risk_level,
            requires_security_agent=False,
            matched_rules=matched_rules,
            reasons=reasons or ["No sensitive risk detected."],
            sanitized_payload=sanitized_payload,
        )

    def _requires_security_check(
        self,
        action: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Required compatibility hook.

        Determines whether a task must go through Security Agent.
        """

        payload = payload or {}
        action_text = (action or "").lower()
        combined_text = f"{action_text} {payload}".lower()

        security_terms = [
            "delete",
            "remove",
            "overwrite",
            "send",
            "email",
            "sms",
            "call",
            "payment",
            "invoice",
            "billing",
            "bank",
            "card",
            "token",
            "password",
            "api_key",
            "secret",
            "private_key",
            "oauth",
            "admin",
            "role",
            "permission",
            "system",
            "terminal",
            "shell",
            "browser",
            "login",
            "scrape",
            "download",
            "upload",
            "memory",
            "forget",
            "personal data",
            "customer",
            "lead",
            "credential",
        ]

        if any(term in combined_text for term in security_terms):
            return True

        return self._contains_sensitive_keys(payload)

    def _request_security_approval(
        self,
        context: Optional[Any],
        action: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Required compatibility hook.

        Creates a Security Agent approval request payload.
        """

        return self.request_security_approval(
            action=action,
            payload=data or {},
            context=context,
            reason="Compatibility hook requested security approval.",
        )

    # =========================================================================
    # Approval Request / Security Agent Bridge
    # =========================================================================

    def _build_approval_request(
        self,
        action: str,
        action_type: str,
        risk_level: str,
        payload: Dict[str, Any],
        context: Optional[Any],
        matched_rules: List[Dict[str, Any]],
        reasons: List[str],
    ) -> SecurityApprovalRequest:
        """
        Build structured approval request for Security Agent.
        """

        payload_hash = self._hash_payload(payload)

        approval_seed = (
            f"{self._get_context_value(context, 'user_id')}:"
            f"{self._get_context_value(context, 'workspace_id')}:"
            f"{self._get_context_value(context, 'task_id')}:"
            f"{action}:"
            f"{payload_hash}:"
            f"{datetime.now(timezone.utc).isoformat()}"
        )

        approval_id = hashlib.sha256(approval_seed.encode("utf-8")).hexdigest()[:32]

        return SecurityApprovalRequest(
            approval_id=approval_id,
            user_id=self._get_context_value(context, "user_id"),
            workspace_id=self._get_context_value(context, "workspace_id"),
            task_id=self._get_context_value(context, "task_id"),
            action=action,
            action_type=action_type,
            risk_level=risk_level,
            payload_hash=payload_hash,
            sanitized_payload=payload,
            matched_rules=matched_rules,
            reasons=reasons,
        )

    def _send_to_security_agent(
        self,
        approval_request: SecurityApprovalRequest,
    ) -> Dict[str, Any]:
        """
        Send approval request to real Security Agent when available.

        Supported Security Agent method names:
            - review_task
            - approve_task
            - check_permission
            - inspect_security_request
            - handle_security_request

        If Security Agent does not exist yet, returns pending response.
        """

        if self.security_agent is None:
            return {
                "success": False,
                "approved": False,
                "pending": True,
                "message": "Security Agent is not available yet. Approval request prepared but not executed.",
                "data": {
                    "approval_id": approval_request.approval_id,
                    "status": SafetyStatus.PENDING.value,
                },
                "error": None,
            }

        request_dict = asdict(approval_request)

        if hasattr(self.security_agent, "run_task"):
            # The real agents.security_agent.security_agent.SecurityAgent
            # only exposes run_task(task: dict), keyed by task["command"]
            # ("authorize", "permission_check", "risk_assessment", ...) --
            # it has none of the 5 method names probed below, so this
            # always fell through to "Security Agent has no compatible
            # approval method yet" (pending=True, approved=False) even
            # after a real SecurityAgent instance was wired in.
            try:
                response = self.security_agent.run_task({  # type: ignore
                    "command": "authorize",
                    "protected_action": approval_request.action,
                    "user_id": approval_request.user_id,
                    "workspace_id": approval_request.workspace_id,
                    "task_id": approval_request.task_id,
                    "payload": approval_request.sanitized_payload,
                })

                if isinstance(response, dict):
                    decision_data = response.get("data", {})
                    return self._sanitize_payload({
                        "success": bool(response.get("success")),
                        "approved": bool(decision_data.get("authorized")),
                        "denied": decision_data.get("decision") in {"deny", "locked"},
                        "blocked": decision_data.get("decision") in {"deny", "locked"},
                        "message": response.get("message", "Security Agent authorization completed."),
                        "data": decision_data,
                        "error": response.get("error"),
                    })
            except Exception as exc:
                return {
                    "success": False,
                    "approved": False,
                    "pending": True,
                    "message": "Security Agent run_task failed.",
                    "data": {"approval_id": approval_request.approval_id},
                    "error": {"type": exc.__class__.__name__, "message": str(exc)},
                }

        method_names = [
            "review_task",
            "approve_task",
            "check_permission",
            "inspect_security_request",
            "handle_security_request",
        ]

        for method_name in method_names:
            method = getattr(self.security_agent, method_name, None)

            if callable(method):
                try:
                    response = method(request_dict)

                    if isinstance(response, dict):
                        return self._sanitize_payload(response)

                    return {
                        "success": True,
                        "approved": bool(response),
                        "message": f"Security Agent method {method_name} returned non-dict response.",
                        "data": {
                            "raw_response": str(response),
                        },
                        "error": None,
                    }

                except TypeError:
                    try:
                        response = method(**request_dict)

                        if isinstance(response, dict):
                            return self._sanitize_payload(response)

                        return {
                            "success": True,
                            "approved": bool(response),
                            "message": f"Security Agent method {method_name} returned non-dict response.",
                            "data": {
                                "raw_response": str(response),
                            },
                            "error": None,
                        }

                    except Exception as exc:
                        return {
                            "success": False,
                            "approved": False,
                            "pending": True,
                            "message": f"Security Agent method {method_name} failed.",
                            "data": {
                                "approval_id": approval_request.approval_id,
                            },
                            "error": {
                                "type": exc.__class__.__name__,
                                "message": str(exc),
                            },
                        }

                except Exception as exc:
                    return {
                        "success": False,
                        "approved": False,
                        "pending": True,
                        "message": f"Security Agent method {method_name} failed.",
                        "data": {
                            "approval_id": approval_request.approval_id,
                        },
                        "error": {
                            "type": exc.__class__.__name__,
                            "message": str(exc),
                        },
                    }

        return {
            "success": False,
            "approved": False,
            "pending": True,
            "message": "Security Agent has no compatible approval method yet.",
            "data": {
                "approval_id": approval_request.approval_id,
                "expected_methods": method_names,
            },
            "error": None,
        }

    # =========================================================================
    # Rules
    # =========================================================================

    def _build_default_rules(self) -> List[SafetyRule]:
        """
        Build local default safety rules.

        These rules catch sensitive tasks before Security Agent.
        """

        return [
            SafetyRule(
                rule_id="system_command_review",
                name="System Command Review",
                description="System, shell, terminal, or OS-level actions require approval.",
                keywords=[
                    "system",
                    "shell",
                    "terminal",
                    "cmd",
                    "powershell",
                    "bash",
                    "sudo",
                    "process",
                    "restart",
                    "shutdown",
                    "install",
                ],
                action_type=SensitiveActionType.SYSTEM.value,
                risk_level=RiskLevel.HIGH.value,
                require_approval=True,
            ),
            SafetyRule(
                rule_id="destructive_file_review",
                name="Destructive File Review",
                description="File deletion, overwrite, or destructive write actions require approval.",
                keywords=[
                    "delete",
                    "remove",
                    "overwrite",
                    "wipe",
                    "destroy",
                    "drop",
                    "truncate",
                    "format",
                ],
                action_type=SensitiveActionType.FILE.value,
                risk_level=RiskLevel.HIGH.value,
                require_approval=True,
            ),
            SafetyRule(
                rule_id="credential_review",
                name="Credential Review",
                description="Credential, token, secret, or API key related actions require approval.",
                keywords=[
                    "password",
                    "token",
                    "secret",
                    "api_key",
                    "private_key",
                    "credential",
                    "authorization",
                    "oauth",
                ],
                action_type=SensitiveActionType.SECURITY.value,
                risk_level=RiskLevel.HIGH.value,
                require_approval=True,
            ),
            SafetyRule(
                rule_id="financial_review",
                name="Financial Review",
                description="Financial, billing, card, refund, charge, or transfer actions require approval.",
                keywords=[
                    "payment",
                    "billing",
                    "invoice",
                    "bank",
                    "card",
                    "refund",
                    "charge",
                    "transfer",
                    "subscription",
                ],
                action_type=SensitiveActionType.FINANCE.value,
                risk_level=RiskLevel.CRITICAL.value,
                require_approval=True,
            ),
            SafetyRule(
                rule_id="communication_review",
                name="Communication Review",
                description="Sending external emails, SMS, calls, or messages requires approval.",
                keywords=[
                    "send email",
                    "send sms",
                    "send message",
                    "forward email",
                    "reply email",
                    "call",
                    "dial",
                    "whatsapp",
                    "telegram",
                ],
                action_type=SensitiveActionType.MESSAGE.value,
                risk_level=RiskLevel.HIGH.value,
                require_approval=True,
            ),
            SafetyRule(
                rule_id="user_data_review",
                name="User Data Review",
                description="Sensitive user, customer, lead, or workspace data access requires approval.",
                keywords=[
                    "customer data",
                    "user data",
                    "personal data",
                    "lead data",
                    "contacts",
                    "workspace data",
                    "export users",
                    "download users",
                ],
                action_type=SensitiveActionType.USER_DATA.value,
                risk_level=RiskLevel.HIGH.value,
                require_approval=True,
            ),
            SafetyRule(
                rule_id="critical_unknown_block",
                name="Critical Unknown Block",
                description="Unknown action containing critical destructive wording is blocked locally.",
                keywords=[
                    "sudo rm",
                    "drop database",
                    "delete database",
                    "wipe server",
                    "format disk",
                    "exfiltrate",
                    "steal",
                    "bypass security",
                ],
                action_type=SensitiveActionType.UNKNOWN.value,
                risk_level=RiskLevel.CRITICAL.value,
                require_approval=False,
                block_immediately=True,
            ),
        ]

    def _match_rules(
        self,
        action: str,
        payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Match local rules against action and payload.
        """

        text = f"{action} {payload}".lower()
        matched: List[Dict[str, Any]] = []

        for rule in self.rules:
            if any(keyword.lower() in text for keyword in rule.keywords):
                matched.append(asdict(rule))

        return matched

    # =========================================================================
    # Required Compatibility Hooks
    # =========================================================================

    def _validate_task_context(self, context: Optional[Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Validate SaaS context.

        If context exists and strict SaaS isolation is enabled,
        user_id and workspace_id must be present.
        """

        if context is None:
            return True, None

        user_id = self._get_context_value(context, "user_id")
        workspace_id = self._get_context_value(context, "workspace_id")

        if self.strict_saas_isolation:
            missing = []

            if user_id in (None, "", 0):
                missing.append("user_id")

            if workspace_id in (None, "", 0):
                missing.append("workspace_id")

            if missing:
                return False, {
                    "missing_fields": missing,
                    "message": "SaaS isolation requires user_id and workspace_id.",
                }

        return True, None

    def _prepare_verification_payload(
        self,
        context: Optional[Any],
        action: str,
        decision: str,
        execution_result: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.
        """

        return {
            "verification_type": "safety_bridge_decision",
            "agent_name": self.agent_name,
            "module_name": self.module_name,
            "user_id": self._get_context_value(context, "user_id"),
            "workspace_id": self._get_context_value(context, "workspace_id"),
            "task_id": self._get_context_value(context, "task_id"),
            "action": action,
            "decision": decision,
            "has_execution_result": execution_result is not None,
            "requires_human_review": decision in {
                SafetyDecision.REQUIRE_APPROVAL.value,
                SafetyDecision.REVIEW.value,
                SafetyDecision.BLOCK.value,
            },
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def _prepare_memory_payload(
        self,
        context: Optional[Any],
        action: str,
        decision: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Does not store memory directly.
        """

        return {
            "memory_type": "safety_decision_summary",
            "user_id": self._get_context_value(context, "user_id"),
            "workspace_id": self._get_context_value(context, "workspace_id"),
            "task_id": self._get_context_value(context, "task_id"),
            "summary": f"SafetyBridge decision for action '{action}': {decision}",
            "decision": decision,
            "action_type": self.classify_action_type(action, payload or {}),
            "risk_level": self.calculate_risk_level(action, payload or {}),
            "created_by": self.agent_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
        context: Optional[Any] = None,
    ) -> None:
        """
        Emit router/dashboard compatible event.
        """

        event_payload = {
            "event_name": event_name,
            "agent_name": self.agent_name,
            "module_name": self.module_name,
            "user_id": self._get_context_value(context, "user_id"),
            "workspace_id": self._get_context_value(context, "workspace_id"),
            "task_id": self._get_context_value(context, "task_id"),
            "payload": self._safe_payload_summary(payload),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            emit = getattr(super(), "emit_event", None)
            if callable(emit):
                emit(event_name, event_payload)
            else:
                logger.debug("SafetyBridge event: %s", event_payload)
        except Exception as exc:
            logger.debug("Failed to emit SafetyBridge event: %s", exc)

    def _log_audit_event(
        self,
        action: str,
        context: Optional[Any],
        payload: Optional[Dict[str, Any]] = None,
        severity: str = AuditSeverity.LOW.value,
    ) -> None:
        """
        Log audit-compatible record.

        Does not persist by itself unless BaseAgent provides persistence.
        """

        if not self.enable_audit_log:
            return

        audit_payload = {
            "action": action,
            "severity": severity,
            "agent_name": self.agent_name,
            "module_name": self.module_name,
            "user_id": self._get_context_value(context, "user_id"),
            "workspace_id": self._get_context_value(context, "workspace_id"),
            "task_id": self._get_context_value(context, "task_id"),
            "payload_summary": self._safe_payload_summary(payload or {}),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            log_audit = getattr(super(), "log_audit", None)
            if callable(log_audit):
                log_audit(audit_payload)
            else:
                logger.info("SafetyBridge audit: %s", audit_payload)
        except Exception as exc:
            logger.debug("Failed to log SafetyBridge audit: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        context: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
        status: str = SafetyStatus.SUCCESS.value,
    ) -> Dict[str, Any]:
        """
        Standard safe success response.
        """

        response_data = data or {}

        if self.enable_verification_payload and "verification_payload" not in response_data:
            response_data["verification_payload"] = {
                "verification_type": "safety_bridge_response",
                "status": status,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }

        if self.enable_memory_payload and "memory_payload" not in response_data:
            response_data["memory_payload"] = {
                "memory_type": "safety_bridge_response_summary",
                "summary": message,
                "status": status,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }

        return {
            "success": True,
            "message": message,
            "data": response_data,
            "error": None,
            "metadata": metadata or self._build_metadata(context=context),
        }

    def _error_result(
        self,
        message: str,
        error_code: str = "SAFETY_BRIDGE_ERROR",
        details: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        context: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard safe error response.
        """

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": {
                "error_code": error_code,
                "message": message,
                "details": self._sanitize_payload(details or {}),
            },
            "metadata": metadata or self._build_metadata(context=context),
        }

    # =========================================================================
    # Utilities
    # =========================================================================

    def _init_security_agent(self) -> Optional[Any]:
        """
        Initialize Security Agent safely if available.
        """

        if SecurityAgent is None:
            return None

        try:
            return SecurityAgent()
        except Exception as exc:
            logger.debug("SecurityAgent could not be initialized: %s", exc)
            return None

    def _init_response_builder(self) -> Optional[Any]:
        """
        Initialize ResponseBuilder safely if available.
        """

        if ResponseBuilder is None:
            return None

        try:
            return ResponseBuilder()
        except Exception as exc:
            logger.debug("ResponseBuilder could not be initialized: %s", exc)
            return None

    def _build_metadata(self, context: Optional[Any] = None) -> Dict[str, Any]:
        """
        Build standard metadata.
        """

        return asdict(
            SafetyMetadata(
                user_id=self._get_context_value(context, "user_id"),
                workspace_id=self._get_context_value(context, "workspace_id"),
                task_id=self._get_context_value(context, "task_id"),
                request_id=self._get_context_value(context, "request_id"),
                trace_id=self._get_context_value(context, "trace_id"),
            )
        )

    def _get_context_value(self, context: Optional[Any], key: str) -> Optional[Any]:
        """
        Safely read context from dict/dataclass/object.
        """

        if context is None:
            return None

        if isinstance(context, dict):
            return context.get(key)

        if hasattr(context, key):
            return getattr(context, key)

        try:
            if hasattr(context, "get"):
                return context.get(key)
        except Exception:
            return None

        return None

    def _contains_sensitive_keys(self, payload: Any) -> bool:
        """
        Check nested payload for sensitive keys.
        """

        if isinstance(payload, dict):
            for key, value in payload.items():
                if str(key).lower() in self.SENSITIVE_KEYS:
                    return True

                if self._contains_sensitive_keys(value):
                    return True

        elif isinstance(payload, list):
            return any(self._contains_sensitive_keys(item) for item in payload)

        elif isinstance(payload, tuple):
            return any(self._contains_sensitive_keys(item) for item in payload)

        return False

    def _sanitize_payload(self, payload: Any) -> Any:
        """
        Redact sensitive fields recursively.
        """

        if isinstance(payload, dict):
            clean: Dict[str, Any] = {}

            for key, value in payload.items():
                if str(key).lower() in self.SENSITIVE_KEYS:
                    clean[key] = "[REDACTED]"
                else:
                    clean[key] = self._sanitize_payload(value)

            return clean

        if isinstance(payload, list):
            return [self._sanitize_payload(item) for item in payload]

        if isinstance(payload, tuple):
            return tuple(self._sanitize_payload(item) for item in payload)

        return payload

    def _hash_payload(self, payload: Dict[str, Any]) -> str:
        """
        Create deterministic hash of sanitized payload.
        """

        safe_string = str(self._sanitize_payload(payload)).encode("utf-8")
        return hashlib.sha256(safe_string).hexdigest()

    def _safe_payload_summary(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create audit-safe payload summary.
        """

        clean = self._sanitize_payload(payload)

        return {
            "success": clean.get("success") if isinstance(clean, dict) else None,
            "message": clean.get("message") if isinstance(clean, dict) else None,
            "has_data": bool(clean.get("data")) if isinstance(clean, dict) else False,
            "has_error": bool(clean.get("error")) if isinstance(clean, dict) else False,
            "metadata_keys": sorted(list((clean.get("metadata") or {}).keys()))
            if isinstance(clean, dict)
            else [],
        }

    def _risk_to_audit_severity(self, risk_level: str) -> str:
        """
        Map risk level to audit severity.
        """

        mapping = {
            RiskLevel.NONE.value: AuditSeverity.LOW.value,
            RiskLevel.LOW.value: AuditSeverity.LOW.value,
            RiskLevel.MEDIUM.value: AuditSeverity.MEDIUM.value,
            RiskLevel.HIGH.value: AuditSeverity.HIGH.value,
            RiskLevel.CRITICAL.value: AuditSeverity.CRITICAL.value,
        }

        return mapping.get(risk_level, AuditSeverity.MEDIUM.value)

    # =========================================================================
    # Registry / Router Compatibility
    # =========================================================================

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Return registry-compatible manifest.
        """

        return {
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "module_name": self.module_name,
            "file_name": "safety_bridge.py",
            "version": "1.0.0",
            "capabilities": [
                "inspect_task",
                "guard_task",
                "request_security_approval",
                "approve_or_block_from_security_response",
                "classify_action_type",
                "calculate_risk_level",
                "is_sensitive_task",
                "build_module_completion_response",
            ],
            "requires_security_agent": True,
            "supports_saas_isolation": True,
            "supports_memory_payload": True,
            "supports_verification_payload": True,
            "safe_to_import": True,
        }

    def health_check(self) -> Dict[str, Any]:
        """
        Dashboard/API health check.
        """

        return {
            "success": True,
            "message": "SafetyBridge is healthy.",
            "data": {
                "agent_name": self.agent_name,
                "module_name": self.module_name,
                "created_at": self.created_at,
                "strict_saas_isolation": self.strict_saas_isolation,
                "audit_enabled": self.enable_audit_log,
                "memory_payload_enabled": self.enable_memory_payload,
                "verification_payload_enabled": self.enable_verification_payload,
                "security_agent_available": self.security_agent is not None,
                "rules_loaded": len(self.rules),
            },
            "error": None,
            "metadata": self._build_metadata(),
        }


# =============================================================================
# Convenience Singleton
# =============================================================================

safety_bridge = SafetyBridge()


# =============================================================================
# Convenience Functions
# =============================================================================

def inspect_task(
    action: str,
    payload: Optional[Dict[str, Any]] = None,
    context: Optional[Any] = None,
    force_security_check: bool = False,
) -> Dict[str, Any]:
    """
    Convenience function for inspecting a task.
    """

    return safety_bridge.inspect_task(
        action=action,
        payload=payload,
        context=context,
        force_security_check=force_security_check,
    )


def guard_task(
    action: str,
    payload: Optional[Dict[str, Any]] = None,
    context: Optional[Any] = None,
    executor: Optional[Callable[..., Any]] = None,
    executor_kwargs: Optional[Dict[str, Any]] = None,
    force_security_check: bool = False,
) -> Dict[str, Any]:
    """
    Convenience function for guarded task execution.
    """

    return safety_bridge.guard_task(
        action=action,
        payload=payload,
        context=context,
        executor=executor,
        executor_kwargs=executor_kwargs,
        force_security_check=force_security_check,
    )


def request_security_approval(
    action: str,
    payload: Optional[Dict[str, Any]] = None,
    context: Optional[Any] = None,
    reason: Optional[str] = None,
    risk_level: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Convenience function for requesting Security Agent approval.
    """

    return safety_bridge.request_security_approval(
        action=action,
        payload=payload,
        context=context,
        reason=reason,
        risk_level=risk_level,
    )


# =============================================================================
# Local Manual Test
# =============================================================================

if __name__ == "__main__":
    test_context = {
        "user_id": "user_001",
        "workspace_id": "workspace_001",
        "task_id": "task_safety_bridge_test",
        "request_id": "req_001",
    }

    bridge = SafetyBridge()

    print("HEALTH CHECK:")
    print(bridge.health_check())

    print("\nSAFE TASK INSPECTION:")
    print(
        bridge.inspect_task(
            action="summarize user dashboard metrics",
            payload={"metric": "task_count"},
            context=test_context,
        )
    )

    print("\nSENSITIVE TASK INSPECTION:")
    print(
        bridge.inspect_task(
            action="send email to customer",
            payload={
                "to": "customer@example.com",
                "subject": "Project update",
                "access_token": "secret-token-example",
            },
            context=test_context,
        )
    )

    print("\nCOMPLETION:")
    print(bridge.build_module_completion_response(context=test_context))