"""Central policy engine for the William / Jarvis multi-agent SaaS system.

The engine evaluates normalized action requests against platform, workspace,
role, subscription, agent, resource, and user-scoped policies. It is designed
for use by the Master Agent, Security Agent, Agent Router, dashboard/API, and
all plugin-style agents without performing protected actions itself.
"""

from __future__ import annotations

import copy
import fnmatch
import hashlib
import inspect
import json
import logging
import re
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any,
    Callable,
    Iterable,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
)


LOGGER = logging.getLogger(__name__)


try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore[override]
        """Import-safe BaseAgent fallback.

        This fallback allows PolicyEngine to be imported and tested before the
        final William BaseAgent implementation is available.
        """

        agent_name = "base_agent"
        agent_version = "0.0.0"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.logger = kwargs.get("logger") or logging.getLogger(
                self.__class__.__name__
            )


class PolicyEffect(str, Enum):
    """Supported policy effects."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_CONFIRMATION = "require_confirmation"
    REQUIRE_SECURITY_APPROVAL = "require_security_approval"
    REQUIRE_BIOMETRIC = "require_biometric"
    REQUIRE_MFA = "require_mfa"
    REQUIRE_TRUSTED_DEVICE = "require_trusted_device"
    REQUIRE_ADMIN = "require_admin"
    READ_ONLY = "read_only"
    REDACT = "redact"
    RATE_LIMIT = "rate_limit"


class PolicyScope(str, Enum):
    """Supported policy ownership and isolation scopes."""

    PLATFORM = "platform"
    SUBSCRIPTION = "subscription"
    WORKSPACE = "workspace"
    ROLE = "role"
    AGENT = "agent"
    RESOURCE = "resource"
    USER = "user"
    SESSION = "session"


class PolicyDecision(str, Enum):
    """Normalized policy decisions returned to agents and APIs."""

    ALLOWED = "allowed"
    DENIED = "denied"
    CHALLENGE_REQUIRED = "challenge_required"
    READ_ONLY = "read_only"
    REDACTED = "redacted"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"


class RiskLevel(str, Enum):
    """Normalized action risk levels."""

    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_EFFECT_PRECEDENCE: dict[PolicyEffect, int] = {
    PolicyEffect.DENY: 100,
    PolicyEffect.RATE_LIMIT: 90,
    PolicyEffect.REQUIRE_ADMIN: 85,
    PolicyEffect.REQUIRE_BIOMETRIC: 80,
    PolicyEffect.REQUIRE_MFA: 75,
    PolicyEffect.REQUIRE_TRUSTED_DEVICE: 70,
    PolicyEffect.REQUIRE_SECURITY_APPROVAL: 65,
    PolicyEffect.REQUIRE_CONFIRMATION: 60,
    PolicyEffect.READ_ONLY: 50,
    PolicyEffect.REDACT: 40,
    PolicyEffect.ALLOW: 10,
}

_SCOPE_PRECEDENCE: dict[PolicyScope, int] = {
    PolicyScope.PLATFORM: 80,
    PolicyScope.SESSION: 75,
    PolicyScope.USER: 70,
    PolicyScope.WORKSPACE: 60,
    PolicyScope.ROLE: 50,
    PolicyScope.SUBSCRIPTION: 45,
    PolicyScope.AGENT: 40,
    PolicyScope.RESOURCE: 30,
}

_RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.MINIMAL: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}

_SAFE_IDENTIFIER = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.:@/\-]{0,255}$"
)

_SECRET_KEY_RE = re.compile(
    (
        r"(?:password|passwd|secret|token|api[_-]?key|authorization|"
        r"cookie|session[_-]?id|private[_-]?key)"
    ),
    re.IGNORECASE,
)


@dataclass(frozen=True)
class PolicyRule:
    """Declarative policy rule evaluated by PolicyEngine.

    Rules can be platform-wide or restricted to specific workspaces, users,
    roles, plans, agents, resources, actions, or risk levels.
    """

    policy_id: str
    name: str
    effect: PolicyEffect
    scope: PolicyScope = PolicyScope.PLATFORM
    priority: int = 0
    enabled: bool = True
    description: str = ""

    actions: tuple[str, ...] = ("*",)
    resources: tuple[str, ...] = ("*",)
    source_agents: tuple[str, ...] = ("*",)
    target_agents: tuple[str, ...] = ("*",)

    roles: tuple[str, ...] = ()
    subscription_plans: tuple[str, ...] = ()
    user_ids: tuple[str, ...] = ()
    workspace_ids: tuple[str, ...] = ()
    risk_levels: tuple[RiskLevel, ...] = ()

    conditions: Mapping[str, Any] = field(default_factory=dict)
    obligations: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    reason: str = ""
    expires_at: Optional[str] = None
    created_at: str = field(default_factory=lambda: _utc_now_iso())
    updated_at: str = field(default_factory=lambda: _utc_now_iso())

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible policy representation."""

        value = asdict(self)
        value["effect"] = self.effect.value
        value["scope"] = self.scope.value
        value["risk_levels"] = [
            risk_level.value for risk_level in self.risk_levels
        ]
        value["conditions"] = copy.deepcopy(dict(self.conditions))
        value["obligations"] = copy.deepcopy(dict(self.obligations))
        value["metadata"] = copy.deepcopy(dict(self.metadata))
        return value

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "PolicyRule":
        """Build and normalize a policy rule from a dictionary."""

        if not isinstance(value, Mapping):
            raise TypeError("Policy rule must be a mapping.")

        now = _utc_now_iso()

        policy_id = str(
            value.get("policy_id")
            or value.get("id")
            or uuid.uuid4().hex
        )

        name = str(value.get("name") or policy_id)

        effect = _coerce_enum(
            PolicyEffect,
            value.get("effect", PolicyEffect.DENY.value),
        )

        scope = _coerce_enum(
            PolicyScope,
            value.get("scope", PolicyScope.PLATFORM.value),
        )

        return cls(
            policy_id=policy_id,
            name=name,
            effect=effect,
            scope=scope,
            priority=int(value.get("priority", 0)),
            enabled=bool(value.get("enabled", True)),
            description=str(value.get("description") or ""),
            actions=_as_string_tuple(
                value.get("actions"),
                default=("*",),
            ),
            resources=_as_string_tuple(
                value.get("resources"),
                default=("*",),
            ),
            source_agents=_as_string_tuple(
                value.get("source_agents"),
                default=("*",),
            ),
            target_agents=_as_string_tuple(
                value.get("target_agents"),
                default=("*",),
            ),
            roles=_as_string_tuple(
                value.get("roles"),
                default=(),
            ),
            subscription_plans=_as_string_tuple(
                value.get("subscription_plans"),
                default=(),
            ),
            user_ids=_as_string_tuple(
                value.get("user_ids"),
                default=(),
            ),
            workspace_ids=_as_string_tuple(
                value.get("workspace_ids"),
                default=(),
            ),
            risk_levels=tuple(
                _coerce_enum(RiskLevel, item)
                for item in _as_sequence(value.get("risk_levels"))
            ),
            conditions=copy.deepcopy(
                dict(value.get("conditions") or {})
            ),
            obligations=copy.deepcopy(
                dict(value.get("obligations") or {})
            ),
            metadata=copy.deepcopy(
                dict(value.get("metadata") or {})
            ),
            reason=str(value.get("reason") or ""),
            expires_at=_optional_string(value.get("expires_at")),
            created_at=str(value.get("created_at") or now),
            updated_at=str(value.get("updated_at") or now),
        )


@dataclass(frozen=True)
class PolicyMatch:
    """Internal representation of a matched policy."""

    policy_id: str
    name: str
    effect: PolicyEffect
    scope: PolicyScope
    priority: int
    reason: str
    obligations: Mapping[str, Any]
    specificity: int

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible matched-policy representation."""

        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "effect": self.effect.value,
            "scope": self.scope.value,
            "priority": self.priority,
            "reason": self.reason,
            "obligations": copy.deepcopy(dict(self.obligations)),
            "specificity": self.specificity,
        }


@dataclass
class RateLimitState:
    """In-memory rate-limit state.

    A production deployment can inject a Redis-backed MutableMapping through
    PolicyEngine's rate_limit_backend argument.
    """

    window_started_at: float
    count: int = 0


class PolicyEngine(BaseAgent):
    """Central policy engine applied consistently across all William agents.

    Integration responsibilities:

    Master Agent:
        Calls execute(), handle_task(), evaluate(), or evaluate_policy() before
        routing sensitive or user-specific operations.

    Security Agent:
        Supplies the security_approval_handler for approval, biometric, MFA,
        confirmation, or administrator challenge workflows.

    Memory Agent:
        Receives tenant-scoped policy-decision memory payloads through the
        optional memory_handler.

    Verification Agent:
        Receives verification payloads and deterministic decision checksums
        through the optional verification_handler.

    Dashboard/API:
        Uses register_policy(), remove_policy(), list_policies(),
        import_policies(), export_policies(), get_metrics(), and health_check().

    Agent Registry and Loader:
        Can inspect registry_manifest(), agent_name, agent_type, version,
        capabilities, and standard execution entrypoints.

    This class never directly executes financial, browser, messaging, calling,
    terminal, file deletion, account, or destructive actions.
    """

    agent_name = "policy_engine"
    agent_type = "security"
    agent_version = "1.0.0"

    capabilities = (
        "policy.evaluate",
        "policy.register",
        "policy.remove",
        "policy.list",
        "policy.export",
        "policy.import",
        "policy.simulate",
    )

    def __init__(
        self,
        policies: Optional[
            Iterable[PolicyRule | Mapping[str, Any]]
        ] = None,
        *,
        default_effect: PolicyEffect | str = PolicyEffect.DENY,
        fail_closed: bool = True,
        security_approval_handler: Optional[
            Callable[..., Any]
        ] = None,
        audit_handler: Optional[Callable[..., Any]] = None,
        event_handler: Optional[Callable[..., Any]] = None,
        verification_handler: Optional[Callable[..., Any]] = None,
        memory_handler: Optional[Callable[..., Any]] = None,
        context_validator: Optional[Callable[..., Any]] = None,
        rate_limit_backend: Optional[
            MutableMapping[str, RateLimitState]
        ] = None,
        max_policies: int = 10_000,
        logger: Optional[logging.Logger] = None,
        load_default_policies: bool = True,
        **base_kwargs: Any,
    ) -> None:
        """Initialize the central policy engine.

        Args:
            policies:
                Optional initial policy rules.

            default_effect:
                Effect used when no policy matches. The production-safe default
                is deny.

            fail_closed:
                When True, unexpected evaluation failures deny the action.

            security_approval_handler:
                Security Agent or Approval Manager callback.

            audit_handler:
                Callback for Audit Logger integration.

            event_handler:
                Callback for dashboard/event-bus integration.

            verification_handler:
                Callback for Verification Agent integration.

            memory_handler:
                Callback for Memory Agent integration.

            context_validator:
                Optional external context-validation callback.

            rate_limit_backend:
                Optional mutable mapping, such as a Redis adapter.

            max_policies:
                Maximum number of policies allowed in memory.

            load_default_policies:
                Load conservative William platform policies.
        """

        try:
            super().__init__(logger=logger, **base_kwargs)
        except TypeError:
            super().__init__()

        self.logger = logger or getattr(self, "logger", LOGGER)

        self.default_effect = _coerce_enum(
            PolicyEffect,
            default_effect,
        )

        self.fail_closed = bool(fail_closed)
        self.max_policies = max(1, int(max_policies))

        self.security_approval_handler = security_approval_handler
        self.audit_handler = audit_handler
        self.event_handler = event_handler
        self.verification_handler = verification_handler
        self.memory_handler = memory_handler
        self.context_validator = context_validator

        self._policies: dict[str, PolicyRule] = {}
        self._lock = threading.RLock()

        self._rate_limit_state: MutableMapping[
            str,
            RateLimitState,
        ] = (
            rate_limit_backend
            if rate_limit_backend is not None
            else {}
        )

        self._metrics: defaultdict[str, int] = defaultdict(int)

        if load_default_policies:
            for rule in self._build_default_policies():
                self._policies[rule.policy_id] = rule

        if policies:
            for policy in policies:
                rule = (
                    policy
                    if isinstance(policy, PolicyRule)
                    else PolicyRule.from_mapping(policy)
                )

                self._validate_policy_rule(rule)
                self._policies[rule.policy_id] = rule

    # ------------------------------------------------------------------
    # Public policy administration API
    # ------------------------------------------------------------------

    def register_policy(
        self,
        policy: PolicyRule | Mapping[str, Any],
        *,
        replace: bool = False,
        actor_context: Optional[Mapping[str, Any]] = None,
    ) -> dict[str, Any]:
        """Register a validated policy.

        Policy registration should normally be protected by Security Agent,
        administrator permissions, and API-level authentication.
        """

        try:
            rule = (
                policy
                if isinstance(policy, PolicyRule)
                else PolicyRule.from_mapping(policy)
            )

            self._validate_policy_rule(rule)

            with self._lock:
                policy_exists = rule.policy_id in self._policies

                if (
                    len(self._policies) >= self.max_policies
                    and not policy_exists
                ):
                    return self._error_result(
                        "Policy limit reached.",
                        code="POLICY_LIMIT_REACHED",
                        metadata={
                            "max_policies": self.max_policies,
                        },
                    )

                if policy_exists and not replace:
                    return self._error_result(
                        "Policy already exists.",
                        code="POLICY_ALREADY_EXISTS",
                        metadata={
                            "policy_id": rule.policy_id,
                        },
                    )

                self._policies[rule.policy_id] = rule

            self._metrics["policies_registered"] += 1

            self._emit_agent_event(
                "policy.registered",
                {
                    "policy": rule.to_dict(),
                    "actor_context": self._sanitize(
                        actor_context or {}
                    ),
                },
            )

            self._log_audit_event(
                "policy_registered",
                actor_context or {},
                details={
                    "policy_id": rule.policy_id,
                    "replace": replace,
                },
            )

            return self._safe_result(
                True,
                "Policy registered successfully.",
                data={
                    "policy": rule.to_dict(),
                },
                metadata={
                    "agent": self.agent_name,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to register policy")

            return self._error_result(
                "Unable to register policy.",
                code="POLICY_REGISTRATION_FAILED",
                error=exc,
            )

    def remove_policy(
        self,
        policy_id: str,
        *,
        actor_context: Optional[Mapping[str, Any]] = None,
    ) -> dict[str, Any]:
        """Remove one policy by its identifier."""

        try:
            normalized_id = self._validate_identifier(
                policy_id,
                "policy_id",
            )

            with self._lock:
                removed = self._policies.pop(
                    normalized_id,
                    None,
                )

            if removed is None:
                return self._error_result(
                    "Policy not found.",
                    code="POLICY_NOT_FOUND",
                    metadata={
                        "policy_id": normalized_id,
                    },
                )

            self._metrics["policies_removed"] += 1

            self._emit_agent_event(
                "policy.removed",
                {
                    "policy_id": normalized_id,
                    "actor_context": self._sanitize(
                        actor_context or {}
                    ),
                },
            )

            self._log_audit_event(
                "policy_removed",
                actor_context or {},
                details={
                    "policy_id": normalized_id,
                },
            )

            return self._safe_result(
                True,
                "Policy removed successfully.",
                data={
                    "policy": removed.to_dict(),
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to remove policy")

            return self._error_result(
                "Unable to remove policy.",
                "POLICY_REMOVE_FAILED",
                exc,
            )

    def get_policy(
        self,
        policy_id: str,
    ) -> dict[str, Any]:
        """Retrieve one policy."""

        try:
            normalized_id = self._validate_identifier(
                policy_id,
                "policy_id",
            )

            with self._lock:
                rule = self._policies.get(normalized_id)

            if rule is None:
                return self._error_result(
                    "Policy not found.",
                    "POLICY_NOT_FOUND",
                    metadata={
                        "policy_id": normalized_id,
                    },
                )

            return self._safe_result(
                True,
                "Policy retrieved.",
                data={
                    "policy": rule.to_dict(),
                },
            )

        except Exception as exc:
            return self._error_result(
                "Unable to retrieve policy.",
                "POLICY_GET_FAILED",
                exc,
            )

    def list_policies(
        self,
        *,
        scope: Optional[PolicyScope | str] = None,
        effect: Optional[PolicyEffect | str] = None,
        enabled: Optional[bool] = None,
        workspace_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """List policies with optional tenant-safe filters."""

        try:
            scope_value = (
                _coerce_enum(PolicyScope, scope)
                if scope is not None
                else None
            )

            effect_value = (
                _coerce_enum(PolicyEffect, effect)
                if effect is not None
                else None
            )

            with self._lock:
                policies = list(self._policies.values())

            filtered: list[PolicyRule] = []

            for rule in policies:
                if (
                    scope_value is not None
                    and rule.scope != scope_value
                ):
                    continue

                if (
                    effect_value is not None
                    and rule.effect != effect_value
                ):
                    continue

                if (
                    enabled is not None
                    and rule.enabled != enabled
                ):
                    continue

                if (
                    workspace_id is not None
                    and rule.workspace_ids
                    and workspace_id not in rule.workspace_ids
                ):
                    continue

                if (
                    user_id is not None
                    and rule.user_ids
                    and user_id not in rule.user_ids
                ):
                    continue

                filtered.append(rule)

            filtered.sort(
                key=self._policy_sort_key,
                reverse=True,
            )

            return self._safe_result(
                True,
                "Policies retrieved.",
                data={
                    "policies": [
                        rule.to_dict()
                        for rule in filtered
                    ],
                    "count": len(filtered),
                },
            )

        except Exception as exc:
            return self._error_result(
                "Unable to list policies.",
                "POLICY_LIST_FAILED",
                exc,
            )

    def export_policies(
        self,
        *,
        include_disabled: bool = True,
    ) -> dict[str, Any]:
        """Export policies with a deterministic SHA-256 checksum."""

        try:
            with self._lock:
                policies = [
                    rule.to_dict()
                    for rule in self._policies.values()
                    if include_disabled or rule.enabled
                ]

            policies.sort(
                key=lambda item: (
                    item["scope"],
                    item["priority"],
                    item["policy_id"],
                )
            )

            payload: dict[str, Any] = {
                "schema_version": "1.0",
                "exported_at": _utc_now_iso(),
                "agent": self.agent_name,
                "policies": policies,
            }

            payload["checksum"] = self._stable_checksum(
                payload["policies"]
            )

            return self._safe_result(
                True,
                "Policies exported.",
                data=payload,
            )

        except Exception as exc:
            return self._error_result(
                "Unable to export policies.",
                "POLICY_EXPORT_FAILED",
                exc,
            )

    def import_policies(
        self,
        payload: (
            Mapping[str, Any]
            | Sequence[Mapping[str, Any]]
        ),
        *,
        replace_existing: bool = False,
        verify_checksum: bool = True,
        actor_context: Optional[Mapping[str, Any]] = None,
    ) -> dict[str, Any]:
        """Import and validate policy rules atomically."""

        try:
            if isinstance(payload, Mapping):
                raw_policies = payload.get("policies")
                expected_checksum = payload.get("checksum")
            else:
                raw_policies = payload
                expected_checksum = None

            if (
                not isinstance(raw_policies, Sequence)
                or isinstance(raw_policies, (str, bytes))
            ):
                raise ValueError(
                    "Import payload must contain a policy list."
                )

            if verify_checksum and expected_checksum:
                actual_checksum = self._stable_checksum(
                    raw_policies
                )

                if not _constant_time_equal(
                    str(expected_checksum),
                    actual_checksum,
                ):
                    return self._error_result(
                        "Policy checksum verification failed.",
                        "POLICY_CHECKSUM_MISMATCH",
                    )

            rules = [
                PolicyRule.from_mapping(item)
                for item in raw_policies
            ]

            for rule in rules:
                self._validate_policy_rule(rule)

            imported = 0
            skipped: list[str] = []

            with self._lock:
                projected = (
                    len(self._policies)
                    + sum(
                        1
                        for rule in rules
                        if rule.policy_id not in self._policies
                    )
                )

                if projected > self.max_policies:
                    return self._error_result(
                        "Import would exceed policy limit.",
                        "POLICY_LIMIT_REACHED",
                        metadata={
                            "max_policies": self.max_policies,
                            "projected": projected,
                        },
                    )

                for rule in rules:
                    if (
                        rule.policy_id in self._policies
                        and not replace_existing
                    ):
                        skipped.append(rule.policy_id)
                        continue

                    self._policies[rule.policy_id] = rule
                    imported += 1

            self._metrics["policies_imported"] += imported

            self._emit_agent_event(
                "policy.imported",
                {
                    "imported": imported,
                    "skipped": skipped,
                    "actor_context": self._sanitize(
                        actor_context or {}
                    ),
                },
            )

            self._log_audit_event(
                "policies_imported",
                actor_context or {},
                details={
                    "imported": imported,
                    "skipped": skipped,
                },
            )

            return self._safe_result(
                True,
                "Policy import completed.",
                data={
                    "imported": imported,
                    "skipped": skipped,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to import policies")

            return self._error_result(
                "Unable to import policies.",
                "POLICY_IMPORT_FAILED",
                exc,
            )

    # ------------------------------------------------------------------
    # Public evaluation API
    # ------------------------------------------------------------------

    def evaluate_policy(
        self,
        task_context: Mapping[str, Any],
        action: Optional[str] = None,
        *,
        resource: Optional[str] = None,
        source_agent: Optional[str] = None,
        target_agent: Optional[str] = None,
        risk_level: Optional[RiskLevel | str] = None,
        request_security_approval: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Evaluate an action and return a structured policy decision.

        This is the primary public method used across William/Jarvis agents.
        """

        evaluation_id = uuid.uuid4().hex
        started_at = time.monotonic()

        self._metrics["evaluations_total"] += 1

        try:
            validation = self._validate_task_context(
                task_context
            )

            if not validation["success"]:
                self._metrics[
                    "evaluations_invalid_context"
                ] += 1

                return self._finalize_evaluation_result(
                    validation,
                    evaluation_id=evaluation_id,
                    started_at=started_at,
                    task_context=task_context,
                    action=(
                        action
                        or str(
                            task_context.get("action")
                            or "unknown"
                        )
                    ),
                    resource=(
                        resource
                        or str(
                            task_context.get("resource")
                            or "unknown"
                        )
                    ),
                    dry_run=dry_run,
                )

            context = self._normalize_context(
                task_context,
                action=action,
                resource=resource,
                source_agent=source_agent,
                target_agent=target_agent,
                risk_level=risk_level,
            )

            isolation_error = (
                self._validate_tenant_isolation(context)
            )

            if isolation_error is not None:
                self._metrics[
                    "evaluations_isolation_denied"
                ] += 1

                result = self._decision_result(
                    decision=PolicyDecision.DENIED,
                    message=(
                        "Cross-tenant or incomplete tenant "
                        "context was blocked."
                    ),
                    context=context,
                    evaluation_id=evaluation_id,
                    matched_policies=[],
                    effective_effect=PolicyEffect.DENY,
                    reason=isolation_error,
                    obligations={
                        "audit": True,
                        "security_review": True,
                    },
                    dry_run=dry_run,
                )

                return self._finalize_evaluation_result(
                    result,
                    evaluation_id,
                    started_at,
                    context,
                    context["action"],
                    context["resource"],
                    dry_run,
                )

            matches = self._find_matching_policies(
                context
            )

            (
                effective_effect,
                dominant_match,
                obligations,
            ) = self._resolve_effect(
                matches,
                context,
            )

            if effective_effect == PolicyEffect.RATE_LIMIT:
                (
                    rate_allowed,
                    rate_metadata,
                ) = self._check_rate_limit(
                    context,
                    obligations,
                    dry_run=dry_run,
                )

                obligations = self._merge_obligations(
                    obligations,
                    {
                        "rate_limit": rate_metadata,
                    },
                )

                if not rate_allowed:
                    decision = PolicyDecision.RATE_LIMITED
                    reason = (
                        dominant_match.reason
                        if dominant_match
                        else "Rate limit exceeded."
                    )
                else:
                    effective_effect = PolicyEffect.ALLOW
                    decision = PolicyDecision.ALLOWED
                    reason = (
                        "Rate limit policy matched and "
                        "capacity remains."
                    )
            else:
                decision = self._decision_for_effect(
                    effective_effect
                )

                reason = (
                    dominant_match.reason
                    if (
                        dominant_match
                        and dominant_match.reason
                    )
                    else self._default_reason(
                        effective_effect
                    )
                )

            approval_result: Optional[
                dict[str, Any]
            ] = None

            if (
                request_security_approval
                and decision
                == PolicyDecision.CHALLENGE_REQUIRED
                and not dry_run
            ):
                approval_result = (
                    self._request_security_approval(
                        context,
                        effective_effect=effective_effect,
                        obligations=obligations,
                        matched_policies=[
                            match.to_dict()
                            for match in matches
                        ],
                        evaluation_id=evaluation_id,
                    )
                )

                if (
                    approval_result.get("success")
                    and approval_result.get(
                        "data",
                        {},
                    ).get("approved")
                ):
                    decision = PolicyDecision.ALLOWED
                    reason = (
                        "Security approval requirement "
                        "was satisfied."
                    )

                    obligations = (
                        self._merge_obligations(
                            obligations,
                            {
                                "security_approval": {
                                    "satisfied": True,
                                    "approval_id": (
                                        approval_result.get(
                                            "data",
                                            {},
                                        ).get(
                                            "approval_id"
                                        )
                                    ),
                                }
                            },
                        )
                    )

                elif approval_result.get(
                    "data",
                    {},
                ).get("denied"):
                    decision = PolicyDecision.DENIED
                    reason = (
                        "Security approval was denied."
                    )

            result = self._decision_result(
                decision=decision,
                message=self._message_for_decision(
                    decision
                ),
                context=context,
                evaluation_id=evaluation_id,
                matched_policies=matches,
                effective_effect=effective_effect,
                reason=reason,
                obligations=obligations,
                approval_result=approval_result,
                dry_run=dry_run,
            )

            return self._finalize_evaluation_result(
                result,
                evaluation_id,
                started_at,
                context,
                context["action"],
                context["resource"],
                dry_run,
            )

        except Exception as exc:
            self._metrics["evaluations_error"] += 1
            self.logger.exception(
                "Policy evaluation failed"
            )

            effect = (
                PolicyEffect.DENY
                if self.fail_closed
                else PolicyEffect.ALLOW
            )

            decision = (
                PolicyDecision.DENIED
                if self.fail_closed
                else PolicyDecision.ALLOWED
            )

            result = self._decision_result(
                decision=decision,
                message=(
                    "Policy evaluation failed; "
                    "fail-closed protection applied."
                    if self.fail_closed
                    else (
                        "Policy evaluation failed; "
                        "fail-open configuration applied."
                    )
                ),
                context=self._sanitize(
                    dict(task_context)
                ),
                evaluation_id=evaluation_id,
                matched_policies=[],
                effective_effect=effect,
                reason=str(exc),
                obligations={
                    "audit": True,
                    "security_review": self.fail_closed,
                },
                dry_run=dry_run,
                error={
                    "code": "POLICY_EVALUATION_FAILED",
                    "type": type(exc).__name__,
                },
            )

            return self._finalize_evaluation_result(
                result,
                evaluation_id,
                started_at,
                task_context,
                (
                    action
                    or str(
                        task_context.get("action")
                        or "unknown"
                    )
                ),
                (
                    resource
                    or str(
                        task_context.get("resource")
                        or "unknown"
                    )
                ),
                dry_run,
            )

    def evaluate(
        self,
        task: Mapping[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """BaseAgent and Registry-compatible evaluation entrypoint."""

        return self.evaluate_policy(
            task,
            **kwargs,
        )

    def execute(
        self,
        task: Mapping[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Master Agent-compatible execution entrypoint.

        PolicyEngine only evaluates the requested action. It never executes the
        underlying protected operation.
        """

        return self.evaluate_policy(
            task,
            **kwargs,
        )

    def handle_task(
        self,
        task: Mapping[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Agent Router-compatible task entrypoint."""

        return self.evaluate_policy(
            task,
            **kwargs,
        )

    def check(
        self,
        task_context: Mapping[str, Any],
        action: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Compact alias for check(context, action)."""

        return self.evaluate_policy(
            task_context,
            action=action,
            **kwargs,
        )

    def is_allowed(
        self,
        task_context: Mapping[str, Any],
        action: str,
        **kwargs: Any,
    ) -> bool:
        """Return a convenience boolean.

        Structured evaluate_policy() results should remain the source of truth
        for production decisions and audit records.
        """

        result = self.evaluate_policy(
            task_context,
            action=action,
            **kwargs,
        )

        return bool(
            result.get("success")
            and result.get(
                "data",
                {},
            ).get("allowed")
        )

    def simulate(
        self,
        task_context: Mapping[str, Any],
        action: Optional[str] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Evaluate without external approvals or rate-counter mutations."""

        kwargs["dry_run"] = True
        kwargs["request_security_approval"] = False

        return self.evaluate_policy(
            task_context,
            action=action,
            **kwargs,
        )

    def evaluate_batch(
        self,
        requests: Sequence[Mapping[str, Any]],
        *,
        stop_on_deny: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Evaluate multiple policy requests."""

        if (
            not isinstance(requests, Sequence)
            or isinstance(requests, (str, bytes))
        ):
            return self._error_result(
                "Requests must be a sequence.",
                "INVALID_BATCH",
            )

        results: list[dict[str, Any]] = []

        for request in requests:
            if not isinstance(request, Mapping):
                results.append(
                    self._error_result(
                        "Batch item must be a mapping.",
                        "INVALID_BATCH_ITEM",
                    )
                )

                if stop_on_deny:
                    break

                continue

            result = self.evaluate_policy(
                request,
                dry_run=dry_run,
            )

            results.append(result)

            if (
                stop_on_deny
                and not result.get(
                    "data",
                    {},
                ).get("allowed", False)
            ):
                break

        allowed_count = sum(
            1
            for item in results
            if item.get(
                "data",
                {},
            ).get("allowed")
        )

        not_allowed_count = (
            len(results) - allowed_count
        )

        return self._safe_result(
            not_allowed_count == 0,
            "Batch policy evaluation completed.",
            data={
                "results": results,
                "total": len(results),
                "allowed": allowed_count,
                "not_allowed": not_allowed_count,
            },
        )

    def get_metrics(self) -> dict[str, Any]:
        """Return dashboard-compatible policy metrics."""

        with self._lock:
            policy_count = len(self._policies)
            metrics = dict(self._metrics)

        metrics["policy_count"] = policy_count

        return self._safe_result(
            True,
            "Policy engine metrics retrieved.",
            data={
                "metrics": metrics,
            },
        )

    def health_check(self) -> dict[str, Any]:
        """Return an Agent Loader and monitoring-compatible health result."""

        with self._lock:
            policy_count = len(self._policies)

        return self._safe_result(
            True,
            "Policy engine is healthy.",
            data={
                "agent": self.agent_name,
                "version": self.agent_version,
                "policy_count": policy_count,
                "fail_closed": self.fail_closed,
                "default_effect": (
                    self.default_effect.value
                ),
            },
        )

    def registry_manifest(self) -> dict[str, Any]:
        """Return Agent Registry metadata."""

        return {
            "name": self.agent_name,
            "type": self.agent_type,
            "version": self.agent_version,
            "class": self.__class__.__name__,
            "capabilities": list(self.capabilities),
            "entrypoints": [
                "execute",
                "handle_task",
                "evaluate",
                "evaluate_policy",
            ],
            "requires_user_context": True,
            "requires_workspace_context": True,
            "sensitive": True,
        }

    # ------------------------------------------------------------------
    # William compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        task_context: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Validate required SaaS and routing context."""

        if not isinstance(task_context, Mapping):
            return self._error_result(
                "Task context must be a mapping.",
                "INVALID_TASK_CONTEXT",
            )

        required_fields = (
            "user_id",
            "workspace_id",
        )

        missing_fields = [
            field_name
            for field_name in required_fields
            if not str(
                task_context.get(field_name)
                or ""
            ).strip()
        ]

        if missing_fields:
            return self._error_result(
                (
                    "Task context is missing required "
                    "SaaS isolation fields."
                ),
                "MISSING_TENANT_CONTEXT",
                metadata={
                    "missing_fields": missing_fields,
                },
            )

        try:
            self._validate_identifier(
                str(task_context["user_id"]),
                "user_id",
            )

            self._validate_identifier(
                str(task_context["workspace_id"]),
                "workspace_id",
            )

            for optional_field in (
                "source_agent",
                "target_agent",
                "session_id",
                "request_id",
            ):
                if task_context.get(optional_field):
                    self._validate_identifier(
                        str(
                            task_context[
                                optional_field
                            ]
                        ),
                        optional_field,
                    )

        except ValueError as exc:
            return self._error_result(
                str(exc),
                "INVALID_CONTEXT_IDENTIFIER",
            )

        if self.context_validator is not None:
            try:
                external_result = self._invoke_handler(
                    self.context_validator,
                    task_context=dict(task_context),
                )

                if (
                    isinstance(
                        external_result,
                        Mapping,
                    )
                    and not external_result.get(
                        "success",
                        True,
                    )
                ):
                    return self._error_result(
                        str(
                            external_result.get(
                                "message"
                            )
                            or (
                                "External context "
                                "validation failed."
                            )
                        ),
                        (
                            "EXTERNAL_CONTEXT_"
                            "VALIDATION_FAILED"
                        ),
                        metadata={
                            "validator_result": (
                                self._sanitize(
                                    external_result
                                )
                            ),
                        },
                    )

                if external_result is False:
                    return self._error_result(
                        (
                            "External context "
                            "validation failed."
                        ),
                        (
                            "EXTERNAL_CONTEXT_"
                            "VALIDATION_FAILED"
                        ),
                    )

            except Exception as exc:
                if self.fail_closed:
                    return self._error_result(
                        "Context validator failed.",
                        "CONTEXT_VALIDATOR_ERROR",
                        exc,
                    )

                self.logger.warning(
                    (
                        "Context validator failed in "
                        "fail-open mode: %s"
                    ),
                    exc,
                )

        return self._safe_result(
            True,
            "Task context validated.",
            data={
                "valid": True,
            },
        )

    def _requires_security_check(
        self,
        task_context: Mapping[str, Any],
        *,
        action: Optional[str] = None,
        risk_level: Optional[
            RiskLevel | str
        ] = None,
    ) -> bool:
        """Determine whether an action is security-sensitive."""

        normalized_action = str(
            action
            or task_context.get("action")
            or ""
        ).lower()

        risk = _coerce_enum(
            RiskLevel,
            (
                risk_level
                or task_context.get("risk_level")
                or RiskLevel.MEDIUM.value
            ),
        )

        sensitive_prefixes = (
            "delete",
            "remove",
            "execute",
            "terminal",
            "shell",
            "payment",
            "transfer",
            "purchase",
            "message.send",
            "email.send",
            "call.",
            "browser.submit",
            "credential",
            "secret",
            "permission",
            "admin",
            "export",
            "download",
            "system.",
            "file.write",
            "file.move",
            "account.",
            "device.",
        )

        return (
            _RISK_ORDER[risk]
            >= _RISK_ORDER[RiskLevel.HIGH]
            or normalized_action.startswith(
                sensitive_prefixes
            )
        )

    def _request_security_approval(
        self,
        task_context: Mapping[str, Any],
        **approval_context: Any,
    ) -> dict[str, Any]:
        """Request approval through Security Agent or Approval Manager."""

        if self.security_approval_handler is None:
            return self._safe_result(
                False,
                (
                    "Security approval is required but "
                    "no approval handler is configured."
                ),
                data={
                    "approved": False,
                    "pending": True,
                    "denied": False,
                },
                error={
                    "code": (
                        "SECURITY_APPROVAL_"
                        "HANDLER_UNAVAILABLE"
                    ),
                },
                metadata={
                    "approval_context": self._sanitize(
                        approval_context
                    ),
                },
            )

        try:
            raw_result = self._invoke_handler(
                self.security_approval_handler,
                task_context=dict(task_context),
                approval_context=approval_context,
            )

            if isinstance(raw_result, Mapping):
                raw_data = raw_result.get(
                    "data",
                    {},
                )

                if not isinstance(raw_data, Mapping):
                    raw_data = {}

                approved = bool(
                    raw_result.get("approved")
                    or raw_data.get("approved")
                )

                denied = bool(
                    raw_result.get("denied")
                    or raw_data.get("denied")
                )

                pending = not approved and not denied

                return self._safe_result(
                    approved,
                    str(
                        raw_result.get("message")
                        or (
                            "Security approval granted."
                            if approved
                            else (
                                "Security approval pending "
                                "or denied."
                            )
                        )
                    ),
                    data={
                        "approved": approved,
                        "denied": denied,
                        "pending": pending,
                        "approval_id": (
                            raw_result.get(
                                "approval_id"
                            )
                            or raw_data.get(
                                "approval_id"
                            )
                        ),
                        "raw": self._sanitize(
                            raw_result
                        ),
                    },
                )

            approved = bool(raw_result)

            return self._safe_result(
                approved,
                (
                    "Security approval granted."
                    if approved
                    else "Security approval denied."
                ),
                data={
                    "approved": approved,
                    "denied": not approved,
                    "pending": False,
                },
            )

        except Exception as exc:
            self.logger.exception(
                "Security approval handler failed"
            )

            return self._error_result(
                "Security approval handler failed.",
                "SECURITY_APPROVAL_FAILED",
                exc,
                data={
                    "approved": False,
                    "pending": True,
                    "denied": False,
                },
            )

    def _prepare_verification_payload(
        self,
        result: Mapping[str, Any],
        task_context: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Prepare a Verification Agent-compatible payload."""

        raw_data = result.get("data", {})

        data = (
            raw_data
            if isinstance(raw_data, Mapping)
            else {}
        )

        matched_policy_ids = [
            item.get("policy_id")
            for item in data.get(
                "matched_policies",
                [],
            )
            if isinstance(item, Mapping)
        ]

        checksum_source = {
            "evaluation_id": data.get(
                "evaluation_id"
            ),
            "decision": data.get("decision"),
            "effective_effect": data.get(
                "effective_effect"
            ),
            "user_id": task_context.get(
                "user_id"
            ),
            "workspace_id": task_context.get(
                "workspace_id"
            ),
        }

        return {
            "schema_version": "1.0",
            "payload_type": (
                "policy_decision_verification"
            ),
            "agent": self.agent_name,
            "generated_at": _utc_now_iso(),
            "user_id": task_context.get(
                "user_id"
            ),
            "workspace_id": task_context.get(
                "workspace_id"
            ),
            "request_id": task_context.get(
                "request_id"
            ),
            "evaluation_id": data.get(
                "evaluation_id"
            ),
            "decision": data.get("decision"),
            "allowed": data.get("allowed"),
            "effective_effect": data.get(
                "effective_effect"
            ),
            "matched_policy_ids": (
                matched_policy_ids
            ),
            "decision_checksum": (
                self._stable_checksum(
                    checksum_source
                )
            ),
        }

    def _prepare_memory_payload(
        self,
        result: Mapping[str, Any],
        task_context: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Prepare a tenant-isolated Memory Agent payload."""

        raw_data = result.get("data", {})

        data = (
            raw_data
            if isinstance(raw_data, Mapping)
            else {}
        )

        return {
            "schema_version": "1.0",
            "payload_type": (
                "policy_decision_memory"
            ),
            "memory_category": (
                "security_policy_decision"
            ),
            "generated_at": _utc_now_iso(),
            "user_id": task_context.get(
                "user_id"
            ),
            "workspace_id": task_context.get(
                "workspace_id"
            ),
            "session_id": task_context.get(
                "session_id"
            ),
            "request_id": task_context.get(
                "request_id"
            ),
            "agent": self.agent_name,
            "summary": {
                "action": task_context.get(
                    "action"
                ),
                "resource": task_context.get(
                    "resource"
                ),
                "decision": data.get("decision"),
                "effective_effect": data.get(
                    "effective_effect"
                ),
                "reason": data.get("reason"),
            },
            "retention": (
                "security_audit_policy"
            ),
            "sensitivity": "restricted",
            "do_not_cross_tenant_boundary": True,
        }

    def _emit_agent_event(
        self,
        event_type: str,
        payload: Mapping[str, Any],
    ) -> None:
        """Emit an event for Agent Registry, dashboard, or event bus."""

        event = {
            "event_id": uuid.uuid4().hex,
            "event_type": event_type,
            "agent": self.agent_name,
            "timestamp": _utc_now_iso(),
            "payload": self._sanitize(payload),
        }

        if self.event_handler is None:
            self.logger.debug(
                "Agent event: %s",
                event,
            )
            return

        try:
            self._invoke_handler(
                self.event_handler,
                event=event,
            )
        except Exception:
            self.logger.exception(
                "Agent event handler failed"
            )

    def _log_audit_event(
        self,
        event_type: str,
        task_context: Mapping[str, Any],
        *,
        details: Optional[
            Mapping[str, Any]
        ] = None,
    ) -> None:
        """Send a tenant-scoped event to Audit Logger."""

        event = {
            "audit_id": uuid.uuid4().hex,
            "event_type": event_type,
            "agent": self.agent_name,
            "timestamp": _utc_now_iso(),
            "user_id": task_context.get(
                "user_id"
            ),
            "workspace_id": task_context.get(
                "workspace_id"
            ),
            "session_id": task_context.get(
                "session_id"
            ),
            "request_id": task_context.get(
                "request_id"
            ),
            "details": self._sanitize(
                details or {}
            ),
        }

        if self.audit_handler is None:
            self.logger.info(
                "Policy audit event: %s",
                event,
            )
            return

        try:
            self._invoke_handler(
                self.audit_handler,
                event=event,
            )
        except Exception:
            self.logger.exception(
                "Audit handler failed"
            )

    def _safe_result(
        self,
        success: bool,
        message: str,
        *,
        data: Optional[
            Mapping[str, Any]
        ] = None,
        error: Optional[
            Mapping[str, Any]
        ] = None,
        metadata: Optional[
            Mapping[str, Any]
        ] = None,
    ) -> dict[str, Any]:
        """Return William's standard structured result."""

        return {
            "success": bool(success),
            "message": str(message),
            "data": copy.deepcopy(
                dict(data or {})
            ),
            "error": (
                copy.deepcopy(dict(error))
                if error
                else None
            ),
            "metadata": {
                "agent": self.agent_name,
                "agent_version": (
                    self.agent_version
                ),
                "timestamp": _utc_now_iso(),
                **copy.deepcopy(
                    dict(metadata or {})
                ),
            },
        }

    def _error_result(
        self,
        message: str,
        code: str = "POLICY_ENGINE_ERROR",
        error: Optional[
            BaseException
        ] = None,
        *,
        data: Optional[
            Mapping[str, Any]
        ] = None,
        metadata: Optional[
            Mapping[str, Any]
        ] = None,
    ) -> dict[str, Any]:
        """Return William's standard structured error result."""

        error_payload: dict[str, Any] = {
            "code": code,
        }

        if error is not None:
            error_payload.update(
                {
                    "type": (
                        type(error).__name__
                    ),
                    "details": str(error),
                }
            )

        return self._safe_result(
            False,
            message,
            data=data,
            error=error_payload,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Policy matching and conflict resolution
    # ------------------------------------------------------------------

    def _normalize_context(
        self,
        task_context: Mapping[str, Any],
        *,
        action: Optional[str],
        resource: Optional[str],
        source_agent: Optional[str],
        target_agent: Optional[str],
        risk_level: Optional[
            RiskLevel | str
        ],
    ) -> dict[str, Any]:
        """Normalize task input without mutating the caller's mapping."""

        context = copy.deepcopy(
            dict(task_context)
        )

        context["user_id"] = str(
            context["user_id"]
        )

        context["workspace_id"] = str(
            context["workspace_id"]
        )

        context["action"] = str(
            action
            or context.get("action")
            or "unknown"
        ).strip().lower()

        context["resource"] = str(
            resource
            or context.get("resource")
            or "unknown"
        ).strip().lower()

        context["source_agent"] = str(
            source_agent
            or context.get("source_agent")
            or "unknown"
        ).strip().lower()

        context["target_agent"] = str(
            target_agent
            or context.get("target_agent")
            or context["source_agent"]
        ).strip().lower()

        context["role"] = str(
            context.get("role")
            or "member"
        ).strip().lower()

        context["subscription_plan"] = str(
            context.get("subscription_plan")
            or "free"
        ).strip().lower()

        context["risk_level"] = _coerce_enum(
            RiskLevel,
            (
                risk_level
                or context.get("risk_level")
                or RiskLevel.MEDIUM.value
            ),
        ).value

        context["timestamp"] = str(
            context.get("timestamp")
            or _utc_now_iso()
        )

        context["attributes"] = copy.deepcopy(
            dict(
                context.get("attributes")
                or {}
            )
        )

        context["permissions"] = sorted(
            {
                str(item).lower()
                for item in _as_sequence(
                    context.get("permissions")
                )
            }
        )

        context["workspace_roles"] = sorted(
            {
                str(item).lower()
                for item in _as_sequence(
                    context.get(
                        "workspace_roles"
                    )
                )
            }
        )

        context["authenticated"] = bool(
            context.get(
                "authenticated",
                True,
            )
        )

        context["trusted_device"] = bool(
            context.get(
                "trusted_device",
                False,
            )
        )

        context["mfa_verified"] = bool(
            context.get(
                "mfa_verified",
                False,
            )
        )

        context["biometric_verified"] = bool(
            context.get(
                "biometric_verified",
                False,
            )
        )

        context["user_confirmed"] = bool(
            context.get(
                "user_confirmed",
                False,
            )
        )

        context["admin_approved"] = bool(
            context.get(
                "admin_approved",
                False,
            )
        )

        context["security_approved"] = bool(
            context.get(
                "security_approved",
                False,
            )
        )

        return context

    def _validate_tenant_isolation(
        self,
        context: Mapping[str, Any],
    ) -> Optional[str]:
        """Enforce workspace and private-user resource isolation."""

        user_id = str(
            context.get("user_id")
            or ""
        )

        workspace_id = str(
            context.get("workspace_id")
            or ""
        )

        if not user_id or not workspace_id:
            return (
                "Both user_id and workspace_id "
                "are mandatory."
            )

        owner_user_id = context.get(
            "resource_owner_user_id"
        )

        owner_workspace_id = context.get(
            "resource_workspace_id"
        )

        cross_workspace = bool(
            context.get(
                "cross_workspace",
                False,
            )
        )

        platform_admin = self._is_platform_admin(
            context
        )

        if (
            owner_workspace_id
            and str(owner_workspace_id)
            != workspace_id
        ):
            cross_workspace_allowed = bool(
                cross_workspace
                and platform_admin
                and context.get(
                    "cross_workspace_approved"
                )
            )

            if not cross_workspace_allowed:
                return (
                    "Resource belongs to another "
                    "workspace."
                )

        if (
            owner_user_id
            and str(owner_user_id) != user_id
            and bool(
                context.get(
                    "user_private_resource",
                    False,
                )
            )
        ):
            private_access_allowed = bool(
                platform_admin
                and context.get(
                    "private_resource_access_approved"
                )
            )

            if not private_access_allowed:
                return (
                    "Private resource belongs to "
                    "another user."
                )

        return None

    def _find_matching_policies(
        self,
        context: Mapping[str, Any],
    ) -> list[PolicyMatch]:
        """Find all active policy rules matching the request."""

        with self._lock:
            policies = list(
                self._policies.values()
            )

        matches: list[PolicyMatch] = []

        for rule in policies:
            if (
                not rule.enabled
                or self._is_expired(
                    rule.expires_at
                )
            ):
                continue

            if not self._rule_matches(
                rule,
                context,
            ):
                continue

            matches.append(
                PolicyMatch(
                    policy_id=rule.policy_id,
                    name=rule.name,
                    effect=rule.effect,
                    scope=rule.scope,
                    priority=rule.priority,
                    reason=(
                        rule.reason
                        or rule.description
                    ),
                    obligations=copy.deepcopy(
                        dict(rule.obligations)
                    ),
                    specificity=(
                        self._calculate_specificity(
                            rule
                        )
                    ),
                )
            )

        matches.sort(
            key=self._match_sort_key,
            reverse=True,
        )

        return matches

    def _rule_matches(
        self,
        rule: PolicyRule,
        context: Mapping[str, Any],
    ) -> bool:
        """Check whether a policy applies to the normalized context."""

        if (
            rule.workspace_ids
            and str(
                context.get("workspace_id")
            )
            not in rule.workspace_ids
        ):
            return False

        if (
            rule.user_ids
            and str(context.get("user_id"))
            not in rule.user_ids
        ):
            return False

        if (
            rule.roles
            and str(
                context.get("role", "")
            ).lower()
            not in {
                item.lower()
                for item in rule.roles
            }
        ):
            return False

        if (
            rule.subscription_plans
            and str(
                context.get(
                    "subscription_plan",
                    "",
                )
            ).lower()
            not in {
                item.lower()
                for item
                in rule.subscription_plans
            }
        ):
            return False

        if rule.risk_levels:
            context_risk = _coerce_enum(
                RiskLevel,
                context.get("risk_level"),
            )

            if context_risk not in rule.risk_levels:
                return False

        if not self._matches_patterns(
            str(
                context.get(
                    "action",
                    "unknown",
                )
            ),
            rule.actions,
        ):
            return False

        if not self._matches_patterns(
            str(
                context.get(
                    "resource",
                    "unknown",
                )
            ),
            rule.resources,
        ):
            return False

        if not self._matches_patterns(
            str(
                context.get(
                    "source_agent",
                    "unknown",
                )
            ),
            rule.source_agents,
        ):
            return False

        if not self._matches_patterns(
            str(
                context.get(
                    "target_agent",
                    "unknown",
                )
            ),
            rule.target_agents,
        ):
            return False

        return self._conditions_match(
            rule.conditions,
            context,
        )

    def _conditions_match(
        self,
        conditions: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> bool:
        """Evaluate declarative nested policy conditions."""

        for key, expected in conditions.items():
            if (
                key == "all"
                and isinstance(
                    expected,
                    Sequence,
                )
                and not isinstance(
                    expected,
                    (str, bytes),
                )
            ):
                mappings = [
                    item
                    for item in expected
                    if isinstance(item, Mapping)
                ]

                if not all(
                    self._conditions_match(
                        item,
                        context,
                    )
                    for item in mappings
                ):
                    return False

                continue

            if (
                key == "any"
                and isinstance(
                    expected,
                    Sequence,
                )
                and not isinstance(
                    expected,
                    (str, bytes),
                )
            ):
                mappings = [
                    item
                    for item in expected
                    if isinstance(item, Mapping)
                ]

                if (
                    not mappings
                    or not any(
                        self._conditions_match(
                            item,
                            context,
                        )
                        for item in mappings
                    )
                ):
                    return False

                continue

            if (
                key == "not"
                and isinstance(
                    expected,
                    Mapping,
                )
            ):
                if self._conditions_match(
                    expected,
                    context,
                ):
                    return False

                continue

            actual = self._resolve_path(
                context,
                key,
            )

            if (
                isinstance(expected, Mapping)
                and self._looks_like_operator_mapping(
                    expected
                )
            ):
                if not self._evaluate_operators(
                    actual,
                    expected,
                ):
                    return False

            elif actual != expected:
                return False

        return True

    def _evaluate_operators(
        self,
        actual: Any,
        operators: Mapping[str, Any],
    ) -> bool:
        """Evaluate supported condition operators."""

        for operator, expected in operators.items():
            if (
                operator == "eq"
                and actual != expected
            ):
                return False

            if (
                operator == "ne"
                and actual == expected
            ):
                return False

            if (
                operator == "in"
                and actual
                not in _as_sequence(expected)
            ):
                return False

            if (
                operator == "not_in"
                and actual
                in _as_sequence(expected)
            ):
                return False

            if operator == "contains":
                try:
                    if expected not in actual:
                        return False
                except TypeError:
                    return False

            if operator == "contains_any":
                try:
                    if not any(
                        item in actual
                        for item in _as_sequence(
                            expected
                        )
                    ):
                        return False
                except TypeError:
                    return False

            if operator == "contains_all":
                try:
                    if not all(
                        item in actual
                        for item in _as_sequence(
                            expected
                        )
                    ):
                        return False
                except TypeError:
                    return False

            if (
                operator == "exists"
                and bool(actual is not None)
                != bool(expected)
            ):
                return False

            if (
                operator == "truthy"
                and bool(actual)
                != bool(expected)
            ):
                return False

            if (
                operator == "glob"
                and not fnmatch.fnmatchcase(
                    str(actual).lower(),
                    str(expected).lower(),
                )
            ):
                return False

            if operator == "regex":
                try:
                    if (
                        re.search(
                            str(expected),
                            str(actual),
                        )
                        is None
                    ):
                        return False
                except re.error:
                    return False

            if operator in {
                "gt",
                "gte",
                "lt",
                "lte",
            }:
                try:
                    if (
                        operator == "gt"
                        and not actual > expected
                    ):
                        return False

                    if (
                        operator == "gte"
                        and not actual >= expected
                    ):
                        return False

                    if (
                        operator == "lt"
                        and not actual < expected
                    ):
                        return False

                    if (
                        operator == "lte"
                        and not actual <= expected
                    ):
                        return False

                except TypeError:
                    return False

        return True

    def _resolve_effect(
        self,
        matches: Sequence[PolicyMatch],
        context: Mapping[str, Any],
    ) -> tuple[
        PolicyEffect,
        Optional[PolicyMatch],
        dict[str, Any],
    ]:
        """Resolve policy conflicts using safety-first precedence."""

        if not matches:
            return (
                self.default_effect,
                None,
                {},
            )

        dominant_match = max(
            matches,
            key=self._match_sort_key,
        )

        obligations: dict[str, Any] = {}

        for match in reversed(matches):
            obligations = (
                self._merge_obligations(
                    obligations,
                    match.obligations,
                )
            )

        effective_effect = (
            self._satisfy_challenge_if_preverified(
                dominant_match.effect,
                context,
            )
        )

        return (
            effective_effect,
            dominant_match,
            obligations,
        )

    def _satisfy_challenge_if_preverified(
        self,
        effect: PolicyEffect,
        context: Mapping[str, Any],
    ) -> PolicyEffect:
        """Convert satisfied challenges to allow."""

        if (
            effect
            == PolicyEffect.REQUIRE_CONFIRMATION
            and context.get("user_confirmed")
        ):
            return PolicyEffect.ALLOW

        if (
            effect
            == PolicyEffect.REQUIRE_BIOMETRIC
            and context.get(
                "biometric_verified"
            )
        ):
            return PolicyEffect.ALLOW

        if (
            effect
            == PolicyEffect.REQUIRE_MFA
            and context.get("mfa_verified")
        ):
            return PolicyEffect.ALLOW

        if (
            effect
            == PolicyEffect.REQUIRE_TRUSTED_DEVICE
            and context.get("trusted_device")
        ):
            return PolicyEffect.ALLOW

        if (
            effect
            == PolicyEffect.REQUIRE_ADMIN
            and (
                context.get("admin_approved")
                or self._is_platform_admin(
                    context
                )
            )
        ):
            return PolicyEffect.ALLOW

        if (
            effect
            == PolicyEffect.REQUIRE_SECURITY_APPROVAL
            and context.get(
                "security_approved"
            )
        ):
            return PolicyEffect.ALLOW

        return effect

    def _decision_for_effect(
        self,
        effect: PolicyEffect,
    ) -> PolicyDecision:
        """Map a policy effect to a public decision."""

        if effect == PolicyEffect.ALLOW:
            return PolicyDecision.ALLOWED

        if effect == PolicyEffect.DENY:
            return PolicyDecision.DENIED

        if effect == PolicyEffect.READ_ONLY:
            return PolicyDecision.READ_ONLY

        if effect == PolicyEffect.REDACT:
            return PolicyDecision.REDACTED

        if effect == PolicyEffect.RATE_LIMIT:
            return PolicyDecision.RATE_LIMITED

        return PolicyDecision.CHALLENGE_REQUIRED

    def _decision_result(
        self,
        *,
        decision: PolicyDecision,
        message: str,
        context: Mapping[str, Any],
        evaluation_id: str,
        matched_policies: (
            Sequence[PolicyMatch]
            | Sequence[Mapping[str, Any]]
        ),
        effective_effect: PolicyEffect,
        reason: str,
        obligations: Mapping[str, Any],
        dry_run: bool,
        approval_result: Optional[
            Mapping[str, Any]
        ] = None,
        error: Optional[
            Mapping[str, Any]
        ] = None,
    ) -> dict[str, Any]:
        """Build a normalized policy evaluation result."""

        serialized_matches = [
            (
                item.to_dict()
                if isinstance(item, PolicyMatch)
                else copy.deepcopy(dict(item))
            )
            for item in matched_policies
        ]

        allowed = (
            decision == PolicyDecision.ALLOWED
        )

        success = (
            decision != PolicyDecision.ERROR
        )

        return self._safe_result(
            success,
            message,
            data={
                "evaluation_id": evaluation_id,
                "decision": decision.value,
                "allowed": allowed,
                "effective_effect": (
                    effective_effect.value
                ),
                "reason": reason,
                "action": context.get("action"),
                "resource": context.get(
                    "resource"
                ),
                "user_id": context.get(
                    "user_id"
                ),
                "workspace_id": context.get(
                    "workspace_id"
                ),
                "source_agent": context.get(
                    "source_agent"
                ),
                "target_agent": context.get(
                    "target_agent"
                ),
                "risk_level": context.get(
                    "risk_level"
                ),
                "matched_policies": (
                    serialized_matches
                ),
                "obligations": copy.deepcopy(
                    dict(obligations)
                ),
                "approval": (
                    copy.deepcopy(
                        dict(
                            approval_result or {}
                        )
                    )
                    if approval_result
                    else None
                ),
                "dry_run": dry_run,
            },
            error=error,
            metadata={
                "policy_count_matched": len(
                    serialized_matches
                ),
            },
        )

    def _finalize_evaluation_result(
        self,
        result: dict[str, Any],
        evaluation_id: str,
        started_at: float,
        task_context: Mapping[str, Any],
        action: str,
        resource: str,
        dry_run: bool,
    ) -> dict[str, Any]:
        """Attach integrations, metrics, audit data, and verification payloads."""

        duration_ms = round(
            (
                time.monotonic()
                - started_at
            )
            * 1000,
            3,
        )

        result.setdefault(
            "metadata",
            {},
        )["evaluation_id"] = evaluation_id

        result["metadata"]["duration_ms"] = (
            duration_ms
        )

        result["metadata"]["dry_run"] = (
            dry_run
        )

        result_data = result.get(
            "data",
            {},
        )

        if not isinstance(result_data, dict):
            result_data = {}
            result["data"] = result_data

        decision = result_data.get(
            "decision"
        )

        if decision:
            self._metrics[
                f"decision_{decision}"
            ] += 1

        matched_policy_ids = [
            item.get("policy_id")
            for item in result_data.get(
                "matched_policies",
                [],
            )
            if isinstance(item, Mapping)
        ]

        audit_details = {
            "evaluation_id": evaluation_id,
            "action": action,
            "resource": resource,
            "decision": decision,
            "effective_effect": (
                result_data.get(
                    "effective_effect"
                )
            ),
            "matched_policy_ids": (
                matched_policy_ids
            ),
            "duration_ms": duration_ms,
            "dry_run": dry_run,
        }

        if not dry_run:
            self._log_audit_event(
                "policy_evaluated",
                task_context,
                details=audit_details,
            )

            self._emit_agent_event(
                "policy.evaluated",
                {
                    "user_id": (
                        task_context.get(
                            "user_id"
                        )
                    ),
                    "workspace_id": (
                        task_context.get(
                            "workspace_id"
                        )
                    ),
                    **audit_details,
                },
            )

        verification_payload = (
            self._prepare_verification_payload(
                result,
                task_context,
            )
        )

        memory_payload = (
            self._prepare_memory_payload(
                result,
                task_context,
            )
        )

        result_data[
            "verification_payload"
        ] = verification_payload

        result_data[
            "memory_payload"
        ] = memory_payload

        if (
            not dry_run
            and self.verification_handler
            is not None
        ):
            try:
                self._invoke_handler(
                    self.verification_handler,
                    payload=verification_payload,
                )
            except Exception:
                self.logger.exception(
                    (
                        "Verification handler "
                        "failed"
                    )
                )

        if (
            not dry_run
            and self.memory_handler
            is not None
        ):
            try:
                self._invoke_handler(
                    self.memory_handler,
                    payload=memory_payload,
                )
            except Exception:
                self.logger.exception(
                    "Memory handler failed"
                )

        return result

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def _check_rate_limit(
        self,
        context: Mapping[str, Any],
        obligations: Mapping[str, Any],
        *,
        dry_run: bool,
    ) -> tuple[bool, dict[str, Any]]:
        """Evaluate a rate-limit obligation."""

        raw_config = obligations.get(
            "rate_limit",
            obligations,
        )

        config = (
            raw_config
            if isinstance(raw_config, Mapping)
            else {}
        )

        limit = max(
            1,
            int(config.get("limit", 10)),
        )

        window_seconds = max(
            1,
            int(
                config.get(
                    "window_seconds",
                    60,
                )
            ),
        )

        dimensions = _as_string_tuple(
            config.get("dimensions"),
            default=(
                "workspace_id",
                "user_id",
                "action",
                "resource",
            ),
        )

        key_parts = [
            str(
                self._resolve_path(
                    context,
                    dimension,
                )
                or "-"
            )
            for dimension in dimensions
        ]

        key = "|".join(key_parts)
        now = time.monotonic()

        with self._lock:
            state = self._rate_limit_state.get(
                key
            )

            if (
                state is None
                or (
                    now
                    - state.window_started_at
                )
                >= window_seconds
            ):
                state = RateLimitState(
                    window_started_at=now,
                    count=0,
                )

                if not dry_run:
                    self._rate_limit_state[
                        key
                    ] = state

            projected_count = (
                state.count + 1
            )

            allowed = (
                projected_count <= limit
            )

            if not dry_run and allowed:
                state.count = projected_count

        elapsed = max(
            0.0,
            now - state.window_started_at,
        )

        reset_after = max(
            0.0,
            window_seconds - elapsed,
        )

        return (
            allowed,
            {
                "key_hash": hashlib.sha256(
                    key.encode("utf-8")
                ).hexdigest()[:24],
                "limit": limit,
                "window_seconds": (
                    window_seconds
                ),
                "count": projected_count,
                "remaining": max(
                    0,
                    limit - projected_count,
                ),
                "reset_after_seconds": round(
                    reset_after,
                    3,
                ),
                "dry_run": dry_run,
            },
        )

    # ------------------------------------------------------------------
    # Policy validation and default platform policies
    # ------------------------------------------------------------------

    def _validate_policy_rule(
        self,
        rule: PolicyRule,
    ) -> None:
        """Validate a policy before registration or import."""

        self._validate_identifier(
            rule.policy_id,
            "policy_id",
        )

        if not rule.name.strip():
            raise ValueError(
                "Policy name is required."
            )

        if not (
            -1_000_000
            <= rule.priority
            <= 1_000_000
        ):
            raise ValueError(
                (
                    "Policy priority is outside "
                    "the supported range."
                )
            )

        collection_names = (
            "actions",
            "resources",
            "source_agents",
            "target_agents",
            "roles",
            "subscription_plans",
            "user_ids",
            "workspace_ids",
        )

        for collection_name in collection_names:
            collection = getattr(
                rule,
                collection_name,
            )

            if len(collection) > 1_000:
                raise ValueError(
                    (
                        f"Policy field "
                        f"'{collection_name}' "
                        f"is too large."
                    )
                )

            for item in collection:
                if (
                    not isinstance(item, str)
                    or not item.strip()
                ):
                    raise ValueError(
                        (
                            f"Policy field "
                            f"'{collection_name}' "
                            f"contains an invalid value."
                        )
                    )

        if rule.expires_at:
            _parse_iso_datetime(
                rule.expires_at
            )

        self._validate_condition_depth(
            rule.conditions
        )

    def _validate_condition_depth(
        self,
        value: Any,
        depth: int = 0,
    ) -> None:
        """Protect the engine from oversized or deeply nested conditions."""

        if depth > 12:
            raise ValueError(
                (
                    "Policy conditions exceed "
                    "maximum nesting depth."
                )
            )

        if isinstance(value, Mapping):
            if len(value) > 500:
                raise ValueError(
                    (
                        "Policy conditions contain "
                        "too many keys."
                    )
                )

            for key, nested_value in value.items():
                if not isinstance(key, str):
                    raise ValueError(
                        (
                            "Policy condition keys "
                            "must be strings."
                        )
                    )

                self._validate_condition_depth(
                    nested_value,
                    depth + 1,
                )

        elif (
            isinstance(value, Sequence)
            and not isinstance(
                value,
                (str, bytes),
            )
        ):
            if len(value) > 1_000:
                raise ValueError(
                    (
                        "Policy condition list "
                        "is too large."
                    )
                )

            for nested_value in value:
                self._validate_condition_depth(
                    nested_value,
                    depth + 1,
                )

    def _build_default_policies(
        self,
    ) -> tuple[PolicyRule, ...]:
        """Build conservative William/Jarvis platform policies."""

        return (
            PolicyRule(
                policy_id=(
                    "platform.deny.cross_tenant"
                ),
                name="Deny cross-tenant access",
                effect=PolicyEffect.DENY,
                scope=PolicyScope.PLATFORM,
                priority=100_000,
                actions=("*",),
                conditions={
                    "cross_tenant_violation": {
                        "truthy": True,
                    }
                },
                reason=(
                    "Cross-tenant access is "
                    "prohibited."
                ),
                obligations={
                    "audit": True,
                    "alert_security": True,
                },
            ),
            PolicyRule(
                policy_id=(
                    "platform.deny."
                    "unauthenticated_sensitive"
                ),
                name=(
                    "Deny unauthenticated "
                    "sensitive actions"
                ),
                effect=PolicyEffect.DENY,
                scope=PolicyScope.PLATFORM,
                priority=90_000,
                actions=(
                    "delete*",
                    "remove*",
                    "execute*",
                    "terminal*",
                    "shell*",
                    "payment*",
                    "transfer*",
                    "purchase*",
                    "message.send*",
                    "email.send*",
                    "call.*",
                    "credential*",
                    "secret*",
                    "permission*",
                    "admin*",
                    "system.*",
                ),
                conditions={
                    "authenticated": {
                        "eq": False,
                    }
                },
                reason=(
                    "Authentication is required "
                    "for sensitive actions."
                ),
                obligations={
                    "audit": True,
                },
            ),
            PolicyRule(
                policy_id=(
                    "platform.require_approval."
                    "financial"
                ),
                name=(
                    "Require approval for "
                    "financial actions"
                ),
                effect=(
                    PolicyEffect
                    .REQUIRE_SECURITY_APPROVAL
                ),
                scope=PolicyScope.PLATFORM,
                priority=80_000,
                actions=(
                    "payment*",
                    "transfer*",
                    "purchase*",
                    "banking*",
                    "finance.execute*",
                ),
                reason=(
                    "Financial actions require "
                    "explicit security approval."
                ),
                obligations={
                    "user_confirmation": True,
                    "never_auto_execute": True,
                    "verification_required": True,
                    "audit": True,
                },
            ),
            PolicyRule(
                policy_id=(
                    "platform.require_biometric."
                    "critical"
                ),
                name=(
                    "Require biometric verification "
                    "for critical actions"
                ),
                effect=(
                    PolicyEffect
                    .REQUIRE_BIOMETRIC
                ),
                scope=PolicyScope.PLATFORM,
                priority=75_000,
                risk_levels=(
                    RiskLevel.CRITICAL,
                ),
                reason=(
                    "Critical-risk actions require "
                    "biometric verification."
                ),
                obligations={
                    "audit": True,
                    "verification_required": True,
                },
            ),
            PolicyRule(
                policy_id=(
                    "platform.require_confirmation."
                    "destructive"
                ),
                name=(
                    "Require confirmation for "
                    "destructive actions"
                ),
                effect=(
                    PolicyEffect
                    .REQUIRE_CONFIRMATION
                ),
                scope=PolicyScope.PLATFORM,
                priority=70_000,
                actions=(
                    "delete*",
                    "remove*",
                    "file.delete*",
                    "file.overwrite*",
                    "database.drop*",
                    "system.shutdown*",
                    "system.restart*",
                    "account.close*",
                    "workspace.delete*",
                ),
                reason=(
                    "Destructive actions require "
                    "explicit user confirmation."
                ),
                obligations={
                    "backup_before_action": True,
                    "audit": True,
                    "verification_required": True,
                },
            ),
            PolicyRule(
                policy_id=(
                    "platform.require_approval."
                    "external_communication"
                ),
                name=(
                    "Require approval for "
                    "external communication"
                ),
                effect=(
                    PolicyEffect
                    .REQUIRE_SECURITY_APPROVAL
                ),
                scope=PolicyScope.PLATFORM,
                priority=60_000,
                actions=(
                    "message.send*",
                    "email.send*",
                    "call.place*",
                    "browser.submit*",
                    "social.publish*",
                ),
                reason=(
                    "External communication requires "
                    "Security Agent approval."
                ),
                obligations={
                    "preview_required": True,
                    "audit": True,
                },
            ),
            PolicyRule(
                policy_id=(
                    "platform.redact.secrets"
                ),
                name="Redact secrets from outputs",
                effect=PolicyEffect.REDACT,
                scope=PolicyScope.PLATFORM,
                priority=50_000,
                actions=(
                    "memory.store*",
                    "log.write*",
                    "analytics.record*",
                    "agent.output*",
                ),
                conditions={
                    "contains_secrets": {
                        "truthy": True,
                    }
                },
                reason=(
                    "Secrets must be redacted before "
                    "storage, logging, analytics, "
                    "or output."
                ),
                obligations={
                    "redact_secrets": True,
                    "audit": True,
                },
            ),
            PolicyRule(
                policy_id=(
                    "platform.allow.safe_read"
                ),
                name=(
                    "Allow authenticated low-risk "
                    "reads"
                ),
                effect=PolicyEffect.ALLOW,
                scope=PolicyScope.PLATFORM,
                priority=100,
                actions=(
                    "read*",
                    "list*",
                    "view*",
                    "search*",
                    "status*",
                    "health*",
                ),
                risk_levels=(
                    RiskLevel.MINIMAL,
                    RiskLevel.LOW,
                ),
                conditions={
                    "authenticated": {
                        "eq": True,
                    }
                },
                reason=(
                    "Authenticated low-risk read "
                    "operation is allowed."
                ),
                obligations={
                    "tenant_filter_required": True,
                },
            ),
        )

    # ------------------------------------------------------------------
    # Internal utilities
    # ------------------------------------------------------------------

    def _policy_sort_key(
        self,
        rule: PolicyRule,
    ) -> tuple[int, int, int, int, str]:
        """Return deterministic policy administration order."""

        return (
            _EFFECT_PRECEDENCE[rule.effect],
            rule.priority,
            _SCOPE_PRECEDENCE[rule.scope],
            self._calculate_specificity(rule),
            rule.policy_id,
        )

    def _match_sort_key(
        self,
        match: PolicyMatch,
    ) -> tuple[int, int, int, int, str]:
        """Return safety-first conflict-resolution order."""

        return (
            _EFFECT_PRECEDENCE[match.effect],
            match.priority,
            _SCOPE_PRECEDENCE[match.scope],
            match.specificity,
            match.policy_id,
        )

    def _calculate_specificity(
        self,
        rule: PolicyRule,
    ) -> int:
        """Calculate how specifically a rule targets the request."""

        score = 0

        pattern_collections = (
            rule.actions,
            rule.resources,
            rule.source_agents,
            rule.target_agents,
        )

        for patterns in pattern_collections:
            score += sum(
                (
                    0
                    if item == "*"
                    else (
                        2
                        if (
                            "*" in item
                            or "?" in item
                        )
                        else 4
                    )
                )
                for item in patterns
            )

        score += len(rule.roles) * 3
        score += len(
            rule.subscription_plans
        ) * 3
        score += len(rule.user_ids) * 8
        score += len(
            rule.workspace_ids
        ) * 6
        score += len(
            rule.risk_levels
        ) * 2
        score += len(rule.conditions) * 4

        return score

    def _matches_patterns(
        self,
        value: str,
        patterns: Sequence[str],
    ) -> bool:
        """Match a value against case-insensitive glob patterns."""

        normalized_value = value.lower()

        return any(
            fnmatch.fnmatchcase(
                normalized_value,
                str(pattern).lower(),
            )
            for pattern in patterns
        )

    def _is_expired(
        self,
        expires_at: Optional[str],
    ) -> bool:
        """Return whether a policy expiry timestamp has passed."""

        if not expires_at:
            return False

        return (
            _parse_iso_datetime(expires_at)
            <= datetime.now(timezone.utc)
        )

    def _is_platform_admin(
        self,
        context: Mapping[str, Any],
    ) -> bool:
        """Check normalized administrator roles and permissions."""

        role = str(
            context.get("role")
            or ""
        ).lower()

        roles = {
            str(item).lower()
            for item in _as_sequence(
                context.get("workspace_roles")
            )
        }

        permissions = {
            str(item).lower()
            for item in _as_sequence(
                context.get("permissions")
            )
        }

        return bool(
            role in {
                "platform_admin",
                "super_admin",
            }
            or roles.intersection(
                {
                    "platform_admin",
                    "super_admin",
                }
            )
            or "platform.*" in permissions
            or (
                "security.policy.override"
                in permissions
            )
        )

    def _merge_obligations(
        self,
        base: Mapping[str, Any],
        overlay: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Recursively merge policy obligations."""

        result = copy.deepcopy(
            dict(base)
        )

        for key, value in overlay.items():
            if (
                isinstance(value, Mapping)
                and isinstance(
                    result.get(key),
                    Mapping,
                )
            ):
                result[key] = (
                    self._merge_obligations(
                        result[key],
                        value,
                    )
                )

            elif (
                isinstance(value, list)
                and isinstance(
                    result.get(key),
                    list,
                )
            ):
                result[key] = list(
                    dict.fromkeys(
                        [
                            *result[key],
                            *copy.deepcopy(value),
                        ]
                    )
                )

            else:
                result[key] = copy.deepcopy(
                    value
                )

        return result

    def _resolve_path(
        self,
        value: Mapping[str, Any],
        path: str,
    ) -> Any:
        """Resolve a dot-delimited path inside a mapping."""

        current: Any = value

        for part in path.split("."):
            if (
                not isinstance(
                    current,
                    Mapping,
                )
                or part not in current
            ):
                return None

            current = current[part]

        return current

    def _looks_like_operator_mapping(
        self,
        value: Mapping[str, Any],
    ) -> bool:
        """Detect whether a condition uses supported operators."""

        operators = {
            "eq",
            "ne",
            "in",
            "not_in",
            "contains",
            "contains_any",
            "contains_all",
            "exists",
            "truthy",
            "glob",
            "regex",
            "gt",
            "gte",
            "lt",
            "lte",
        }

        return bool(
            set(value).intersection(
                operators
            )
        )

    def _message_for_decision(
        self,
        decision: PolicyDecision,
    ) -> str:
        """Return a stable public decision message."""

        messages = {
            PolicyDecision.ALLOWED: (
                "Policy evaluation allowed "
                "the action."
            ),
            PolicyDecision.DENIED: (
                "Policy evaluation denied "
                "the action."
            ),
            PolicyDecision.CHALLENGE_REQUIRED: (
                "Additional verification or "
                "approval is required."
            ),
            PolicyDecision.READ_ONLY: (
                "The action is restricted to "
                "read-only behavior."
            ),
            PolicyDecision.REDACTED: (
                "The action is permitted only "
                "with required redaction."
            ),
            PolicyDecision.RATE_LIMITED: (
                "The action was rate limited."
            ),
            PolicyDecision.ERROR: (
                "Policy evaluation encountered "
                "an error."
            ),
        }

        return messages[decision]

    def _default_reason(
        self,
        effect: PolicyEffect,
    ) -> str:
        """Return a fallback policy reason."""

        return (
            f"Effective policy effect: "
            f"{effect.value}."
        )

    def _validate_identifier(
        self,
        value: str,
        field_name: str,
    ) -> str:
        """Validate tenant, request, policy, session, and agent IDs."""

        normalized = str(value).strip()

        if (
            not normalized
            or not _SAFE_IDENTIFIER.fullmatch(
                normalized
            )
        ):
            raise ValueError(
                f"Invalid {field_name}."
            )

        return normalized

    def _stable_checksum(
        self,
        value: Any,
    ) -> str:
        """Return a deterministic SHA-256 checksum."""

        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")

        return hashlib.sha256(
            encoded
        ).hexdigest()

    def _sanitize(
        self,
        value: Any,
        depth: int = 0,
    ) -> Any:
        """Redact likely secrets before logs, events, or callback payloads."""

        if depth > 12:
            return "<max-depth>"

        if isinstance(value, Mapping):
            sanitized: dict[str, Any] = {}

            for key, item in value.items():
                key_string = str(key)

                if _SECRET_KEY_RE.search(
                    key_string
                ):
                    sanitized[
                        key_string
                    ] = "<redacted>"
                else:
                    sanitized[
                        key_string
                    ] = self._sanitize(
                        item,
                        depth + 1,
                    )

            return sanitized

        if isinstance(
            value,
            (list, tuple, set),
        ):
            return [
                self._sanitize(
                    item,
                    depth + 1,
                )
                for item in value
            ]

        if isinstance(value, Enum):
            return value.value

        if (
            isinstance(
                value,
                (
                    str,
                    int,
                    float,
                    bool,
                ),
            )
            or value is None
        ):
            return value

        return str(value)

    def _invoke_handler(
        self,
        handler: Callable[..., Any],
        **kwargs: Any,
    ) -> Any:
        """Invoke integration callbacks safely.

        The synchronous PolicyEngine rejects returned awaitables. Async FastAPI
        applications should provide a synchronous adapter or call asynchronous
        integrations in their own application service layer.
        """

        signature = inspect.signature(
            handler
        )

        accepts_kwargs = any(
            parameter.kind
            == inspect.Parameter.VAR_KEYWORD
            for parameter
            in signature.parameters.values()
        )

        if accepts_kwargs:
            result = handler(**kwargs)

        else:
            accepted_arguments = {
                key: value
                for key, value in kwargs.items()
                if key
                in signature.parameters
            }

            if accepted_arguments:
                result = handler(
                    **accepted_arguments
                )

            elif len(signature.parameters) == 1:
                result = handler(
                    next(
                        iter(kwargs.values())
                    )
                )

            else:
                result = handler()

        if inspect.isawaitable(result):
            raise RuntimeError(
                (
                    "Async callback returned an "
                    "awaitable to the synchronous "
                    "PolicyEngine. Provide a "
                    "synchronous adapter or call the "
                    "callback in the async application "
                    "layer."
                )
            )

        return result


def _utc_now_iso() -> str:
    """Return the current UTC time in ISO-8601 format."""

    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _parse_iso_datetime(
    value: str,
) -> datetime:
    """Parse an ISO-8601 timestamp and normalize it to UTC."""

    normalized = value.strip().replace(
        "Z",
        "+00:00",
    )

    parsed = datetime.fromisoformat(
        normalized
    )

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed.astimezone(
        timezone.utc
    )


def _coerce_enum(
    enum_type: type[Enum],
    value: Any,
) -> Any:
    """Coerce a string or enum instance into an enum member."""

    if isinstance(value, enum_type):
        return value

    normalized = str(value).strip().lower()

    for member in enum_type:
        if (
            str(member.value).lower()
            == normalized
            or member.name.lower()
            == normalized
        ):
            return member

    allowed = ", ".join(
        str(member.value)
        for member in enum_type
    )

    raise ValueError(
        (
            f"Invalid {enum_type.__name__}: "
            f"{value!r}. Allowed values: "
            f"{allowed}."
        )
    )


def _as_sequence(
    value: Any,
) -> list[Any]:
    """Normalize a scalar or iterable value into a list."""

    if value is None:
        return []

    if isinstance(
        value,
        (str, bytes),
    ):
        return [value]

    if isinstance(value, Sequence):
        return list(value)

    if isinstance(value, Iterable):
        return list(value)

    return [value]


def _as_string_tuple(
    value: Any,
    *,
    default: tuple[str, ...],
) -> tuple[str, ...]:
    """Normalize a value into a non-empty tuple of strings."""

    if value is None:
        return default

    result = tuple(
        str(item).strip()
        for item in _as_sequence(value)
        if str(item).strip()
    )

    return result or default


def _optional_string(
    value: Any,
) -> Optional[str]:
    """Normalize an optional string."""

    if value is None:
        return None

    normalized = str(value).strip()

    return normalized or None


def _constant_time_equal(
    left: str,
    right: str,
) -> bool:
    """Compare checksum strings using constant-time comparison."""

    import hmac

    return hmac.compare_digest(
        left.encode("utf-8"),
        right.encode("utf-8"),
    )


__all__ = [
    "PolicyEngine",
    "PolicyRule",
    "PolicyMatch",
    "PolicyEffect",
    "PolicyScope",
    "PolicyDecision",
    "RiskLevel",
]