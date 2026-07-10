"""
agents/workflow_agent/condition_engine.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Workflow Agent condition engine for:
    - If/else rules
    - Filtering workflow items
    - Lead scoring
    - Duplicate checks
    - Spam checks
    - Routing decisions

Architecture Compatibility:
    - BaseAgent compatible with import-safe fallback
    - Agent Registry / Agent Loader safe
    - Master Agent routing ready
    - Security Agent approval hooks
    - Verification Agent payload preparation
    - Memory Agent payload preparation
    - Dashboard / FastAPI structured responses
    - SaaS user_id / workspace_id isolation

Important:
    This file is intentionally self-contained and import-safe. If William core
    modules are not available yet, fallback classes are used so this file can
    still be imported, tested, and integrated later.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
import operator
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# =============================================================================
# Safe Optional Imports / Fallbacks
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for isolated imports
    class BaseAgent:  # type: ignore
        """
        Import-safe fallback BaseAgent.

        Real William/Jarvis deployments should provide agents.base_agent.BaseAgent.
        This fallback exists only to keep this file importable during staged builds.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            raise NotImplementedError("Fallback BaseAgent.run is not implemented.")


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for staged builds
    SecurityAgent = None  # type: ignore


try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for staged builds
    VerificationAgent = None  # type: ignore


try:
    from agents.memory_agent.memory_agent import MemoryAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for staged builds
    MemoryAgent = None  # type: ignore


# =============================================================================
# Logging
# =============================================================================

LOGGER = logging.getLogger("William.WorkflowAgent.ConditionEngine")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


# =============================================================================
# Enums / Data Structures
# =============================================================================

class ConditionOperator(str, Enum):
    """Supported safe condition operators."""

    EQ = "eq"
    NE = "ne"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"

    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"

    IN = "in"
    NOT_IN = "not_in"

    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    EMPTY = "empty"
    NOT_EMPTY = "not_empty"

    REGEX = "regex"
    NOT_REGEX = "not_regex"

    BETWEEN = "between"
    NOT_BETWEEN = "not_between"

    IS_TRUE = "is_true"
    IS_FALSE = "is_false"

    CHANGED = "changed"
    NOT_CHANGED = "not_changed"


class LogicalJoin(str, Enum):
    """Logical grouping modes."""

    ALL = "all"
    ANY = "any"
    NONE = "none"


class RouteDecision(str, Enum):
    """Common workflow routing outcomes."""

    PASS = "pass"
    FAIL = "fail"
    REVIEW = "review"
    DUPLICATE = "duplicate"
    SPAM = "spam"
    HIGH_VALUE = "high_value"
    LOW_VALUE = "low_value"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Risk levels used for audit/security/verification metadata."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ConditionRule:
    """
    Single condition rule.

    Example:
        {
            "field": "lead.email",
            "operator": "contains",
            "value": "@gmail.com",
            "case_sensitive": false
        }
    """

    field: str
    operator: Union[str, ConditionOperator]
    value: Any = None
    case_sensitive: bool = False
    negate: bool = False
    weight: float = 0.0
    label: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RuleGroup:
    """
    Group of condition rules with logical join.

    Example:
        {
            "join": "all",
            "rules": [
                {"field": "lead.email", "operator": "not_empty"},
                {"field": "lead.phone", "operator": "not_empty"}
            ]
        }
    """

    join: Union[str, LogicalJoin] = LogicalJoin.ALL
    rules: List[Union[ConditionRule, Dict[str, Any]]] = field(default_factory=list)
    groups: List[Union["RuleGroup", Dict[str, Any]]] = field(default_factory=list)
    label: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LeadScoringRule:
    """
    Lead scoring rule.

    If the condition passes, score_delta is added to the lead score.
    """

    condition: Union[ConditionRule, RuleGroup, Dict[str, Any]]
    score_delta: float
    reason: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RoutingRule:
    """
    Routing rule.

    If condition passes, the engine returns the configured route.
    """

    condition: Union[ConditionRule, RuleGroup, Dict[str, Any]]
    route: str
    priority: int = 100
    reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DuplicateCheckConfig:
    """
    Duplicate check configuration.

    match_fields:
        Fields used to build duplicate signature.
    fuzzy_fields:
        Optional fields normalized more aggressively.
    """

    match_fields: List[str] = field(default_factory=lambda: ["email", "phone"])
    fuzzy_fields: List[str] = field(default_factory=lambda: ["name"])
    strict: bool = False
    normalize_phone: bool = True
    normalize_email: bool = True


@dataclass
class SpamCheckConfig:
    """Spam detection configuration."""

    honeypot_fields: List[str] = field(default_factory=lambda: ["website", "url", "homepage"])
    spam_keywords: List[str] = field(default_factory=lambda: [
        "casino",
        "crypto giveaway",
        "free money",
        "viagra",
        "loan approved",
        "make money fast",
        "adult",
        "betting",
        "forex signals",
        "telegram pump",
        "work from home guaranteed",
    ])
    max_links: int = 5
    max_repeated_chars: int = 8
    min_quality_score: float = 20.0
    suspicious_tlds: List[str] = field(default_factory=lambda: [".xyz", ".top", ".click", ".work", ".rest"])
    disposable_email_domains: List[str] = field(default_factory=lambda: [
        "mailinator.com",
        "tempmail.com",
        "10minutemail.com",
        "guerrillamail.com",
        "yopmail.com",
        "throwawaymail.com",
    ])


# =============================================================================
# Condition Engine
# =============================================================================

class ConditionEngine(BaseAgent):
    """
    Production-ready Workflow Agent condition engine.

    Responsibilities:
        - Evaluate if/else rules
        - Filter workflow data
        - Score leads
        - Detect duplicates
        - Detect spam
        - Route workflow payloads

    Master Agent:
        Can call `run(task)` or direct public methods.

    Security Agent:
        Sensitive decisions can pass through `_request_security_approval()`.

    Memory Agent:
        Useful context is prepared through `_prepare_memory_payload()`.

    Verification Agent:
        Completed decisions are prepared through `_prepare_verification_payload()`.

    Dashboard/API:
        Every public method returns structured dict responses:
        {
            "success": bool,
            "message": str,
            "data": dict,
            "error": optional,
            "metadata": dict
        }
    """

    AGENT_NAME = "ConditionEngine"
    AGENT_TYPE = "workflow_agent.condition_engine"
    VERSION = "1.0.0"

    SAFE_OPERATORS: Dict[ConditionOperator, Callable[..., bool]] = {}

    def __init__(
        self,
        security_agent: Any = None,
        memory_agent: Any = None,
        verification_agent: Any = None,
        logger: Optional[logging.Logger] = None,
        default_spam_config: Optional[SpamCheckConfig] = None,
        default_duplicate_config: Optional[DuplicateCheckConfig] = None,
        enable_security_checks: bool = True,
        enable_audit_log: bool = True,
        enable_memory_payloads: bool = True,
        enable_verification_payloads: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.AGENT_NAME, agent_id=self.AGENT_TYPE, **kwargs)

        self.logger = logger or LOGGER
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent

        self.default_spam_config = default_spam_config or SpamCheckConfig()
        self.default_duplicate_config = default_duplicate_config or DuplicateCheckConfig()

        self.enable_security_checks = bool(enable_security_checks)
        self.enable_audit_log = bool(enable_audit_log)
        self.enable_memory_payloads = bool(enable_memory_payloads)
        self.enable_verification_payloads = bool(enable_verification_payloads)

        self._operator_map = self._build_operator_map()

    # =========================================================================
    # BaseAgent / Master Agent Entry Point
    # =========================================================================

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Master Agent / Agent Router entry point.

        Supported task actions:
            - evaluate_condition
            - evaluate_rules
            - filter_items
            - score_lead
            - duplicate_check
            - spam_check
            - route_payload
            - process_conditions
        """

        context_validation = self._validate_task_context(task)
        if not context_validation["success"]:
            return context_validation

        action = str(task.get("action", "")).strip().lower()
        payload = task.get("payload", {}) or {}
        user_id = task.get("user_id")
        workspace_id = task.get("workspace_id")

        if self._requires_security_check(task):
            approval = self._request_security_approval(task)
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for condition engine task.",
                    error="security_approval_denied",
                    metadata={
                        "action": action,
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "approval": approval,
                    },
                )

        try:
            if action == "evaluate_condition":
                result = self.evaluate_condition(
                    data=payload.get("data", {}),
                    rule=payload.get("rule", {}),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=task.get("metadata", {}),
                )

            elif action == "evaluate_rules":
                result = self.evaluate_rules(
                    data=payload.get("data", {}),
                    rule_group=payload.get("rule_group", payload.get("rules", {})),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=task.get("metadata", {}),
                )

            elif action == "filter_items":
                result = self.filter_items(
                    items=payload.get("items", []),
                    rule_group=payload.get("rule_group", payload.get("rules", {})),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=task.get("metadata", {}),
                )

            elif action == "score_lead":
                result = self.score_lead(
                    lead=payload.get("lead", {}),
                    scoring_rules=payload.get("scoring_rules", []),
                    base_score=float(payload.get("base_score", 0.0)),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=task.get("metadata", {}),
                )

            elif action == "duplicate_check":
                result = self.check_duplicate(
                    record=payload.get("record", {}),
                    existing_records=payload.get("existing_records", []),
                    config=payload.get("config"),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=task.get("metadata", {}),
                )

            elif action == "spam_check":
                result = self.check_spam(
                    record=payload.get("record", {}),
                    config=payload.get("config"),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=task.get("metadata", {}),
                )

            elif action == "route_payload":
                result = self.route_payload(
                    payload=payload.get("workflow_payload", payload.get("data", {})),
                    routing_rules=payload.get("routing_rules", []),
                    default_route=payload.get("default_route", "review"),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=task.get("metadata", {}),
                )

            elif action == "process_conditions":
                result = self.process_conditions(
                    payload=payload.get("workflow_payload", payload.get("data", {})),
                    condition_config=payload.get("condition_config", {}),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=task.get("metadata", {}),
                )

            else:
                return self._error_result(
                    message=f"Unsupported condition engine action: {action or 'missing'}",
                    error="unsupported_action",
                    metadata={
                        "supported_actions": [
                            "evaluate_condition",
                            "evaluate_rules",
                            "filter_items",
                            "score_lead",
                            "duplicate_check",
                            "spam_check",
                            "route_payload",
                            "process_conditions",
                        ],
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

            self._emit_agent_event(
                event_type="condition_engine.task_completed",
                payload={
                    "action": action,
                    "success": result.get("success", False),
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )
            return result

        except Exception as exc:
            self.logger.exception("ConditionEngine.run failed")
            return self._error_result(
                message="Condition engine task failed.",
                error=str(exc),
                metadata={
                    "action": action,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

    # =========================================================================
    # Public Methods
    # =========================================================================

    def evaluate_condition(
        self,
        data: Mapping[str, Any],
        rule: Union[ConditionRule, Mapping[str, Any]],
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate a single if/else condition rule against payload data.
        """

        try:
            context_result = self._validate_context_values(user_id, workspace_id)
            if not context_result["success"]:
                return context_result

            normalized_rule = self._normalize_condition_rule(rule)
            passed, details = self._evaluate_single_rule(data, normalized_rule)

            result_data = {
                "passed": passed,
                "rule": self._serialize_dataclass(normalized_rule),
                "details": details,
                "decision": RouteDecision.PASS.value if passed else RouteDecision.FAIL.value,
            }

            result = self._safe_result(
                message="Condition evaluated successfully.",
                data=result_data,
                metadata=self._build_metadata(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    operation="evaluate_condition",
                    input_metadata=metadata,
                ),
            )

            self._after_decision_hooks(
                operation="evaluate_condition",
                user_id=user_id,
                workspace_id=workspace_id,
                result=result,
            )
            return result

        except Exception as exc:
            self.logger.exception("evaluate_condition failed")
            return self._error_result(
                message="Failed to evaluate condition.",
                error=str(exc),
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "operation": "evaluate_condition",
                },
            )

    def evaluate_rules(
        self,
        data: Mapping[str, Any],
        rule_group: Union[RuleGroup, Mapping[str, Any], Sequence[Mapping[str, Any]]],
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate grouped if/else rules against payload data.
        """

        try:
            context_result = self._validate_context_values(user_id, workspace_id)
            if not context_result["success"]:
                return context_result

            normalized_group = self._normalize_rule_group(rule_group)
            passed, details = self._evaluate_rule_group(data, normalized_group)

            result = self._safe_result(
                message="Rule group evaluated successfully.",
                data={
                    "passed": passed,
                    "decision": RouteDecision.PASS.value if passed else RouteDecision.FAIL.value,
                    "rule_group": self._serialize_dataclass(normalized_group),
                    "details": details,
                },
                metadata=self._build_metadata(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    operation="evaluate_rules",
                    input_metadata=metadata,
                ),
            )

            self._after_decision_hooks(
                operation="evaluate_rules",
                user_id=user_id,
                workspace_id=workspace_id,
                result=result,
            )
            return result

        except Exception as exc:
            self.logger.exception("evaluate_rules failed")
            return self._error_result(
                message="Failed to evaluate rules.",
                error=str(exc),
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "operation": "evaluate_rules",
                },
            )

    def filter_items(
        self,
        items: Sequence[Mapping[str, Any]],
        rule_group: Union[RuleGroup, Mapping[str, Any], Sequence[Mapping[str, Any]]],
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Filter workflow records/items based on condition rules.

        Returns matching and rejected items with evaluation details.
        """

        try:
            context_result = self._validate_context_values(user_id, workspace_id)
            if not context_result["success"]:
                return context_result

            if not isinstance(items, Sequence) or isinstance(items, (str, bytes, bytearray)):
                return self._error_result(
                    message="items must be a sequence of mapping objects.",
                    error="invalid_items",
                    metadata={"user_id": user_id, "workspace_id": workspace_id},
                )

            normalized_group = self._normalize_rule_group(rule_group)
            matched: List[Dict[str, Any]] = []
            rejected: List[Dict[str, Any]] = []
            evaluations: List[Dict[str, Any]] = []

            for index, item in enumerate(items):
                if not isinstance(item, Mapping):
                    rejected.append({"index": index, "item": item, "reason": "item_not_mapping"})
                    evaluations.append({
                        "index": index,
                        "passed": False,
                        "reason": "item_not_mapping",
                    })
                    continue

                passed, details = self._evaluate_rule_group(item, normalized_group)
                item_copy = copy.deepcopy(dict(item))

                evaluations.append({
                    "index": index,
                    "passed": passed,
                    "details": details,
                })

                if passed:
                    matched.append(item_copy)
                else:
                    rejected.append({
                        "index": index,
                        "item": item_copy,
                        "reason": "condition_failed",
                    })

            result = self._safe_result(
                message="Items filtered successfully.",
                data={
                    "matched": matched,
                    "rejected": rejected,
                    "evaluations": evaluations,
                    "counts": {
                        "total": len(items),
                        "matched": len(matched),
                        "rejected": len(rejected),
                    },
                },
                metadata=self._build_metadata(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    operation="filter_items",
                    input_metadata=metadata,
                ),
            )

            self._after_decision_hooks(
                operation="filter_items",
                user_id=user_id,
                workspace_id=workspace_id,
                result=result,
            )
            return result

        except Exception as exc:
            self.logger.exception("filter_items failed")
            return self._error_result(
                message="Failed to filter items.",
                error=str(exc),
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "operation": "filter_items",
                },
            )

    def score_lead(
        self,
        lead: Mapping[str, Any],
        scoring_rules: Sequence[Union[LeadScoringRule, Mapping[str, Any]]],
        base_score: float = 0.0,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Score a lead using weighted condition rules.

        Example scoring rule:
            {
                "condition": {"field": "budget", "operator": "gte", "value": 1000},
                "score_delta": 25,
                "reason": "Budget is high"
            }
        """

        try:
            context_result = self._validate_context_values(user_id, workspace_id)
            if not context_result["success"]:
                return context_result

            if not isinstance(lead, Mapping):
                return self._error_result(
                    message="lead must be a mapping object.",
                    error="invalid_lead",
                    metadata={"user_id": user_id, "workspace_id": workspace_id},
                )

            score = float(base_score)
            matched_rules: List[Dict[str, Any]] = []
            failed_rules: List[Dict[str, Any]] = []

            for raw_rule in scoring_rules:
                scoring_rule = self._normalize_scoring_rule(raw_rule)
                condition = scoring_rule.condition

                if self._looks_like_rule_group(condition):
                    group = self._normalize_rule_group(condition)  # type: ignore[arg-type]
                    passed, details = self._evaluate_rule_group(lead, group)
                    serialized_condition = self._serialize_dataclass(group)
                else:
                    rule = self._normalize_condition_rule(condition)  # type: ignore[arg-type]
                    passed, details = self._evaluate_single_rule(lead, rule)
                    serialized_condition = self._serialize_dataclass(rule)

                entry = {
                    "passed": passed,
                    "score_delta": scoring_rule.score_delta,
                    "reason": scoring_rule.reason,
                    "condition": serialized_condition,
                    "details": details,
                    "metadata": scoring_rule.metadata,
                }

                if passed:
                    score += float(scoring_rule.score_delta)
                    matched_rules.append(entry)
                else:
                    failed_rules.append(entry)

            score = self._clamp(score, 0.0, 100.0)
            lead_quality = self._lead_quality_bucket(score)

            result = self._safe_result(
                message="Lead scored successfully.",
                data={
                    "score": score,
                    "quality": lead_quality,
                    "base_score": base_score,
                    "matched_rules": matched_rules,
                    "failed_rules": failed_rules,
                    "matched_count": len(matched_rules),
                    "failed_count": len(failed_rules),
                },
                metadata=self._build_metadata(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    operation="score_lead",
                    input_metadata=metadata,
                ),
            )

            self._after_decision_hooks(
                operation="score_lead",
                user_id=user_id,
                workspace_id=workspace_id,
                result=result,
            )
            return result

        except Exception as exc:
            self.logger.exception("score_lead failed")
            return self._error_result(
                message="Failed to score lead.",
                error=str(exc),
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "operation": "score_lead",
                },
            )

    def check_duplicate(
        self,
        record: Mapping[str, Any],
        existing_records: Sequence[Mapping[str, Any]],
        config: Optional[Union[DuplicateCheckConfig, Mapping[str, Any]]] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Check whether a record already exists.

        This method does not query databases directly. The caller must pass
        workspace-scoped existing_records, preserving SaaS isolation.
        """

        try:
            context_result = self._validate_context_values(user_id, workspace_id)
            if not context_result["success"]:
                return context_result

            if not isinstance(record, Mapping):
                return self._error_result(
                    message="record must be a mapping object.",
                    error="invalid_record",
                    metadata={"user_id": user_id, "workspace_id": workspace_id},
                )

            duplicate_config = self._normalize_duplicate_config(config)
            target_signature = self._build_duplicate_signature(record, duplicate_config)

            matches: List[Dict[str, Any]] = []

            for index, existing in enumerate(existing_records):
                if not isinstance(existing, Mapping):
                    continue

                existing_signature = self._build_duplicate_signature(existing, duplicate_config)
                exact_signature_match = bool(target_signature and target_signature == existing_signature)

                field_matches = self._duplicate_field_matches(
                    record=record,
                    existing=existing,
                    config=duplicate_config,
                )

                is_duplicate = exact_signature_match or self._is_duplicate_by_fields(
                    field_matches=field_matches,
                    config=duplicate_config,
                )

                if is_duplicate:
                    matches.append({
                        "index": index,
                        "match_type": "signature" if exact_signature_match else "field_match",
                        "signature": existing_signature,
                        "field_matches": field_matches,
                        "record": copy.deepcopy(dict(existing)),
                    })

            is_duplicate = len(matches) > 0

            result = self._safe_result(
                message="Duplicate check completed.",
                data={
                    "is_duplicate": is_duplicate,
                    "decision": RouteDecision.DUPLICATE.value if is_duplicate else RouteDecision.PASS.value,
                    "duplicate_count": len(matches),
                    "matches": matches,
                    "target_signature": target_signature,
                    "config": self._serialize_dataclass(duplicate_config),
                },
                metadata=self._build_metadata(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    operation="duplicate_check",
                    input_metadata=metadata,
                    risk_level=RiskLevel.MEDIUM.value if is_duplicate else RiskLevel.LOW.value,
                ),
            )

            self._after_decision_hooks(
                operation="duplicate_check",
                user_id=user_id,
                workspace_id=workspace_id,
                result=result,
            )
            return result

        except Exception as exc:
            self.logger.exception("check_duplicate failed")
            return self._error_result(
                message="Failed to check duplicate.",
                error=str(exc),
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "operation": "duplicate_check",
                },
            )

    def check_spam(
        self,
        record: Mapping[str, Any],
        config: Optional[Union[SpamCheckConfig, Mapping[str, Any]]] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Check a lead/form/webhook record for spam indicators.
        """

        try:
            context_result = self._validate_context_values(user_id, workspace_id)
            if not context_result["success"]:
                return context_result

            if not isinstance(record, Mapping):
                return self._error_result(
                    message="record must be a mapping object.",
                    error="invalid_record",
                    metadata={"user_id": user_id, "workspace_id": workspace_id},
                )

            spam_config = self._normalize_spam_config(config)
            risk_points = 0.0
            reasons: List[Dict[str, Any]] = []

            honeypot_result = self._check_honeypot(record, spam_config)
            if honeypot_result["triggered"]:
                risk_points += 45.0
                reasons.append(honeypot_result)

            keyword_result = self._check_spam_keywords(record, spam_config)
            if keyword_result["triggered"]:
                risk_points += min(30.0, 5.0 * len(keyword_result.get("matches", [])))
                reasons.append(keyword_result)

            link_result = self._check_link_count(record, spam_config)
            if link_result["triggered"]:
                risk_points += 20.0
                reasons.append(link_result)

            repeated_chars_result = self._check_repeated_chars(record, spam_config)
            if repeated_chars_result["triggered"]:
                risk_points += 12.0
                reasons.append(repeated_chars_result)

            disposable_email_result = self._check_disposable_email(record, spam_config)
            if disposable_email_result["triggered"]:
                risk_points += 25.0
                reasons.append(disposable_email_result)

            suspicious_tld_result = self._check_suspicious_tld(record, spam_config)
            if suspicious_tld_result["triggered"]:
                risk_points += 15.0
                reasons.append(suspicious_tld_result)

            quality_score = self._calculate_record_quality_score(record)
            if quality_score < spam_config.min_quality_score:
                risk_points += 18.0
                reasons.append({
                    "triggered": True,
                    "type": "low_quality_record",
                    "message": "Record quality score is below minimum threshold.",
                    "quality_score": quality_score,
                    "threshold": spam_config.min_quality_score,
                })

            risk_points = self._clamp(risk_points, 0.0, 100.0)
            is_spam = risk_points >= 50.0 or honeypot_result["triggered"]
            spam_risk = self._spam_risk_bucket(risk_points)

            result = self._safe_result(
                message="Spam check completed.",
                data={
                    "is_spam": is_spam,
                    "decision": RouteDecision.SPAM.value if is_spam else RouteDecision.PASS.value,
                    "risk_score": risk_points,
                    "risk_level": spam_risk,
                    "quality_score": quality_score,
                    "reasons": reasons,
                    "config": self._serialize_dataclass(spam_config),
                },
                metadata=self._build_metadata(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    operation="spam_check",
                    input_metadata=metadata,
                    risk_level=spam_risk,
                ),
            )

            self._after_decision_hooks(
                operation="spam_check",
                user_id=user_id,
                workspace_id=workspace_id,
                result=result,
            )
            return result

        except Exception as exc:
            self.logger.exception("check_spam failed")
            return self._error_result(
                message="Failed to check spam.",
                error=str(exc),
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "operation": "spam_check",
                },
            )

    def route_payload(
        self,
        payload: Mapping[str, Any],
        routing_rules: Sequence[Union[RoutingRule, Mapping[str, Any]]],
        default_route: str = "review",
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Route payload based on prioritized routing rules.

        First matching route with lowest priority number wins.
        """

        try:
            context_result = self._validate_context_values(user_id, workspace_id)
            if not context_result["success"]:
                return context_result

            if not isinstance(payload, Mapping):
                return self._error_result(
                    message="payload must be a mapping object.",
                    error="invalid_payload",
                    metadata={"user_id": user_id, "workspace_id": workspace_id},
                )

            normalized_rules = [self._normalize_routing_rule(rule) for rule in routing_rules]
            normalized_rules.sort(key=lambda item: int(item.priority))

            evaluated_routes: List[Dict[str, Any]] = []
            selected_route = default_route
            selected_reason = "Default route selected because no routing rule matched."
            selected_rule: Optional[Dict[str, Any]] = None

            for routing_rule in normalized_rules:
                condition = routing_rule.condition

                if self._looks_like_rule_group(condition):
                    group = self._normalize_rule_group(condition)  # type: ignore[arg-type]
                    passed, details = self._evaluate_rule_group(payload, group)
                    serialized_condition = self._serialize_dataclass(group)
                else:
                    rule = self._normalize_condition_rule(condition)  # type: ignore[arg-type]
                    passed, details = self._evaluate_single_rule(payload, rule)
                    serialized_condition = self._serialize_dataclass(rule)

                evaluation = {
                    "passed": passed,
                    "route": routing_rule.route,
                    "priority": routing_rule.priority,
                    "reason": routing_rule.reason,
                    "condition": serialized_condition,
                    "details": details,
                    "metadata": routing_rule.metadata,
                }
                evaluated_routes.append(evaluation)

                if passed:
                    selected_route = routing_rule.route
                    selected_reason = routing_rule.reason or f"Matched route {routing_rule.route}."
                    selected_rule = evaluation
                    break

            result = self._safe_result(
                message="Payload routed successfully.",
                data={
                    "route": selected_route,
                    "reason": selected_reason,
                    "selected_rule": selected_rule,
                    "evaluated_routes": evaluated_routes,
                    "default_route": default_route,
                },
                metadata=self._build_metadata(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    operation="route_payload",
                    input_metadata=metadata,
                ),
            )

            self._after_decision_hooks(
                operation="route_payload",
                user_id=user_id,
                workspace_id=workspace_id,
                result=result,
            )
            return result

        except Exception as exc:
            self.logger.exception("route_payload failed")
            return self._error_result(
                message="Failed to route payload.",
                error=str(exc),
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "operation": "route_payload",
                },
            )

    def process_conditions(
        self,
        payload: Mapping[str, Any],
        condition_config: Mapping[str, Any],
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Full condition processing pipeline.

        Optional condition_config keys:
            - rules / rule_group
            - scoring_rules
            - base_score
            - existing_records
            - duplicate_config
            - spam_config
            - routing_rules
            - default_route

        This method is useful for form_pipeline.py, webhook_manager.py,
        trigger_engine.py, and action_router.py.
        """

        try:
            context_result = self._validate_context_values(user_id, workspace_id)
            if not context_result["success"]:
                return context_result

            if not isinstance(payload, Mapping):
                return self._error_result(
                    message="payload must be a mapping object.",
                    error="invalid_payload",
                    metadata={"user_id": user_id, "workspace_id": workspace_id},
                )

            if not isinstance(condition_config, Mapping):
                return self._error_result(
                    message="condition_config must be a mapping object.",
                    error="invalid_condition_config",
                    metadata={"user_id": user_id, "workspace_id": workspace_id},
                )

            pipeline_results: Dict[str, Any] = {}
            final_decision = RouteDecision.PASS.value
            final_route = condition_config.get("default_route", "review")
            should_continue = True

            if condition_config.get("rules") or condition_config.get("rule_group"):
                rules_result = self.evaluate_rules(
                    data=payload,
                    rule_group=condition_config.get("rule_group", condition_config.get("rules", {})),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=metadata,
                )
                pipeline_results["rules"] = rules_result
                if not self._extract_data_value(rules_result, "passed", False):
                    should_continue = False
                    final_decision = RouteDecision.FAIL.value

            if should_continue and condition_config.get("spam_check", True):
                spam_result = self.check_spam(
                    record=payload,
                    config=condition_config.get("spam_config"),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=metadata,
                )
                pipeline_results["spam"] = spam_result
                if self._extract_data_value(spam_result, "is_spam", False):
                    should_continue = False
                    final_decision = RouteDecision.SPAM.value
                    final_route = condition_config.get("spam_route", "spam_review")

            if should_continue and condition_config.get("duplicate_check", False):
                duplicate_result = self.check_duplicate(
                    record=payload,
                    existing_records=condition_config.get("existing_records", []),
                    config=condition_config.get("duplicate_config"),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=metadata,
                )
                pipeline_results["duplicate"] = duplicate_result
                if self._extract_data_value(duplicate_result, "is_duplicate", False):
                    should_continue = bool(condition_config.get("continue_on_duplicate", False))
                    final_decision = RouteDecision.DUPLICATE.value
                    final_route = condition_config.get("duplicate_route", "duplicate_review")

            if should_continue and condition_config.get("scoring_rules"):
                score_result = self.score_lead(
                    lead=payload,
                    scoring_rules=condition_config.get("scoring_rules", []),
                    base_score=float(condition_config.get("base_score", 0.0)),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=metadata,
                )
                pipeline_results["score"] = score_result

                score = self._extract_data_value(score_result, "score", 0.0)
                if score >= float(condition_config.get("high_value_threshold", 75.0)):
                    final_decision = RouteDecision.HIGH_VALUE.value
                elif score <= float(condition_config.get("low_value_threshold", 25.0)):
                    final_decision = RouteDecision.LOW_VALUE.value

            if should_continue and condition_config.get("routing_rules"):
                route_result = self.route_payload(
                    payload=payload,
                    routing_rules=condition_config.get("routing_rules", []),
                    default_route=str(condition_config.get("default_route", final_route)),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=metadata,
                )
                pipeline_results["route"] = route_result
                final_route = self._extract_data_value(route_result, "route", final_route)

            result = self._safe_result(
                message="Condition pipeline processed successfully.",
                data={
                    "final_decision": final_decision,
                    "final_route": final_route,
                    "should_continue": should_continue,
                    "pipeline_results": pipeline_results,
                },
                metadata=self._build_metadata(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    operation="process_conditions",
                    input_metadata=metadata,
                    risk_level=self._decision_to_risk(final_decision),
                ),
            )

            self._after_decision_hooks(
                operation="process_conditions",
                user_id=user_id,
                workspace_id=workspace_id,
                result=result,
            )
            return result

        except Exception as exc:
            self.logger.exception("process_conditions failed")
            return self._error_result(
                message="Failed to process condition pipeline.",
                error=str(exc),
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "operation": "process_conditions",
                },
            )

    # =========================================================================
    # Rule Evaluation Internals
    # =========================================================================

    def _evaluate_single_rule(
        self,
        data: Mapping[str, Any],
        rule: ConditionRule,
    ) -> Tuple[bool, Dict[str, Any]]:
        """Evaluate one normalized ConditionRule."""

        operator_value = ConditionOperator(str(rule.operator).lower())
        actual_exists, actual_value = self._get_path(data, rule.field)

        comparison_value = rule.value
        if not rule.case_sensitive:
            actual_value_cmp = self._casefold_value(actual_value)
            comparison_value_cmp = self._casefold_value(comparison_value)
        else:
            actual_value_cmp = actual_value
            comparison_value_cmp = comparison_value

        operator_fn = self._operator_map.get(operator_value)
        if not operator_fn:
            raise ValueError(f"Unsupported condition operator: {rule.operator}")

        passed = bool(operator_fn(actual_exists, actual_value_cmp, comparison_value_cmp))
        if rule.negate:
            passed = not passed

        return passed, {
            "field": rule.field,
            "operator": operator_value.value,
            "expected": comparison_value,
            "actual": actual_value,
            "exists": actual_exists,
            "passed": passed,
            "negate": rule.negate,
            "weight": rule.weight,
            "label": rule.label,
        }

    def _evaluate_rule_group(
        self,
        data: Mapping[str, Any],
        group: RuleGroup,
    ) -> Tuple[bool, Dict[str, Any]]:
        """Evaluate nested rule group."""

        join = LogicalJoin(str(group.join).lower())
        evaluations: List[Dict[str, Any]] = []
        booleans: List[bool] = []

        for raw_rule in group.rules:
            rule = self._normalize_condition_rule(raw_rule)
            passed, details = self._evaluate_single_rule(data, rule)
            evaluations.append(details)
            booleans.append(passed)

        group_evaluations: List[Dict[str, Any]] = []
        for raw_group in group.groups:
            nested_group = self._normalize_rule_group(raw_group)
            passed, details = self._evaluate_rule_group(data, nested_group)
            group_evaluations.append(details)
            booleans.append(passed)

        if not booleans:
            passed = True
        elif join == LogicalJoin.ALL:
            passed = all(booleans)
        elif join == LogicalJoin.ANY:
            passed = any(booleans)
        elif join == LogicalJoin.NONE:
            passed = not any(booleans)
        else:
            raise ValueError(f"Unsupported logical join: {group.join}")

        return passed, {
            "join": join.value,
            "passed": passed,
            "rule_evaluations": evaluations,
            "group_evaluations": group_evaluations,
            "label": group.label,
            "metadata": group.metadata,
        }

    def _build_operator_map(self) -> Dict[ConditionOperator, Callable[[bool, Any, Any], bool]]:
        """Build safe operator map."""

        return {
            ConditionOperator.EQ: lambda exists, actual, expected: exists and actual == expected,
            ConditionOperator.NE: lambda exists, actual, expected: (not exists) or actual != expected,
            ConditionOperator.GT: lambda exists, actual, expected: exists and self._numeric_compare(actual, expected, operator.gt),
            ConditionOperator.GTE: lambda exists, actual, expected: exists and self._numeric_compare(actual, expected, operator.ge),
            ConditionOperator.LT: lambda exists, actual, expected: exists and self._numeric_compare(actual, expected, operator.lt),
            ConditionOperator.LTE: lambda exists, actual, expected: exists and self._numeric_compare(actual, expected, operator.le),
            ConditionOperator.CONTAINS: lambda exists, actual, expected: exists and self._contains(actual, expected),
            ConditionOperator.NOT_CONTAINS: lambda exists, actual, expected: (not exists) or not self._contains(actual, expected),
            ConditionOperator.STARTS_WITH: lambda exists, actual, expected: exists and str(actual).startswith(str(expected)),
            ConditionOperator.ENDS_WITH: lambda exists, actual, expected: exists and str(actual).endswith(str(expected)),
            ConditionOperator.IN: lambda exists, actual, expected: exists and self._in_collection(actual, expected),
            ConditionOperator.NOT_IN: lambda exists, actual, expected: (not exists) or not self._in_collection(actual, expected),
            ConditionOperator.EXISTS: lambda exists, actual, expected: exists,
            ConditionOperator.NOT_EXISTS: lambda exists, actual, expected: not exists,
            ConditionOperator.EMPTY: lambda exists, actual, expected: (not exists) or self._is_empty(actual),
            ConditionOperator.NOT_EMPTY: lambda exists, actual, expected: exists and not self._is_empty(actual),
            ConditionOperator.REGEX: lambda exists, actual, expected: exists and self._regex_match(actual, expected),
            ConditionOperator.NOT_REGEX: lambda exists, actual, expected: (not exists) or not self._regex_match(actual, expected),
            ConditionOperator.BETWEEN: lambda exists, actual, expected: exists and self._between(actual, expected),
            ConditionOperator.NOT_BETWEEN: lambda exists, actual, expected: (not exists) or not self._between(actual, expected),
            ConditionOperator.IS_TRUE: lambda exists, actual, expected: exists and self._to_bool(actual) is True,
            ConditionOperator.IS_FALSE: lambda exists, actual, expected: exists and self._to_bool(actual) is False,
            ConditionOperator.CHANGED: lambda exists, actual, expected: exists and self._changed(actual, expected),
            ConditionOperator.NOT_CHANGED: lambda exists, actual, expected: exists and not self._changed(actual, expected),
        }

    # =========================================================================
    # Normalizers
    # =========================================================================

    def _normalize_condition_rule(self, rule: Union[ConditionRule, Mapping[str, Any]]) -> ConditionRule:
        """Normalize mapping/dataclass into ConditionRule."""

        if isinstance(rule, ConditionRule):
            normalized = rule
        elif isinstance(rule, Mapping):
            normalized = ConditionRule(
                field=str(rule.get("field", "")).strip(),
                operator=rule.get("operator", ConditionOperator.EXISTS.value),
                value=rule.get("value"),
                case_sensitive=bool(rule.get("case_sensitive", False)),
                negate=bool(rule.get("negate", False)),
                weight=float(rule.get("weight", 0.0) or 0.0),
                label=rule.get("label"),
                metadata=dict(rule.get("metadata", {}) or {}),
            )
        else:
            raise TypeError("Condition rule must be ConditionRule or mapping.")

        if not normalized.field:
            raise ValueError("Condition rule field is required.")

        try:
            normalized.operator = ConditionOperator(str(normalized.operator).lower())
        except Exception as exc:
            raise ValueError(f"Unsupported condition operator: {normalized.operator}") from exc

        return normalized

    def _normalize_rule_group(
        self,
        rule_group: Union[RuleGroup, Mapping[str, Any], Sequence[Mapping[str, Any]]],
    ) -> RuleGroup:
        """Normalize mapping/list/dataclass into RuleGroup."""

        if isinstance(rule_group, RuleGroup):
            group = rule_group
        elif isinstance(rule_group, Sequence) and not isinstance(rule_group, (str, bytes, bytearray, Mapping)):
            group = RuleGroup(join=LogicalJoin.ALL, rules=list(rule_group))
        elif isinstance(rule_group, Mapping):
            rules = rule_group.get("rules", [])
            if "field" in rule_group and "operator" in rule_group:
                rules = [rule_group]

            group = RuleGroup(
                join=rule_group.get("join", LogicalJoin.ALL.value),
                rules=list(rules or []),
                groups=list(rule_group.get("groups", []) or []),
                label=rule_group.get("label"),
                metadata=dict(rule_group.get("metadata", {}) or {}),
            )
        else:
            raise TypeError("Rule group must be RuleGroup, mapping, or sequence of rules.")

        try:
            group.join = LogicalJoin(str(group.join).lower())
        except Exception as exc:
            raise ValueError(f"Unsupported rule group join: {group.join}") from exc

        return group

    def _normalize_scoring_rule(self, rule: Union[LeadScoringRule, Mapping[str, Any]]) -> LeadScoringRule:
        """Normalize scoring rule."""

        if isinstance(rule, LeadScoringRule):
            return rule

        if not isinstance(rule, Mapping):
            raise TypeError("Lead scoring rule must be LeadScoringRule or mapping.")

        return LeadScoringRule(
            condition=rule.get("condition", {}),
            score_delta=float(rule.get("score_delta", rule.get("points", 0.0)) or 0.0),
            reason=str(rule.get("reason", "Matched scoring condition.")),
            metadata=dict(rule.get("metadata", {}) or {}),
        )

    def _normalize_routing_rule(self, rule: Union[RoutingRule, Mapping[str, Any]]) -> RoutingRule:
        """Normalize routing rule."""

        if isinstance(rule, RoutingRule):
            return rule

        if not isinstance(rule, Mapping):
            raise TypeError("Routing rule must be RoutingRule or mapping.")

        route = str(rule.get("route", "")).strip()
        if not route:
            raise ValueError("Routing rule route is required.")

        return RoutingRule(
            condition=rule.get("condition", {}),
            route=route,
            priority=int(rule.get("priority", 100)),
            reason=str(rule.get("reason", "")),
            metadata=dict(rule.get("metadata", {}) or {}),
        )

    def _normalize_duplicate_config(
        self,
        config: Optional[Union[DuplicateCheckConfig, Mapping[str, Any]]],
    ) -> DuplicateCheckConfig:
        """Normalize duplicate config."""

        if config is None:
            return copy.deepcopy(self.default_duplicate_config)

        if isinstance(config, DuplicateCheckConfig):
            return config

        if not isinstance(config, Mapping):
            raise TypeError("Duplicate config must be DuplicateCheckConfig or mapping.")

        return DuplicateCheckConfig(
            match_fields=list(config.get("match_fields", self.default_duplicate_config.match_fields)),
            fuzzy_fields=list(config.get("fuzzy_fields", self.default_duplicate_config.fuzzy_fields)),
            strict=bool(config.get("strict", self.default_duplicate_config.strict)),
            normalize_phone=bool(config.get("normalize_phone", self.default_duplicate_config.normalize_phone)),
            normalize_email=bool(config.get("normalize_email", self.default_duplicate_config.normalize_email)),
        )

    def _normalize_spam_config(
        self,
        config: Optional[Union[SpamCheckConfig, Mapping[str, Any]]],
    ) -> SpamCheckConfig:
        """Normalize spam config."""

        if config is None:
            return copy.deepcopy(self.default_spam_config)

        if isinstance(config, SpamCheckConfig):
            return config

        if not isinstance(config, Mapping):
            raise TypeError("Spam config must be SpamCheckConfig or mapping.")

        return SpamCheckConfig(
            honeypot_fields=list(config.get("honeypot_fields", self.default_spam_config.honeypot_fields)),
            spam_keywords=list(config.get("spam_keywords", self.default_spam_config.spam_keywords)),
            max_links=int(config.get("max_links", self.default_spam_config.max_links)),
            max_repeated_chars=int(config.get("max_repeated_chars", self.default_spam_config.max_repeated_chars)),
            min_quality_score=float(config.get("min_quality_score", self.default_spam_config.min_quality_score)),
            suspicious_tlds=list(config.get("suspicious_tlds", self.default_spam_config.suspicious_tlds)),
            disposable_email_domains=list(
                config.get("disposable_email_domains", self.default_spam_config.disposable_email_domains)
            ),
        )

    # =========================================================================
    # Duplicate Helpers
    # =========================================================================

    def _build_duplicate_signature(
        self,
        record: Mapping[str, Any],
        config: DuplicateCheckConfig,
    ) -> str:
        """Build normalized duplicate signature from configured fields."""

        parts: List[str] = []

        for field_name in config.match_fields:
            exists, value = self._get_path(record, field_name)
            if not exists or self._is_empty(value):
                continue
            parts.append(f"{field_name}:{self._normalize_duplicate_value(field_name, value, config)}")

        for field_name in config.fuzzy_fields:
            exists, value = self._get_path(record, field_name)
            if not exists or self._is_empty(value):
                continue
            parts.append(f"{field_name}:{self._normalize_fuzzy_value(value)}")

        raw_signature = "|".join(sorted(parts))
        if not raw_signature:
            return ""

        return hashlib.sha256(raw_signature.encode("utf-8")).hexdigest()

    def _duplicate_field_matches(
        self,
        record: Mapping[str, Any],
        existing: Mapping[str, Any],
        config: DuplicateCheckConfig,
    ) -> List[Dict[str, Any]]:
        """Return per-field duplicate match details."""

        matches: List[Dict[str, Any]] = []

        for field_name in config.match_fields:
            record_exists, record_value = self._get_path(record, field_name)
            existing_exists, existing_value = self._get_path(existing, field_name)

            if not record_exists or not existing_exists:
                continue

            normalized_record = self._normalize_duplicate_value(field_name, record_value, config)
            normalized_existing = self._normalize_duplicate_value(field_name, existing_value, config)
            matched = bool(normalized_record and normalized_record == normalized_existing)

            if matched:
                matches.append({
                    "field": field_name,
                    "match_type": "exact_normalized",
                    "record_value": record_value,
                    "existing_value": existing_value,
                })

        for field_name in config.fuzzy_fields:
            record_exists, record_value = self._get_path(record, field_name)
            existing_exists, existing_value = self._get_path(existing, field_name)

            if not record_exists or not existing_exists:
                continue

            normalized_record = self._normalize_fuzzy_value(record_value)
            normalized_existing = self._normalize_fuzzy_value(existing_value)
            matched = bool(normalized_record and normalized_record == normalized_existing)

            if matched:
                matches.append({
                    "field": field_name,
                    "match_type": "fuzzy_normalized",
                    "record_value": record_value,
                    "existing_value": existing_value,
                })

        return matches

    def _is_duplicate_by_fields(
        self,
        field_matches: Sequence[Mapping[str, Any]],
        config: DuplicateCheckConfig,
    ) -> bool:
        """Determine duplicate by field match policy."""

        if not field_matches:
            return False

        if config.strict:
            required_fields = set(config.match_fields)
            matched_fields = {str(match.get("field")) for match in field_matches}
            return required_fields.issubset(matched_fields)

        return True

    def _normalize_duplicate_value(
        self,
        field_name: str,
        value: Any,
        config: DuplicateCheckConfig,
    ) -> str:
        """Normalize field value for duplicate checking."""

        text = str(value or "").strip().lower()

        if config.normalize_email and "email" in field_name.lower():
            return self._normalize_email(text)

        if config.normalize_phone and ("phone" in field_name.lower() or "mobile" in field_name.lower()):
            return self._normalize_phone(text)

        return re.sub(r"\s+", " ", text)

    def _normalize_email(self, value: str) -> str:
        """Normalize email address."""

        email = value.strip().lower()
        if "@" not in email:
            return email

        local, domain = email.split("@", 1)
        if domain in {"gmail.com", "googlemail.com"}:
            local = local.split("+", 1)[0].replace(".", "")
            domain = "gmail.com"
        else:
            local = local.split("+", 1)[0]

        return f"{local}@{domain}"

    def _normalize_phone(self, value: str) -> str:
        """Normalize phone number to digits with optional leading plus removed."""

        digits = re.sub(r"\D+", "", value or "")
        if len(digits) == 11 and digits.startswith("1"):
            digits = digits[1:]
        return digits

    def _normalize_fuzzy_value(self, value: Any) -> str:
        """Aggressive string normalization for fuzzy duplicate fields."""

        text = str(value or "").strip().lower()
        text = re.sub(r"[^a-z0-9]+", "", text)
        return text

    # =========================================================================
    # Spam Helpers
    # =========================================================================

    def _check_honeypot(self, record: Mapping[str, Any], config: SpamCheckConfig) -> Dict[str, Any]:
        """Check honeypot fields."""

        triggered_fields: List[Dict[str, Any]] = []

        for field_name in config.honeypot_fields:
            exists, value = self._get_path(record, field_name)
            if exists and not self._is_empty(value):
                triggered_fields.append({"field": field_name, "value": value})

        return {
            "triggered": bool(triggered_fields),
            "type": "honeypot",
            "message": "Honeypot field was filled." if triggered_fields else "No honeypot trigger.",
            "fields": triggered_fields,
        }

    def _check_spam_keywords(self, record: Mapping[str, Any], config: SpamCheckConfig) -> Dict[str, Any]:
        """Check spam keyword matches."""

        text = self._record_to_text(record).lower()
        matches = [keyword for keyword in config.spam_keywords if keyword.lower() in text]

        return {
            "triggered": bool(matches),
            "type": "spam_keywords",
            "message": "Spam keywords detected." if matches else "No spam keywords detected.",
            "matches": matches,
        }

    def _check_link_count(self, record: Mapping[str, Any], config: SpamCheckConfig) -> Dict[str, Any]:
        """Check excessive URL count."""

        text = self._record_to_text(record)
        links = re.findall(r"https?://|www\.", text, flags=re.IGNORECASE)
        count = len(links)

        return {
            "triggered": count > config.max_links,
            "type": "excessive_links",
            "message": "Too many links detected." if count > config.max_links else "Link count acceptable.",
            "link_count": count,
            "max_links": config.max_links,
        }

    def _check_repeated_chars(self, record: Mapping[str, Any], config: SpamCheckConfig) -> Dict[str, Any]:
        """Check repeated character patterns."""

        text = self._record_to_text(record)
        pattern = re.compile(r"(.)\1{" + str(max(config.max_repeated_chars - 1, 1)) + r",}", flags=re.IGNORECASE)
        matches = pattern.findall(text)

        return {
            "triggered": bool(matches),
            "type": "repeated_characters",
            "message": "Repeated character spam pattern detected." if matches else "No repeated character pattern.",
            "match_count": len(matches),
            "max_repeated_chars": config.max_repeated_chars,
        }

    def _check_disposable_email(self, record: Mapping[str, Any], config: SpamCheckConfig) -> Dict[str, Any]:
        """Check disposable email domains."""

        emails = self._extract_emails(record)
        disposable_domains = {domain.lower() for domain in config.disposable_email_domains}
        matches: List[str] = []

        for email in emails:
            domain = email.split("@", 1)[-1].lower()
            if domain in disposable_domains:
                matches.append(email)

        return {
            "triggered": bool(matches),
            "type": "disposable_email",
            "message": "Disposable email detected." if matches else "No disposable email detected.",
            "matches": matches,
        }

    def _check_suspicious_tld(self, record: Mapping[str, Any], config: SpamCheckConfig) -> Dict[str, Any]:
        """Check suspicious TLDs in URLs/emails."""

        text = self._record_to_text(record).lower()
        matches = [tld for tld in config.suspicious_tlds if tld.lower() in text]

        return {
            "triggered": bool(matches),
            "type": "suspicious_tld",
            "message": "Suspicious domain TLD detected." if matches else "No suspicious TLD detected.",
            "matches": matches,
        }

    def _calculate_record_quality_score(self, record: Mapping[str, Any]) -> float:
        """Calculate simple quality score for a form/lead record."""

        score = 0.0

        common_identity_fields = ["name", "full_name", "first_name", "last_name", "email", "phone", "message"]
        present_count = 0

        for field_name in common_identity_fields:
            exists, value = self._get_path(record, field_name)
            if exists and not self._is_empty(value):
                present_count += 1

        score += min(45.0, present_count * 7.5)

        emails = self._extract_emails(record)
        if emails:
            score += 20.0

        phones = self._extract_phone_candidates(record)
        if phones:
            score += 15.0

        text_length = len(self._record_to_text(record))
        if text_length >= 40:
            score += 10.0
        if text_length >= 120:
            score += 10.0

        return self._clamp(score, 0.0, 100.0)

    # =========================================================================
    # Generic Value Helpers
    # =========================================================================

    def _get_path(self, data: Mapping[str, Any], path: str) -> Tuple[bool, Any]:
        """
        Safe dot-path getter.

        Supports:
            "lead.email"
            "items.0.name"
            "email"
        """

        if not path:
            return False, None

        current: Any = data
        parts = str(path).split(".")

        for part in parts:
            if isinstance(current, Mapping):
                if part not in current:
                    return False, None
                current = current[part]
            elif isinstance(current, Sequence) and not isinstance(current, (str, bytes, bytearray)):
                if not part.isdigit():
                    return False, None
                index = int(part)
                if index < 0 or index >= len(current):
                    return False, None
                current = current[index]
            else:
                return False, None

        return True, current

    def _casefold_value(self, value: Any) -> Any:
        """Case-fold strings recursively for case-insensitive comparison."""

        if isinstance(value, str):
            return value.casefold()
        if isinstance(value, list):
            return [self._casefold_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._casefold_value(item) for item in value)
        if isinstance(value, set):
            return {self._casefold_value(item) for item in value}
        if isinstance(value, Mapping):
            return {key: self._casefold_value(val) for key, val in value.items()}
        return value

    def _numeric_compare(self, actual: Any, expected: Any, op: Callable[[float, float], bool]) -> bool:
        """Safe numeric comparison."""

        try:
            actual_num = float(actual)
            expected_num = float(expected)
            if math.isnan(actual_num) or math.isnan(expected_num):
                return False
            return bool(op(actual_num, expected_num))
        except Exception:
            return False

    def _contains(self, actual: Any, expected: Any) -> bool:
        """Safe contains operation."""

        if actual is None:
            return False

        if isinstance(actual, Mapping):
            return expected in actual or str(expected) in actual

        if isinstance(actual, (list, tuple, set)):
            return expected in actual

        return str(expected) in str(actual)

    def _in_collection(self, actual: Any, expected: Any) -> bool:
        """Safe 'actual in expected' operation."""

        if expected is None:
            return False

        if isinstance(expected, Mapping):
            return actual in expected or str(actual) in expected

        if isinstance(expected, (list, tuple, set)):
            return actual in expected

        return str(actual) in str(expected)

    def _regex_match(self, actual: Any, expected_pattern: Any) -> bool:
        """Safe regex match with defensive error handling."""

        try:
            pattern = str(expected_pattern)
            return bool(re.search(pattern, str(actual or ""), flags=re.IGNORECASE))
        except re.error:
            return False

    def _between(self, actual: Any, expected: Any) -> bool:
        """Check numeric between [min, max]."""

        if not isinstance(expected, Sequence) or isinstance(expected, (str, bytes, bytearray)) or len(expected) != 2:
            return False

        try:
            actual_num = float(actual)
            min_value = float(expected[0])
            max_value = float(expected[1])
            return min_value <= actual_num <= max_value
        except Exception:
            return False

    def _changed(self, actual: Any, expected: Any) -> bool:
        """
        Changed comparison.

        expected may be:
            - previous value directly
            - {"previous": value}
            - {"old": value}
        """

        previous = expected
        if isinstance(expected, Mapping):
            previous = expected.get("previous", expected.get("old"))
        return actual != previous

    def _to_bool(self, value: Any) -> Optional[bool]:
        """Convert common values to bool safely."""

        if isinstance(value, bool):
            return value

        if value is None:
            return False

        if isinstance(value, (int, float)):
            return bool(value)

        text = str(value).strip().lower()
        if text in {"true", "1", "yes", "y", "on", "enabled"}:
            return True
        if text in {"false", "0", "no", "n", "off", "disabled", ""}:
            return False

        return None

    def _is_empty(self, value: Any) -> bool:
        """Check empty-like values."""

        if value is None:
            return True

        if isinstance(value, str):
            return value.strip() == ""

        if isinstance(value, (list, tuple, set, dict)):
            return len(value) == 0

        return False

    def _record_to_text(self, record: Mapping[str, Any]) -> str:
        """Flatten record values to searchable text."""

        values: List[str] = []

        def walk(value: Any) -> None:
            if isinstance(value, Mapping):
                for nested in value.values():
                    walk(nested)
            elif isinstance(value, (list, tuple, set)):
                for nested in value:
                    walk(nested)
            elif value is not None:
                values.append(str(value))

        walk(record)
        return " ".join(values)

    def _extract_emails(self, record: Mapping[str, Any]) -> List[str]:
        """Extract email addresses from record."""

        text = self._record_to_text(record)
        return re.findall(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", text, flags=re.IGNORECASE)

    def _extract_phone_candidates(self, record: Mapping[str, Any]) -> List[str]:
        """Extract likely phone numbers from record."""

        text = self._record_to_text(record)
        candidates = re.findall(r"(?:\+?\d[\d\s().\-]{7,}\d)", text)
        return [candidate for candidate in candidates if len(re.sub(r"\D+", "", candidate)) >= 8]

    def _lead_quality_bucket(self, score: float) -> str:
        """Lead quality bucket."""

        if score >= 80:
            return "excellent"
        if score >= 65:
            return "good"
        if score >= 40:
            return "warm"
        if score >= 20:
            return "weak"
        return "poor"

    def _spam_risk_bucket(self, risk_score: float) -> str:
        """Spam risk bucket."""

        if risk_score >= 85:
            return RiskLevel.CRITICAL.value
        if risk_score >= 60:
            return RiskLevel.HIGH.value
        if risk_score >= 30:
            return RiskLevel.MEDIUM.value
        return RiskLevel.LOW.value

    def _decision_to_risk(self, decision: str) -> str:
        """Map final decision to risk level."""

        if decision in {RouteDecision.SPAM.value}:
            return RiskLevel.HIGH.value
        if decision in {RouteDecision.DUPLICATE.value, RouteDecision.REVIEW.value, RouteDecision.FAIL.value}:
            return RiskLevel.MEDIUM.value
        return RiskLevel.LOW.value

    def _clamp(self, value: float, minimum: float, maximum: float) -> float:
        """Clamp number."""

        return max(minimum, min(maximum, float(value)))

    def _looks_like_rule_group(self, value: Any) -> bool:
        """Detect whether condition value looks like a RuleGroup."""

        if isinstance(value, RuleGroup):
            return True
        if isinstance(value, Mapping):
            return "rules" in value or "groups" in value or "join" in value
        return False

    def _extract_data_value(self, result: Mapping[str, Any], key: str, default: Any = None) -> Any:
        """Extract result['data'][key] safely."""

        data = result.get("data", {})
        if isinstance(data, Mapping):
            return data.get(key, default)
        return default

    # =========================================================================
    # Compatibility Hooks
    # =========================================================================

    def _validate_task_context(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate task context required by William/Jarvis SaaS isolation rules.

        Every workflow execution involving user data must include user_id and
        workspace_id to avoid cross-user/cross-workspace mixing.
        """

        if not isinstance(task, Mapping):
            return self._error_result(
                message="Task must be a mapping/dict.",
                error="invalid_task",
            )

        user_id = task.get("user_id")
        workspace_id = task.get("workspace_id")

        return self._validate_context_values(user_id, workspace_id)

    def _validate_context_values(
        self,
        user_id: Optional[Any],
        workspace_id: Optional[Any],
    ) -> Dict[str, Any]:
        """Validate user/workspace context values."""

        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                message="user_id is required for SaaS-safe workflow condition execution.",
                error="missing_user_id",
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                message="workspace_id is required for SaaS-safe workflow condition execution.",
                error="missing_workspace_id",
                metadata={"user_id": str(user_id)},
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
            },
        )

    def _requires_security_check(self, task: Mapping[str, Any]) -> bool:
        """
        Decide whether a Security Agent approval should be requested.

        Condition evaluation is usually read-only. Security check is required
        when:
            - task explicitly asks for security approval
            - task is marked sensitive
            - condition result may trigger external/destructive/high-risk actions
        """

        if not self.enable_security_checks:
            return False

        if bool(task.get("requires_security_check", False)):
            return True

        risk_level = str(task.get("risk_level", "")).lower()
        if risk_level in {RiskLevel.HIGH.value, RiskLevel.CRITICAL.value}:
            return True

        action = str(task.get("action", "")).lower()
        sensitive_actions = {
            "route_payload",
            "process_conditions",
        }

        downstream_action = str(task.get("downstream_action", "")).lower()
        sensitive_downstream_keywords = {
            "send",
            "delete",
            "archive",
            "call",
            "payment",
            "financial",
            "browser",
            "system",
            "external",
            "webhook",
        }

        return action in sensitive_actions and any(keyword in downstream_action for keyword in sensitive_downstream_keywords)

    def _request_security_approval(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Request approval from Security Agent if available.

        Fallback behavior:
            Allows low/medium risk tasks and denies high/critical tasks unless
            explicitly marked as preapproved.
        """

        user_id = task.get("user_id")
        workspace_id = task.get("workspace_id")
        risk_level = str(task.get("risk_level", RiskLevel.LOW.value)).lower()

        approval_request = {
            "request_id": self._new_id("sec"),
            "agent": self.AGENT_TYPE,
            "action": task.get("action"),
            "risk_level": risk_level,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "metadata": task.get("metadata", {}),
            "created_at": self._utc_now(),
        }

        if self.security_agent and hasattr(self.security_agent, "approve"):
            try:
                response = self.security_agent.approve(approval_request)
                if isinstance(response, Mapping):
                    return dict(response)
            except Exception as exc:
                self.logger.warning("Security approval call failed: %s", exc)

        if bool(task.get("security_preapproved", False)):
            return {
                "approved": True,
                "mode": "fallback_preapproved",
                "request": approval_request,
            }

        approved = risk_level not in {RiskLevel.HIGH.value, RiskLevel.CRITICAL.value}
        return {
            "approved": approved,
            "mode": "fallback_policy",
            "request": approval_request,
            "reason": "Fallback policy denies high/critical risk tasks without explicit approval."
            if not approved
            else "Fallback policy approved low/medium risk task.",
        }

    def _prepare_verification_payload(
        self,
        operation: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can later validate decision integrity, rule outcomes,
        routing accuracy, and audit consistency.
        """

        return {
            "verification_id": self._new_id("ver"),
            "source_agent": self.AGENT_TYPE,
            "operation": operation,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "success": bool(result.get("success", False)),
            "message": result.get("message"),
            "data_summary": self._safe_summary(result.get("data", {})),
            "metadata": result.get("metadata", {}),
            "created_at": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        operation: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        This does not directly store memory unless an injected Memory Agent
        supports it. It keeps useful workflow context isolated per user/workspace.
        """

        return {
            "memory_id": self._new_id("mem"),
            "source_agent": self.AGENT_TYPE,
            "memory_type": "workflow_condition_result",
            "operation": operation,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "content": {
                "message": result.get("message"),
                "success": result.get("success", False),
                "data_summary": self._safe_summary(result.get("data", {})),
            },
            "metadata": result.get("metadata", {}),
            "created_at": self._utc_now(),
        }

    def _emit_agent_event(self, event_type: str, payload: Mapping[str, Any]) -> None:
        """
        Emit event hook for Dashboard/API/Event Bus.

        Current implementation logs only. Future integrations can override this
        method or attach an event bus.
        """

        try:
            safe_payload = self._redact_sensitive(copy.deepcopy(dict(payload)))
            self.logger.info("agent_event=%s payload=%s", event_type, safe_payload)
        except Exception:
            self.logger.debug("Failed to emit agent event.", exc_info=True)

    def _log_audit_event(
        self,
        operation: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
        result: Mapping[str, Any],
    ) -> None:
        """
        Audit log hook.

        Current implementation logs structured audit info. Production can replace
        this with database-backed audit logging.
        """

        if not self.enable_audit_log:
            return

        audit_event = {
            "audit_id": self._new_id("aud"),
            "agent": self.AGENT_TYPE,
            "operation": operation,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "success": result.get("success", False),
            "message": result.get("message"),
            "risk_level": (result.get("metadata") or {}).get("risk_level", RiskLevel.LOW.value),
            "created_at": self._utc_now(),
        }

        try:
            self.logger.info("audit_event=%s", self._redact_sensitive(audit_event))
        except Exception:
            self.logger.debug("Failed to write audit event.", exc_info=True)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success response."""

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Any,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error response."""

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": str(error) if error is not None else "unknown_error",
            "metadata": metadata or {},
        }

    # =========================================================================
    # Hook Orchestration
    # =========================================================================

    def _after_decision_hooks(
        self,
        operation: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
        result: Dict[str, Any],
    ) -> None:
        """Run audit, memory, verification, and event hooks."""

        self._log_audit_event(
            operation=operation,
            user_id=user_id,
            workspace_id=workspace_id,
            result=result,
        )

        if self.enable_verification_payloads:
            verification_payload = self._prepare_verification_payload(
                operation=operation,
                user_id=user_id,
                workspace_id=workspace_id,
                result=result,
            )
            result.setdefault("metadata", {})["verification_payload"] = verification_payload

            if self.verification_agent and hasattr(self.verification_agent, "receive_payload"):
                try:
                    self.verification_agent.receive_payload(verification_payload)
                except Exception as exc:
                    self.logger.warning("Verification Agent payload delivery failed: %s", exc)

        if self.enable_memory_payloads:
            memory_payload = self._prepare_memory_payload(
                operation=operation,
                user_id=user_id,
                workspace_id=workspace_id,
                result=result,
            )
            result.setdefault("metadata", {})["memory_payload"] = memory_payload

            if self.memory_agent and hasattr(self.memory_agent, "remember"):
                try:
                    self.memory_agent.remember(memory_payload)
                except Exception as exc:
                    self.logger.warning("Memory Agent payload delivery failed: %s", exc)

        self._emit_agent_event(
            event_type=f"condition_engine.{operation}",
            payload={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "success": result.get("success", False),
                "message": result.get("message"),
            },
        )

    # =========================================================================
    # Metadata / Serialization / Redaction
    # =========================================================================

    def _build_metadata(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        operation: str,
        input_metadata: Optional[Dict[str, Any]] = None,
        risk_level: str = RiskLevel.LOW.value,
    ) -> Dict[str, Any]:
        """Build standard metadata."""

        return {
            "agent": self.AGENT_TYPE,
            "agent_name": self.AGENT_NAME,
            "version": self.VERSION,
            "operation": operation,
            "user_id": str(user_id) if user_id is not None else None,
            "workspace_id": str(workspace_id) if workspace_id is not None else None,
            "risk_level": risk_level,
            "request_id": self._new_id("cond"),
            "timestamp": self._utc_now(),
            "input_metadata": input_metadata or {},
        }

    def _serialize_dataclass(self, value: Any) -> Any:
        """Serialize dataclasses/enums into JSON-safe structures."""

        if hasattr(value, "__dataclass_fields__"):
            return self._serialize_dataclass(asdict(value))

        if isinstance(value, Enum):
            return value.value

        if isinstance(value, Mapping):
            return {key: self._serialize_dataclass(val) for key, val in value.items()}

        if isinstance(value, list):
            return [self._serialize_dataclass(item) for item in value]

        if isinstance(value, tuple):
            return tuple(self._serialize_dataclass(item) for item in value)

        return value

    def _safe_summary(self, value: Any, max_length: int = 1200) -> Any:
        """
        Create safe, short summary for memory/verification metadata.

        Avoid storing huge payloads or sensitive-looking values.
        """

        redacted = self._redact_sensitive(copy.deepcopy(value))

        try:
            serialized = json.dumps(redacted, default=str, ensure_ascii=False)
        except Exception:
            serialized = str(redacted)

        if len(serialized) <= max_length:
            return redacted

        return {
            "summary_truncated": True,
            "preview": serialized[:max_length],
            "original_length": len(serialized),
        }

    def _redact_sensitive(self, value: Any) -> Any:
        """Redact sensitive-looking fields."""

        sensitive_keys = {
            "password",
            "token",
            "secret",
            "api_key",
            "apikey",
            "authorization",
            "auth",
            "cookie",
            "private_key",
            "access_token",
            "refresh_token",
        }

        if isinstance(value, Mapping):
            cleaned: Dict[str, Any] = {}
            for key, val in value.items():
                key_text = str(key).lower()
                if any(sensitive in key_text for sensitive in sensitive_keys):
                    cleaned[key] = "***REDACTED***"
                else:
                    cleaned[key] = self._redact_sensitive(val)
            return cleaned

        if isinstance(value, list):
            return [self._redact_sensitive(item) for item in value]

        if isinstance(value, tuple):
            return tuple(self._redact_sensitive(item) for item in value)

        return value

    def _new_id(self, prefix: str) -> str:
        """Create stable unique ID."""

        return f"{prefix}_{uuid.uuid4().hex}"

    def _utc_now(self) -> str:
        """Current UTC timestamp."""

        return datetime.now(timezone.utc).isoformat()

    # =========================================================================
    # Convenience Presets
    # =========================================================================

    def default_lead_scoring_rules(self) -> List[Dict[str, Any]]:
        """
        Return safe default lead scoring rules.

        These are generic and can be customized per workspace from dashboard/API.
        """

        return [
            {
                "condition": {"field": "email", "operator": "not_empty"},
                "score_delta": 15,
                "reason": "Email is present.",
            },
            {
                "condition": {"field": "phone", "operator": "not_empty"},
                "score_delta": 20,
                "reason": "Phone number is present.",
            },
            {
                "condition": {"field": "message", "operator": "not_empty"},
                "score_delta": 10,
                "reason": "Message is present.",
            },
            {
                "condition": {"field": "budget", "operator": "gte", "value": 1000},
                "score_delta": 25,
                "reason": "Budget is at or above high-intent threshold.",
            },
            {
                "condition": {
                    "join": "any",
                    "rules": [
                        {"field": "service", "operator": "contains", "value": "web"},
                        {"field": "service", "operator": "contains", "value": "seo"},
                        {"field": "service", "operator": "contains", "value": "ads"},
                        {"field": "service", "operator": "contains", "value": "automation"},
                    ],
                },
                "score_delta": 15,
                "reason": "Lead selected a supported Digital Promotix service.",
            },
        ]

    def default_routing_rules(self) -> List[Dict[str, Any]]:
        """
        Return safe default routing rules.

        These can be used by form_pipeline.py, webhook_manager.py, and
        action_router.py as starting rules.
        """

        return [
            {
                "condition": {"field": "spam.is_spam", "operator": "is_true"},
                "route": "spam_review",
                "priority": 10,
                "reason": "Payload was flagged as spam.",
            },
            {
                "condition": {"field": "duplicate.is_duplicate", "operator": "is_true"},
                "route": "duplicate_review",
                "priority": 20,
                "reason": "Payload appears to be duplicate.",
            },
            {
                "condition": {"field": "score.score", "operator": "gte", "value": 75},
                "route": "sales_priority",
                "priority": 30,
                "reason": "Lead score is high.",
            },
            {
                "condition": {"field": "score.score", "operator": "lt", "value": 30},
                "route": "nurture",
                "priority": 40,
                "reason": "Lead score is low and should go to nurture.",
            },
        ]

    # =========================================================================
    # Registry Metadata
    # =========================================================================

    @classmethod
    def registry_metadata(cls) -> Dict[str, Any]:
        """
        Agent Registry / Agent Loader metadata.

        The registry can call this without instantiating the class.
        """

        return {
            "agent_name": cls.AGENT_NAME,
            "agent_type": cls.AGENT_TYPE,
            "class_name": cls.__name__,
            "version": cls.VERSION,
            "module": "agents.workflow_agent.condition_engine",
            "file_path": "agents/workflow_agent/condition_engine.py",
            "capabilities": [
                "if_else_rules",
                "filtering",
                "lead_scoring",
                "duplicate_checks",
                "spam_checks",
                "routing_decisions",
                "saas_context_validation",
                "security_agent_hook",
                "memory_agent_payload",
                "verification_agent_payload",
                "audit_event_hook",
            ],
            "safe_to_import": True,
            "requires_user_context": True,
            "requires_workspace_context": True,
        }


__all__ = [
    "ConditionEngine",
    "ConditionOperator",
    "LogicalJoin",
    "RouteDecision",
    "RiskLevel",
    "ConditionRule",
    "RuleGroup",
    "LeadScoringRule",
    "RoutingRule",
    "DuplicateCheckConfig",
    "SpamCheckConfig",
]