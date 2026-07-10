"""
agents/super_agents/finance_agent/config.py

Finance Agent configuration for William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    Finance safe-mode settings, blocked actions, approval thresholds, permission
    metadata, and safe configuration helpers for Finance Agent submodules.

This file is intentionally import-safe:
    - It does not require the rest of the William/Jarvis codebase to exist.
    - It does not execute real financial, system, browser, call, message, or destructive actions.
    - It provides safe fallback stubs for optional BaseAgent-style compatibility.
    - It exposes structured JSON/dict-style results for dashboard/API/FastAPI usage.

Architecture compatibility:
    - Master Agent routing:
        FinanceConfig exposes capabilities, route metadata, safety policies,
        blocked actions, and approval requirements that can be inspected by
        Master Agent or Agent Registry.

    - Security Agent:
        FinanceConfig centralizes finance-sensitive actions and determines
        whether Security Agent approval is required.

    - Verification Agent:
        FinanceConfig prepares verification payloads after configuration checks,
        policy decisions, threshold evaluations, and safety validations.

    - Memory Agent:
        FinanceConfig prepares memory-compatible payloads for safe, non-sensitive
        finance preferences and user/workspace-safe settings.

    - Dashboard/API:
        FinanceConfig returns structured results with:
            success, message, data, error, metadata

    - SaaS isolation:
        Every user/workspace-aware public method accepts or validates user_id and
        workspace_id where task-specific execution is involved.

Important:
    This file stores policy/configuration only. It never submits payments,
    transfers funds, changes bank records, sends invoices, deletes data, or
    performs destructive financial activity.
"""

from __future__ import annotations

import copy
import enum
import logging
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent compatibility
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import-safe standalone use
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This allows FinanceConfig to import safely even before the full
        William/Jarvis BaseAgent implementation exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("William.Jarvis.FinanceConfig")
if not LOGGER.handlers:
    logging.basicConfig(level=os.getenv("WILLIAM_LOG_LEVEL", "INFO"))


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODULE_NAME = "finance_agent"
FILE_NAME = "config.py"
AGENT_NAME = "Finance Agent"
CONFIG_CLASS_NAME = "FinanceConfig"
DEFAULT_CURRENCY = "USD"
DEFAULT_SAFE_MODE = True
DEFAULT_REQUIRE_SECURITY_APPROVAL = True
DEFAULT_REQUIRE_VERIFICATION_PAYLOAD = True
DEFAULT_REQUIRE_AUDIT_LOG = True
DEFAULT_ALLOW_DRAFT_ONLY = True

CONFIG_VERSION = "1.0.0"
CONFIG_SCHEMA_VERSION = "finance-config-v1"

SENSITIVE_VALUE_REDACTION = "***REDACTED***"

DEFAULT_MAX_NOTE_LENGTH = 2000
DEFAULT_MAX_METADATA_DEPTH = 6


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FinanceAction(str, enum.Enum):
    """
    Canonical finance action names used by Master Agent, Security Agent,
    Finance Agent submodules, dashboard/API, and audit logs.
    """

    # Read / analysis actions
    READ_FINANCE_SUMMARY = "read_finance_summary"
    READ_BUDGET = "read_budget"
    READ_INVOICE = "read_invoice"
    READ_RECEIPT = "read_receipt"
    READ_REPORT = "read_report"
    READ_SUBSCRIPTION = "read_subscription"
    READ_TAX_SUMMARY = "read_tax_summary"
    CATEGORIZE_EXPENSE = "categorize_expense"
    DETECT_DUPLICATE_EXPENSE = "detect_duplicate_expense"
    PARSE_RECEIPT = "parse_receipt"
    GENERATE_REPORT = "generate_report"
    FORECAST_BUDGET = "forecast_budget"

    # Draft-only actions
    CREATE_INVOICE_DRAFT = "create_invoice_draft"
    UPDATE_INVOICE_DRAFT = "update_invoice_draft"
    CREATE_PAYMENT_DRAFT = "create_payment_draft"
    CREATE_TRANSACTION_DRAFT = "create_transaction_draft"
    CREATE_BUDGET_DRAFT = "create_budget_draft"
    CREATE_TAX_PREP_SUMMARY = "create_tax_prep_summary"
    CREATE_SUBSCRIPTION_REMINDER_DRAFT = "create_subscription_reminder_draft"
    CREATE_CLIENT_REMINDER_DRAFT = "create_client_reminder_draft"

    # Write/update actions requiring controls
    UPDATE_BUDGET = "update_budget"
    UPDATE_EXPENSE_CATEGORY = "update_expense_category"
    UPDATE_INVOICE_STATUS = "update_invoice_status"
    UPDATE_SUBSCRIPTION_RECORD = "update_subscription_record"
    UPDATE_TAX_RECORD_CATEGORY = "update_tax_record_category"
    STORE_FINANCE_MEMORY = "store_finance_memory"

    # Sensitive / blocked / externally dangerous actions
    SUBMIT_PAYMENT = "submit_payment"
    SEND_PAYMENT = "send_payment"
    TRANSFER_FUNDS = "transfer_funds"
    WITHDRAW_FUNDS = "withdraw_funds"
    DEPOSIT_FUNDS = "deposit_funds"
    AUTHORIZE_CARD_CHARGE = "authorize_card_charge"
    CHARGE_CUSTOMER = "charge_customer"
    REFUND_CUSTOMER = "refund_customer"
    PAY_INVOICE = "pay_invoice"
    PAY_BILL = "pay_bill"
    CONNECT_BANK_ACCOUNT = "connect_bank_account"
    DISCONNECT_BANK_ACCOUNT = "disconnect_bank_account"
    EXPORT_BANK_CREDENTIALS = "export_bank_credentials"
    VIEW_FULL_BANK_CREDENTIALS = "view_full_bank_credentials"
    MODIFY_BANK_ACCOUNT = "modify_bank_account"
    MODIFY_PAYMENT_METHOD = "modify_payment_method"
    DELETE_FINANCIAL_RECORD = "delete_financial_record"
    DELETE_INVOICE = "delete_invoice"
    DELETE_TRANSACTION = "delete_transaction"
    DELETE_BUDGET = "delete_budget"
    DELETE_TAX_RECORD = "delete_tax_record"
    FILE_TAX_RETURN = "file_tax_return"
    SUBMIT_TAX_PAYMENT = "submit_tax_payment"
    LEGAL_FINANCIAL_ADVICE = "legal_financial_advice"
    INVESTMENT_TRADE = "investment_trade"
    BUY_SECURITY = "buy_security"
    SELL_SECURITY = "sell_security"
    CRYPTO_TRANSFER = "crypto_transfer"


class FinanceRiskLevel(str, enum.Enum):
    """Risk levels used for Finance Agent safety decisions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    BLOCKED = "blocked"


class ApprovalPolicy(str, enum.Enum):
    """Approval policy result for a requested finance action."""

    ALLOWED = "allowed"
    SECURITY_APPROVAL_REQUIRED = "security_approval_required"
    HUMAN_APPROVAL_REQUIRED = "human_approval_required"
    BLOCKED = "blocked"
    DRAFT_ONLY = "draft_only"


class FinancePermission(str, enum.Enum):
    """Finance permission keys for SaaS roles/workspaces."""

    FINANCE_READ = "finance:read"
    FINANCE_ANALYZE = "finance:analyze"
    FINANCE_DRAFT = "finance:draft"
    FINANCE_WRITE = "finance:write"
    FINANCE_APPROVE = "finance:approve"
    FINANCE_ADMIN = "finance:admin"
    FINANCE_EXPORT = "finance:export"
    FINANCE_MEMORY_WRITE = "finance:memory_write"
    FINANCE_AUDIT_READ = "finance:audit_read"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ApprovalThreshold:
    """
    Defines an approval threshold for a finance action.

    amount:
        Threshold amount in currency units.

    currency:
        ISO-like display currency. This file does not perform FX conversion.

    risk_level:
        Risk level once threshold is met.

    require_security_approval:
        Whether Security Agent approval is required.

    require_human_approval:
        Whether human approval is required.

    draft_only:
        Whether action may only create a draft and never execute externally.
    """

    amount: Decimal
    currency: str = DEFAULT_CURRENCY
    risk_level: FinanceRiskLevel = FinanceRiskLevel.MEDIUM
    require_security_approval: bool = True
    require_human_approval: bool = False
    draft_only: bool = False
    note: str = ""


@dataclass(frozen=True)
class ActionSafetyRule:
    """
    Safety rule for a FinanceAction.

    Used by:
        - Finance Agent
        - Payment Guard
        - Transaction Preparer
        - Invoice Manager
        - Budget Tracker
        - Master Agent routing
        - Security Agent handoff
    """

    action: FinanceAction
    policy: ApprovalPolicy
    risk_level: FinanceRiskLevel
    required_permissions: Tuple[FinancePermission, ...] = field(default_factory=tuple)
    requires_user_id: bool = True
    requires_workspace_id: bool = True
    requires_security_approval: bool = False
    requires_human_approval: bool = False
    requires_verification_payload: bool = True
    audit_required: bool = True
    draft_only: bool = False
    reason: str = ""


@dataclass
class FinanceContext:
    """
    Normalized SaaS task context.

    Finance submodules may pass raw dicts, and FinanceConfig will normalize
    and validate them before safety decisions.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    subscription_plan: Optional[str] = None
    permissions: Tuple[str, ...] = field(default_factory=tuple)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FinanceConfigSnapshot:
    """
    Serializable snapshot of safe-mode finance configuration.

    This can be returned to dashboards, API routes, agent registry, or tests.
    """

    module_name: str
    file_name: str
    class_name: str
    config_version: str
    config_schema_version: str
    safe_mode_enabled: bool
    default_currency: str
    draft_only_mode: bool
    require_security_approval_by_default: bool
    require_verification_payload: bool
    require_audit_log: bool
    blocked_actions: List[str]
    security_required_actions: List[str]
    human_approval_actions: List[str]
    draft_only_actions: List[str]
    allowed_read_actions: List[str]
    thresholds: Dict[str, Dict[str, Any]]
    metadata: Dict[str, Any]


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _now_epoch() -> float:
    """Return current epoch timestamp."""

    return time.time()


def _safe_str(value: Any, *, max_length: int = 500) -> str:
    """Convert a value to safe string for metadata/results."""

    if value is None:
        return ""
    text = str(value)
    if len(text) > max_length:
        return text[: max_length - 3] + "..."
    return text


def _to_decimal(value: Any, default: Decimal = Decimal("0")) -> Decimal:
    """Convert amount-like values to Decimal safely."""

    if value is None:
        return default
    if isinstance(value, Decimal):
        return value
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return default


def _normalize_action(action: Union[str, FinanceAction]) -> Optional[FinanceAction]:
    """Normalize string/enum action into FinanceAction."""

    if isinstance(action, FinanceAction):
        return action
    if isinstance(action, str):
        clean = action.strip().lower()
        for member in FinanceAction:
            if member.value == clean or member.name.lower() == clean:
                return member
    return None


def _normalize_permissions(permissions: Optional[Iterable[Union[str, FinancePermission]]]) -> Tuple[str, ...]:
    """Normalize permissions into tuple of strings."""

    if not permissions:
        return tuple()

    normalized: List[str] = []
    for permission in permissions:
        if isinstance(permission, FinancePermission):
            normalized.append(permission.value)
        elif isinstance(permission, str) and permission.strip():
            normalized.append(permission.strip())

    return tuple(sorted(set(normalized)))


def _decimal_to_json(value: Decimal) -> Union[int, float, str]:
    """
    Convert Decimal to JSON-safe primitive.

    Use int when exact integer, float for simple decimal values, else string.
    """

    try:
        if value == value.to_integral_value():
            return int(value)
        return float(value)
    except Exception:
        return str(value)


def _dataclass_to_json_safe(value: Any) -> Any:
    """Convert dataclass/enums/decimals to JSON-safe structures."""

    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, Decimal):
        return _decimal_to_json(value)
    if isinstance(value, tuple):
        return [_dataclass_to_json_safe(item) for item in value]
    if isinstance(value, list):
        return [_dataclass_to_json_safe(item) for item in value]
    if isinstance(value, set):
        return sorted(_dataclass_to_json_safe(item) for item in value)
    if isinstance(value, dict):
        return {
            _safe_str(key): _dataclass_to_json_safe(item)
            for key, item in value.items()
        }
    if hasattr(value, "__dataclass_fields__"):
        return _dataclass_to_json_safe(asdict(value))
    return value


def _redact_sensitive_mapping(data: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Redact sensitive finance values from metadata.

    This is intentionally conservative.
    """

    sensitive_fragments = (
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "auth",
        "credential",
        "bank_account",
        "routing",
        "iban",
        "swift",
        "card",
        "cvv",
        "cvc",
        "pin",
        "ssn",
        "tax_id",
        "ein",
        "cnic",
    )

    redacted: Dict[str, Any] = {}
    for key, value in data.items():
        key_str = _safe_str(key).lower()
        if any(fragment in key_str for fragment in sensitive_fragments):
            redacted[_safe_str(key)] = SENSITIVE_VALUE_REDACTION
        elif isinstance(value, Mapping):
            redacted[_safe_str(key)] = _redact_sensitive_mapping(value)
        elif isinstance(value, list):
            redacted[_safe_str(key)] = [
                _redact_sensitive_mapping(item) if isinstance(item, Mapping) else item
                for item in value
            ]
        else:
            redacted[_safe_str(key)] = value
    return redacted


# ---------------------------------------------------------------------------
# FinanceConfig
# ---------------------------------------------------------------------------

class FinanceConfig(BaseAgent):
    """
    Finance safe-mode configuration brain.

    This class centralizes:
        - Finance safe-mode settings
        - Blocked actions
        - Draft-only restrictions
        - Approval thresholds
        - Permission requirements
        - Security Agent handoff hints
        - Verification Agent payload preparation
        - Memory Agent payload preparation
        - Audit/event payload preparation
        - Master Agent and Registry metadata

    It is intentionally safe-by-default:
        - Real payment execution is blocked.
        - Fund transfers are blocked.
        - Bank credential exposure is blocked.
        - Tax filing/payment submission is blocked.
        - Investment/crypto trading is blocked.
        - Draft creation is allowed only with context and permissions.
    """

    def __init__(
        self,
        *,
        safe_mode_enabled: bool = DEFAULT_SAFE_MODE,
        default_currency: str = DEFAULT_CURRENCY,
        draft_only_mode: bool = DEFAULT_ALLOW_DRAFT_ONLY,
        require_security_approval_by_default: bool = DEFAULT_REQUIRE_SECURITY_APPROVAL,
        require_verification_payload: bool = DEFAULT_REQUIRE_VERIFICATION_PAYLOAD,
        require_audit_log: bool = DEFAULT_REQUIRE_AUDIT_LOG,
        logger: Optional[logging.Logger] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(agent_name=AGENT_NAME, agent_id=MODULE_NAME)

        self.logger = logger or LOGGER
        self.safe_mode_enabled = bool(safe_mode_enabled)
        self.default_currency = (default_currency or DEFAULT_CURRENCY).upper()
        self.draft_only_mode = bool(draft_only_mode)
        self.require_security_approval_by_default = bool(require_security_approval_by_default)
        self.require_verification_payload = bool(require_verification_payload)
        self.require_audit_log = bool(require_audit_log)
        self.metadata = _redact_sensitive_mapping(metadata or {})

        self._thresholds: Dict[str, ApprovalThreshold] = self._build_default_thresholds()
        self._action_rules: Dict[FinanceAction, ActionSafetyRule] = self._build_default_action_rules()

    # ------------------------------------------------------------------
    # Structured result helpers
    # ------------------------------------------------------------------

    def _safe_result(
        self,
        *,
        message: str = "Success.",
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return a standard success result.

        Shape:
            {
                "success": true,
                "message": "...",
                "data": {...},
                "error": null,
                "metadata": {...}
            }
        """

        return {
            "success": True,
            "message": message,
            "data": _dataclass_to_json_safe(data or {}),
            "error": None,
            "metadata": _redact_sensitive_mapping({
                "module": MODULE_NAME,
                "file": FILE_NAME,
                "class": CONFIG_CLASS_NAME,
                "timestamp": _now_epoch(),
                **(metadata or {}),
            }),
        }

    def _error_result(
        self,
        *,
        message: str = "Error.",
        error: Optional[Union[str, Exception, Dict[str, Any]]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return a standard error result.

        No exception is raised by default so dashboard/API callers can safely
        consume structured failures.
        """

        if isinstance(error, Exception):
            error_payload: Any = {
                "type": error.__class__.__name__,
                "message": str(error),
            }
        else:
            error_payload = error

        return {
            "success": False,
            "message": message,
            "data": _dataclass_to_json_safe(data or {}),
            "error": _dataclass_to_json_safe(error_payload),
            "metadata": _redact_sensitive_mapping({
                "module": MODULE_NAME,
                "file": FILE_NAME,
                "class": CONFIG_CLASS_NAME,
                "timestamp": _now_epoch(),
                **(metadata or {}),
            }),
        }

    # ------------------------------------------------------------------
    # Default configuration builders
    # ------------------------------------------------------------------

    def _build_default_thresholds(self) -> Dict[str, ApprovalThreshold]:
        """
        Build default approval thresholds.

        These thresholds do not authorize financial execution. They only help
        classify risk and decide whether Security Agent / human approval is
        required for draft creation, updates, summaries, or dashboard operations.
        """

        currency = self.default_currency

        return {
            "invoice_low": ApprovalThreshold(
                amount=Decimal("1000"),
                currency=currency,
                risk_level=FinanceRiskLevel.LOW,
                require_security_approval=False,
                require_human_approval=False,
                draft_only=True,
                note="Low-value invoice draft threshold.",
            ),
            "invoice_medium": ApprovalThreshold(
                amount=Decimal("5000"),
                currency=currency,
                risk_level=FinanceRiskLevel.MEDIUM,
                require_security_approval=True,
                require_human_approval=False,
                draft_only=True,
                note="Medium-value invoice draft threshold.",
            ),
            "invoice_high": ApprovalThreshold(
                amount=Decimal("25000"),
                currency=currency,
                risk_level=FinanceRiskLevel.HIGH,
                require_security_approval=True,
                require_human_approval=True,
                draft_only=True,
                note="High-value invoice draft threshold.",
            ),
            "transaction_draft_low": ApprovalThreshold(
                amount=Decimal("500"),
                currency=currency,
                risk_level=FinanceRiskLevel.MEDIUM,
                require_security_approval=True,
                require_human_approval=False,
                draft_only=True,
                note="Transaction drafts are never submitted by Finance Agent.",
            ),
            "transaction_draft_high": ApprovalThreshold(
                amount=Decimal("2500"),
                currency=currency,
                risk_level=FinanceRiskLevel.HIGH,
                require_security_approval=True,
                require_human_approval=True,
                draft_only=True,
                note="Large transaction drafts require human review.",
            ),
            "budget_update_medium": ApprovalThreshold(
                amount=Decimal("10000"),
                currency=currency,
                risk_level=FinanceRiskLevel.MEDIUM,
                require_security_approval=True,
                require_human_approval=False,
                draft_only=False,
                note="Budget updates above this amount need Security Agent review.",
            ),
            "budget_update_high": ApprovalThreshold(
                amount=Decimal("50000"),
                currency=currency,
                risk_level=FinanceRiskLevel.HIGH,
                require_security_approval=True,
                require_human_approval=True,
                draft_only=False,
                note="Large budget updates need human review.",
            ),
            "report_export_sensitive": ApprovalThreshold(
                amount=Decimal("0"),
                currency=currency,
                risk_level=FinanceRiskLevel.HIGH,
                require_security_approval=True,
                require_human_approval=False,
                draft_only=False,
                note="Sensitive finance exports require approval regardless of amount.",
            ),
        }

    def _build_default_action_rules(self) -> Dict[FinanceAction, ActionSafetyRule]:
        """Build default safety rules for every FinanceAction."""

        rules: Dict[FinanceAction, ActionSafetyRule] = {}

        read_actions = {
            FinanceAction.READ_FINANCE_SUMMARY,
            FinanceAction.READ_BUDGET,
            FinanceAction.READ_INVOICE,
            FinanceAction.READ_RECEIPT,
            FinanceAction.READ_REPORT,
            FinanceAction.READ_SUBSCRIPTION,
            FinanceAction.READ_TAX_SUMMARY,
            FinanceAction.CATEGORIZE_EXPENSE,
            FinanceAction.DETECT_DUPLICATE_EXPENSE,
            FinanceAction.PARSE_RECEIPT,
            FinanceAction.GENERATE_REPORT,
            FinanceAction.FORECAST_BUDGET,
        }

        draft_actions = {
            FinanceAction.CREATE_INVOICE_DRAFT,
            FinanceAction.UPDATE_INVOICE_DRAFT,
            FinanceAction.CREATE_PAYMENT_DRAFT,
            FinanceAction.CREATE_TRANSACTION_DRAFT,
            FinanceAction.CREATE_BUDGET_DRAFT,
            FinanceAction.CREATE_TAX_PREP_SUMMARY,
            FinanceAction.CREATE_SUBSCRIPTION_REMINDER_DRAFT,
            FinanceAction.CREATE_CLIENT_REMINDER_DRAFT,
        }

        controlled_write_actions = {
            FinanceAction.UPDATE_BUDGET,
            FinanceAction.UPDATE_EXPENSE_CATEGORY,
            FinanceAction.UPDATE_INVOICE_STATUS,
            FinanceAction.UPDATE_SUBSCRIPTION_RECORD,
            FinanceAction.UPDATE_TAX_RECORD_CATEGORY,
            FinanceAction.STORE_FINANCE_MEMORY,
        }

        human_approval_actions = {
            FinanceAction.UPDATE_BUDGET,
            FinanceAction.UPDATE_TAX_RECORD_CATEGORY,
            FinanceAction.STORE_FINANCE_MEMORY,
        }

        blocked_actions = self.get_blocked_action_set()

        for action in read_actions:
            rules[action] = ActionSafetyRule(
                action=action,
                policy=ApprovalPolicy.ALLOWED,
                risk_level=FinanceRiskLevel.LOW,
                required_permissions=(
                    FinancePermission.FINANCE_READ,
                    FinancePermission.FINANCE_ANALYZE,
                ),
                requires_security_approval=False,
                requires_human_approval=False,
                draft_only=False,
                reason="Read/analysis finance action allowed with finance read/analyze permissions.",
            )

        for action in draft_actions:
            rules[action] = ActionSafetyRule(
                action=action,
                policy=ApprovalPolicy.DRAFT_ONLY,
                risk_level=FinanceRiskLevel.MEDIUM,
                required_permissions=(
                    FinancePermission.FINANCE_READ,
                    FinancePermission.FINANCE_DRAFT,
                ),
                requires_security_approval=True,
                requires_human_approval=False,
                draft_only=True,
                reason="Finance Agent may prepare drafts only; no external submission is allowed.",
            )

        for action in controlled_write_actions:
            rules[action] = ActionSafetyRule(
                action=action,
                policy=ApprovalPolicy.SECURITY_APPROVAL_REQUIRED,
                risk_level=FinanceRiskLevel.HIGH,
                required_permissions=(
                    FinancePermission.FINANCE_READ,
                    FinancePermission.FINANCE_WRITE,
                ),
                requires_security_approval=True,
                requires_human_approval=action in human_approval_actions,
                draft_only=False,
                reason="Finance write operation requires SaaS context, permissions, audit, and Security Agent review.",
            )

        for action in blocked_actions:
            rules[action] = ActionSafetyRule(
                action=action,
                policy=ApprovalPolicy.BLOCKED,
                risk_level=FinanceRiskLevel.BLOCKED,
                required_permissions=(
                    FinancePermission.FINANCE_ADMIN,
                    FinancePermission.FINANCE_APPROVE,
                ),
                requires_security_approval=True,
                requires_human_approval=True,
                draft_only=False,
                reason="Blocked by Finance Agent safe-mode. This action must not be executed by the agent.",
            )

        return rules

    # ------------------------------------------------------------------
    # Public configuration accessors
    # ------------------------------------------------------------------

    def get_blocked_action_set(self) -> Set[FinanceAction]:
        """
        Return actions that Finance Agent must never execute directly.

        These are blocked even if a future integration exists. Another trusted
        external system may handle them only through explicit user approval,
        secure provider authorization, and separate policy controls.
        """

        return {
            FinanceAction.SUBMIT_PAYMENT,
            FinanceAction.SEND_PAYMENT,
            FinanceAction.TRANSFER_FUNDS,
            FinanceAction.WITHDRAW_FUNDS,
            FinanceAction.DEPOSIT_FUNDS,
            FinanceAction.AUTHORIZE_CARD_CHARGE,
            FinanceAction.CHARGE_CUSTOMER,
            FinanceAction.REFUND_CUSTOMER,
            FinanceAction.PAY_INVOICE,
            FinanceAction.PAY_BILL,
            FinanceAction.CONNECT_BANK_ACCOUNT,
            FinanceAction.DISCONNECT_BANK_ACCOUNT,
            FinanceAction.EXPORT_BANK_CREDENTIALS,
            FinanceAction.VIEW_FULL_BANK_CREDENTIALS,
            FinanceAction.MODIFY_BANK_ACCOUNT,
            FinanceAction.MODIFY_PAYMENT_METHOD,
            FinanceAction.DELETE_FINANCIAL_RECORD,
            FinanceAction.DELETE_INVOICE,
            FinanceAction.DELETE_TRANSACTION,
            FinanceAction.DELETE_BUDGET,
            FinanceAction.DELETE_TAX_RECORD,
            FinanceAction.FILE_TAX_RETURN,
            FinanceAction.SUBMIT_TAX_PAYMENT,
            FinanceAction.LEGAL_FINANCIAL_ADVICE,
            FinanceAction.INVESTMENT_TRADE,
            FinanceAction.BUY_SECURITY,
            FinanceAction.SELL_SECURITY,
            FinanceAction.CRYPTO_TRANSFER,
        }

    def get_draft_only_action_set(self) -> Set[FinanceAction]:
        """Return actions allowed only as drafts."""

        return {
            action
            for action, rule in self._action_rules.items()
            if rule.draft_only or rule.policy == ApprovalPolicy.DRAFT_ONLY
        }

    def get_security_required_action_set(self) -> Set[FinanceAction]:
        """Return actions requiring Security Agent review."""

        return {
            action
            for action, rule in self._action_rules.items()
            if rule.requires_security_approval
        }

    def get_human_approval_action_set(self) -> Set[FinanceAction]:
        """Return actions requiring human approval."""

        return {
            action
            for action, rule in self._action_rules.items()
            if rule.requires_human_approval
        }

    def get_allowed_read_action_set(self) -> Set[FinanceAction]:
        """Return low-risk read/analysis actions."""

        return {
            action
            for action, rule in self._action_rules.items()
            if rule.policy == ApprovalPolicy.ALLOWED
        }

    def get_action_rule(
        self,
        action: Union[str, FinanceAction],
    ) -> Dict[str, Any]:
        """Return structured safety rule for an action."""

        normalized = _normalize_action(action)
        if not normalized:
            return self._error_result(
                message="Unknown finance action.",
                error={"action": _safe_str(action)},
            )

        rule = self._action_rules.get(normalized)
        if not rule:
            return self._error_result(
                message="No safety rule found for finance action.",
                error={"action": normalized.value},
            )

        return self._safe_result(
            message="Finance action safety rule loaded.",
            data={"rule": _dataclass_to_json_safe(rule)},
        )

    def get_thresholds(self) -> Dict[str, Any]:
        """Return all approval thresholds as structured result."""

        return self._safe_result(
            message="Finance approval thresholds loaded.",
            data={
                "thresholds": {
                    name: _dataclass_to_json_safe(threshold)
                    for name, threshold in self._thresholds.items()
                }
            },
        )

    def get_config_snapshot(self) -> Dict[str, Any]:
        """
        Return a complete safe configuration snapshot.

        This is suitable for:
            - Agent Registry
            - Agent Loader
            - Master Agent capability inspection
            - Dashboard settings page
            - API diagnostics
            - Unit tests
        """

        snapshot = FinanceConfigSnapshot(
            module_name=MODULE_NAME,
            file_name=FILE_NAME,
            class_name=CONFIG_CLASS_NAME,
            config_version=CONFIG_VERSION,
            config_schema_version=CONFIG_SCHEMA_VERSION,
            safe_mode_enabled=self.safe_mode_enabled,
            default_currency=self.default_currency,
            draft_only_mode=self.draft_only_mode,
            require_security_approval_by_default=self.require_security_approval_by_default,
            require_verification_payload=self.require_verification_payload,
            require_audit_log=self.require_audit_log,
            blocked_actions=sorted(action.value for action in self.get_blocked_action_set()),
            security_required_actions=sorted(action.value for action in self.get_security_required_action_set()),
            human_approval_actions=sorted(action.value for action in self.get_human_approval_action_set()),
            draft_only_actions=sorted(action.value for action in self.get_draft_only_action_set()),
            allowed_read_actions=sorted(action.value for action in self.get_allowed_read_action_set()),
            thresholds={
                name: _dataclass_to_json_safe(threshold)
                for name, threshold in self._thresholds.items()
            },
            metadata={
                "agent_name": AGENT_NAME,
                "safe_import": True,
                "executes_financial_actions": False,
                "submits_payments": False,
                "transfers_funds": False,
                "supports_saas_isolation": True,
                "supports_master_agent_routing": True,
                "supports_security_agent_handoff": True,
                "supports_verification_payload": True,
                "supports_memory_payload": True,
                **self.metadata,
            },
        )

        return self._safe_result(
            message="Finance configuration snapshot loaded.",
            data={"config": _dataclass_to_json_safe(snapshot)},
        )

    # ------------------------------------------------------------------
    # SaaS context validation
    # ------------------------------------------------------------------

    def normalize_task_context(
        self,
        context: Optional[Union[FinanceContext, Mapping[str, Any]]] = None,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        role: Optional[str] = None,
        subscription_plan: Optional[str] = None,
        permissions: Optional[Iterable[Union[str, FinancePermission]]] = None,
        request_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Normalize SaaS user/workspace context.

        Public finance actions should call this or _validate_task_context()
        before making decisions.
        """

        try:
            if isinstance(context, FinanceContext):
                base = {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "role": context.role,
                    "subscription_plan": context.subscription_plan,
                    "permissions": context.permissions,
                    "request_id": context.request_id,
                    "correlation_id": context.correlation_id,
                    "metadata": context.metadata,
                }
            elif isinstance(context, Mapping):
                base = dict(context)
            else:
                base = {}

            merged_metadata = {}
            if isinstance(base.get("metadata"), Mapping):
                merged_metadata.update(base.get("metadata", {}))
            if metadata:
                merged_metadata.update(metadata)

            normalized = FinanceContext(
                user_id=_safe_str(user_id or base.get("user_id")),
                workspace_id=_safe_str(workspace_id or base.get("workspace_id")),
                role=role or base.get("role"),
                subscription_plan=subscription_plan or base.get("subscription_plan"),
                permissions=_normalize_permissions(permissions or base.get("permissions")),
                request_id=_safe_str(request_id or base.get("request_id") or str(uuid.uuid4())),
                correlation_id=correlation_id or base.get("correlation_id"),
                metadata=_redact_sensitive_mapping(merged_metadata),
            )

            return self._safe_result(
                message="Finance task context normalized.",
                data={"context": _dataclass_to_json_safe(normalized)},
            )
        except Exception as exc:
            self.logger.exception("Failed to normalize Finance task context.")
            return self._error_result(
                message="Failed to normalize Finance task context.",
                error=exc,
            )

    def _validate_task_context(
        self,
        context: Optional[Union[FinanceContext, Mapping[str, Any]]] = None,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        required_permissions: Optional[Iterable[Union[str, FinancePermission]]] = None,
        allow_missing_permissions: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        Required compatibility hook.

        Rules:
            - user_id is required for user-specific finance actions.
            - workspace_id is required for workspace-specific finance actions.
            - permissions can be checked when provided.
            - no user/workspace mixing is allowed.
        """

        normalized_result = self.normalize_task_context(
            context,
            user_id=user_id,
            workspace_id=workspace_id,
            metadata=metadata,
        )

        if not normalized_result.get("success"):
            return normalized_result

        normalized_context = normalized_result["data"]["context"]
        errors: List[str] = []

        if not normalized_context.get("user_id"):
            errors.append("Missing required user_id.")

        if not normalized_context.get("workspace_id"):
            errors.append("Missing required workspace_id.")

        required = _normalize_permissions(required_permissions)
        actual = set(_normalize_permissions(normalized_context.get("permissions")))

        missing_permissions = sorted(permission for permission in required if permission not in actual)

        if missing_permissions and not allow_missing_permissions:
            errors.append(f"Missing required permissions: {', '.join(missing_permissions)}.")

        if errors:
            return self._error_result(
                message="Finance task context validation failed.",
                error={
                    "errors": errors,
                    "missing_permissions": missing_permissions,
                },
                data={"context": normalized_context},
                metadata={
                    "validation": "task_context",
                    "request_id": normalized_context.get("request_id"),
                    "correlation_id": normalized_context.get("correlation_id"),
                },
            )

        return self._safe_result(
            message="Finance task context validation passed.",
            data={
                "context": normalized_context,
                "missing_permissions": missing_permissions,
                "valid": True,
            },
            metadata={
                "validation": "task_context",
                "request_id": normalized_context.get("request_id"),
                "correlation_id": normalized_context.get("correlation_id"),
            },
        )

    # ------------------------------------------------------------------
    # Safety and approval decisions
    # ------------------------------------------------------------------

    def evaluate_action(
        self,
        action: Union[str, FinanceAction],
        *,
        amount: Optional[Union[int, float, str, Decimal]] = None,
        currency: Optional[str] = None,
        context: Optional[Union[FinanceContext, Mapping[str, Any]]] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        permissions: Optional[Iterable[Union[str, FinancePermission]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate whether a finance action is allowed, draft-only, requires approval,
        or is blocked.

        This method does not execute the action.
        """

        normalized_action = _normalize_action(action)
        if not normalized_action:
            return self._error_result(
                message="Unknown finance action.",
                error={"action": _safe_str(action)},
            )

        rule = self._action_rules.get(normalized_action)
        if not rule:
            return self._error_result(
                message="Finance action has no safety rule.",
                error={"action": normalized_action.value},
            )

        context_result = self.normalize_task_context(
            context,
            user_id=user_id,
            workspace_id=workspace_id,
            permissions=permissions,
            metadata=metadata,
        )
        normalized_context = (
            context_result.get("data", {}).get("context", {})
            if context_result.get("success")
            else {}
        )

        context_validation = self._validate_task_context(
            normalized_context,
            required_permissions=rule.required_permissions,
            allow_missing_permissions=True,
            metadata={"action": normalized_action.value},
        )

        threshold_result = self.evaluate_threshold(
            action=normalized_action,
            amount=amount,
            currency=currency,
            metadata=metadata,
        )

        threshold_data = threshold_result.get("data", {}) if threshold_result.get("success") else {}

        missing_permissions = context_validation.get("data", {}).get("missing_permissions", [])
        effective_policy = rule.policy
        effective_risk = rule.risk_level
        requires_security = rule.requires_security_approval
        requires_human = rule.requires_human_approval
        draft_only = rule.draft_only

        if self.safe_mode_enabled and normalized_action in self.get_blocked_action_set():
            effective_policy = ApprovalPolicy.BLOCKED
            effective_risk = FinanceRiskLevel.BLOCKED
            requires_security = True
            requires_human = True

        if threshold_data.get("threshold_requires_security_approval"):
            requires_security = True

        if threshold_data.get("threshold_requires_human_approval"):
            requires_human = True

        threshold_risk = threshold_data.get("risk_level")
        if threshold_risk in {FinanceRiskLevel.HIGH.value, FinanceRiskLevel.CRITICAL.value}:
            effective_risk = FinanceRiskLevel(threshold_risk)

        if threshold_data.get("draft_only"):
            draft_only = True
            if effective_policy != ApprovalPolicy.BLOCKED:
                effective_policy = ApprovalPolicy.DRAFT_ONLY

        if missing_permissions and effective_policy not in {ApprovalPolicy.BLOCKED}:
            requires_security = True

        decision = {
            "action": normalized_action.value,
            "policy": effective_policy.value,
            "risk_level": effective_risk.value,
            "allowed": effective_policy == ApprovalPolicy.ALLOWED,
            "blocked": effective_policy == ApprovalPolicy.BLOCKED,
            "draft_only": draft_only,
            "requires_security_approval": requires_security,
            "requires_human_approval": requires_human,
            "requires_verification_payload": rule.requires_verification_payload,
            "audit_required": rule.audit_required or self.require_audit_log,
            "required_permissions": [permission.value for permission in rule.required_permissions],
            "missing_permissions": missing_permissions,
            "amount": _decimal_to_json(_to_decimal(amount)) if amount is not None else None,
            "currency": (currency or self.default_currency).upper(),
            "reason": rule.reason,
            "safe_mode_enabled": self.safe_mode_enabled,
            "context_valid": bool(context_validation.get("success")),
            "context": normalized_context,
            "threshold": threshold_data,
        }

        return self._safe_result(
            message="Finance action safety evaluation completed.",
            data={"decision": decision},
            metadata={
                "action": normalized_action.value,
                "policy": effective_policy.value,
                "risk_level": effective_risk.value,
                "request_id": normalized_context.get("request_id"),
                "correlation_id": normalized_context.get("correlation_id"),
            },
        )

    def evaluate_threshold(
        self,
        *,
        action: Union[str, FinanceAction],
        amount: Optional[Union[int, float, str, Decimal]] = None,
        currency: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate amount against finance approval thresholds.

        This method is conservative and never authorizes real money movement.
        """

        normalized_action = _normalize_action(action)
        if not normalized_action:
            return self._error_result(
                message="Cannot evaluate threshold for unknown action.",
                error={"action": _safe_str(action)},
            )

        amount_decimal = _to_decimal(amount, Decimal("0"))
        active_currency = (currency or self.default_currency).upper()

        matched_thresholds: List[Dict[str, Any]] = []
        risk_level = FinanceRiskLevel.LOW
        requires_security = False
        requires_human = False
        draft_only = False

        threshold_keys = self._threshold_keys_for_action(normalized_action)

        for key in threshold_keys:
            threshold = self._thresholds.get(key)
            if not threshold:
                continue
            if amount_decimal >= threshold.amount:
                matched_thresholds.append({
                    "name": key,
                    "threshold": _dataclass_to_json_safe(threshold),
                })
                requires_security = requires_security or threshold.require_security_approval
                requires_human = requires_human or threshold.require_human_approval
                draft_only = draft_only or threshold.draft_only
                risk_level = self._max_risk_level(risk_level, threshold.risk_level)

        data = {
            "action": normalized_action.value,
            "amount": _decimal_to_json(amount_decimal),
            "currency": active_currency,
            "configured_currency": self.default_currency,
            "currency_matches_default": active_currency == self.default_currency,
            "risk_level": risk_level.value,
            "threshold_requires_security_approval": requires_security,
            "threshold_requires_human_approval": requires_human,
            "draft_only": draft_only,
            "matched_thresholds": matched_thresholds,
            "metadata": _redact_sensitive_mapping(metadata or {}),
        }

        return self._safe_result(
            message="Finance threshold evaluation completed.",
            data=data,
            metadata={
                "action": normalized_action.value,
                "risk_level": risk_level.value,
            },
        )

    def _threshold_keys_for_action(self, action: FinanceAction) -> Tuple[str, ...]:
        """Return threshold keys relevant to an action."""

        if action in {
            FinanceAction.CREATE_INVOICE_DRAFT,
            FinanceAction.UPDATE_INVOICE_DRAFT,
            FinanceAction.UPDATE_INVOICE_STATUS,
            FinanceAction.READ_INVOICE,
        }:
            return ("invoice_low", "invoice_medium", "invoice_high")

        if action in {
            FinanceAction.CREATE_PAYMENT_DRAFT,
            FinanceAction.CREATE_TRANSACTION_DRAFT,
        }:
            return ("transaction_draft_low", "transaction_draft_high")

        if action in {
            FinanceAction.UPDATE_BUDGET,
            FinanceAction.CREATE_BUDGET_DRAFT,
            FinanceAction.FORECAST_BUDGET,
        }:
            return ("budget_update_medium", "budget_update_high")

        if action in {
            FinanceAction.GENERATE_REPORT,
            FinanceAction.READ_REPORT,
            FinanceAction.READ_TAX_SUMMARY,
            FinanceAction.CREATE_TAX_PREP_SUMMARY,
        }:
            return ("report_export_sensitive",)

        return tuple()

    def _max_risk_level(
        self,
        current: FinanceRiskLevel,
        candidate: FinanceRiskLevel,
    ) -> FinanceRiskLevel:
        """Return the higher risk level."""

        rank = {
            FinanceRiskLevel.LOW: 1,
            FinanceRiskLevel.MEDIUM: 2,
            FinanceRiskLevel.HIGH: 3,
            FinanceRiskLevel.CRITICAL: 4,
            FinanceRiskLevel.BLOCKED: 5,
        }
        return candidate if rank[candidate] > rank[current] else current

    def _requires_security_check(
        self,
        action: Union[str, FinanceAction],
        *,
        amount: Optional[Union[int, float, str, Decimal]] = None,
        context: Optional[Union[FinanceContext, Mapping[str, Any]]] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        permissions: Optional[Iterable[Union[str, FinancePermission]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Required compatibility hook.

        Returns whether a finance action requires Security Agent review.
        """

        evaluation = self.evaluate_action(
            action,
            amount=amount,
            context=context,
            user_id=user_id,
            workspace_id=workspace_id,
            permissions=permissions,
            metadata=metadata,
        )

        if not evaluation.get("success"):
            return evaluation

        decision = evaluation["data"]["decision"]

        return self._safe_result(
            message="Finance security-check requirement evaluated.",
            data={
                "requires_security_check": bool(decision.get("requires_security_approval")),
                "decision": decision,
            },
            metadata={
                "action": decision.get("action"),
                "policy": decision.get("policy"),
                "risk_level": decision.get("risk_level"),
            },
        )

    def _request_security_approval(
        self,
        action: Union[str, FinanceAction],
        *,
        amount: Optional[Union[int, float, str, Decimal]] = None,
        currency: Optional[str] = None,
        context: Optional[Union[FinanceContext, Mapping[str, Any]]] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        permissions: Optional[Iterable[Union[str, FinancePermission]]] = None,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Required compatibility hook.

        Prepares a Security Agent approval request payload.

        This method does not call Security Agent directly because the full
        Security Agent may not exist yet. It returns a payload that Master Agent,
        Router, or API layer can forward to Security Agent.
        """

        evaluation = self.evaluate_action(
            action,
            amount=amount,
            currency=currency,
            context=context,
            user_id=user_id,
            workspace_id=workspace_id,
            permissions=permissions,
            metadata=metadata,
        )

        if not evaluation.get("success"):
            return evaluation

        decision = evaluation["data"]["decision"]
        normalized_context = decision.get("context", {})
        approval_id = str(uuid.uuid4())

        payload = {
            "approval_id": approval_id,
            "target_agent": "security_agent",
            "source_agent": MODULE_NAME,
            "source_file": FILE_NAME,
            "action": decision.get("action"),
            "policy": decision.get("policy"),
            "risk_level": decision.get("risk_level"),
            "amount": decision.get("amount"),
            "currency": decision.get("currency"),
            "blocked": decision.get("blocked"),
            "draft_only": decision.get("draft_only"),
            "requires_security_approval": decision.get("requires_security_approval"),
            "requires_human_approval": decision.get("requires_human_approval"),
            "reason": reason or decision.get("reason"),
            "user_id": normalized_context.get("user_id"),
            "workspace_id": normalized_context.get("workspace_id"),
            "request_id": normalized_context.get("request_id"),
            "correlation_id": normalized_context.get("correlation_id"),
            "permissions": normalized_context.get("permissions", []),
            "metadata": _redact_sensitive_mapping({
                "safe_mode_enabled": self.safe_mode_enabled,
                "config_version": CONFIG_VERSION,
                "schema_version": CONFIG_SCHEMA_VERSION,
                **(metadata or {}),
            }),
            "created_at": _now_epoch(),
        }

        return self._safe_result(
            message="Security approval payload prepared.",
            data={"security_approval_request": payload},
            metadata={
                "approval_id": approval_id,
                "action": decision.get("action"),
                "risk_level": decision.get("risk_level"),
            },
        )

    # ------------------------------------------------------------------
    # Verification, memory, events, audit
    # ------------------------------------------------------------------

    def _prepare_verification_payload(
        self,
        *,
        action: Union[str, FinanceAction],
        result: Optional[Mapping[str, Any]] = None,
        context: Optional[Union[FinanceContext, Mapping[str, Any]]] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Required compatibility hook.

        Prepares a Verification Agent payload after a finance configuration
        decision/check. This payload is safe and redacted.
        """

        normalized_action = _normalize_action(action)
        if not normalized_action:
            return self._error_result(
                message="Cannot prepare verification payload for unknown action.",
                error={"action": _safe_str(action)},
            )

        context_result = self.normalize_task_context(
            context,
            user_id=user_id,
            workspace_id=workspace_id,
            metadata=metadata,
        )

        normalized_context = (
            context_result.get("data", {}).get("context", {})
            if context_result.get("success")
            else {}
        )

        verification_payload = {
            "verification_id": str(uuid.uuid4()),
            "target_agent": "verification_agent",
            "source_agent": MODULE_NAME,
            "source_file": FILE_NAME,
            "action": normalized_action.value,
            "verification_type": "finance_config_policy_check",
            "status": "prepared",
            "safe_mode_enabled": self.safe_mode_enabled,
            "result_summary": _redact_sensitive_mapping(dict(result or {})),
            "user_id": normalized_context.get("user_id"),
            "workspace_id": normalized_context.get("workspace_id"),
            "request_id": normalized_context.get("request_id"),
            "correlation_id": normalized_context.get("correlation_id"),
            "metadata": _redact_sensitive_mapping({
                "config_version": CONFIG_VERSION,
                "schema_version": CONFIG_SCHEMA_VERSION,
                **(metadata or {}),
            }),
            "created_at": _now_epoch(),
        }

        return self._safe_result(
            message="Verification payload prepared.",
            data={"verification_payload": verification_payload},
            metadata={
                "action": normalized_action.value,
                "verification_type": "finance_config_policy_check",
            },
        )

    def _prepare_memory_payload(
        self,
        *,
        action: Union[str, FinanceAction],
        memory_type: str = "finance_config_preference",
        content: Optional[Mapping[str, Any]] = None,
        context: Optional[Union[FinanceContext, Mapping[str, Any]]] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Required compatibility hook.

        Prepares a Memory Agent payload for safe, non-sensitive finance
        configuration preferences.

        Sensitive finance values are redacted before payload creation.
        """

        normalized_action = _normalize_action(action)
        if not normalized_action:
            return self._error_result(
                message="Cannot prepare memory payload for unknown action.",
                error={"action": _safe_str(action)},
            )

        context_result = self.normalize_task_context(
            context,
            user_id=user_id,
            workspace_id=workspace_id,
            metadata=metadata,
        )

        normalized_context = (
            context_result.get("data", {}).get("context", {})
            if context_result.get("success")
            else {}
        )

        safe_content = _redact_sensitive_mapping(dict(content or {}))

        memory_payload = {
            "memory_id": str(uuid.uuid4()),
            "target_agent": "memory_agent",
            "source_agent": MODULE_NAME,
            "source_file": FILE_NAME,
            "action": normalized_action.value,
            "memory_type": memory_type,
            "scope": "workspace",
            "user_id": normalized_context.get("user_id"),
            "workspace_id": normalized_context.get("workspace_id"),
            "request_id": normalized_context.get("request_id"),
            "correlation_id": normalized_context.get("correlation_id"),
            "content": safe_content,
            "metadata": _redact_sensitive_mapping({
                "safe_to_store": True,
                "contains_raw_bank_credentials": False,
                "contains_payment_authorization": False,
                "config_version": CONFIG_VERSION,
                **(metadata or {}),
            }),
            "created_at": _now_epoch(),
        }

        return self._safe_result(
            message="Memory payload prepared.",
            data={"memory_payload": memory_payload},
            metadata={
                "action": normalized_action.value,
                "memory_type": memory_type,
            },
        )

    def _emit_agent_event(
        self,
        *,
        event_name: str,
        action: Optional[Union[str, FinanceAction]] = None,
        context: Optional[Union[FinanceContext, Mapping[str, Any]]] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        payload: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Required compatibility hook.

        Prepares an agent event payload for dashboard/API/event bus.

        This method does not publish to a live queue. It returns a structured
        event that a future event bus can consume.
        """

        normalized_action = _normalize_action(action) if action else None

        context_result = self.normalize_task_context(
            context,
            user_id=user_id,
            workspace_id=workspace_id,
            metadata=metadata,
        )

        normalized_context = (
            context_result.get("data", {}).get("context", {})
            if context_result.get("success")
            else {}
        )

        event = {
            "event_id": str(uuid.uuid4()),
            "event_name": _safe_str(event_name),
            "source_agent": MODULE_NAME,
            "source_file": FILE_NAME,
            "action": normalized_action.value if normalized_action else None,
            "user_id": normalized_context.get("user_id"),
            "workspace_id": normalized_context.get("workspace_id"),
            "request_id": normalized_context.get("request_id"),
            "correlation_id": normalized_context.get("correlation_id"),
            "payload": _redact_sensitive_mapping(dict(payload or {})),
            "metadata": _redact_sensitive_mapping({
                "config_version": CONFIG_VERSION,
                "safe_mode_enabled": self.safe_mode_enabled,
                **(metadata or {}),
            }),
            "created_at": _now_epoch(),
        }

        return self._safe_result(
            message="Finance agent event prepared.",
            data={"event": event},
            metadata={
                "event_name": event_name,
                "action": event.get("action"),
            },
        )

    def _log_audit_event(
        self,
        *,
        action: Union[str, FinanceAction],
        decision: Optional[Mapping[str, Any]] = None,
        context: Optional[Union[FinanceContext, Mapping[str, Any]]] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        outcome: str = "prepared",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Required compatibility hook.

        Prepares an audit event. It does not write to a database directly.
        The dashboard/API/persistence layer can store this returned payload.
        """

        normalized_action = _normalize_action(action)
        if not normalized_action:
            return self._error_result(
                message="Cannot prepare audit event for unknown action.",
                error={"action": _safe_str(action)},
            )

        context_result = self.normalize_task_context(
            context,
            user_id=user_id,
            workspace_id=workspace_id,
            metadata=metadata,
        )

        normalized_context = (
            context_result.get("data", {}).get("context", {})
            if context_result.get("success")
            else {}
        )

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "source_agent": MODULE_NAME,
            "source_file": FILE_NAME,
            "action": normalized_action.value,
            "outcome": _safe_str(outcome),
            "user_id": normalized_context.get("user_id"),
            "workspace_id": normalized_context.get("workspace_id"),
            "request_id": normalized_context.get("request_id"),
            "correlation_id": normalized_context.get("correlation_id"),
            "decision": _redact_sensitive_mapping(dict(decision or {})),
            "metadata": _redact_sensitive_mapping({
                "audit_required": True,
                "safe_mode_enabled": self.safe_mode_enabled,
                "config_version": CONFIG_VERSION,
                **(metadata or {}),
            }),
            "created_at": _now_epoch(),
        }

        return self._safe_result(
            message="Finance audit event prepared.",
            data={"audit_event": audit_event},
            metadata={
                "action": normalized_action.value,
                "outcome": outcome,
            },
        )

    # ------------------------------------------------------------------
    # Runtime customization helpers
    # ------------------------------------------------------------------

    def set_threshold(
        self,
        name: str,
        *,
        amount: Union[int, float, str, Decimal],
        currency: Optional[str] = None,
        risk_level: Union[str, FinanceRiskLevel] = FinanceRiskLevel.MEDIUM,
        require_security_approval: bool = True,
        require_human_approval: bool = False,
        draft_only: bool = False,
        note: str = "",
        context: Optional[Union[FinanceContext, Mapping[str, Any]]] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        permissions: Optional[Iterable[Union[str, FinancePermission]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Update or create a threshold in memory.

        This is a controlled configuration change. It does not persist to DB.
        Future dashboard/API code may call this and then store the snapshot.

        Requires finance admin/approve style permissions when enforced by caller.
        """

        validation = self._validate_task_context(
            context,
            user_id=user_id,
            workspace_id=workspace_id,
            required_permissions=(
                FinancePermission.FINANCE_ADMIN,
                FinancePermission.FINANCE_APPROVE,
            ),
            allow_missing_permissions=True,
            metadata=metadata,
        )

        if not validation.get("success"):
            return validation

        clean_name = _safe_str(name, max_length=120).strip().lower()
        if not clean_name:
            return self._error_result(
                message="Threshold name is required.",
                error={"name": name},
            )

        try:
            normalized_risk = (
                risk_level
                if isinstance(risk_level, FinanceRiskLevel)
                else FinanceRiskLevel(str(risk_level).lower())
            )
        except Exception:
            return self._error_result(
                message="Invalid threshold risk level.",
                error={"risk_level": _safe_str(risk_level)},
            )

        threshold = ApprovalThreshold(
            amount=_to_decimal(amount),
            currency=(currency or self.default_currency).upper(),
            risk_level=normalized_risk,
            require_security_approval=bool(require_security_approval),
            require_human_approval=bool(require_human_approval),
            draft_only=bool(draft_only),
            note=_safe_str(note, max_length=DEFAULT_MAX_NOTE_LENGTH),
        )

        self._thresholds[clean_name] = threshold

        audit = self._log_audit_event(
            action=FinanceAction.UPDATE_BUDGET,
            decision={
                "config_change": "set_threshold",
                "threshold_name": clean_name,
                "threshold": _dataclass_to_json_safe(threshold),
            },
            context=validation["data"]["context"],
            outcome="threshold_updated",
            metadata=metadata,
        )

        return self._safe_result(
            message="Finance threshold updated in runtime configuration.",
            data={
                "threshold_name": clean_name,
                "threshold": _dataclass_to_json_safe(threshold),
                "audit_event": audit.get("data", {}).get("audit_event"),
            },
            metadata={
                "threshold_name": clean_name,
                "config_change": True,
            },
        )

    def update_safe_mode(
        self,
        enabled: bool,
        *,
        context: Optional[Union[FinanceContext, Mapping[str, Any]]] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        permissions: Optional[Iterable[Union[str, FinancePermission]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Update safe mode.

        Disabling safe mode is not recommended and still does not allow blocked
        financial execution in this file. Blocked actions remain blocked by
        action policy.
        """

        validation = self._validate_task_context(
            context,
            user_id=user_id,
            workspace_id=workspace_id,
            required_permissions=(
                FinancePermission.FINANCE_ADMIN,
                FinancePermission.FINANCE_APPROVE,
            ),
            allow_missing_permissions=True,
            metadata=metadata,
        )

        if not validation.get("success"):
            return validation

        previous = self.safe_mode_enabled
        self.safe_mode_enabled = bool(enabled)

        audit = self._log_audit_event(
            action=FinanceAction.STORE_FINANCE_MEMORY,
            decision={
                "config_change": "update_safe_mode",
                "previous": previous,
                "new": self.safe_mode_enabled,
                "note": "Blocked action list remains enforced.",
            },
            context=validation["data"]["context"],
            outcome="safe_mode_updated",
            metadata=metadata,
        )

        return self._safe_result(
            message="Finance safe mode setting updated.",
            data={
                "previous_safe_mode_enabled": previous,
                "safe_mode_enabled": self.safe_mode_enabled,
                "blocked_actions_still_enforced": True,
                "audit_event": audit.get("data", {}).get("audit_event"),
            },
        )

    # ------------------------------------------------------------------
    # Registry / Master Agent metadata
    # ------------------------------------------------------------------

    def get_registry_metadata(self) -> Dict[str, Any]:
        """
        Return metadata for Agent Registry / Agent Loader.

        This does not register anything by itself.
        """

        capabilities = [
            "finance_safe_mode_config",
            "blocked_action_policy",
            "approval_thresholds",
            "security_agent_handoff_payloads",
            "verification_payloads",
            "memory_payloads",
            "audit_event_payloads",
            "saas_user_workspace_context_validation",
            "master_agent_route_metadata",
        ]

        routes = {
            "finance.config.snapshot": "get_config_snapshot",
            "finance.config.evaluate_action": "evaluate_action",
            "finance.config.evaluate_threshold": "evaluate_threshold",
            "finance.config.requires_security_check": "_requires_security_check",
            "finance.config.security_approval_payload": "_request_security_approval",
            "finance.config.verification_payload": "_prepare_verification_payload",
            "finance.config.memory_payload": "_prepare_memory_payload",
        }

        return self._safe_result(
            message="FinanceConfig registry metadata loaded.",
            data={
                "agent_name": AGENT_NAME,
                "module_name": MODULE_NAME,
                "file_name": FILE_NAME,
                "class_name": CONFIG_CLASS_NAME,
                "config_version": CONFIG_VERSION,
                "config_schema_version": CONFIG_SCHEMA_VERSION,
                "capabilities": capabilities,
                "routes": routes,
                "safe_to_import": True,
                "requires_external_services": False,
                "executes_financial_actions": False,
                "blocked_action_count": len(self.get_blocked_action_set()),
                "safe_mode_enabled": self.safe_mode_enabled,
            },
        )

    def to_dict(self) -> Dict[str, Any]:
        """Return a compact dict representation of current config."""

        snapshot_result = self.get_config_snapshot()
        if snapshot_result.get("success"):
            return snapshot_result["data"]["config"]
        return {
            "module_name": MODULE_NAME,
            "file_name": FILE_NAME,
            "class_name": CONFIG_CLASS_NAME,
            "safe_mode_enabled": self.safe_mode_enabled,
            "error": snapshot_result.get("error"),
        }

    def clone(self) -> "FinanceConfig":
        """Return a safe deep copy of this config object."""

        cloned = FinanceConfig(
            safe_mode_enabled=self.safe_mode_enabled,
            default_currency=self.default_currency,
            draft_only_mode=self.draft_only_mode,
            require_security_approval_by_default=self.require_security_approval_by_default,
            require_verification_payload=self.require_verification_payload,
            require_audit_log=self.require_audit_log,
            logger=self.logger,
            metadata=copy.deepcopy(self.metadata),
        )
        cloned._thresholds = copy.deepcopy(self._thresholds)
        cloned._action_rules = copy.deepcopy(self._action_rules)
        return cloned


# ---------------------------------------------------------------------------
# Module-level helpers for simple imports
# ---------------------------------------------------------------------------

DEFAULT_FINANCE_CONFIG = FinanceConfig()


def get_default_finance_config() -> FinanceConfig:
    """
    Return the module-level default FinanceConfig instance.

    Useful for simple imports:
        from agents.super_agents.finance_agent.config import get_default_finance_config
    """

    return DEFAULT_FINANCE_CONFIG


def get_finance_config_snapshot() -> Dict[str, Any]:
    """Return default FinanceConfig snapshot."""

    return DEFAULT_FINANCE_CONFIG.get_config_snapshot()


def evaluate_finance_action(
    action: Union[str, FinanceAction],
    *,
    amount: Optional[Union[int, float, str, Decimal]] = None,
    currency: Optional[str] = None,
    context: Optional[Union[FinanceContext, Mapping[str, Any]]] = None,
    user_id: Optional[str] = None,
    workspace_id: Optional[str] = None,
    permissions: Optional[Iterable[Union[str, FinancePermission]]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Convenience module-level action evaluator.

    This is safe for FastAPI routes, tests, and Finance submodules.
    """

    return DEFAULT_FINANCE_CONFIG.evaluate_action(
        action,
        amount=amount,
        currency=currency,
        context=context,
        user_id=user_id,
        workspace_id=workspace_id,
        permissions=permissions,
        metadata=metadata,
    )


def requires_finance_security_check(
    action: Union[str, FinanceAction],
    *,
    amount: Optional[Union[int, float, str, Decimal]] = None,
    context: Optional[Union[FinanceContext, Mapping[str, Any]]] = None,
    user_id: Optional[str] = None,
    workspace_id: Optional[str] = None,
    permissions: Optional[Iterable[Union[str, FinancePermission]]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Convenience module-level security check helper."""

    return DEFAULT_FINANCE_CONFIG._requires_security_check(
        action,
        amount=amount,
        context=context,
        user_id=user_id,
        workspace_id=workspace_id,
        permissions=permissions,
        metadata=metadata,
    )


__all__ = [
    "AGENT_NAME",
    "CONFIG_CLASS_NAME",
    "CONFIG_SCHEMA_VERSION",
    "CONFIG_VERSION",
    "DEFAULT_FINANCE_CONFIG",
    "FILE_NAME",
    "MODULE_NAME",
    "ActionSafetyRule",
    "ApprovalPolicy",
    "ApprovalThreshold",
    "FinanceAction",
    "FinanceConfig",
    "FinanceConfigSnapshot",
    "FinanceContext",
    "FinancePermission",
    "FinanceRiskLevel",
    "evaluate_finance_action",
    "get_default_finance_config",
    "get_finance_config_snapshot",
    "requires_finance_security_check",
]


if __name__ == "__main__":
    # Safe smoke test only. No financial actions are executed.
    config = FinanceConfig()
    smoke_context = {
        "user_id": "test_user",
        "workspace_id": "test_workspace",
        "permissions": [
            FinancePermission.FINANCE_READ.value,
            FinancePermission.FINANCE_DRAFT.value,
        ],
    }

    print(config.get_registry_metadata())
    print(config.evaluate_action(
        FinanceAction.CREATE_TRANSACTION_DRAFT,
        amount="1200",
        currency="USD",
        context=smoke_context,
    ))
    print(config.evaluate_action(
        FinanceAction.TRANSFER_FUNDS,
        amount="1200",
        currency="USD",
        context=smoke_context,
    ))