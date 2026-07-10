"""
agents/super_agents/finance_agent/tax_helper.py

William / Jarvis Multi-Agent AI SaaS System
Finance Agent Helper: TaxHelper

Purpose:
    Categorizes tax-related records and generates preparation summaries.

Important:
    This module DOES NOT provide legal/tax advice, file taxes, submit returns,
    contact tax authorities, move money, or make binding compliance decisions.
    It prepares structured tax-related organization data for review by the user,
    accountant, finance team, or approved downstream William/Jarvis agents.

Architecture Compatibility:
    - BaseAgent compatible with safe fallback if BaseAgent is not available.
    - Master Agent / Agent Router compatible through clear public methods.
    - Security Agent compatible through approval hooks.
    - Verification Agent compatible through structured verification payloads.
    - Memory Agent compatible through structured memory payloads.
    - Dashboard/API compatible through structured dict/JSON-style results.
    - SaaS-safe: every user-specific operation validates user_id/workspace_id.
"""

from __future__ import annotations

import copy
import dataclasses
import datetime as _dt
import hashlib
import json
import logging
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import safety
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent stub.

        This keeps the file import-safe even when the full William/Jarvis
        project scaffolding is not present yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, *args: Any, **kwargs: Any) -> None:
            return None


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_AGENT_NAME = "TaxHelper"
DEFAULT_AGENT_ID = "finance.tax_helper"
DEFAULT_MODULE = "Finance Agent"
DEFAULT_CURRENCY = "USD"

_RESULT_SUCCESS_KEYS = ("success", "message", "data", "error", "metadata")

SENSITIVE_FIELDS = {
    "ssn",
    "social_security_number",
    "ein",
    "tax_id",
    "tin",
    "iban",
    "bank_account",
    "routing_number",
    "card_number",
    "credit_card",
    "password",
    "secret",
    "api_key",
    "token",
}

DEFAULT_DEDUCTIBILITY_HINTS: Dict[str, str] = {
    "advertising_marketing": "commonly_business_related",
    "software_subscriptions": "commonly_business_related",
    "office_supplies": "commonly_business_related",
    "professional_services": "commonly_business_related",
    "contractor_payments": "commonly_business_related",
    "travel": "review_required",
    "meals": "partial_or_review_required",
    "vehicle": "review_required",
    "rent_office": "commonly_business_related",
    "utilities": "commonly_business_related",
    "internet_phone": "commonly_business_related",
    "training_education": "review_required",
    "bank_fees": "commonly_business_related",
    "taxes_licenses": "review_required",
    "insurance": "review_required",
    "payroll": "commonly_business_related",
    "uncategorized_tax_review": "review_required",
    "income_sales": "income",
    "income_services": "income",
    "refunds_rebates": "review_required",
    "owner_draw_distribution": "not_expense_review_required",
    "capital_asset_equipment": "capitalize_or_review_required",
}

DEFAULT_TAX_CATEGORIES: Dict[str, Dict[str, Any]] = {
    "income_sales": {
        "label": "Income - Product Sales",
        "type": "income",
        "keywords": [
            "sale", "sales", "shopify", "woocommerce", "stripe sale", "square sale",
            "paypal sale", "product revenue", "ecommerce", "store revenue",
        ],
    },
    "income_services": {
        "label": "Income - Services",
        "type": "income",
        "keywords": [
            "client payment", "service revenue", "consulting", "retainer", "project payment",
            "invoice paid", "web development", "seo payment", "marketing service",
            "design service", "agency service", "subscription revenue",
        ],
    },
    "refunds_rebates": {
        "label": "Refunds / Rebates / Adjustments",
        "type": "adjustment",
        "keywords": [
            "refund", "rebate", "cashback", "chargeback", "reversal", "adjustment",
            "returned", "credit memo",
        ],
    },
    "advertising_marketing": {
        "label": "Advertising & Marketing",
        "type": "expense",
        "keywords": [
            "google ads", "facebook ads", "meta ads", "tiktok ads", "linkedin ads",
            "bing ads", "microsoft ads", "advertising", "marketing", "promotion",
            "seo tool", "semrush", "ahrefs", "mailchimp", "klaviyo", "sendgrid",
            "campaign", "sponsored", "lead generation", "ad spend",
        ],
    },
    "software_subscriptions": {
        "label": "Software & SaaS Subscriptions",
        "type": "expense",
        "keywords": [
            "subscription", "software", "saas", "openai", "chatgpt", "github",
            "figma", "notion", "slack", "zoom", "canva", "adobe", "zapier",
            "hubspot", "crm", "hosting", "hostinger", "cloudflare", "aws",
            "azure", "google cloud", "digitalocean", "vercel", "netlify",
            "elementor", "wordpress plugin", "license renewal",
        ],
    },
    "office_supplies": {
        "label": "Office Supplies",
        "type": "expense",
        "keywords": [
            "office supplies", "stationery", "printer ink", "paper", "notebook",
            "keyboard", "mouse", "desk supplies", "pens", "toner",
        ],
    },
    "professional_services": {
        "label": "Professional Services",
        "type": "expense",
        "keywords": [
            "accountant", "bookkeeper", "lawyer", "legal", "consultant",
            "professional fee", "agency contractor", "audit service", "tax preparer",
            "advisor", "outsourcing",
        ],
    },
    "contractor_payments": {
        "label": "Contractor / Freelancer Payments",
        "type": "expense",
        "keywords": [
            "freelancer", "contractor", "upwork", "fiverr", "toptal",
            "developer payment", "designer payment", "copywriter", "virtual assistant",
            "va payment", "outsourced labor",
        ],
    },
    "travel": {
        "label": "Business Travel",
        "type": "expense",
        "keywords": [
            "flight", "airline", "hotel", "uber", "lyft", "taxi", "train",
            "airbnb", "booking.com", "expedia", "travel", "lodging", "motel",
            "business trip", "conference travel",
        ],
    },
    "meals": {
        "label": "Meals & Entertainment",
        "type": "expense",
        "keywords": [
            "restaurant", "cafe", "coffee", "meal", "lunch", "dinner",
            "doordash", "ubereats", "food", "client dinner", "business meal",
        ],
    },
    "vehicle": {
        "label": "Vehicle / Mileage / Fuel",
        "type": "expense",
        "keywords": [
            "fuel", "gas", "petrol", "diesel", "parking", "toll", "vehicle",
            "car maintenance", "mileage", "auto repair", "oil change",
        ],
    },
    "rent_office": {
        "label": "Office Rent / Workspace",
        "type": "expense",
        "keywords": [
            "office rent", "coworking", "workspace", "wework", "regus",
            "studio rent", "rent payment", "lease",
        ],
    },
    "utilities": {
        "label": "Utilities",
        "type": "expense",
        "keywords": [
            "electric", "electricity", "water bill", "gas bill", "utility",
            "heating", "cooling", "power bill",
        ],
    },
    "internet_phone": {
        "label": "Internet & Phone",
        "type": "expense",
        "keywords": [
            "internet", "broadband", "wifi", "phone bill", "mobile bill",
            "cellular", "telecom", "voip", "twilio", "ringcentral",
        ],
    },
    "training_education": {
        "label": "Training & Education",
        "type": "expense",
        "keywords": [
            "course", "training", "workshop", "webinar", "certification",
            "udemy", "coursera", "book", "ebook", "conference ticket",
        ],
    },
    "bank_fees": {
        "label": "Bank Fees & Payment Processing",
        "type": "expense",
        "keywords": [
            "bank fee", "monthly fee", "wire fee", "stripe fee", "paypal fee",
            "processing fee", "merchant fee", "transaction fee", "charge fee",
        ],
    },
    "taxes_licenses": {
        "label": "Taxes, Licenses & Government Fees",
        "type": "expense",
        "keywords": [
            "business license", "license fee", "state fee", "annual report",
            "franchise tax", "sales tax", "vat", "gst", "tax payment",
            "government fee", "registration fee",
        ],
    },
    "insurance": {
        "label": "Insurance",
        "type": "expense",
        "keywords": [
            "insurance", "liability policy", "business insurance",
            "professional liability", "errors omissions", "e&o",
        ],
    },
    "payroll": {
        "label": "Payroll & Employee Costs",
        "type": "expense",
        "keywords": [
            "payroll", "salary", "wages", "employee", "gusto", "adp",
            "paychex", "benefits", "health benefits", "employer tax",
        ],
    },
    "owner_draw_distribution": {
        "label": "Owner Draw / Distribution",
        "type": "equity",
        "keywords": [
            "owner draw", "distribution", "dividend", "member draw",
            "partner draw", "capital withdrawal",
        ],
    },
    "capital_asset_equipment": {
        "label": "Capital Asset / Equipment Review",
        "type": "asset",
        "keywords": [
            "laptop", "computer", "camera", "equipment", "server", "machinery",
            "furniture", "monitor", "phone purchase", "capital asset",
        ],
    },
    "uncategorized_tax_review": {
        "label": "Uncategorized - Tax Review Needed",
        "type": "review",
        "keywords": [],
    },
}


# ---------------------------------------------------------------------------
# Enums and data models
# ---------------------------------------------------------------------------

class TaxRecordType(str, Enum):
    INCOME = "income"
    EXPENSE = "expense"
    ASSET = "asset"
    LIABILITY = "liability"
    EQUITY = "equity"
    ADJUSTMENT = "adjustment"
    REVIEW = "review"


class TaxRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TaxAction(str, Enum):
    CATEGORIZE_RECORDS = "categorize_records"
    SUMMARIZE_PREPARATION = "summarize_preparation"
    BUILD_DEDUCTION_REVIEW = "build_deduction_review"
    BUILD_EXPORT_PACKAGE = "build_export_package"
    VALIDATE_TAX_RECORDS = "validate_tax_records"


@dataclass(frozen=True)
class TaxHelperConfig:
    """
    Configuration for TaxHelper.

    This class is intentionally lightweight so it can be replaced later by
    agents/super_agents/finance_agent/config.py without breaking this file.
    """

    default_currency: str = DEFAULT_CURRENCY
    confidence_threshold: Decimal = Decimal("0.55")
    high_confidence_threshold: Decimal = Decimal("0.80")
    max_description_length: int = 500
    max_records_per_call: int = 5000
    require_security_for_exports: bool = True
    require_security_for_sensitive_records: bool = True
    retain_raw_sensitive_values: bool = False
    tax_disclaimer: str = (
        "Prepared for organization and review only. This is not legal, tax, "
        "accounting, or financial advice. A qualified professional should review "
        "tax treatment before filing or making compliance decisions."
    )


@dataclass
class TaskContext:
    """
    SaaS execution context.

    Every user/workspace-specific method validates this to prevent data mixing.
    """

    user_id: str
    workspace_id: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    role: Optional[str] = None
    permissions: Sequence[str] = field(default_factory=list)
    source: str = "finance_agent"
    locale: Optional[str] = None
    currency: str = DEFAULT_CURRENCY
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TaxCategoryMatch:
    category_key: str
    label: str
    category_type: str
    confidence: Decimal
    matched_keywords: List[str] = field(default_factory=list)
    reason: str = ""
    deductibility_hint: str = "review_required"


@dataclass
class NormalizedTaxRecord:
    """
    Normalized internal representation of a tax-related record.
    """

    record_id: str
    date: Optional[str]
    description: str
    amount: Decimal
    currency: str
    merchant: Optional[str]
    source: Optional[str]
    record_type: str
    original_category: Optional[str]
    metadata: Dict[str, Any]
    raw: Dict[str, Any]


@dataclass
class CategorizedTaxRecord:
    """
    Final categorized record returned to API/dashboard callers.
    """

    record_id: str
    date: Optional[str]
    description: str
    amount: str
    currency: str
    merchant: Optional[str]
    source: Optional[str]
    record_type: str
    tax_category: str
    tax_category_label: str
    confidence: str
    matched_keywords: List[str]
    deductibility_hint: str
    review_required: bool
    risk_level: str
    notes: List[str]
    metadata: Dict[str, Any]


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).isoformat()


def _safe_string(value: Any, max_length: int = 1000) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if len(text) > max_length:
        return text[: max_length - 3] + "..."
    return text


def _normalize_space(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def _to_decimal(value: Any, default: Decimal = Decimal("0")) -> Decimal:
    if isinstance(value, Decimal):
        return value
    if value is None:
        return default
    try:
        cleaned = str(value).strip().replace(",", "")
        if cleaned == "":
            return default
        return Decimal(cleaned)
    except (InvalidOperation, ValueError, TypeError):
        return default


def _decimal_to_str(value: Decimal) -> str:
    return str(value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def _safe_lower(value: Any) -> str:
    return _safe_string(value).lower()


def _hash_record_payload(payload: Mapping[str, Any]) -> str:
    safe_payload = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(safe_payload.encode("utf-8")).hexdigest()


def _generate_record_id(record: Mapping[str, Any], index: int) -> str:
    existing = (
        record.get("record_id")
        or record.get("id")
        or record.get("transaction_id")
        or record.get("receipt_id")
        or record.get("invoice_id")
    )
    if existing:
        return _safe_string(existing, 128)
    digest = _hash_record_payload({"index": index, "record": record})[:16]
    return f"taxrec_{digest}"


def _redact_sensitive_mapping(data: Any, retain_raw_sensitive_values: bool = False) -> Any:
    """
    Recursively redact known sensitive keys.

    The redaction helps ensure audit logs, dashboard events, memory payloads,
    and verification payloads do not leak tax IDs, tokens, bank details, etc.
    """

    if retain_raw_sensitive_values:
        return copy.deepcopy(data)

    if isinstance(data, Mapping):
        redacted: Dict[str, Any] = {}
        for key, value in data.items():
            key_text = str(key).lower()
            if any(sensitive in key_text for sensitive in SENSITIVE_FIELDS):
                redacted[str(key)] = "[REDACTED]"
            else:
                redacted[str(key)] = _redact_sensitive_mapping(value, retain_raw_sensitive_values=False)
        return redacted

    if isinstance(data, list):
        return [_redact_sensitive_mapping(item, retain_raw_sensitive_values=False) for item in data]

    if isinstance(data, tuple):
        return tuple(_redact_sensitive_mapping(item, retain_raw_sensitive_values=False) for item in data)

    return copy.deepcopy(data)


def _contains_sensitive_fields(data: Any) -> bool:
    if isinstance(data, Mapping):
        for key, value in data.items():
            key_text = str(key).lower()
            if any(sensitive in key_text for sensitive in SENSITIVE_FIELDS):
                return True
            if _contains_sensitive_fields(value):
                return True
    elif isinstance(data, list):
        return any(_contains_sensitive_fields(item) for item in data)
    elif isinstance(data, tuple):
        return any(_contains_sensitive_fields(item) for item in data)
    return False


# ---------------------------------------------------------------------------
# TaxHelper
# ---------------------------------------------------------------------------

class TaxHelper(BaseAgent):
    """
    Finance Agent helper for tax record categorization and preparation summaries.

    Public methods:
        - categorize_records()
        - summarize_tax_preparation()
        - build_deduction_review()
        - validate_tax_records()
        - build_export_package()
        - get_supported_tax_categories()
        - health_check()

    Master Agent:
        Can route tax organization tasks here when the task is preparation,
        categorization, summarization, or dashboard reporting.

    Security Agent:
        Sensitive exports or records containing sensitive fields are routed
        through _request_security_approval() before continuing.

    Memory Agent:
        This helper prepares safe memory payloads describing preferences,
        category decisions, and summary metadata. It does not write memory directly.

    Verification Agent:
        Every successful action includes a verification payload that can be
        handed to the Verification Agent for auditability.

    Dashboard/API:
        All methods return structured dicts with:
        success, message, data, error, metadata.
    """

    def __init__(
        self,
        config: Optional[Union[TaxHelperConfig, Mapping[str, Any]]] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        categories: Optional[Mapping[str, Mapping[str, Any]]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        kwargs.setdefault("agent_name", DEFAULT_AGENT_NAME)
        kwargs.setdefault("agent_id", DEFAULT_AGENT_ID)
        super().__init__(*args, **kwargs)

        self.logger = getattr(self, "logger", LOGGER)
        self.config = self._coerce_config(config)
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger

        self.categories: Dict[str, Dict[str, Any]] = self._normalize_categories(
            categories or DEFAULT_TAX_CATEGORIES
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def categorize_records(
        self,
        records: Sequence[Mapping[str, Any]],
        user_id: str,
        workspace_id: str,
        tax_year: Optional[Union[int, str]] = None,
        jurisdiction: Optional[str] = None,
        currency: Optional[str] = None,
        category_overrides: Optional[Mapping[str, str]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Categorize tax-related records.

        Args:
            records:
                Sequence of transaction/receipt/invoice-like dictionaries.
            user_id:
                SaaS user ID. Required.
            workspace_id:
                SaaS workspace ID. Required.
            tax_year:
                Optional year used for filtering/reporting metadata.
            jurisdiction:
                Optional jurisdiction label, such as "US", "UK", "PK", etc.
                This helper does not apply jurisdiction-specific tax law.
            currency:
                Default currency for records that do not include one.
            category_overrides:
                Optional mapping of record_id -> category_key.
            context:
                Optional metadata for dashboard/API/Master Agent.

        Returns:
            Structured result dict.
        """

        task_context = self._build_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            currency=currency or self.config.default_currency,
            metadata={
                "tax_year": tax_year,
                "jurisdiction": jurisdiction,
                "operation": TaxAction.CATEGORIZE_RECORDS.value,
                **dict(context or {}),
            },
        )

        validation = self._validate_task_context(task_context)
        if not validation["success"]:
            return validation

        if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
            return self._error_result(
                message="Records must be a sequence of dictionaries.",
                code="INVALID_RECORDS_INPUT",
                metadata=self._base_metadata(task_context, TaxAction.CATEGORIZE_RECORDS.value),
            )

        if len(records) > self.config.max_records_per_call:
            return self._error_result(
                message=f"Too many records. Max allowed: {self.config.max_records_per_call}.",
                code="RECORD_LIMIT_EXCEEDED",
                metadata=self._base_metadata(task_context, TaxAction.CATEGORIZE_RECORDS.value),
            )

        action_payload = {
            "record_count": len(records),
            "tax_year": tax_year,
            "jurisdiction": jurisdiction,
            "contains_sensitive_fields": _contains_sensitive_fields(records),
        }

        if self._requires_security_check(TaxAction.CATEGORIZE_RECORDS.value, action_payload):
            approval = self._request_security_approval(
                task_context=task_context,
                action=TaxAction.CATEGORIZE_RECORDS.value,
                payload=action_payload,
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval is required before categorizing sensitive tax records.",
                    code="SECURITY_APPROVAL_REQUIRED",
                    data={"security": approval},
                    metadata=self._base_metadata(task_context, TaxAction.CATEGORIZE_RECORDS.value),
                )

        try:
            normalized_records: List[NormalizedTaxRecord] = []
            record_errors: List[Dict[str, Any]] = []

            for index, record in enumerate(records):
                try:
                    normalized_records.append(
                        self._normalize_record(
                            record=record,
                            index=index,
                            default_currency=currency or self.config.default_currency,
                        )
                    )
                except Exception as exc:
                    record_errors.append(
                        {
                            "index": index,
                            "record_id": _generate_record_id(record, index) if isinstance(record, Mapping) else None,
                            "error": str(exc),
                        }
                    )

            categorized: List[CategorizedTaxRecord] = []
            overrides = dict(category_overrides or {})

            for normalized in normalized_records:
                if normalized.record_id in overrides:
                    match = self._category_from_override(overrides[normalized.record_id])
                else:
                    match = self._match_tax_category(normalized)

                review_required, risk_level, notes = self._review_flags(normalized, match)

                categorized.append(
                    CategorizedTaxRecord(
                        record_id=normalized.record_id,
                        date=normalized.date,
                        description=normalized.description,
                        amount=_decimal_to_str(normalized.amount),
                        currency=normalized.currency,
                        merchant=normalized.merchant,
                        source=normalized.source,
                        record_type=match.category_type,
                        tax_category=match.category_key,
                        tax_category_label=match.label,
                        confidence=_decimal_to_str(match.confidence),
                        matched_keywords=match.matched_keywords,
                        deductibility_hint=match.deductibility_hint,
                        review_required=review_required,
                        risk_level=risk_level.value,
                        notes=notes,
                        metadata=_redact_sensitive_mapping(normalized.metadata, self.config.retain_raw_sensitive_values),
                    )
                )

            summary = self._build_category_summary(categorized)
            preparation_summary = self._build_preparation_summary_from_categorized(
                categorized=categorized,
                tax_year=tax_year,
                jurisdiction=jurisdiction,
                currency=currency or self.config.default_currency,
            )

            data = {
                "records": [dataclasses.asdict(item) for item in categorized],
                "summary": summary,
                "preparation_summary": preparation_summary,
                "record_errors": record_errors,
                "disclaimer": self.config.tax_disclaimer,
            }

            verification_payload = self._prepare_verification_payload(
                task_context=task_context,
                action=TaxAction.CATEGORIZE_RECORDS.value,
                data=data,
            )
            memory_payload = self._prepare_memory_payload(
                task_context=task_context,
                action=TaxAction.CATEGORIZE_RECORDS.value,
                data={
                    "tax_year": tax_year,
                    "jurisdiction": jurisdiction,
                    "summary": summary,
                    "category_overrides_used": bool(category_overrides),
                },
            )

            metadata = self._base_metadata(task_context, TaxAction.CATEGORIZE_RECORDS.value)
            metadata.update(
                {
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                    "records_received": len(records),
                    "records_categorized": len(categorized),
                    "records_failed": len(record_errors),
                }
            )

            self._emit_agent_event(
                task_context=task_context,
                event_type="finance.tax.records_categorized",
                payload={
                    "records_categorized": len(categorized),
                    "records_failed": len(record_errors),
                    "tax_year": tax_year,
                    "jurisdiction": jurisdiction,
                },
            )
            self._log_audit_event(
                task_context=task_context,
                action=TaxAction.CATEGORIZE_RECORDS.value,
                status="success",
                payload={
                    "records_received": len(records),
                    "records_categorized": len(categorized),
                    "records_failed": len(record_errors),
                },
            )

            return self._safe_result(
                success=True,
                message="Tax records categorized for review.",
                data=data,
                metadata=metadata,
            )

        except Exception as exc:
            self.logger.exception("Failed to categorize tax records.")
            self._log_audit_event(
                task_context=task_context,
                action=TaxAction.CATEGORIZE_RECORDS.value,
                status="error",
                payload={"error": str(exc)},
            )
            return self._error_result(
                message="Failed to categorize tax records.",
                code="TAX_CATEGORIZATION_FAILED",
                exception=exc,
                metadata=self._base_metadata(task_context, TaxAction.CATEGORIZE_RECORDS.value),
            )

    def summarize_tax_preparation(
        self,
        categorized_records: Sequence[Mapping[str, Any]],
        user_id: str,
        workspace_id: str,
        tax_year: Optional[Union[int, str]] = None,
        jurisdiction: Optional[str] = None,
        currency: Optional[str] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build a tax preparation summary from already categorized records.

        This is useful for dashboards, accountant handoff, monthly/quarterly
        review, or Finance Agent reporting.
        """

        task_context = self._build_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            currency=currency or self.config.default_currency,
            metadata={
                "tax_year": tax_year,
                "jurisdiction": jurisdiction,
                "operation": TaxAction.SUMMARIZE_PREPARATION.value,
                **dict(context or {}),
            },
        )

        validation = self._validate_task_context(task_context)
        if not validation["success"]:
            return validation

        try:
            normalized_categorized = self._coerce_categorized_records(categorized_records)
            preparation_summary = self._build_preparation_summary_from_categorized(
                categorized=normalized_categorized,
                tax_year=tax_year,
                jurisdiction=jurisdiction,
                currency=currency or self.config.default_currency,
            )

            data = {
                "preparation_summary": preparation_summary,
                "disclaimer": self.config.tax_disclaimer,
            }

            metadata = self._base_metadata(task_context, TaxAction.SUMMARIZE_PREPARATION.value)
            metadata["verification_payload"] = self._prepare_verification_payload(
                task_context=task_context,
                action=TaxAction.SUMMARIZE_PREPARATION.value,
                data=data,
            )
            metadata["memory_payload"] = self._prepare_memory_payload(
                task_context=task_context,
                action=TaxAction.SUMMARIZE_PREPARATION.value,
                data={
                    "tax_year": tax_year,
                    "jurisdiction": jurisdiction,
                    "record_count": len(normalized_categorized),
                    "totals": preparation_summary.get("totals", {}),
                },
            )

            self._emit_agent_event(
                task_context=task_context,
                event_type="finance.tax.preparation_summary_created",
                payload={
                    "record_count": len(normalized_categorized),
                    "tax_year": tax_year,
                    "jurisdiction": jurisdiction,
                },
            )
            self._log_audit_event(
                task_context=task_context,
                action=TaxAction.SUMMARIZE_PREPARATION.value,
                status="success",
                payload={"record_count": len(normalized_categorized)},
            )

            return self._safe_result(
                success=True,
                message="Tax preparation summary created.",
                data=data,
                metadata=metadata,
            )

        except Exception as exc:
            self.logger.exception("Failed to summarize tax preparation.")
            self._log_audit_event(
                task_context=task_context,
                action=TaxAction.SUMMARIZE_PREPARATION.value,
                status="error",
                payload={"error": str(exc)},
            )
            return self._error_result(
                message="Failed to summarize tax preparation.",
                code="TAX_SUMMARY_FAILED",
                exception=exc,
                metadata=self._base_metadata(task_context, TaxAction.SUMMARIZE_PREPARATION.value),
            )

    def build_deduction_review(
        self,
        categorized_records: Sequence[Mapping[str, Any]],
        user_id: str,
        workspace_id: str,
        tax_year: Optional[Union[int, str]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build a review queue for possible deductions.

        This method flags low-confidence, partial/review-required, high-risk,
        capital asset, meals, travel, vehicle, tax/government, and uncategorized
        items for accountant/user review.
        """

        task_context = self._build_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            metadata={
                "tax_year": tax_year,
                "operation": TaxAction.BUILD_DEDUCTION_REVIEW.value,
                **dict(context or {}),
            },
        )

        validation = self._validate_task_context(task_context)
        if not validation["success"]:
            return validation

        try:
            records = self._coerce_categorized_records(categorized_records)
            review_items: List[Dict[str, Any]] = []

            for record in records:
                review_reason = self._deduction_review_reason(record)
                if review_reason:
                    review_items.append(
                        {
                            "record_id": record.record_id,
                            "date": record.date,
                            "description": record.description,
                            "amount": record.amount,
                            "currency": record.currency,
                            "merchant": record.merchant,
                            "tax_category": record.tax_category,
                            "tax_category_label": record.tax_category_label,
                            "deductibility_hint": record.deductibility_hint,
                            "risk_level": record.risk_level,
                            "confidence": record.confidence,
                            "review_reason": review_reason,
                            "suggested_next_step": self._suggest_review_next_step(record),
                            "notes": record.notes,
                        }
                    )

            totals_by_reason: Dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
            count_by_reason: Dict[str, int] = defaultdict(int)
            for item in review_items:
                reason = item["review_reason"]
                totals_by_reason[reason] += _to_decimal(item["amount"])
                count_by_reason[reason] += 1

            data = {
                "review_items": review_items,
                "summary": {
                    "review_item_count": len(review_items),
                    "total_review_amount": _decimal_to_str(
                        sum((_to_decimal(item["amount"]) for item in review_items), Decimal("0"))
                    ),
                    "count_by_reason": dict(count_by_reason),
                    "totals_by_reason": {
                        reason: _decimal_to_str(total)
                        for reason, total in totals_by_reason.items()
                    },
                },
                "disclaimer": self.config.tax_disclaimer,
            }

            metadata = self._base_metadata(task_context, TaxAction.BUILD_DEDUCTION_REVIEW.value)
            metadata["verification_payload"] = self._prepare_verification_payload(
                task_context=task_context,
                action=TaxAction.BUILD_DEDUCTION_REVIEW.value,
                data=data,
            )

            self._emit_agent_event(
                task_context=task_context,
                event_type="finance.tax.deduction_review_created",
                payload={
                    "review_item_count": len(review_items),
                    "tax_year": tax_year,
                },
            )
            self._log_audit_event(
                task_context=task_context,
                action=TaxAction.BUILD_DEDUCTION_REVIEW.value,
                status="success",
                payload={"review_item_count": len(review_items)},
            )

            return self._safe_result(
                success=True,
                message="Deduction review queue created.",
                data=data,
                metadata=metadata,
            )

        except Exception as exc:
            self.logger.exception("Failed to build deduction review.")
            self._log_audit_event(
                task_context=task_context,
                action=TaxAction.BUILD_DEDUCTION_REVIEW.value,
                status="error",
                payload={"error": str(exc)},
            )
            return self._error_result(
                message="Failed to build deduction review.",
                code="DEDUCTION_REVIEW_FAILED",
                exception=exc,
                metadata=self._base_metadata(task_context, TaxAction.BUILD_DEDUCTION_REVIEW.value),
            )

    def validate_tax_records(
        self,
        records: Sequence[Mapping[str, Any]],
        user_id: str,
        workspace_id: str,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate raw records before categorization or export.

        Checks:
            - required SaaS context
            - record input shape
            - amount parseability
            - date parseability when present
            - missing description
            - sensitive field presence
        """

        task_context = self._build_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            metadata={
                "operation": TaxAction.VALIDATE_TAX_RECORDS.value,
                **dict(context or {}),
            },
        )

        validation = self._validate_task_context(task_context)
        if not validation["success"]:
            return validation

        if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
            return self._error_result(
                message="Records must be a sequence of dictionaries.",
                code="INVALID_RECORDS_INPUT",
                metadata=self._base_metadata(task_context, TaxAction.VALIDATE_TAX_RECORDS.value),
            )

        issues: List[Dict[str, Any]] = []
        sensitive_count = 0

        for index, record in enumerate(records):
            if not isinstance(record, Mapping):
                issues.append(
                    {
                        "index": index,
                        "severity": "high",
                        "code": "INVALID_RECORD_TYPE",
                        "message": "Record must be a dictionary-like mapping.",
                    }
                )
                continue

            record_id = _generate_record_id(record, index)

            if _contains_sensitive_fields(record):
                sensitive_count += 1
                issues.append(
                    {
                        "index": index,
                        "record_id": record_id,
                        "severity": "medium",
                        "code": "SENSITIVE_FIELDS_PRESENT",
                        "message": "Record contains sensitive fields that should be redacted before memory/audit/export.",
                    }
                )

            description = (
                record.get("description")
                or record.get("memo")
                or record.get("merchant")
                or record.get("vendor")
                or record.get("name")
            )
            if not _safe_string(description):
                issues.append(
                    {
                        "index": index,
                        "record_id": record_id,
                        "severity": "medium",
                        "code": "MISSING_DESCRIPTION",
                        "message": "Record has no usable description, merchant, vendor, memo, or name.",
                    }
                )

            amount_value = (
                record.get("amount")
                if "amount" in record
                else record.get("total", record.get("value", record.get("net_amount")))
            )
            if amount_value is None or _safe_string(amount_value) == "":
                issues.append(
                    {
                        "index": index,
                        "record_id": record_id,
                        "severity": "high",
                        "code": "MISSING_AMOUNT",
                        "message": "Record has no amount.",
                    }
                )
            else:
                amount = _to_decimal(amount_value, default=Decimal("__NaN__")) if False else None
                try:
                    Decimal(str(amount_value).replace(",", "").strip())
                except Exception:
                    issues.append(
                        {
                            "index": index,
                            "record_id": record_id,
                            "severity": "high",
                            "code": "INVALID_AMOUNT",
                            "message": "Record amount could not be parsed as a decimal number.",
                        }
                    )

            date_value = record.get("date") or record.get("transaction_date") or record.get("created_at")
            if date_value and not self._parse_date(date_value):
                issues.append(
                    {
                        "index": index,
                        "record_id": record_id,
                        "severity": "low",
                        "code": "UNPARSEABLE_DATE",
                        "message": "Record date could not be parsed safely.",
                    }
                )

        high = sum(1 for issue in issues if issue["severity"] == "high")
        medium = sum(1 for issue in issues if issue["severity"] == "medium")
        low = sum(1 for issue in issues if issue["severity"] == "low")

        data = {
            "valid": high == 0,
            "record_count": len(records),
            "issue_count": len(issues),
            "issues": issues,
            "summary": {
                "high": high,
                "medium": medium,
                "low": low,
                "sensitive_record_count": sensitive_count,
            },
        }

        metadata = self._base_metadata(task_context, TaxAction.VALIDATE_TAX_RECORDS.value)
        metadata["verification_payload"] = self._prepare_verification_payload(
            task_context=task_context,
            action=TaxAction.VALIDATE_TAX_RECORDS.value,
            data=data,
        )

        self._log_audit_event(
            task_context=task_context,
            action=TaxAction.VALIDATE_TAX_RECORDS.value,
            status="success",
            payload={
                "record_count": len(records),
                "issue_count": len(issues),
                "high_issues": high,
            },
        )

        return self._safe_result(
            success=True,
            message="Tax records validated.",
            data=data,
            metadata=metadata,
        )

    def build_export_package(
        self,
        categorized_records: Sequence[Mapping[str, Any]],
        user_id: str,
        workspace_id: str,
        tax_year: Optional[Union[int, str]] = None,
        jurisdiction: Optional[str] = None,
        include_review_items: bool = True,
        include_raw_records: bool = False,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build a structured export package for accountant handoff or dashboard download.

        This method returns in-memory JSON-style data only. It does not write files,
        email anyone, upload anything, submit tax filings, or perform destructive actions.
        """

        task_context = self._build_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            metadata={
                "tax_year": tax_year,
                "jurisdiction": jurisdiction,
                "operation": TaxAction.BUILD_EXPORT_PACKAGE.value,
                **dict(context or {}),
            },
        )

        validation = self._validate_task_context(task_context)
        if not validation["success"]:
            return validation

        action_payload = {
            "record_count": len(categorized_records),
            "include_raw_records": include_raw_records,
            "contains_sensitive_fields": _contains_sensitive_fields(categorized_records),
        }

        if self._requires_security_check(TaxAction.BUILD_EXPORT_PACKAGE.value, action_payload):
            approval = self._request_security_approval(
                task_context=task_context,
                action=TaxAction.BUILD_EXPORT_PACKAGE.value,
                payload=action_payload,
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval is required before building this tax export package.",
                    code="SECURITY_APPROVAL_REQUIRED",
                    data={"security": approval},
                    metadata=self._base_metadata(task_context, TaxAction.BUILD_EXPORT_PACKAGE.value),
                )

        try:
            records = self._coerce_categorized_records(categorized_records)
            preparation_summary = self._build_preparation_summary_from_categorized(
                categorized=records,
                tax_year=tax_year,
                jurisdiction=jurisdiction,
                currency=task_context.currency,
            )

            review_items: List[Dict[str, Any]] = []
            if include_review_items:
                for record in records:
                    reason = self._deduction_review_reason(record)
                    if reason:
                        review_items.append(
                            {
                                "record_id": record.record_id,
                                "date": record.date,
                                "description": record.description,
                                "amount": record.amount,
                                "currency": record.currency,
                                "tax_category": record.tax_category,
                                "tax_category_label": record.tax_category_label,
                                "review_reason": reason,
                                "suggested_next_step": self._suggest_review_next_step(record),
                            }
                        )

            export_records = [
                self._export_record_view(record, include_raw=include_raw_records)
                for record in records
            ]

            package_id = f"tax_export_{uuid.uuid4().hex[:16]}"
            generated_at = _utc_now_iso()

            package = {
                "package_id": package_id,
                "generated_at": generated_at,
                "module": DEFAULT_MODULE,
                "agent": DEFAULT_AGENT_NAME,
                "user_id": task_context.user_id,
                "workspace_id": task_context.workspace_id,
                "tax_year": tax_year,
                "jurisdiction": jurisdiction,
                "summary": preparation_summary,
                "records": export_records,
                "review_items": review_items,
                "disclaimer": self.config.tax_disclaimer,
                "export_notes": [
                    "This package is prepared for review only.",
                    "No tax return has been filed or submitted by this helper.",
                    "Sensitive fields are redacted unless explicitly allowed by configuration and approved by Security Agent.",
                ],
            }

            package_hash = _hash_record_payload(
                {
                    "package_id": package_id,
                    "generated_at": generated_at,
                    "record_count": len(export_records),
                    "summary": preparation_summary,
                }
            )

            data = {
                "export_package": package,
                "package_hash": package_hash,
            }

            metadata = self._base_metadata(task_context, TaxAction.BUILD_EXPORT_PACKAGE.value)
            metadata["verification_payload"] = self._prepare_verification_payload(
                task_context=task_context,
                action=TaxAction.BUILD_EXPORT_PACKAGE.value,
                data={
                    "package_id": package_id,
                    "package_hash": package_hash,
                    "record_count": len(export_records),
                    "review_item_count": len(review_items),
                },
            )

            self._emit_agent_event(
                task_context=task_context,
                event_type="finance.tax.export_package_created",
                payload={
                    "package_id": package_id,
                    "record_count": len(export_records),
                    "review_item_count": len(review_items),
                },
            )
            self._log_audit_event(
                task_context=task_context,
                action=TaxAction.BUILD_EXPORT_PACKAGE.value,
                status="success",
                payload={
                    "package_id": package_id,
                    "record_count": len(export_records),
                    "review_item_count": len(review_items),
                    "include_raw_records": include_raw_records,
                },
            )

            return self._safe_result(
                success=True,
                message="Tax preparation export package created.",
                data=data,
                metadata=metadata,
            )

        except Exception as exc:
            self.logger.exception("Failed to build tax export package.")
            self._log_audit_event(
                task_context=task_context,
                action=TaxAction.BUILD_EXPORT_PACKAGE.value,
                status="error",
                payload={"error": str(exc)},
            )
            return self._error_result(
                message="Failed to build tax export package.",
                code="TAX_EXPORT_PACKAGE_FAILED",
                exception=exc,
                metadata=self._base_metadata(task_context, TaxAction.BUILD_EXPORT_PACKAGE.value),
            )

    def get_supported_tax_categories(
        self,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Return supported tax categorization labels and hints.

        user_id/workspace_id are optional here because this is static reference
        metadata, but if one is supplied then both must be supplied to avoid
        ambiguous SaaS context.
        """

        if (user_id and not workspace_id) or (workspace_id and not user_id):
            return self._error_result(
                message="Both user_id and workspace_id are required when requesting categories in a SaaS context.",
                code="INVALID_CONTEXT",
            )

        categories = []
        for key, value in sorted(self.categories.items()):
            categories.append(
                {
                    "category_key": key,
                    "label": value.get("label", key),
                    "type": value.get("type", TaxRecordType.REVIEW.value),
                    "deductibility_hint": DEFAULT_DEDUCTIBILITY_HINTS.get(key, "review_required"),
                    "keyword_count": len(value.get("keywords", [])),
                }
            )

        return self._safe_result(
            success=True,
            message="Supported tax categories returned.",
            data={
                "categories": categories,
                "category_count": len(categories),
                "disclaimer": self.config.tax_disclaimer,
            },
            metadata={
                "agent": DEFAULT_AGENT_NAME,
                "agent_id": DEFAULT_AGENT_ID,
                "module": DEFAULT_MODULE,
                "generated_at": _utc_now_iso(),
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Lightweight health check for Agent Registry, Loader, Router, and API.
        """

        return self._safe_result(
            success=True,
            message="TaxHelper is importable and ready.",
            data={
                "agent": DEFAULT_AGENT_NAME,
                "agent_id": DEFAULT_AGENT_ID,
                "module": DEFAULT_MODULE,
                "category_count": len(self.categories),
                "supports_security_client": self.security_client is not None,
                "supports_memory_client": self.memory_client is not None,
                "supports_verification_client": self.verification_client is not None,
            },
            metadata={
                "generated_at": _utc_now_iso(),
                "version": "1.0.0",
            },
        )

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: TaskContext) -> Dict[str, Any]:
        """
        Validate SaaS context to prevent user/workspace data mixing.
        """

        if not isinstance(context, TaskContext):
            return self._error_result(
                message="Invalid task context object.",
                code="INVALID_TASK_CONTEXT",
            )

        if not _safe_string(context.user_id):
            return self._error_result(
                message="user_id is required for tax helper operations.",
                code="MISSING_USER_ID",
            )

        if not _safe_string(context.workspace_id):
            return self._error_result(
                message="workspace_id is required for tax helper operations.",
                code="MISSING_WORKSPACE_ID",
            )

        if not _safe_string(context.request_id):
            return self._error_result(
                message="request_id is required for traceability.",
                code="MISSING_REQUEST_ID",
            )

        return self._safe_result(
            success=True,
            message="Task context validated.",
            data={
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "request_id": context.request_id,
            },
            metadata={
                "validated_at": _utc_now_iso(),
                "agent": DEFAULT_AGENT_NAME,
            },
        )

    def _requires_security_check(self, action: str, payload: Optional[Mapping[str, Any]] = None) -> bool:
        """
        Decide whether a Security Agent check is required.

        Tax-related data may contain sensitive IDs or financial details.
        Export package creation and sensitive raw records are protected.
        """

        payload = payload or {}

        if action == TaxAction.BUILD_EXPORT_PACKAGE.value and self.config.require_security_for_exports:
            return True

        if self.config.require_security_for_sensitive_records and payload.get("contains_sensitive_fields"):
            return True

        if payload.get("include_raw_records"):
            return True

        return False

    def _request_security_approval(
        self,
        task_context: TaskContext,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval if available.

        Safe fallback:
            If no security_client is connected, this method denies actions that
            require approval. This prevents accidental sensitive export in early
            development environments.
        """

        safe_payload = _redact_sensitive_mapping(payload or {}, self.config.retain_raw_sensitive_values)

        if self.security_client is None:
            return {
                "approved": False,
                "reason": "No Security Agent client configured.",
                "action": action,
                "required": True,
            }

        try:
            if hasattr(self.security_client, "approve_action"):
                response = self.security_client.approve_action(
                    user_id=task_context.user_id,
                    workspace_id=task_context.workspace_id,
                    action=action,
                    payload=safe_payload,
                    agent=DEFAULT_AGENT_NAME,
                )
            elif hasattr(self.security_client, "request_approval"):
                response = self.security_client.request_approval(
                    {
                        "user_id": task_context.user_id,
                        "workspace_id": task_context.workspace_id,
                        "request_id": task_context.request_id,
                        "action": action,
                        "payload": safe_payload,
                        "agent": DEFAULT_AGENT_NAME,
                    }
                )
            else:
                return {
                    "approved": False,
                    "reason": "Security client does not expose an approval method.",
                    "action": action,
                    "required": True,
                }

            if isinstance(response, Mapping):
                approved = bool(response.get("approved", response.get("success", False)))
                return {
                    "approved": approved,
                    "reason": response.get("reason") or response.get("message"),
                    "raw": _redact_sensitive_mapping(response, self.config.retain_raw_sensitive_values),
                    "action": action,
                    "required": True,
                }

            return {
                "approved": bool(response),
                "reason": "Security client returned boolean-like response.",
                "action": action,
                "required": True,
            }

        except Exception as exc:
            self.logger.exception("Security approval request failed.")
            return {
                "approved": False,
                "reason": f"Security approval request failed: {exc}",
                "action": action,
                "required": True,
            }

    def _prepare_verification_payload(
        self,
        task_context: TaskContext,
        action: str,
        data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        The helper returns this payload instead of forcing an external call,
        keeping this file import-safe and testable.
        """

        safe_data = _redact_sensitive_mapping(data or {}, self.config.retain_raw_sensitive_values)
        return {
            "verification_type": "finance_tax_helper_action",
            "agent": DEFAULT_AGENT_NAME,
            "agent_id": DEFAULT_AGENT_ID,
            "module": DEFAULT_MODULE,
            "action": action,
            "user_id": task_context.user_id,
            "workspace_id": task_context.workspace_id,
            "request_id": task_context.request_id,
            "created_at": _utc_now_iso(),
            "data_hash": _hash_record_payload(safe_data),
            "summary": self._verification_summary(action, safe_data),
            "disclaimer": self.config.tax_disclaimer,
        }

    def _prepare_memory_payload(
        self,
        task_context: TaskContext,
        action: str,
        data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        This should be stored only if Memory Agent policy allows it. Raw records,
        sensitive fields, tax IDs, banking details, and full transaction lists
        should not be stored by default.
        """

        safe_data = _redact_sensitive_mapping(data or {}, retain_raw_sensitive_values=False)

        return {
            "memory_type": "finance_tax_preparation_context",
            "agent": DEFAULT_AGENT_NAME,
            "agent_id": DEFAULT_AGENT_ID,
            "module": DEFAULT_MODULE,
            "action": action,
            "user_id": task_context.user_id,
            "workspace_id": task_context.workspace_id,
            "request_id": task_context.request_id,
            "created_at": _utc_now_iso(),
            "safe_to_store": True,
            "retention_hint": "workspace_finance_tax_summary",
            "data": safe_data,
        }

    def _emit_agent_event(
        self,
        task_context: TaskContext,
        event_type: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit dashboard/API/registry event if an emitter is configured.
        """

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": DEFAULT_AGENT_NAME,
            "agent_id": DEFAULT_AGENT_ID,
            "module": DEFAULT_MODULE,
            "user_id": task_context.user_id,
            "workspace_id": task_context.workspace_id,
            "request_id": task_context.request_id,
            "created_at": _utc_now_iso(),
            "payload": _redact_sensitive_mapping(payload or {}, self.config.retain_raw_sensitive_values),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event)
            elif hasattr(self, "emit_event"):
                try:
                    self.emit_event(event)  # type: ignore[misc]
                except TypeError:
                    self.emit_event(event_type, event)  # type: ignore[misc]
        except Exception:
            self.logger.exception("Failed to emit TaxHelper event.")

    def _log_audit_event(
        self,
        task_context: TaskContext,
        action: str,
        status: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Log audit-safe event.

        This method does not raise; audit failure should not crash the user flow.
        """

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "agent": DEFAULT_AGENT_NAME,
            "agent_id": DEFAULT_AGENT_ID,
            "module": DEFAULT_MODULE,
            "action": action,
            "status": status,
            "user_id": task_context.user_id,
            "workspace_id": task_context.workspace_id,
            "request_id": task_context.request_id,
            "created_at": _utc_now_iso(),
            "payload": _redact_sensitive_mapping(payload or {}, self.config.retain_raw_sensitive_values),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit_event)
            else:
                self.logger.info("TaxHelper audit event: %s", json.dumps(audit_event, default=str))
        except Exception:
            self.logger.exception("Failed to write TaxHelper audit event.")

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis result shape.
        """

        return {
            "success": bool(success),
            "message": _safe_string(message, 1000),
            "data": dict(data or {}),
            "error": dict(error or {}) if error else None,
            "metadata": dict(metadata or {}),
        }

    def _error_result(
        self,
        message: str,
        code: str = "ERROR",
        exception: Optional[BaseException] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error response.
        """

        error = {
            "code": code,
            "message": _safe_string(message, 1000),
        }
        if exception is not None:
            error["exception_type"] = exception.__class__.__name__
            error["exception_message"] = _safe_string(str(exception), 1000)

        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=error,
            metadata=metadata or {},
        )

    # ------------------------------------------------------------------
    # Internal normalization and categorization
    # ------------------------------------------------------------------

    def _coerce_config(
        self,
        config: Optional[Union[TaxHelperConfig, Mapping[str, Any]]],
    ) -> TaxHelperConfig:
        if config is None:
            return TaxHelperConfig()

        if isinstance(config, TaxHelperConfig):
            return config

        if isinstance(config, Mapping):
            allowed = {field.name for field in dataclasses.fields(TaxHelperConfig)}
            filtered = {key: value for key, value in config.items() if key in allowed}

            if "confidence_threshold" in filtered:
                filtered["confidence_threshold"] = _to_decimal(filtered["confidence_threshold"], Decimal("0.55"))

            if "high_confidence_threshold" in filtered:
                filtered["high_confidence_threshold"] = _to_decimal(
                    filtered["high_confidence_threshold"],
                    Decimal("0.80"),
                )

            return TaxHelperConfig(**filtered)

        return TaxHelperConfig()

    def _normalize_categories(
        self,
        categories: Mapping[str, Mapping[str, Any]],
    ) -> Dict[str, Dict[str, Any]]:
        normalized: Dict[str, Dict[str, Any]] = {}

        for key, value in categories.items():
            category_key = _safe_string(key, 100)
            if not category_key:
                continue

            label = _safe_string(value.get("label", category_key), 150)
            category_type = _safe_string(value.get("type", TaxRecordType.REVIEW.value), 50)
            keywords = value.get("keywords", [])

            normalized[category_key] = {
                "label": label,
                "type": category_type,
                "keywords": [
                    _safe_lower(keyword)
                    for keyword in keywords
                    if _safe_string(keyword)
                ],
            }

        if "uncategorized_tax_review" not in normalized:
            normalized["uncategorized_tax_review"] = DEFAULT_TAX_CATEGORIES["uncategorized_tax_review"]

        return normalized

    def _build_task_context(
        self,
        user_id: str,
        workspace_id: str,
        currency: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> TaskContext:
        metadata_dict = dict(metadata or {})
        request_id = _safe_string(metadata_dict.get("request_id") or str(uuid.uuid4()), 128)

        return TaskContext(
            user_id=_safe_string(user_id, 128),
            workspace_id=_safe_string(workspace_id, 128),
            request_id=request_id,
            role=_safe_string(metadata_dict.get("role"), 100) or None,
            permissions=tuple(metadata_dict.get("permissions", []) or []),
            source=_safe_string(metadata_dict.get("source") or "finance_agent", 100),
            locale=_safe_string(metadata_dict.get("locale"), 50) or None,
            currency=_safe_string(currency or metadata_dict.get("currency") or self.config.default_currency, 10).upper(),
            metadata=metadata_dict,
        )

    def _normalize_record(
        self,
        record: Mapping[str, Any],
        index: int,
        default_currency: str,
    ) -> NormalizedTaxRecord:
        if not isinstance(record, Mapping):
            raise ValueError("Record must be a dictionary-like mapping.")

        record_id = _generate_record_id(record, index)
        description = _normalize_space(
            _safe_string(
                record.get("description")
                or record.get("memo")
                or record.get("merchant")
                or record.get("vendor")
                or record.get("name")
                or record.get("title")
                or "",
                self.config.max_description_length,
            )
        )

        merchant = _safe_string(
            record.get("merchant")
            or record.get("vendor")
            or record.get("payee")
            or record.get("payer")
            or "",
            200,
        ) or None

        source = _safe_string(
            record.get("source")
            or record.get("provider")
            or record.get("account")
            or record.get("system")
            or "",
            150,
        ) or None

        amount = self._extract_amount(record)
        currency = _safe_string(record.get("currency") or default_currency, 10).upper()

        date_value = record.get("date") or record.get("transaction_date") or record.get("created_at") or record.get("paid_at")
        parsed_date = self._parse_date(date_value)

        record_type = self._infer_initial_record_type(record=record, amount=amount)
        original_category = _safe_string(
            record.get("category")
            or record.get("accounting_category")
            or record.get("tax_category")
            or "",
            150,
        ) or None

        metadata = {
            "index": index,
            "original_category": original_category,
            "source_type": _safe_string(record.get("source_type") or record.get("record_source"), 100),
            "has_attachment": bool(record.get("attachment") or record.get("receipt_file") or record.get("file_id")),
            "raw_hash": _hash_record_payload(_redact_sensitive_mapping(record)),
        }

        return NormalizedTaxRecord(
            record_id=record_id,
            date=parsed_date,
            description=description,
            amount=amount,
            currency=currency,
            merchant=merchant,
            source=source,
            record_type=record_type,
            original_category=original_category,
            metadata=metadata,
            raw=_redact_sensitive_mapping(record, self.config.retain_raw_sensitive_values),
        )

    def _extract_amount(self, record: Mapping[str, Any]) -> Decimal:
        amount_value = (
            record.get("amount")
            if "amount" in record
            else record.get("total", record.get("value", record.get("net_amount", "0")))
        )

        amount = _to_decimal(amount_value, Decimal("0"))

        direction = _safe_lower(record.get("direction") or record.get("type") or record.get("transaction_type"))
        if direction in {"debit", "expense", "payment_out", "outflow", "withdrawal"} and amount > 0:
            return -amount

        if direction in {"credit", "income", "payment_in", "inflow", "deposit"} and amount < 0:
            return abs(amount)

        return amount

    def _parse_date(self, value: Any) -> Optional[str]:
        if value is None:
            return None

        if isinstance(value, _dt.datetime):
            return value.date().isoformat()

        if isinstance(value, _dt.date):
            return value.isoformat()

        text = _safe_string(value, 100)
        if not text:
            return None

        candidates = [
            "%Y-%m-%d",
            "%Y/%m/%d",
            "%m/%d/%Y",
            "%d/%m/%Y",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%d-%m-%Y",
            "%m-%d-%Y",
        ]

        normalized = text.replace("Z", "+00:00")
        try:
            return _dt.datetime.fromisoformat(normalized).date().isoformat()
        except Exception:
            pass

        for fmt in candidates:
            try:
                return _dt.datetime.strptime(text[:19], fmt).date().isoformat()
            except Exception:
                continue

        return None

    def _infer_initial_record_type(self, record: Mapping[str, Any], amount: Decimal) -> str:
        explicit_type = _safe_lower(record.get("record_type") or record.get("type") or record.get("transaction_type"))
        if explicit_type:
            if explicit_type in {"income", "revenue", "credit", "deposit", "payment_in"}:
                return TaxRecordType.INCOME.value
            if explicit_type in {"expense", "debit", "payment", "payment_out", "withdrawal"}:
                return TaxRecordType.EXPENSE.value
            if explicit_type in {"asset", "equipment", "capital"}:
                return TaxRecordType.ASSET.value
            if explicit_type in {"equity", "draw", "distribution"}:
                return TaxRecordType.EQUITY.value
            if explicit_type in {"refund", "rebate", "adjustment"}:
                return TaxRecordType.ADJUSTMENT.value

        if amount > 0:
            return TaxRecordType.INCOME.value
        if amount < 0:
            return TaxRecordType.EXPENSE.value
        return TaxRecordType.REVIEW.value

    def _match_tax_category(self, record: NormalizedTaxRecord) -> TaxCategoryMatch:
        haystack_parts = [
            record.description,
            record.merchant or "",
            record.source or "",
            record.original_category or "",
            record.record_type,
        ]
        haystack = _safe_lower(" ".join(haystack_parts))

        best_key = "uncategorized_tax_review"
        best_score = Decimal("0")
        best_keywords: List[str] = []

        for category_key, category in self.categories.items():
            keywords = category.get("keywords", [])
            matched = [keyword for keyword in keywords if keyword and keyword in haystack]
            if not matched:
                continue

            keyword_score = Decimal(len(matched)) / Decimal(max(len(keywords), 1))
            density_bonus = min(Decimal(len(matched)) * Decimal("0.15"), Decimal("0.45"))

            type_bonus = Decimal("0")
            category_type = _safe_string(category.get("type"), 50)
            if record.record_type == TaxRecordType.INCOME.value and category_type == TaxRecordType.INCOME.value:
                type_bonus = Decimal("0.20")
            elif record.record_type == TaxRecordType.EXPENSE.value and category_type == TaxRecordType.EXPENSE.value:
                type_bonus = Decimal("0.20")
            elif category_type in {TaxRecordType.ASSET.value, TaxRecordType.EQUITY.value, TaxRecordType.ADJUSTMENT.value}:
                type_bonus = Decimal("0.10")

            score = min(Decimal("1.00"), keyword_score + density_bonus + type_bonus)

            if score > best_score:
                best_key = category_key
                best_score = score
                best_keywords = matched

        if best_score == Decimal("0"):
            best_score = Decimal("0.30")
            inferred_key = self._fallback_category_by_amount_type(record)
            best_key = inferred_key

        category = self.categories.get(best_key, self.categories["uncategorized_tax_review"])
        confidence = best_score.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

        return TaxCategoryMatch(
            category_key=best_key,
            label=_safe_string(category.get("label", best_key), 150),
            category_type=_safe_string(category.get("type", TaxRecordType.REVIEW.value), 50),
            confidence=confidence,
            matched_keywords=best_keywords,
            reason="Matched by keyword and record type." if best_keywords else "Fallback classification by amount/type.",
            deductibility_hint=DEFAULT_DEDUCTIBILITY_HINTS.get(best_key, "review_required"),
        )

    def _fallback_category_by_amount_type(self, record: NormalizedTaxRecord) -> str:
        if record.record_type == TaxRecordType.INCOME.value or record.amount > 0:
            return "income_services"
        if record.record_type == TaxRecordType.EXPENSE.value or record.amount < 0:
            return "uncategorized_tax_review"
        return "uncategorized_tax_review"

    def _category_from_override(self, category_key: str) -> TaxCategoryMatch:
        key = _safe_string(category_key, 100)
        category = self.categories.get(key)
        if not category:
            category = self.categories["uncategorized_tax_review"]
            key = "uncategorized_tax_review"

        return TaxCategoryMatch(
            category_key=key,
            label=_safe_string(category.get("label", key), 150),
            category_type=_safe_string(category.get("type", TaxRecordType.REVIEW.value), 50),
            confidence=Decimal("1.00"),
            matched_keywords=[],
            reason="Applied user/workspace category override.",
            deductibility_hint=DEFAULT_DEDUCTIBILITY_HINTS.get(key, "review_required"),
        )

    def _review_flags(
        self,
        record: NormalizedTaxRecord,
        match: TaxCategoryMatch,
    ) -> Tuple[bool, TaxRiskLevel, List[str]]:
        notes: List[str] = []
        review_required = False
        risk = TaxRiskLevel.LOW

        if match.confidence < self.config.confidence_threshold:
            review_required = True
            risk = TaxRiskLevel.MEDIUM
            notes.append("Low categorization confidence; review recommended.")

        if match.category_key == "uncategorized_tax_review":
            review_required = True
            risk = TaxRiskLevel.MEDIUM
            notes.append("Uncategorized record needs tax review.")

        if match.deductibility_hint in {
            "review_required",
            "partial_or_review_required",
            "capitalize_or_review_required",
            "not_expense_review_required",
        }:
            review_required = True
            if risk == TaxRiskLevel.LOW:
                risk = TaxRiskLevel.MEDIUM
            notes.append(f"Deductibility hint: {match.deductibility_hint}.")

        if abs(record.amount) >= Decimal("5000"):
            review_required = True
            risk = TaxRiskLevel.HIGH
            notes.append("Large amount; review recommended.")

        if not record.description:
            review_required = True
            risk = TaxRiskLevel.HIGH
            notes.append("Missing description.")

        if record.amount == Decimal("0"):
            review_required = True
            if risk != TaxRiskLevel.HIGH:
                risk = TaxRiskLevel.MEDIUM
            notes.append("Zero amount record; verify whether this is valid.")

        if match.category_type == TaxRecordType.ASSET.value:
            review_required = True
            if risk == TaxRiskLevel.LOW:
                risk = TaxRiskLevel.MEDIUM
            notes.append("Potential capital asset; capitalization/depreciation review may be needed.")

        if match.category_key in {"meals", "travel", "vehicle", "taxes_licenses"}:
            review_required = True
            if risk == TaxRiskLevel.LOW:
                risk = TaxRiskLevel.MEDIUM
            notes.append("Category commonly requires documentation or special treatment review.")

        return review_required, risk, notes

    # ------------------------------------------------------------------
    # Summary builders
    # ------------------------------------------------------------------

    def _build_category_summary(
        self,
        categorized: Sequence[CategorizedTaxRecord],
    ) -> Dict[str, Any]:
        by_category: Dict[str, Dict[str, Any]] = {}
        by_type: Dict[str, Dict[str, Any]] = {}
        review_count = 0
        risk_counts: Dict[str, int] = defaultdict(int)

        for record in categorized:
            amount = _to_decimal(record.amount)
            category_key = record.tax_category
            record_type = record.record_type

            if category_key not in by_category:
                by_category[category_key] = {
                    "tax_category": category_key,
                    "tax_category_label": record.tax_category_label,
                    "record_type": record_type,
                    "count": 0,
                    "total": Decimal("0"),
                    "review_required_count": 0,
                }

            by_category[category_key]["count"] += 1
            by_category[category_key]["total"] += amount
            if record.review_required:
                by_category[category_key]["review_required_count"] += 1

            if record_type not in by_type:
                by_type[record_type] = {
                    "record_type": record_type,
                    "count": 0,
                    "total": Decimal("0"),
                }

            by_type[record_type]["count"] += 1
            by_type[record_type]["total"] += amount

            if record.review_required:
                review_count += 1

            risk_counts[record.risk_level] += 1

        return {
            "record_count": len(categorized),
            "review_required_count": review_count,
            "risk_counts": dict(risk_counts),
            "by_category": [
                {
                    **value,
                    "total": _decimal_to_str(value["total"]),
                }
                for value in by_category.values()
            ],
            "by_type": [
                {
                    **value,
                    "total": _decimal_to_str(value["total"]),
                }
                for value in by_type.values()
            ],
        }

    def _build_preparation_summary_from_categorized(
        self,
        categorized: Sequence[CategorizedTaxRecord],
        tax_year: Optional[Union[int, str]],
        jurisdiction: Optional[str],
        currency: str,
    ) -> Dict[str, Any]:
        income_total = Decimal("0")
        expense_total = Decimal("0")
        asset_total = Decimal("0")
        equity_total = Decimal("0")
        adjustment_total = Decimal("0")
        review_total = Decimal("0")

        category_totals: Dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
        category_counts: Dict[str, int] = defaultdict(int)
        monthly_totals: Dict[str, Dict[str, Decimal]] = defaultdict(
            lambda: {
                "income": Decimal("0"),
                "expense": Decimal("0"),
                "asset": Decimal("0"),
                "equity": Decimal("0"),
                "adjustment": Decimal("0"),
                "review": Decimal("0"),
            }
        )

        review_required_count = 0
        high_risk_count = 0
        missing_date_count = 0

        for record in categorized:
            amount = _to_decimal(record.amount)
            absolute_amount = abs(amount)
            record_type = record.record_type

            if record_type == TaxRecordType.INCOME.value:
                income_total += absolute_amount if amount < 0 else amount
            elif record_type == TaxRecordType.EXPENSE.value:
                expense_total += absolute_amount
            elif record_type == TaxRecordType.ASSET.value:
                asset_total += absolute_amount
            elif record_type == TaxRecordType.EQUITY.value:
                equity_total += absolute_amount
            elif record_type == TaxRecordType.ADJUSTMENT.value:
                adjustment_total += amount
            else:
                review_total += amount

            category_totals[record.tax_category] += amount
            category_counts[record.tax_category] += 1

            month_key = self._month_key(record.date)
            monthly_bucket_type = record_type if record_type in monthly_totals[month_key] else "review"
            monthly_totals[month_key][monthly_bucket_type] += amount

            if record.review_required:
                review_required_count += 1

            if record.risk_level == TaxRiskLevel.HIGH.value:
                high_risk_count += 1

            if not record.date:
                missing_date_count += 1

        estimated_net_before_review = income_total - expense_total
        possible_review_exposure = abs(review_total) + asset_total + equity_total

        category_summary = []
        for category_key, total in category_totals.items():
            category_meta = self.categories.get(category_key, {})
            category_summary.append(
                {
                    "tax_category": category_key,
                    "tax_category_label": category_meta.get("label", category_key),
                    "count": category_counts[category_key],
                    "total": _decimal_to_str(total),
                    "deductibility_hint": DEFAULT_DEDUCTIBILITY_HINTS.get(category_key, "review_required"),
                }
            )

        category_summary.sort(key=lambda item: abs(_to_decimal(item["total"])), reverse=True)

        monthly_summary = []
        for month, totals in sorted(monthly_totals.items()):
            monthly_summary.append(
                {
                    "month": month,
                    "income": _decimal_to_str(totals["income"]),
                    "expense": _decimal_to_str(totals["expense"]),
                    "asset": _decimal_to_str(totals["asset"]),
                    "equity": _decimal_to_str(totals["equity"]),
                    "adjustment": _decimal_to_str(totals["adjustment"]),
                    "review": _decimal_to_str(totals["review"]),
                }
            )

        readiness = self._readiness_score(
            total_records=len(categorized),
            review_required_count=review_required_count,
            high_risk_count=high_risk_count,
            missing_date_count=missing_date_count,
        )

        return {
            "tax_year": tax_year,
            "jurisdiction": jurisdiction,
            "currency": currency,
            "record_count": len(categorized),
            "totals": {
                "gross_income": _decimal_to_str(income_total),
                "categorized_expenses": _decimal_to_str(expense_total),
                "capital_asset_review_total": _decimal_to_str(asset_total),
                "owner_equity_draw_distribution_total": _decimal_to_str(equity_total),
                "adjustments_total": _decimal_to_str(adjustment_total),
                "uncategorized_or_review_total": _decimal_to_str(review_total),
                "estimated_net_before_review": _decimal_to_str(estimated_net_before_review),
                "possible_review_exposure": _decimal_to_str(possible_review_exposure),
            },
            "review": {
                "review_required_count": review_required_count,
                "high_risk_count": high_risk_count,
                "missing_date_count": missing_date_count,
                "readiness_score": readiness["score"],
                "readiness_label": readiness["label"],
                "readiness_notes": readiness["notes"],
            },
            "category_summary": category_summary,
            "monthly_summary": monthly_summary,
            "recommended_documents": self._recommended_documents(categorized),
            "next_steps": self._summary_next_steps(
                review_required_count=review_required_count,
                high_risk_count=high_risk_count,
                missing_date_count=missing_date_count,
            ),
        }

    def _month_key(self, date_value: Optional[str]) -> str:
        if not date_value:
            return "undated"
        try:
            parsed = _dt.date.fromisoformat(date_value[:10])
            return f"{parsed.year:04d}-{parsed.month:02d}"
        except Exception:
            return "undated"

    def _readiness_score(
        self,
        total_records: int,
        review_required_count: int,
        high_risk_count: int,
        missing_date_count: int,
    ) -> Dict[str, Any]:
        if total_records <= 0:
            return {
                "score": 0,
                "label": "no_records",
                "notes": ["No records were provided."],
            }

        penalty = 0
        penalty += int((review_required_count / total_records) * 45)
        penalty += int((high_risk_count / total_records) * 35)
        penalty += int((missing_date_count / total_records) * 20)

        score = max(0, min(100, 100 - penalty))

        if score >= 85:
            label = "strong_preparation"
        elif score >= 65:
            label = "mostly_ready_with_review"
        elif score >= 40:
            label = "needs_cleanup"
        else:
            label = "not_ready"

        notes = []
        if review_required_count:
            notes.append(f"{review_required_count} record(s) need review.")
        if high_risk_count:
            notes.append(f"{high_risk_count} high-risk record(s) need attention.")
        if missing_date_count:
            notes.append(f"{missing_date_count} record(s) have missing dates.")
        if not notes:
            notes.append("Records look organized for preliminary review.")

        return {
            "score": score,
            "label": label,
            "notes": notes,
        }

    def _recommended_documents(
        self,
        categorized: Sequence[CategorizedTaxRecord],
    ) -> List[str]:
        category_keys = {record.tax_category for record in categorized}
        recommendations = {
            "Bank and payment processor statements for the selected period.",
            "Invoices issued and received.",
            "Receipts for business expenses.",
        }

        if "contractor_payments" in category_keys:
            recommendations.add("Contractor agreements and year-end contractor payment reports.")
        if "payroll" in category_keys:
            recommendations.add("Payroll summaries, wage reports, and employer tax reports.")
        if "travel" in category_keys:
            recommendations.add("Travel itinerary, business purpose notes, and lodging receipts.")
        if "meals" in category_keys:
            recommendations.add("Meal receipts with business purpose and attendee notes.")
        if "vehicle" in category_keys:
            recommendations.add("Mileage logs, fuel receipts, parking, and toll records.")
        if "capital_asset_equipment" in category_keys:
            recommendations.add("Asset purchase receipts and depreciation/capitalization review notes.")
        if "taxes_licenses" in category_keys:
            recommendations.add("Tax payment confirmations, license renewals, and government fee receipts.")
        if "income_sales" in category_keys or "income_services" in category_keys:
            recommendations.add("Sales reports, paid invoices, and revenue reconciliation statements.")

        return sorted(recommendations)

    def _summary_next_steps(
        self,
        review_required_count: int,
        high_risk_count: int,
        missing_date_count: int,
    ) -> List[str]:
        steps = [
            "Review all category assignments before using them for filing.",
            "Attach receipts or source documents to material expenses.",
            "Reconcile totals against bank, card, invoice, and payment processor statements.",
        ]

        if review_required_count:
            steps.append("Resolve records marked as review_required.")
        if high_risk_count:
            steps.append("Prioritize high-risk records and large transactions for professional review.")
        if missing_date_count:
            steps.append("Add missing dates before accountant handoff or export.")
        steps.append("Have a qualified tax/accounting professional review final tax treatment.")

        return steps

    # ------------------------------------------------------------------
    # Coercion and export helpers
    # ------------------------------------------------------------------

    def _coerce_categorized_records(
        self,
        records: Sequence[Mapping[str, Any]],
    ) -> List[CategorizedTaxRecord]:
        if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
            raise ValueError("Categorized records must be a sequence.")

        coerced: List[CategorizedTaxRecord] = []

        for index, record in enumerate(records):
            if isinstance(record, CategorizedTaxRecord):
                coerced.append(record)
                continue

            if not isinstance(record, Mapping):
                raise ValueError(f"Categorized record at index {index} must be a mapping.")

            record_id = _safe_string(record.get("record_id") or record.get("id") or f"record_{index}", 128)
            tax_category = _safe_string(record.get("tax_category") or "uncategorized_tax_review", 100)
            category = self.categories.get(tax_category, self.categories["uncategorized_tax_review"])

            amount = _to_decimal(record.get("amount", "0"))
            confidence = _to_decimal(record.get("confidence", "0.30"))

            record_type = _safe_string(
                record.get("record_type") or category.get("type") or TaxRecordType.REVIEW.value,
                50,
            )

            review_required = bool(record.get("review_required", confidence < self.config.confidence_threshold))
            risk_level = _safe_string(record.get("risk_level") or TaxRiskLevel.MEDIUM.value, 20)

            coerced.append(
                CategorizedTaxRecord(
                    record_id=record_id,
                    date=self._parse_date(record.get("date")),
                    description=_safe_string(record.get("description"), self.config.max_description_length),
                    amount=_decimal_to_str(amount),
                    currency=_safe_string(record.get("currency") or self.config.default_currency, 10).upper(),
                    merchant=_safe_string(record.get("merchant"), 200) or None,
                    source=_safe_string(record.get("source"), 150) or None,
                    record_type=record_type,
                    tax_category=tax_category,
                    tax_category_label=_safe_string(
                        record.get("tax_category_label") or category.get("label") or tax_category,
                        150,
                    ),
                    confidence=_decimal_to_str(confidence),
                    matched_keywords=list(record.get("matched_keywords", []) or []),
                    deductibility_hint=_safe_string(
                        record.get("deductibility_hint")
                        or DEFAULT_DEDUCTIBILITY_HINTS.get(tax_category, "review_required"),
                        100,
                    ),
                    review_required=review_required,
                    risk_level=risk_level,
                    notes=list(record.get("notes", []) or []),
                    metadata=_redact_sensitive_mapping(record.get("metadata", {}), self.config.retain_raw_sensitive_values),
                )
            )

        return coerced

    def _deduction_review_reason(self, record: CategorizedTaxRecord) -> Optional[str]:
        if record.review_required:
            return "marked_review_required"

        if _to_decimal(record.confidence) < self.config.confidence_threshold:
            return "low_confidence"

        if record.risk_level in {TaxRiskLevel.HIGH.value, TaxRiskLevel.MEDIUM.value}:
            return f"{record.risk_level}_risk"

        if record.deductibility_hint in {
            "review_required",
            "partial_or_review_required",
            "capitalize_or_review_required",
            "not_expense_review_required",
        }:
            return record.deductibility_hint

        if record.tax_category in {
            "meals",
            "travel",
            "vehicle",
            "capital_asset_equipment",
            "taxes_licenses",
            "uncategorized_tax_review",
            "owner_draw_distribution",
        }:
            return f"{record.tax_category}_review"

        return None

    def _suggest_review_next_step(self, record: CategorizedTaxRecord) -> str:
        category = record.tax_category

        if category == "meals":
            return "Confirm business purpose, attendees, receipt, and applicable deductible percentage."
        if category == "travel":
            return "Confirm business purpose, dates, itinerary, and supporting receipts."
        if category == "vehicle":
            return "Attach mileage log or vehicle expense documentation."
        if category == "capital_asset_equipment":
            return "Review whether this should be capitalized, depreciated, or expensed."
        if category == "owner_draw_distribution":
            return "Confirm this is not treated as an operating expense."
        if category == "taxes_licenses":
            return "Confirm tax/license type and whether it is deductible or needs special treatment."
        if category == "uncategorized_tax_review":
            return "Assign a proper tax category after reviewing source document."
        if record.risk_level == TaxRiskLevel.HIGH.value:
            return "Prioritize professional/accountant review due to high risk or large amount."
        return "Review supporting documentation and confirm tax treatment."

    def _export_record_view(
        self,
        record: CategorizedTaxRecord,
        include_raw: bool = False,
    ) -> Dict[str, Any]:
        data = {
            "record_id": record.record_id,
            "date": record.date,
            "description": record.description,
            "amount": record.amount,
            "currency": record.currency,
            "merchant": record.merchant,
            "source": record.source,
            "record_type": record.record_type,
            "tax_category": record.tax_category,
            "tax_category_label": record.tax_category_label,
            "confidence": record.confidence,
            "deductibility_hint": record.deductibility_hint,
            "review_required": record.review_required,
            "risk_level": record.risk_level,
            "notes": record.notes,
            "metadata": _redact_sensitive_mapping(record.metadata, self.config.retain_raw_sensitive_values),
        }

        if include_raw:
            data["raw"] = "[RAW_RECORD_NOT_AVAILABLE_FROM_CATEGORIZED_VIEW]"

        return data

    # ------------------------------------------------------------------
    # Verification helpers
    # ------------------------------------------------------------------

    def _verification_summary(
        self,
        action: str,
        data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        if action == TaxAction.CATEGORIZE_RECORDS.value:
            summary = data.get("summary", {})
            return {
                "records_categorized": summary.get("record_count"),
                "review_required_count": summary.get("review_required_count"),
            }

        if action == TaxAction.SUMMARIZE_PREPARATION.value:
            prep = data.get("preparation_summary", {})
            return {
                "record_count": prep.get("record_count"),
                "totals": prep.get("totals", {}),
                "review": prep.get("review", {}),
            }

        if action == TaxAction.BUILD_DEDUCTION_REVIEW.value:
            summary = data.get("summary", {})
            return {
                "review_item_count": summary.get("review_item_count"),
                "total_review_amount": summary.get("total_review_amount"),
            }

        if action == TaxAction.BUILD_EXPORT_PACKAGE.value:
            return {
                "package_id": data.get("package_id"),
                "package_hash": data.get("package_hash"),
                "record_count": data.get("record_count"),
            }

        return {
            "action": action,
            "data_hash": _hash_record_payload(data),
        }

    def _base_metadata(self, task_context: TaskContext, action: str) -> Dict[str, Any]:
        return {
            "agent": DEFAULT_AGENT_NAME,
            "agent_id": DEFAULT_AGENT_ID,
            "module": DEFAULT_MODULE,
            "action": action,
            "user_id": task_context.user_id,
            "workspace_id": task_context.workspace_id,
            "request_id": task_context.request_id,
            "source": task_context.source,
            "created_at": _utc_now_iso(),
            "currency": task_context.currency,
        }


# ---------------------------------------------------------------------------
# Module-level factory and registry metadata
# ---------------------------------------------------------------------------

def create_tax_helper(
    config: Optional[Union[TaxHelperConfig, Mapping[str, Any]]] = None,
    **kwargs: Any,
) -> TaxHelper:
    """
    Factory function for Agent Loader / Registry integration.
    """

    return TaxHelper(config=config, **kwargs)


AGENT_METADATA: Dict[str, Any] = {
    "agent": DEFAULT_AGENT_NAME,
    "agent_id": DEFAULT_AGENT_ID,
    "module": DEFAULT_MODULE,
    "file_path": "agents/super_agents/finance_agent/tax_helper.py",
    "class_name": "TaxHelper",
    "purpose": "Categorizes tax-related records and preparation summaries.",
    "safe_import": True,
    "requires_user_workspace_context": True,
    "performs_real_tax_filing": False,
    "performs_money_movement": False,
    "public_methods": [
        "categorize_records",
        "summarize_tax_preparation",
        "build_deduction_review",
        "validate_tax_records",
        "build_export_package",
        "get_supported_tax_categories",
        "health_check",
    ],
    "compatibility_hooks": [
        "_validate_task_context",
        "_requires_security_check",
        "_request_security_approval",
        "_prepare_verification_payload",
        "_prepare_memory_payload",
        "_emit_agent_event",
        "_log_audit_event",
        "_safe_result",
        "_error_result",
    ],
}


__all__ = [
    "TaxHelper",
    "TaxHelperConfig",
    "TaxRecordType",
    "TaxRiskLevel",
    "TaxAction",
    "TaxCategoryMatch",
    "NormalizedTaxRecord",
    "CategorizedTaxRecord",
    "TaskContext",
    "create_tax_helper",
    "AGENT_METADATA",
]


# ---------------------------------------------------------------------------
# Minimal local smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    helper = TaxHelper(
        config={
            "require_security_for_exports": False,
            "require_security_for_sensitive_records": False,
        }
    )

    sample_records = [
        {
            "id": "txn_001",
            "date": "2026-01-10",
            "description": "Google Ads campaign spend",
            "amount": "-250.00",
            "currency": "USD",
            "merchant": "Google Ads",
        },
        {
            "id": "txn_002",
            "date": "2026-01-12",
            "description": "Client payment invoice paid for SEO services",
            "amount": "1200.00",
            "currency": "USD",
            "merchant": "Acme Client",
        },
        {
            "id": "txn_003",
            "date": "2026-01-20",
            "description": "Business lunch with client",
            "amount": "-85.40",
            "currency": "USD",
            "merchant": "Restaurant",
        },
    ]

    result = helper.categorize_records(
        records=sample_records,
        user_id="demo_user",
        workspace_id="demo_workspace",
        tax_year=2026,
        jurisdiction="US",
    )

    print(json.dumps(result, indent=2, default=str))