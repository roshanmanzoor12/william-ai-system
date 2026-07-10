"""
agents/security_agent/fraud_detector.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Detect scams, phishing, fake login pages, suspicious invoices, payment
    redirection fraud, credential theft attempts, impersonation, and suspicious
    financial requests.

Security Model:
    - Passive analysis only.
    - Does not open URLs, download files, execute attachments, send messages,
      initiate payments, block accounts, or modify external systems.
    - High-risk findings produce recommendations and approval requirements.
    - All user-specific analysis requires user_id and workspace_id.
    - Audit records contain hashes, classifications, and redacted previews rather
      than raw passwords, tokens, payment numbers, or complete private content.

Architecture Connections:
    Master Agent:
        Routes suspicious emails, messages, web pages, invoices, and payment
        requests to FraudDetector.

    Security Agent:
        Uses FraudDetector as a specialized passive fraud-analysis component.
        High-risk findings can be routed to approval_manager.py, payment_guard.py,
        emergency_lock.py, or policy_engine.py.

    Browser Agent:
        May provide URL metadata, visible page text, DOM summaries, form fields,
        redirect chains, certificate information, and screenshot-derived text.
        FraudDetector never opens the URL itself.

    Visual Agent:
        May provide OCR text and visual indicators from invoices, login pages,
        QR codes, payment screens, or suspicious documents.

    Finance Agent:
        May request invoice and payment-instruction analysis before any financial
        recommendation or action. FraudDetector never authorizes or executes a
        payment.

    Memory Agent:
        Receives safe, redacted fraud-pattern context where retention is useful.
        Raw credentials, complete card numbers, secrets, and authentication codes
        must not be stored.

    Verification Agent:
        Receives a verification payload after every completed analysis.

    Dashboard/API:
        Public methods return predictable JSON-style dictionaries suitable for
        FastAPI endpoints, dashboards, analytics, and task-history storage.

    Agent Registry / Loader / Router:
        Exposes registry metadata, capabilities, health checks, and stable public
        interfaces.

No external dependencies are required.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import math
import re
import time
import unicodedata
import uuid
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from html import unescape
from pathlib import PurePath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union
from urllib.parse import parse_qs, unquote, urlparse


# =============================================================================
# Import-safe William/Jarvis compatibility
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Import-safe BaseAgent fallback.

        The real William BaseAgent will replace this class when available.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get(
                "agent_id",
                self.__class__.__name__.lower(),
            )
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, *args: Any, **kwargs: Any) -> None:
            return None

        def log_audit(self, *args: Any, **kwargs: Any) -> None:
            return None


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger(__name__)

if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# =============================================================================
# Enums
# =============================================================================

class FraudInputType(str, Enum):
    """
    Supported input categories.
    """

    AUTO = "auto"
    EMAIL = "email"
    MESSAGE = "message"
    URL = "url"
    LOGIN_PAGE = "login_page"
    WEB_PAGE = "web_page"
    INVOICE = "invoice"
    PAYMENT_REQUEST = "payment_request"
    DOCUMENT = "document"
    SMS = "sms"
    QR_PAYMENT = "qr_payment"
    UNKNOWN = "unknown"


class FraudCategory(str, Enum):
    """
    Fraud categories detected by this component.
    """

    PHISHING = "phishing"
    CREDENTIAL_THEFT = "credential_theft"
    FAKE_LOGIN_PAGE = "fake_login_page"
    BUSINESS_EMAIL_COMPROMISE = "business_email_compromise"
    INVOICE_FRAUD = "invoice_fraud"
    PAYMENT_REDIRECTION = "payment_redirection"
    IMPERSONATION = "impersonation"
    ADVANCE_FEE_SCAM = "advance_fee_scam"
    TECH_SUPPORT_SCAM = "tech_support_scam"
    ACCOUNT_TAKEOVER = "account_takeover"
    MALWARE_DELIVERY = "malware_delivery"
    CRYPTO_SCAM = "crypto_scam"
    GIFT_CARD_SCAM = "gift_card_scam"
    REFUND_SCAM = "refund_scam"
    ROMANCE_SCAM = "romance_scam"
    JOB_SCAM = "job_scam"
    LOTTERY_SCAM = "lottery_scam"
    CHARITY_SCAM = "charity_scam"
    QR_CODE_SCAM = "qr_code_scam"
    SUSPICIOUS_INVOICE = "suspicious_invoice"
    SUSPICIOUS_PAYMENT = "suspicious_payment"
    SOCIAL_ENGINEERING = "social_engineering"
    DOMAIN_SPOOFING = "domain_spoofing"
    BRAND_IMPERSONATION = "brand_impersonation"
    IDENTITY_VERIFICATION_SCAM = "identity_verification_scam"
    UNKNOWN_FRAUD = "unknown_fraud"


class RiskLevel(str, Enum):
    """
    Normalized fraud risk levels.
    """

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConfidenceLevel(str, Enum):
    """
    Confidence level in the result.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RecommendedAction(str, Enum):
    """
    Non-destructive recommendations returned by FraudDetector.
    """

    ALLOW_WITH_CAUTION = "allow_with_caution"
    VERIFY_INDEPENDENTLY = "verify_independently"
    REQUIRE_HUMAN_REVIEW = "require_human_review"
    REQUIRE_SECURITY_APPROVAL = "require_security_approval"
    HOLD_PAYMENT = "hold_payment"
    DO_NOT_ENTER_CREDENTIALS = "do_not_enter_credentials"
    DO_NOT_OPEN_ATTACHMENT = "do_not_open_attachment"
    DO_NOT_CLICK_LINK = "do_not_click_link"
    BLOCK_RECOMMENDED = "block_recommended"
    ESCALATE_TO_SECURITY = "escalate_to_security"
    PRESERVE_EVIDENCE = "preserve_evidence"


class IndicatorSeverity(str, Enum):
    """
    Severity assigned to an individual fraud indicator.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisStatus(str, Enum):
    """
    Analysis status.
    """

    COMPLETED = "completed"
    NEEDS_MORE_DATA = "needs_more_data"
    SECURITY_APPROVAL_REQUIRED = "security_approval_required"
    FAILED = "failed"


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class FraudDetectorConfig:
    """
    Fraud detector configuration.

    Defaults are conservative and designed to reduce automatic false positives.
    Scores are explainable and are not treated as legal or financial proof.
    """

    version: str = "1.0.0"

    maximum_text_characters: int = 500_000
    maximum_html_characters: int = 1_000_000
    maximum_url_characters: int = 8_192
    maximum_attachments: int = 100
    maximum_indicators: int = 100
    maximum_entities: int = 100
    maximum_recommendations: int = 20

    low_risk_threshold: float = 20.0
    medium_risk_threshold: float = 40.0
    high_risk_threshold: float = 65.0
    critical_risk_threshold: float = 85.0

    high_risk_approval_threshold: float = 65.0
    payment_hold_threshold: float = 65.0
    credential_block_threshold: float = 55.0

    include_evidence_snippets: bool = True
    evidence_snippet_length: int = 180
    redact_sensitive_data: bool = True
    include_source_hash: bool = True
    emit_audit_events: bool = True
    emit_agent_events: bool = True

    suspicious_url_shorteners: Tuple[str, ...] = (
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "buff.ly",
        "is.gd",
        "cutt.ly",
        "rebrand.ly",
        "shorturl.at",
        "tiny.cc",
        "rb.gy",
        "lnkd.in",
        "s.id",
        "qrco.de",
    )

    risky_top_level_domains: Tuple[str, ...] = (
        "zip",
        "mov",
        "click",
        "top",
        "xyz",
        "cam",
        "support",
        "country",
        "stream",
        "download",
        "gq",
        "tk",
        "ml",
        "cf",
        "work",
        "party",
        "buzz",
        "rest",
        "fit",
    )

    suspicious_attachment_extensions: Tuple[str, ...] = (
        ".exe",
        ".scr",
        ".com",
        ".pif",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        ".hta",
        ".msi",
        ".dll",
        ".jar",
        ".iso",
        ".img",
        ".lnk",
        ".reg",
        ".chm",
        ".xll",
    )

    macro_document_extensions: Tuple[str, ...] = (
        ".docm",
        ".xlsm",
        ".pptm",
        ".dotm",
        ".xltm",
        ".potm",
    )

    archive_extensions: Tuple[str, ...] = (
        ".zip",
        ".rar",
        ".7z",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".iso",
        ".img",
    )

    credential_field_names: Tuple[str, ...] = (
        "password",
        "passwd",
        "passcode",
        "pin",
        "otp",
        "one_time_password",
        "verification_code",
        "security_code",
        "cvv",
        "cvc",
        "card_number",
        "account_password",
        "recovery_code",
        "seed_phrase",
        "private_key",
    )

    protected_brand_domains: Mapping[str, Tuple[str, ...]] = field(
        default_factory=lambda: {
            "google": ("google.com", "accounts.google.com"),
            "microsoft": (
                "microsoft.com",
                "live.com",
                "office.com",
                "office365.com",
                "microsoftonline.com",
            ),
            "apple": ("apple.com", "icloud.com"),
            "amazon": ("amazon.com", "amazon.co.uk", "amazon.ca", "amazon.ae"),
            "paypal": ("paypal.com",),
            "stripe": ("stripe.com",),
            "facebook": ("facebook.com", "meta.com"),
            "instagram": ("instagram.com",),
            "linkedin": ("linkedin.com",),
            "dropbox": ("dropbox.com",),
            "docusign": ("docusign.com", "docusign.net"),
            "adobe": ("adobe.com",),
            "chase": ("chase.com",),
            "bank of america": ("bankofamerica.com",),
            "wells fargo": ("wellsfargo.com",),
            "wise": ("wise.com",),
            "revolut": ("revolut.com",),
            "coinbase": ("coinbase.com",),
            "binance": ("binance.com",),
        }
    )

    trusted_payment_domains: Tuple[str, ...] = (
        "paypal.com",
        "stripe.com",
        "wise.com",
        "revolut.com",
        "squareup.com",
    )

    score_weights: Mapping[str, float] = field(
        default_factory=lambda: {
            "credential_request": 22.0,
            "credential_form": 24.0,
            "password_and_external_domain": 25.0,
            "urgent_language": 8.0,
            "threat_language": 10.0,
            "secrecy_request": 14.0,
            "payment_change": 24.0,
            "bank_change": 28.0,
            "gift_card": 32.0,
            "crypto_payment": 20.0,
            "advance_fee": 24.0,
            "remote_access": 24.0,
            "refund_overpayment": 24.0,
            "invoice_mismatch": 22.0,
            "domain_spoofing": 30.0,
            "brand_impersonation": 25.0,
            "lookalike_domain": 26.0,
            "ip_address_url": 18.0,
            "url_shortener": 12.0,
            "risky_tld": 8.0,
            "punycode_domain": 18.0,
            "userinfo_in_url": 24.0,
            "non_https_login": 20.0,
            "excessive_subdomains": 10.0,
            "suspicious_query": 8.0,
            "encoded_url": 7.0,
            "suspicious_attachment": 28.0,
            "macro_attachment": 22.0,
            "double_extension": 20.0,
            "archive_attachment": 8.0,
            "reply_to_mismatch": 18.0,
            "sender_domain_mismatch": 15.0,
            "display_name_impersonation": 16.0,
            "qr_payment": 15.0,
            "poor_identity_context": 5.0,
            "unusual_payment_method": 12.0,
            "invoice_urgency": 8.0,
            "account_verification": 15.0,
            "suspicious_html": 10.0,
            "hidden_form": 22.0,
            "external_form_action": 26.0,
            "script_obfuscation": 18.0,
            "clipboard_manipulation": 22.0,
            "window_location_redirect": 12.0,
            "fake_security_warning": 22.0,
        }
    )


@dataclass
class TaskContext:
    """
    SaaS-isolated execution context.
    """

    user_id: str
    workspace_id: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_id: Optional[str] = None
    session_id: Optional[str] = None
    source_agent: Optional[str] = None
    actor_id: Optional[str] = None
    actor_role: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    subscription_tier: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttachmentMetadata:
    """
    Attachment information supplied by another trusted component.

    FraudDetector does not open or execute the attachment.
    """

    filename: str
    content_type: Optional[str] = None
    size_bytes: Optional[int] = None
    sha256: Optional[str] = None
    password_protected: bool = False
    extracted_text: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FraudIndicator:
    """
    Explainable fraud indicator.
    """

    code: str
    category: FraudCategory
    severity: IndicatorSeverity
    score: float
    title: str
    description: str
    evidence: Optional[str] = None
    source: Optional[str] = None
    confidence: float = 0.75
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FraudAnalysisRequest:
    """
    Main fraud-analysis request.
    """

    context: TaskContext

    input_type: FraudInputType = FraudInputType.AUTO
    text: str = ""
    subject: Optional[str] = None
    sender: Optional[str] = None
    sender_display_name: Optional[str] = None
    reply_to: Optional[str] = None
    recipients: List[str] = field(default_factory=list)

    url: Optional[str] = None
    visible_url: Optional[str] = None
    final_url: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)

    html: Optional[str] = None
    page_title: Optional[str] = None
    form_actions: List[str] = field(default_factory=list)
    form_fields: List[str] = field(default_factory=list)

    attachments: List[AttachmentMetadata] = field(default_factory=list)

    invoice_data: Dict[str, Any] = field(default_factory=dict)
    payment_data: Dict[str, Any] = field(default_factory=dict)
    historical_data: Dict[str, Any] = field(default_factory=dict)

    expected_brand: Optional[str] = None
    expected_domain: Optional[str] = None
    expected_sender_domain: Optional[str] = None
    known_vendor: Optional[str] = None
    known_vendor_domains: List[str] = field(default_factory=list)
    known_bank_accounts: List[str] = field(default_factory=list)

    source_id: Optional[str] = None
    project_id: Optional[str] = None
    client_id: Optional[str] = None
    privacy_level: str = "private"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FraudAnalysisData:
    """
    Structured fraud-analysis output.
    """

    analysis_id: str
    status: str
    input_type: str
    risk_score: float
    risk_level: str
    confidence: str
    is_suspicious: bool
    is_likely_fraud: bool

    primary_category: Optional[str]
    categories: List[str]
    indicators: List[Dict[str, Any]]

    recommendations: List[str]
    approval_required: bool
    payment_hold_recommended: bool
    credential_entry_block_recommended: bool
    link_click_block_recommended: bool
    attachment_open_block_recommended: bool

    extracted_entities: Dict[str, Any]
    source_hash: Optional[str]
    redacted_preview: Optional[str]

    explanation: str
    limitations: List[str]
    metadata: Dict[str, Any]


# =============================================================================
# FraudDetector
# =============================================================================

class FraudDetector(BaseAgent):
    """
    Passive fraud, phishing, fake-login, invoice, and payment-fraud detector.

    The class does not perform external network requests and does not execute
    financial, browser, messaging, device, or destructive actions.

    Public methods:
        detect()
        analyze()
        analyze_text()
        analyze_email()
        analyze_url()
        analyze_login_page()
        analyze_invoice()
        analyze_payment_request()
        analyze_attachments()
        compare_domains()
        health_check()
        get_registry_metadata()
    """

    VERSION = "1.0.0"
    AGENT_NAME = "FraudDetector"
    AGENT_ID = "fraud_detector"
    MODULE = "security_agent"
    FILE_PATH = "agents/security_agent/fraud_detector.py"

    def __init__(
        self,
        config: Optional[FraudDetectorConfig] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=kwargs.get("agent_name", self.AGENT_NAME),
            agent_id=kwargs.get("agent_id", self.AGENT_ID),
        )

        self.config = config or FraudDetectorConfig()
        self.logger = logging.getLogger(self.AGENT_NAME)

    # =========================================================================
    # Required compatibility hooks
    # =========================================================================

    def _validate_task_context(
        self,
        context: Union[TaskContext, Dict[str, Any], None],
        *,
        require_user_workspace: bool = True,
    ) -> Tuple[bool, Optional[TaskContext], Optional[str]]:
        """
        Validate and normalize SaaS execution context.

        user_id and workspace_id prevent findings, logs, and task data from being
        mixed across tenants.
        """

        if context is None:
            return False, None, "Task context is required."

        if isinstance(context, dict):
            try:
                context = TaskContext(
                    user_id=str(context.get("user_id") or "").strip(),
                    workspace_id=str(
                        context.get("workspace_id") or ""
                    ).strip(),
                    request_id=str(
                        context.get("request_id") or uuid.uuid4()
                    ),
                    task_id=self._optional_string(
                        context.get("task_id")
                    ),
                    session_id=self._optional_string(
                        context.get("session_id")
                    ),
                    source_agent=self._optional_string(
                        context.get("source_agent")
                    ),
                    actor_id=self._optional_string(
                        context.get("actor_id")
                    ),
                    actor_role=self._optional_string(
                        context.get("actor_role")
                    ),
                    permissions=self._normalize_string_list(
                        context.get("permissions")
                    ),
                    subscription_tier=self._optional_string(
                        context.get("subscription_tier")
                    ),
                    metadata=self._safe_dict(
                        context.get("metadata")
                    ),
                )
            except Exception as exc:
                return (
                    False,
                    None,
                    f"Invalid task-context structure: {exc}",
                )

        if not isinstance(context, TaskContext):
            return (
                False,
                None,
                "Context must be TaskContext or a dictionary.",
            )

        if require_user_workspace:
            if not context.user_id:
                return False, None, "user_id is required."
            if not context.workspace_id:
                return False, None, "workspace_id is required."

        for field_name, value in (
            ("user_id", context.user_id),
            ("workspace_id", context.workspace_id),
            ("request_id", context.request_id),
        ):
            if len(value) > 256:
                return (
                    False,
                    None,
                    f"{field_name} exceeds 256 characters.",
                )

        if not re.fullmatch(
            r"[A-Za-z0-9_.:@/\-]{1,256}",
            context.user_id,
        ):
            return (
                False,
                None,
                "user_id contains unsupported characters.",
            )

        if not re.fullmatch(
            r"[A-Za-z0-9_.:@/\-]{1,256}",
            context.workspace_id,
        ):
            return (
                False,
                None,
                "workspace_id contains unsupported characters.",
            )

        return True, context, None

    def _requires_security_check(
        self,
        request: FraudAnalysisRequest,
        analysis: Optional[FraudAnalysisData] = None,
    ) -> bool:
        """
        Determine whether the result should be escalated within Security Agent.

        Fraud analysis is itself a security operation. This hook determines
        whether a second approval, human review, payment hold, emergency lock,
        or policy decision should be requested.
        """

        if analysis is not None:
            return (
                analysis.risk_score
                >= self.config.high_risk_approval_threshold
                or analysis.payment_hold_recommended
                or analysis.credential_entry_block_recommended
            )

        has_payment_context = bool(
            request.invoice_data
            or request.payment_data
            or request.input_type
            in {
                FraudInputType.INVOICE,
                FraudInputType.PAYMENT_REQUEST,
                FraudInputType.QR_PAYMENT,
            }
        )

        has_credential_context = bool(
            set(
                field.lower()
                for field in request.form_fields
                if isinstance(field, str)
            )
            & set(self.config.credential_field_names)
        )

        return has_payment_context or has_credential_context

    def _request_security_approval(
        self,
        *,
        request: FraudAnalysisRequest,
        analysis: Optional[FraudAnalysisData] = None,
        reason: str,
        requested_action: str = "review_fraud_finding",
    ) -> Dict[str, Any]:
        """
        Prepare an approval request for Security Agent/Approval Manager.

        This method does not approve or execute an action.
        """

        payload = {
            "approval_required": True,
            "requested_action": requested_action,
            "reason": reason,
            "agent": self.AGENT_ID,
            "module": self.MODULE,
            "user_id": request.context.user_id,
            "workspace_id": request.context.workspace_id,
            "request_id": request.context.request_id,
            "task_id": request.context.task_id,
            "analysis_id": (
                analysis.analysis_id if analysis else None
            ),
            "risk_score": (
                analysis.risk_score if analysis else None
            ),
            "risk_level": (
                analysis.risk_level if analysis else None
            ),
            "primary_category": (
                analysis.primary_category if analysis else None
            ),
            "payment_hold_recommended": (
                analysis.payment_hold_recommended
                if analysis
                else False
            ),
            "credential_entry_block_recommended": (
                analysis.credential_entry_block_recommended
                if analysis
                else False
            ),
            "created_at": self._utc_now(),
        }

        return self._safe_result(
            message="Security approval request prepared.",
            data=payload,
            metadata={
                "approval_hook": True,
                "user_id": request.context.user_id,
                "workspace_id": request.context.workspace_id,
                "request_id": request.context.request_id,
            },
        )

    def _prepare_verification_payload(
        self,
        *,
        request: FraudAnalysisRequest,
        analysis: FraudAnalysisData,
    ) -> Dict[str, Any]:
        """
        Prepare a Verification Agent payload.

        Verification Agent can independently check evidence coverage, score
        consistency, redaction, and whether required escalation was prepared.
        """

        return {
            "verification_type": "fraud_analysis_completed",
            "agent": self.AGENT_ID,
            "module": self.MODULE,
            "version": self.VERSION,
            "analysis_id": analysis.analysis_id,
            "user_id": request.context.user_id,
            "workspace_id": request.context.workspace_id,
            "request_id": request.context.request_id,
            "task_id": request.context.task_id,
            "source_id": request.source_id,
            "checks": {
                "analysis_completed": (
                    analysis.status == AnalysisStatus.COMPLETED.value
                ),
                "score_in_valid_range": (
                    0.0 <= analysis.risk_score <= 100.0
                ),
                "risk_level_present": bool(analysis.risk_level),
                "explanation_present": bool(analysis.explanation),
                "indicator_count": len(analysis.indicators),
                "categories_present": bool(analysis.categories),
                "approval_consistent": (
                    analysis.approval_required
                    == (
                        analysis.risk_score
                        >= self.config.high_risk_approval_threshold
                    )
                ),
                "source_hash_present": bool(analysis.source_hash),
                "sensitive_preview_redacted": (
                    analysis.redacted_preview is None
                    or not self._contains_obvious_secret(
                        analysis.redacted_preview
                    )
                ),
            },
            "risk_score": analysis.risk_score,
            "risk_level": analysis.risk_level,
            "primary_category": analysis.primary_category,
            "recommendations": analysis.recommendations,
            "created_at": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        *,
        request: FraudAnalysisRequest,
        analysis: FraudAnalysisData,
    ) -> Dict[str, Any]:
        """
        Prepare a privacy-conscious Memory Agent payload.

        The payload stores fraud patterns, decisions, and safe metadata. It does
        not intentionally store raw credentials, authentication codes, card
        numbers, private keys, or complete bank details.
        """

        safe_indicators = []

        for item in analysis.indicators:
            safe_indicators.append(
                {
                    "code": item.get("code"),
                    "category": item.get("category"),
                    "severity": item.get("severity"),
                    "score": item.get("score"),
                    "title": item.get("title"),
                    "description": item.get("description"),
                    "source": item.get("source"),
                    "confidence": item.get("confidence"),
                }
            )

        return {
            "memory_payload_type": "security_fraud_analysis",
            "retention_recommendation": (
                "security_pattern"
                if analysis.is_suspicious
                else "short_term_only"
            ),
            "agent": self.AGENT_ID,
            "module": self.MODULE,
            "analysis_id": analysis.analysis_id,
            "user_id": request.context.user_id,
            "workspace_id": request.context.workspace_id,
            "request_id": request.context.request_id,
            "task_id": request.context.task_id,
            "session_id": request.context.session_id,
            "source_agent": request.context.source_agent,
            "source_id": request.source_id,
            "project_id": request.project_id,
            "client_id": request.client_id,
            "input_type": analysis.input_type,
            "risk_score": analysis.risk_score,
            "risk_level": analysis.risk_level,
            "primary_category": analysis.primary_category,
            "categories": analysis.categories,
            "indicators": safe_indicators,
            "recommendations": analysis.recommendations,
            "source_hash": analysis.source_hash,
            "redacted_preview": analysis.redacted_preview,
            "privacy_level": request.privacy_level,
            "metadata": {
                "is_suspicious": analysis.is_suspicious,
                "is_likely_fraud": analysis.is_likely_fraud,
                "approval_required": analysis.approval_required,
                "payment_hold_recommended": (
                    analysis.payment_hold_recommended
                ),
                "credential_entry_block_recommended": (
                    analysis.credential_entry_block_recommended
                ),
                "created_at": self._utc_now(),
            },
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Emit an event for Master Agent, Dashboard, analytics, or event bus.
        """

        if not self.config.emit_agent_events:
            return

        safe_payload = self._sanitize_log_payload(payload)

        try:
            parent_emit = getattr(super(), "emit_event", None)

            if callable(parent_emit):
                parent_emit(event_name, safe_payload)
            else:
                self.logger.debug(
                    "Agent event %s: %s",
                    event_name,
                    json.dumps(safe_payload, default=str)[:4_000],
                )
        except Exception as exc:
            self.logger.debug(
                "Unable to emit agent event %s: %s",
                event_name,
                exc,
            )

    def _log_audit_event(
        self,
        action: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Write a sanitized audit event.

        Sensitive source material is excluded from audit logs.
        """

        if not self.config.emit_audit_events:
            return

        audit_payload = {
            "action": action,
            "agent": self.AGENT_ID,
            "module": self.MODULE,
            "version": self.VERSION,
            "created_at": self._utc_now(),
            **self._sanitize_log_payload(payload),
        }

        try:
            parent_audit = getattr(super(), "log_audit", None)

            if callable(parent_audit):
                parent_audit(audit_payload)
            else:
                self.logger.info(
                    "Fraud audit event: %s",
                    json.dumps(audit_payload, default=str)[:5_000],
                )
        except Exception as exc:
            self.logger.debug(
                "Unable to write audit event: %s",
                exc,
            )

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis success response.
        """

        return {
            "success": True,
            "message": message,
            "data": data if data is not None else {},
            "error": None,
            "metadata": {
                "agent": self.AGENT_ID,
                "module": self.MODULE,
                "version": self.VERSION,
                "timestamp": self._utc_now(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Union[str, Exception],
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis error response.
        """

        error_text = str(error)

        self.logger.error(
            "%s: %s",
            message,
            error_text,
        )

        return {
            "success": False,
            "message": message,
            "data": data if data is not None else {},
            "error": {
                "type": (
                    error.__class__.__name__
                    if isinstance(error, Exception)
                    else "FraudDetectorError"
                ),
                "message": error_text,
            },
            "metadata": {
                "agent": self.AGENT_ID,
                "module": self.MODULE,
                "version": self.VERSION,
                "timestamp": self._utc_now(),
                **(metadata or {}),
            },
        }

    # =========================================================================
    # Main public interface
    # =========================================================================

    def detect(
        self,
        request: Union[FraudAnalysisRequest, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Alias for analyze(), intended for Agent Router compatibility.
        """

        return self.analyze(request)

    def analyze(
        self,
        request: Union[FraudAnalysisRequest, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Run complete fraud analysis.

        The method automatically chooses relevant detectors based on input type
        and available fields.
        """

        started_at = time.perf_counter()
        analysis_id = str(uuid.uuid4())

        try:
            parsed_request = self._parse_request(request)

            valid, context, context_error = self._validate_task_context(
                parsed_request.context
            )

            if not valid or context is None:
                return self._error_result(
                    message="Fraud analysis rejected because context is invalid.",
                    error=context_error or "Invalid task context.",
                )

            parsed_request.context = context

            validation_error = self._validate_request(parsed_request)

            if validation_error:
                return self._error_result(
                    message="Fraud analysis request is invalid.",
                    error=validation_error,
                    metadata={
                        "user_id": context.user_id,
                        "workspace_id": context.workspace_id,
                        "request_id": context.request_id,
                    },
                )

            detected_input_type = self._resolve_input_type(parsed_request)
            parsed_request.input_type = detected_input_type

            self._emit_agent_event(
                "security.fraud_detector.started",
                {
                    "analysis_id": analysis_id,
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "task_id": context.task_id,
                    "input_type": detected_input_type.value,
                    "source_id": parsed_request.source_id,
                },
            )

            indicators: List[FraudIndicator] = []

            combined_text = self._build_combined_text(parsed_request)

            if combined_text:
                indicators.extend(
                    self._analyze_language_patterns(
                        combined_text,
                        parsed_request,
                    )
                )

            indicators.extend(
                self._analyze_sender_identity(parsed_request)
            )

            all_urls = self._collect_urls(parsed_request, combined_text)

            for url in all_urls:
                indicators.extend(
                    self._analyze_url_indicators(
                        url=url,
                        request=parsed_request,
                    )
                )

            if parsed_request.html:
                indicators.extend(
                    self._analyze_html_indicators(parsed_request)
                )

            if (
                parsed_request.form_fields
                or parsed_request.form_actions
                or detected_input_type
                == FraudInputType.LOGIN_PAGE
            ):
                indicators.extend(
                    self._analyze_login_form_indicators(
                        parsed_request
                    )
                )

            if parsed_request.attachments:
                indicators.extend(
                    self._analyze_attachment_indicators(
                        parsed_request.attachments
                    )
                )

            if (
                parsed_request.invoice_data
                or detected_input_type == FraudInputType.INVOICE
            ):
                indicators.extend(
                    self._analyze_invoice_indicators(
                        parsed_request
                    )
                )

            if (
                parsed_request.payment_data
                or detected_input_type
                in {
                    FraudInputType.PAYMENT_REQUEST,
                    FraudInputType.QR_PAYMENT,
                }
            ):
                indicators.extend(
                    self._analyze_payment_indicators(
                        parsed_request
                    )
                )

            indicators = self._deduplicate_indicators(indicators)
            indicators = indicators[: self.config.maximum_indicators]

            risk_score = self._calculate_risk_score(indicators)
            risk_level = self._score_to_risk_level(risk_score)

            categories = self._rank_categories(indicators)
            primary_category = categories[0] if categories else None

            confidence = self._calculate_confidence(
                request=parsed_request,
                indicators=indicators,
            )

            recommendations = self._build_recommendations(
                risk_score=risk_score,
                risk_level=risk_level,
                categories=categories,
                indicators=indicators,
                request=parsed_request,
            )

            approval_required = (
                risk_score
                >= self.config.high_risk_approval_threshold
            )

            payment_hold_recommended = bool(
                risk_score >= self.config.payment_hold_threshold
                and self._has_payment_context(parsed_request)
            )

            credential_block_recommended = bool(
                risk_score >= self.config.credential_block_threshold
                and self._has_credential_context(
                    parsed_request,
                    indicators,
                )
            )

            link_block_recommended = bool(
                risk_score >= self.config.high_risk_threshold
                and all_urls
            )

            attachment_block_recommended = bool(
                any(
                    indicator.code
                    in {
                        "suspicious_attachment",
                        "double_extension",
                        "macro_attachment",
                    }
                    and indicator.severity
                    in {
                        IndicatorSeverity.HIGH,
                        IndicatorSeverity.CRITICAL,
                    }
                    for indicator in indicators
                )
            )

            source_hash = (
                self._build_source_hash(parsed_request)
                if self.config.include_source_hash
                else None
            )

            redacted_preview = self._build_redacted_preview(
                parsed_request
            )

            extracted_entities = self._extract_entities(
                parsed_request,
                all_urls,
            )

            explanation = self._build_explanation(
                risk_score=risk_score,
                risk_level=risk_level,
                categories=categories,
                indicators=indicators,
            )

            limitations = self._build_limitations(parsed_request)

            elapsed_ms = round(
                (time.perf_counter() - started_at) * 1000,
                2,
            )

            analysis_data = FraudAnalysisData(
                analysis_id=analysis_id,
                status=AnalysisStatus.COMPLETED.value,
                input_type=detected_input_type.value,
                risk_score=risk_score,
                risk_level=risk_level.value,
                confidence=confidence.value,
                is_suspicious=(
                    risk_score >= self.config.medium_risk_threshold
                ),
                is_likely_fraud=(
                    risk_score >= self.config.high_risk_threshold
                ),
                primary_category=primary_category,
                categories=categories,
                indicators=[
                    self._indicator_to_dict(item)
                    for item in indicators
                ],
                recommendations=recommendations,
                approval_required=approval_required,
                payment_hold_recommended=payment_hold_recommended,
                credential_entry_block_recommended=(
                    credential_block_recommended
                ),
                link_click_block_recommended=link_block_recommended,
                attachment_open_block_recommended=(
                    attachment_block_recommended
                ),
                extracted_entities=extracted_entities,
                source_hash=source_hash,
                redacted_preview=redacted_preview,
                explanation=explanation,
                limitations=limitations,
                metadata={
                    "indicator_count": len(indicators),
                    "url_count": len(all_urls),
                    "attachment_count": len(
                        parsed_request.attachments
                    ),
                    "elapsed_ms": elapsed_ms,
                    "analyzed_at": self._utc_now(),
                    "detector_version": self.VERSION,
                },
            )

            verification_payload = self._prepare_verification_payload(
                request=parsed_request,
                analysis=analysis_data,
            )

            memory_payload = self._prepare_memory_payload(
                request=parsed_request,
                analysis=analysis_data,
            )

            approval_payload: Optional[Dict[str, Any]] = None

            if self._requires_security_check(
                parsed_request,
                analysis_data,
            ):
                approval_payload = self._request_security_approval(
                    request=parsed_request,
                    analysis=analysis_data,
                    reason=(
                        "High-risk fraud indicators require independent "
                        "security review before credentials, payment, or "
                        "external action."
                    ),
                    requested_action=(
                        "review_and_authorize_next_security_action"
                    ),
                ).get("data")

            self._log_audit_event(
                "fraud_analysis_completed",
                {
                    "analysis_id": analysis_id,
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "task_id": context.task_id,
                    "source_id": parsed_request.source_id,
                    "input_type": detected_input_type.value,
                    "risk_score": risk_score,
                    "risk_level": risk_level.value,
                    "primary_category": primary_category,
                    "categories": categories,
                    "indicator_codes": [
                        item.code for item in indicators
                    ],
                    "approval_required": approval_required,
                    "payment_hold_recommended": (
                        payment_hold_recommended
                    ),
                    "elapsed_ms": elapsed_ms,
                    "source_hash": source_hash,
                },
            )

            self._emit_agent_event(
                "security.fraud_detector.completed",
                {
                    "analysis_id": analysis_id,
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "risk_score": risk_score,
                    "risk_level": risk_level.value,
                    "primary_category": primary_category,
                    "approval_required": approval_required,
                    "elapsed_ms": elapsed_ms,
                },
            )

            return self._safe_result(
                message="Fraud analysis completed successfully.",
                data={
                    "analysis": asdict(analysis_data),
                    "approval_payload": approval_payload,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "analysis_id": analysis_id,
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "risk_score": risk_score,
                    "risk_level": risk_level.value,
                    "elapsed_ms": elapsed_ms,
                },
            )

        except Exception as exc:
            self._emit_agent_event(
                "security.fraud_detector.failed",
                {
                    "analysis_id": analysis_id,
                    "error_type": exc.__class__.__name__,
                    "error": str(exc)[:500],
                },
            )

            return self._error_result(
                message="Fraud analysis failed.",
                error=exc,
                metadata={"analysis_id": analysis_id},
            )

    # =========================================================================
    # Convenience public methods
    # =========================================================================

    def analyze_text(
        self,
        text: str,
        *,
        user_id: str,
        workspace_id: str,
        input_type: FraudInputType = FraudInputType.MESSAGE,
        subject: Optional[str] = None,
        sender: Optional[str] = None,
        expected_brand: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze plain text, SMS, chat, or document content.
        """

        request = FraudAnalysisRequest(
            context=TaskContext(
                user_id=user_id,
                workspace_id=workspace_id,
            ),
            input_type=input_type,
            text=text,
            subject=subject,
            sender=sender,
            expected_brand=expected_brand,
            metadata=metadata or {},
        )

        return self.analyze(request)

    def analyze_email(
        self,
        *,
        user_id: str,
        workspace_id: str,
        subject: str,
        body: str,
        sender: Optional[str] = None,
        sender_display_name: Optional[str] = None,
        reply_to: Optional[str] = None,
        recipients: Optional[Sequence[str]] = None,
        attachments: Optional[
            Sequence[Union[AttachmentMetadata, Dict[str, Any]]]
        ] = None,
        expected_sender_domain: Optional[str] = None,
        known_vendor_domains: Optional[Sequence[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze a suspicious email without opening links or attachments.
        """

        request = FraudAnalysisRequest(
            context=TaskContext(
                user_id=user_id,
                workspace_id=workspace_id,
            ),
            input_type=FraudInputType.EMAIL,
            text=body,
            subject=subject,
            sender=sender,
            sender_display_name=sender_display_name,
            reply_to=reply_to,
            recipients=list(recipients or []),
            attachments=self._parse_attachments(
                attachments or []
            ),
            expected_sender_domain=expected_sender_domain,
            known_vendor_domains=list(
                known_vendor_domains or []
            ),
            metadata=metadata or {},
        )

        return self.analyze(request)

    def analyze_url(
        self,
        url: str,
        *,
        user_id: str,
        workspace_id: str,
        visible_url: Optional[str] = None,
        final_url: Optional[str] = None,
        redirect_chain: Optional[Sequence[str]] = None,
        expected_brand: Optional[str] = None,
        expected_domain: Optional[str] = None,
        page_title: Optional[str] = None,
        page_text: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze URL structure and supplied page metadata.

        This method does not visit the URL.
        """

        request = FraudAnalysisRequest(
            context=TaskContext(
                user_id=user_id,
                workspace_id=workspace_id,
            ),
            input_type=FraudInputType.URL,
            text=page_text or "",
            url=url,
            visible_url=visible_url,
            final_url=final_url,
            redirect_chain=list(redirect_chain or []),
            expected_brand=expected_brand,
            expected_domain=expected_domain,
            page_title=page_title,
            metadata=metadata or {},
        )

        return self.analyze(request)

    def analyze_login_page(
        self,
        *,
        user_id: str,
        workspace_id: str,
        url: str,
        page_title: Optional[str] = None,
        visible_text: str = "",
        html: Optional[str] = None,
        form_actions: Optional[Sequence[str]] = None,
        form_fields: Optional[Sequence[str]] = None,
        expected_brand: Optional[str] = None,
        expected_domain: Optional[str] = None,
        final_url: Optional[str] = None,
        redirect_chain: Optional[Sequence[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze a login page supplied by Browser Agent or Visual Agent.
        """

        request = FraudAnalysisRequest(
            context=TaskContext(
                user_id=user_id,
                workspace_id=workspace_id,
            ),
            input_type=FraudInputType.LOGIN_PAGE,
            text=visible_text,
            url=url,
            final_url=final_url,
            redirect_chain=list(redirect_chain or []),
            html=html,
            page_title=page_title,
            form_actions=list(form_actions or []),
            form_fields=list(form_fields or []),
            expected_brand=expected_brand,
            expected_domain=expected_domain,
            metadata=metadata or {},
        )

        return self.analyze(request)

    def analyze_invoice(
        self,
        invoice_data: Dict[str, Any],
        *,
        user_id: str,
        workspace_id: str,
        invoice_text: str = "",
        sender: Optional[str] = None,
        known_vendor: Optional[str] = None,
        known_vendor_domains: Optional[Sequence[str]] = None,
        known_bank_accounts: Optional[Sequence[str]] = None,
        historical_data: Optional[Dict[str, Any]] = None,
        attachments: Optional[
            Sequence[Union[AttachmentMetadata, Dict[str, Any]]]
        ] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze invoice details for manipulation and payment fraud.
        """

        request = FraudAnalysisRequest(
            context=TaskContext(
                user_id=user_id,
                workspace_id=workspace_id,
            ),
            input_type=FraudInputType.INVOICE,
            text=invoice_text,
            sender=sender,
            invoice_data=self._safe_dict(invoice_data),
            historical_data=self._safe_dict(
                historical_data
            ),
            known_vendor=known_vendor,
            known_vendor_domains=list(
                known_vendor_domains or []
            ),
            known_bank_accounts=list(
                known_bank_accounts or []
            ),
            attachments=self._parse_attachments(
                attachments or []
            ),
            metadata=metadata or {},
        )

        return self.analyze(request)

    def analyze_payment_request(
        self,
        payment_data: Dict[str, Any],
        *,
        user_id: str,
        workspace_id: str,
        message_text: str = "",
        sender: Optional[str] = None,
        known_vendor: Optional[str] = None,
        known_bank_accounts: Optional[Sequence[str]] = None,
        historical_data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze payment instructions before Finance Agent or a user acts.
        """

        request = FraudAnalysisRequest(
            context=TaskContext(
                user_id=user_id,
                workspace_id=workspace_id,
            ),
            input_type=FraudInputType.PAYMENT_REQUEST,
            text=message_text,
            sender=sender,
            payment_data=self._safe_dict(payment_data),
            historical_data=self._safe_dict(
                historical_data
            ),
            known_vendor=known_vendor,
            known_bank_accounts=list(
                known_bank_accounts or []
            ),
            metadata=metadata or {},
        )

        return self.analyze(request)

    def analyze_attachments(
        self,
        attachments: Sequence[
            Union[AttachmentMetadata, Dict[str, Any]]
        ],
        *,
        user_id: str,
        workspace_id: str,
        message_text: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze supplied attachment metadata without opening attachments.
        """

        request = FraudAnalysisRequest(
            context=TaskContext(
                user_id=user_id,
                workspace_id=workspace_id,
            ),
            input_type=FraudInputType.DOCUMENT,
            text=message_text,
            attachments=self._parse_attachments(
                attachments
            ),
            metadata=metadata or {},
        )

        return self.analyze(request)

    def compare_domains(
        self,
        observed_domain: str,
        expected_domain: str,
    ) -> Dict[str, Any]:
        """
        Compare two domains for exact match, subdomain relationship, or
        lookalike risk.
        """

        try:
            observed = self._normalize_domain(observed_domain)
            expected = self._normalize_domain(expected_domain)

            if not observed or not expected:
                return self._error_result(
                    message="Domain comparison failed.",
                    error="Both observed_domain and expected_domain are required.",
                )

            exact_match = observed == expected
            legitimate_subdomain = observed.endswith(
                f".{expected}"
            )
            expected_subdomain_of_observed = expected.endswith(
                f".{observed}"
            )

            distance = self._levenshtein_distance(
                self._registrable_label(observed),
                self._registrable_label(expected),
            )

            similarity = self._string_similarity(
                self._registrable_label(observed),
                self._registrable_label(expected),
            )

            suspicious_lookalike = bool(
                not exact_match
                and not legitimate_subdomain
                and (
                    distance <= 2
                    or similarity >= 0.82
                    or self._contains_homoglyph_pattern(
                        observed,
                        expected,
                    )
                )
            )

            return self._safe_result(
                message="Domain comparison completed.",
                data={
                    "observed_domain": observed,
                    "expected_domain": expected,
                    "exact_match": exact_match,
                    "legitimate_subdomain": legitimate_subdomain,
                    "expected_subdomain_of_observed": (
                        expected_subdomain_of_observed
                    ),
                    "levenshtein_distance": distance,
                    "similarity": round(similarity, 4),
                    "suspicious_lookalike": (
                        suspicious_lookalike
                    ),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Domain comparison failed.",
                error=exc,
            )

    def health_check(self) -> Dict[str, Any]:
        """
        Lightweight health endpoint for Dashboard/API.
        """

        return self._safe_result(
            message="FraudDetector is healthy.",
            data={
                "agent_name": self.AGENT_NAME,
                "agent_id": self.AGENT_ID,
                "module": self.MODULE,
                "version": self.VERSION,
                "file_path": self.FILE_PATH,
                "external_network_calls": False,
                "destructive_actions": False,
                "supported_input_types": [
                    item.value for item in FraudInputType
                ],
                "risk_thresholds": {
                    "low": self.config.low_risk_threshold,
                    "medium": self.config.medium_risk_threshold,
                    "high": self.config.high_risk_threshold,
                    "critical": (
                        self.config.critical_risk_threshold
                    ),
                },
            },
        )

    def get_registry_metadata(self) -> Dict[str, Any]:
        """
        Metadata for Agent Registry, Agent Loader, and Agent Router.
        """

        return {
            "agent_name": self.AGENT_NAME,
            "agent_id": self.AGENT_ID,
            "class_name": self.__class__.__name__,
            "module": self.MODULE,
            "version": self.VERSION,
            "file_path": self.FILE_PATH,
            "description": (
                "Detects scams, phishing, fake login pages, suspicious "
                "invoices, payment redirection, and financial fraud."
            ),
            "capabilities": [
                "detect_phishing",
                "detect_fake_login_page",
                "analyze_suspicious_url",
                "detect_domain_spoofing",
                "detect_brand_impersonation",
                "detect_business_email_compromise",
                "detect_invoice_fraud",
                "detect_payment_redirection",
                "detect_suspicious_attachments",
                "detect_credential_theft",
                "prepare_security_approval",
                "prepare_verification_payload",
                "prepare_memory_payload",
                "emit_audit_event",
            ],
            "supported_input_types": [
                item.value for item in FraudInputType
            ],
            "requires_user_context": True,
            "requires_workspace_context": True,
            "requires_network": False,
            "performs_external_actions": False,
            "performs_financial_actions": False,
            "safe_to_import": True,
            "router_methods": {
                "default": "analyze",
                "detect": "detect",
                "email": "analyze_email",
                "url": "analyze_url",
                "login_page": "analyze_login_page",
                "invoice": "analyze_invoice",
                "payment": "analyze_payment_request",
            },
        }

    # =========================================================================
    # Request parsing and validation
    # =========================================================================

    def _parse_request(
        self,
        request: Union[FraudAnalysisRequest, Dict[str, Any]],
    ) -> FraudAnalysisRequest:
        """
        Convert dictionary input to FraudAnalysisRequest.
        """

        if isinstance(request, FraudAnalysisRequest):
            return request

        if not isinstance(request, dict):
            raise TypeError(
                "Request must be FraudAnalysisRequest or dictionary."
            )

        context_raw = request.get("context") or {
            "user_id": request.get("user_id"),
            "workspace_id": request.get("workspace_id"),
            "request_id": request.get("request_id"),
            "task_id": request.get("task_id"),
            "session_id": request.get("session_id"),
            "source_agent": request.get("source_agent"),
            "actor_id": request.get("actor_id"),
            "actor_role": request.get("actor_role"),
            "permissions": request.get("permissions"),
            "subscription_tier": request.get(
                "subscription_tier"
            ),
            "metadata": request.get("context_metadata"),
        }

        valid, context, context_error = self._validate_task_context(
            context_raw
        )

        if not valid or context is None:
            raise ValueError(
                context_error or "Invalid task context."
            )

        input_type = self._coerce_enum(
            FraudInputType,
            request.get("input_type"),
            FraudInputType.AUTO,
        )

        return FraudAnalysisRequest(
            context=context,
            input_type=input_type,
            text=str(request.get("text") or ""),
            subject=self._optional_string(
                request.get("subject")
            ),
            sender=self._optional_string(
                request.get("sender")
            ),
            sender_display_name=self._optional_string(
                request.get("sender_display_name")
            ),
            reply_to=self._optional_string(
                request.get("reply_to")
            ),
            recipients=self._normalize_string_list(
                request.get("recipients")
            ),
            url=self._optional_string(request.get("url")),
            visible_url=self._optional_string(
                request.get("visible_url")
            ),
            final_url=self._optional_string(
                request.get("final_url")
            ),
            redirect_chain=self._normalize_string_list(
                request.get("redirect_chain")
            ),
            html=self._optional_string(request.get("html")),
            page_title=self._optional_string(
                request.get("page_title")
            ),
            form_actions=self._normalize_string_list(
                request.get("form_actions")
            ),
            form_fields=self._normalize_string_list(
                request.get("form_fields")
            ),
            attachments=self._parse_attachments(
                request.get("attachments") or []
            ),
            invoice_data=self._safe_dict(
                request.get("invoice_data")
            ),
            payment_data=self._safe_dict(
                request.get("payment_data")
            ),
            historical_data=self._safe_dict(
                request.get("historical_data")
            ),
            expected_brand=self._optional_string(
                request.get("expected_brand")
            ),
            expected_domain=self._optional_string(
                request.get("expected_domain")
            ),
            expected_sender_domain=self._optional_string(
                request.get("expected_sender_domain")
            ),
            known_vendor=self._optional_string(
                request.get("known_vendor")
            ),
            known_vendor_domains=self._normalize_string_list(
                request.get("known_vendor_domains")
            ),
            known_bank_accounts=self._normalize_string_list(
                request.get("known_bank_accounts")
            ),
            source_id=self._optional_string(
                request.get("source_id")
            ),
            project_id=self._optional_string(
                request.get("project_id")
            ),
            client_id=self._optional_string(
                request.get("client_id")
            ),
            privacy_level=str(
                request.get("privacy_level") or "private"
            ),
            metadata=self._safe_dict(
                request.get("metadata")
            ),
        )

    def _validate_request(
        self,
        request: FraudAnalysisRequest,
    ) -> Optional[str]:
        """
        Validate input sizes and required content.
        """

        has_content = any(
            [
                request.text.strip(),
                request.subject,
                request.sender,
                request.url,
                request.visible_url,
                request.final_url,
                request.html,
                request.page_title,
                request.form_actions,
                request.form_fields,
                request.attachments,
                request.invoice_data,
                request.payment_data,
            ]
        )

        if not has_content:
            return (
                "At least one text, URL, HTML, form, attachment, invoice, "
                "or payment field is required."
            )

        if len(request.text) > self.config.maximum_text_characters:
            return (
                "Text exceeds maximum allowed length of "
                f"{self.config.maximum_text_characters} characters."
            )

        if (
            request.html
            and len(request.html)
            > self.config.maximum_html_characters
        ):
            return (
                "HTML exceeds maximum allowed length of "
                f"{self.config.maximum_html_characters} characters."
            )

        for url in (
            request.url,
            request.visible_url,
            request.final_url,
            *request.redirect_chain,
            *request.form_actions,
        ):
            if (
                url
                and len(url)
                > self.config.maximum_url_characters
            ):
                return (
                    "A URL exceeds maximum allowed length of "
                    f"{self.config.maximum_url_characters} characters."
                )

        if (
            len(request.attachments)
            > self.config.maximum_attachments
        ):
            return (
                "Attachment count exceeds maximum allowed count of "
                f"{self.config.maximum_attachments}."
            )

        return None

    def _resolve_input_type(
        self,
        request: FraudAnalysisRequest,
    ) -> FraudInputType:
        """
        Infer input type when AUTO is supplied.
        """

        if request.input_type != FraudInputType.AUTO:
            return request.input_type

        if request.invoice_data:
            return FraudInputType.INVOICE

        if request.payment_data:
            return FraudInputType.PAYMENT_REQUEST

        if request.form_fields or request.form_actions:
            return FraudInputType.LOGIN_PAGE

        if request.html and self._html_has_login_form(
            request.html
        ):
            return FraudInputType.LOGIN_PAGE

        if request.subject or request.sender or request.reply_to:
            return FraudInputType.EMAIL

        if request.url or request.final_url:
            return FraudInputType.URL

        if request.attachments:
            return FraudInputType.DOCUMENT

        if request.text:
            return FraudInputType.MESSAGE

        return FraudInputType.UNKNOWN

    # =========================================================================
    # Language and social-engineering analysis
    # =========================================================================

    def _analyze_language_patterns(
        self,
        text: str,
        request: FraudAnalysisRequest,
    ) -> List[FraudIndicator]:
        """
        Analyze text for scam and social-engineering language.
        """

        normalized = self._normalize_text(text)
        indicators: List[FraudIndicator] = []

        pattern_groups: List[
            Tuple[
                str,
                FraudCategory,
                IndicatorSeverity,
                str,
                str,
                Sequence[str],
                float,
            ]
        ] = [
            (
                "credential_request",
                FraudCategory.CREDENTIAL_THEFT,
                IndicatorSeverity.HIGH,
                "Credential or verification-code request",
                (
                    "The content appears to request passwords, login details, "
                    "authentication codes, PINs, recovery codes, seed phrases, "
                    "or other sensitive credentials."
                ),
                (
                    r"\b(send|share|provide|confirm|enter|reply with)\b.{0,45}"
                    r"\b(password|passcode|pin|otp|verification code|"
                    r"security code|recovery code|login details|credentials)\b",
                    r"\b(seed phrase|recovery phrase|private key)\b",
                    r"\bverify your (account|identity)\b.{0,60}"
                    r"\b(password|code|login|credential)\b",
                ),
                self._weight("credential_request"),
            ),
            (
                "urgent_language",
                FraudCategory.SOCIAL_ENGINEERING,
                IndicatorSeverity.MEDIUM,
                "Artificial urgency",
                (
                    "The message uses urgency intended to reduce careful "
                    "verification."
                ),
                (
                    r"\bimmediately\b",
                    r"\burgent\b",
                    r"\bact now\b",
                    r"\bwithin (?:the next )?\d+\s*(minutes?|hours?)\b",
                    r"\btoday only\b",
                    r"\bfinal warning\b",
                    r"\btime sensitive\b",
                    r"\bwithout delay\b",
                ),
                self._weight("urgent_language"),
            ),
            (
                "threat_language",
                FraudCategory.SOCIAL_ENGINEERING,
                IndicatorSeverity.HIGH,
                "Threat or account-pressure language",
                (
                    "The content threatens suspension, closure, legal action, "
                    "loss, or penalties to force a response."
                ),
                (
                    r"\b(account|service|access)\b.{0,30}"
                    r"\b(suspended|disabled|closed|terminated|locked)\b",
                    r"\blegal action\b",
                    r"\bwarrant\b",
                    r"\barrest\b",
                    r"\bpenalt(?:y|ies)\b",
                    r"\bfunds? (?:will be )?(?:lost|frozen|seized)\b",
                    r"\bfailed verification\b",
                ),
                self._weight("threat_language"),
            ),
            (
                "secrecy_request",
                FraudCategory.BUSINESS_EMAIL_COMPROMISE,
                IndicatorSeverity.HIGH,
                "Request for secrecy or bypassing procedure",
                (
                    "The sender asks the recipient to keep the request secret "
                    "or bypass normal approval procedures."
                ),
                (
                    r"\bkeep (?:this|it) (?:strictly )?"
                    r"(?:confidential|secret|between us)\b",
                    r"\bdo not (?:tell|contact|inform|call)\b",
                    r"\bbypass\b.{0,30}\b(approval|procedure|policy)\b",
                    r"\bno need (?:for|to get) approval\b",
                    r"\bdon't discuss\b",
                ),
                self._weight("secrecy_request"),
            ),
            (
                "payment_change",
                FraudCategory.PAYMENT_REDIRECTION,
                IndicatorSeverity.HIGH,
                "Changed payment instructions",
                (
                    "The content announces new or changed payment details, a "
                    "common business-email-compromise pattern."
                ),
                (
                    r"\b(new|updated|different|replacement|changed)\b.{0,40}"
                    r"\b(bank|account|payment|wire|iban|routing)\b",
                    r"\bdo not use\b.{0,50}\b(previous|old)\b.{0,20}"
                    r"\b(account|details)\b",
                    r"\bpayment details have changed\b",
                    r"\bremit to (?:the )?new\b",
                ),
                self._weight("payment_change"),
            ),
            (
                "bank_change",
                FraudCategory.INVOICE_FRAUD,
                IndicatorSeverity.CRITICAL,
                "Bank-account redirection request",
                (
                    "The message directs payment to a new bank account or asks "
                    "for payment-detail changes."
                ),
                (
                    r"\bupdate\b.{0,30}\bbeneficiary\b",
                    r"\bnew bank account\b",
                    r"\bnew iban\b",
                    r"\bnew routing number\b",
                    r"\bchanged beneficiary\b",
                    r"\buse this account instead\b",
                ),
                self._weight("bank_change"),
            ),
            (
                "gift_card",
                FraudCategory.GIFT_CARD_SCAM,
                IndicatorSeverity.CRITICAL,
                "Gift-card payment request",
                (
                    "The sender requests gift cards or gift-card codes, a "
                    "high-confidence scam indicator."
                ),
                (
                    r"\b(gift card|itunes card|apple card|google play card|"
                    r"steam card|amazon card)\b",
                    r"\bscratch.{0,30}\bcode\b",
                    r"\bsend.{0,30}\bgift card.{0,30}\bcode\b",
                ),
                self._weight("gift_card"),
            ),
            (
                "crypto_payment",
                FraudCategory.CRYPTO_SCAM,
                IndicatorSeverity.HIGH,
                "Cryptocurrency payment request",
                (
                    "The content requests cryptocurrency or wallet transfers "
                    "in a suspicious context."
                ),
                (
                    r"\b(send|transfer|pay)\b.{0,35}"
                    r"\b(bitcoin|btc|ethereum|eth|usdt|crypto)\b",
                    r"\bwallet address\b",
                    r"\bguaranteed crypto returns?\b",
                    r"\bdouble your (bitcoin|crypto|investment)\b",
                ),
                self._weight("crypto_payment"),
            ),
            (
                "advance_fee",
                FraudCategory.ADVANCE_FEE_SCAM,
                IndicatorSeverity.HIGH,
                "Advance-fee scam pattern",
                (
                    "The content promises money, prizes, inheritance, loans, "
                    "or returns after an upfront fee."
                ),
                (
                    r"\b(upfront|processing|release|clearance|administrative)"
                    r" fee\b",
                    r"\bpay.{0,40}\b(?:to )?(?:release|unlock|claim)\b",
                    r"\binheritance\b.{0,80}\bfee\b",
                    r"\bloan approved\b.{0,80}\bfee\b",
                    r"\bclaim your prize\b",
                    r"\blottery winner\b",
                ),
                self._weight("advance_fee"),
            ),
            (
                "remote_access",
                FraudCategory.TECH_SUPPORT_SCAM,
                IndicatorSeverity.CRITICAL,
                "Remote-access request",
                (
                    "The message asks the recipient to install remote-control "
                    "software or grant device access."
                ),
                (
                    r"\b(anydesk|teamviewer|ultraviewer|screenconnect|"
                    r"logmein|remote desktop|quicksupport)\b",
                    r"\bgrant (?:me|us) remote access\b",
                    r"\bshare your screen\b",
                    r"\binstall.{0,30}\bremote access\b",
                ),
                self._weight("remote_access"),
            ),
            (
                "refund_overpayment",
                FraudCategory.REFUND_SCAM,
                IndicatorSeverity.HIGH,
                "Refund or overpayment manipulation",
                (
                    "The content describes an accidental overpayment or asks "
                    "the recipient to return excess funds."
                ),
                (
                    r"\boverpaid\b",
                    r"\baccidental(?:ly)? transferred\b",
                    r"\brefund the difference\b",
                    r"\breturn the excess\b",
                    r"\bwrong refund amount\b",
                ),
                self._weight("refund_overpayment"),
            ),
            (
                "account_verification",
                FraudCategory.IDENTITY_VERIFICATION_SCAM,
                IndicatorSeverity.HIGH,
                "Suspicious identity-verification request",
                (
                    "The content requests identity documents or account "
                    "verification in a potentially deceptive context."
                ),
                (
                    r"\bverify your identity\b",
                    r"\bupload.{0,40}\b(passport|driver'?s license|id card)\b",
                    r"\bconfirm your personal information\b",
                    r"\bkyc verification\b",
                ),
                self._weight("account_verification"),
            ),
            (
                "fake_security_warning",
                FraudCategory.TECH_SUPPORT_SCAM,
                IndicatorSeverity.HIGH,
                "Fake security-warning language",
                (
                    "The content claims the device or account is infected, "
                    "compromised, or under immediate attack."
                ),
                (
                    r"\bvirus detected\b",
                    r"\byour device is infected\b",
                    r"\bsecurity breach detected\b",
                    r"\bhackers? (?:have|has) access\b",
                    r"\bcall (?:microsoft|apple|support) now\b",
                ),
                self._weight("fake_security_warning"),
            ),
        ]

        for (
            code,
            category,
            severity,
            title,
            description,
            patterns,
            score,
        ) in pattern_groups:
            match = self._find_first_pattern(
                normalized,
                patterns,
            )

            if match:
                indicators.append(
                    FraudIndicator(
                        code=code,
                        category=category,
                        severity=severity,
                        score=score,
                        title=title,
                        description=description,
                        evidence=self._evidence_snippet(
                            normalized,
                            match.start(),
                            match.end(),
                        ),
                        source="text",
                        confidence=self._severity_confidence(
                            severity
                        ),
                    )
                )

        if self._detect_job_scam_pattern(normalized):
            indicators.append(
                FraudIndicator(
                    code="job_scam_pattern",
                    category=FraudCategory.JOB_SCAM,
                    severity=IndicatorSeverity.HIGH,
                    score=20.0,
                    title="Suspicious job-offer pattern",
                    description=(
                        "The content combines employment promises with "
                        "payments, equipment purchases, checks, or personal "
                        "financial information."
                    ),
                    evidence=self._first_matching_sentence(
                        normalized,
                        (
                            "equipment",
                            "check",
                            "job offer",
                            "hired",
                            "interview",
                        ),
                    ),
                    source="text",
                    confidence=0.78,
                )
            )

        if self._detect_romance_scam_pattern(normalized):
            indicators.append(
                FraudIndicator(
                    code="romance_scam_pattern",
                    category=FraudCategory.ROMANCE_SCAM,
                    severity=IndicatorSeverity.HIGH,
                    score=18.0,
                    title="Romance-scam payment pattern",
                    description=(
                        "The content combines emotional relationship language "
                        "with requests for emergency funds or transfers."
                    ),
                    evidence=self._first_matching_sentence(
                        normalized,
                        (
                            "love",
                            "emergency",
                            "money",
                            "send",
                            "hospital",
                        ),
                    ),
                    source="text",
                    confidence=0.72,
                )
            )

        if self._detect_charity_scam_pattern(normalized):
            indicators.append(
                FraudIndicator(
                    code="charity_scam_pattern",
                    category=FraudCategory.CHARITY_SCAM,
                    severity=IndicatorSeverity.MEDIUM,
                    score=14.0,
                    title="Unverified donation request",
                    description=(
                        "The content pressures the recipient to donate through "
                        "an unverified or unusual payment method."
                    ),
                    evidence=self._first_matching_sentence(
                        normalized,
                        (
                            "donate",
                            "charity",
                            "relief",
                            "victims",
                        ),
                    ),
                    source="text",
                    confidence=0.66,
                )
            )

        return indicators

    # =========================================================================
    # Sender and identity analysis
    # =========================================================================

    def _analyze_sender_identity(
        self,
        request: FraudAnalysisRequest,
    ) -> List[FraudIndicator]:
        """
        Analyze sender, reply-to, display-name, and expected-domain mismatches.
        """

        indicators: List[FraudIndicator] = []

        sender_email = self._extract_email_address(
            request.sender
        )
        reply_email = self._extract_email_address(
            request.reply_to
        )

        sender_domain = self._email_domain(sender_email)
        reply_domain = self._email_domain(reply_email)

        if (
            sender_domain
            and reply_domain
            and sender_domain != reply_domain
            and not self._same_organizational_domain(
                sender_domain,
                reply_domain,
            )
        ):
            indicators.append(
                FraudIndicator(
                    code="reply_to_mismatch",
                    category=FraudCategory.PHISHING,
                    severity=IndicatorSeverity.HIGH,
                    score=self._weight("reply_to_mismatch"),
                    title="Reply-to domain differs from sender domain",
                    description=(
                        "Replies would be sent to a different organization "
                        "than the visible sender."
                    ),
                    evidence=(
                        f"sender_domain={sender_domain}; "
                        f"reply_to_domain={reply_domain}"
                    ),
                    source="email_headers",
                    confidence=0.84,
                )
            )

        expected_sender_domain = self._normalize_domain(
            request.expected_sender_domain
        )

        if (
            sender_domain
            and expected_sender_domain
            and not self._domain_matches_expected(
                sender_domain,
                expected_sender_domain,
            )
        ):
            indicators.append(
                FraudIndicator(
                    code="sender_domain_mismatch",
                    category=FraudCategory.IMPERSONATION,
                    severity=IndicatorSeverity.HIGH,
                    score=self._weight(
                        "sender_domain_mismatch"
                    ),
                    title="Sender domain does not match expected domain",
                    description=(
                        "The sender address is not from the expected "
                        "organization domain."
                    ),
                    evidence=(
                        f"observed={sender_domain}; "
                        f"expected={expected_sender_domain}"
                    ),
                    source="email_headers",
                    confidence=0.9,
                )
            )

            if self._is_lookalike_domain(
                sender_domain,
                expected_sender_domain,
            ):
                indicators.append(
                    FraudIndicator(
                        code="sender_lookalike_domain",
                        category=FraudCategory.DOMAIN_SPOOFING,
                        severity=IndicatorSeverity.CRITICAL,
                        score=self._weight(
                            "lookalike_domain"
                        ),
                        title="Sender uses a lookalike domain",
                        description=(
                            "The sender domain closely resembles the expected "
                            "domain but is not the same domain."
                        ),
                        evidence=(
                            f"observed={sender_domain}; "
                            f"expected={expected_sender_domain}"
                        ),
                        source="email_headers",
                        confidence=0.92,
                    )
                )

        display_name = (
            request.sender_display_name or ""
        ).lower()

        if display_name and sender_domain:
            claimed_brand = self._find_claimed_brand(
                display_name
            )

            if claimed_brand:
                trusted_domains = (
                    self.config.protected_brand_domains.get(
                        claimed_brand,
                        (),
                    )
                )

                if trusted_domains and not any(
                    self._domain_matches_expected(
                        sender_domain,
                        domain,
                    )
                    for domain in trusted_domains
                ):
                    indicators.append(
                        FraudIndicator(
                            code="display_name_impersonation",
                            category=FraudCategory.BRAND_IMPERSONATION,
                            severity=IndicatorSeverity.HIGH,
                            score=self._weight(
                                "display_name_impersonation"
                            ),
                            title="Display-name brand impersonation",
                            description=(
                                "The display name claims a protected brand, "
                                "but the sender domain is unrelated."
                            ),
                            evidence=(
                                f"claimed_brand={claimed_brand}; "
                                f"sender_domain={sender_domain}"
                            ),
                            source="email_headers",
                            confidence=0.88,
                        )
                    )

        return indicators

    # =========================================================================
    # URL and domain analysis
    # =========================================================================

    def _analyze_url_indicators(
        self,
        *,
        url: str,
        request: FraudAnalysisRequest,
    ) -> List[FraudIndicator]:
        """
        Analyze URL syntax without performing a network request.
        """

        indicators: List[FraudIndicator] = []

        normalized_url = self._normalize_url(url)

        if not normalized_url:
            return indicators

        parsed = urlparse(normalized_url)
        domain = self._normalize_domain(parsed.hostname)

        if not domain:
            return indicators

        is_login_context = (
            request.input_type == FraudInputType.LOGIN_PAGE
            or self._has_credential_context(request, [])
        )

        if parsed.username or parsed.password:
            indicators.append(
                FraudIndicator(
                    code="userinfo_in_url",
                    category=FraudCategory.PHISHING,
                    severity=IndicatorSeverity.CRITICAL,
                    score=self._weight("userinfo_in_url"),
                    title="URL contains misleading user-information section",
                    description=(
                        "The URL contains an @-style user-information section "
                        "that can hide the true destination domain."
                    ),
                    evidence=self._redact_url(normalized_url),
                    source="url",
                    confidence=0.95,
                )
            )

        if self._is_ip_address(domain):
            indicators.append(
                FraudIndicator(
                    code="ip_address_url",
                    category=FraudCategory.PHISHING,
                    severity=IndicatorSeverity.HIGH,
                    score=self._weight("ip_address_url"),
                    title="URL uses an IP address instead of a domain",
                    description=(
                        "Credential and payment pages hosted directly on IP "
                        "addresses are commonly suspicious."
                    ),
                    evidence=domain,
                    source="url",
                    confidence=0.78,
                )
            )

        if domain.startswith("xn--") or ".xn--" in domain:
            indicators.append(
                FraudIndicator(
                    code="punycode_domain",
                    category=FraudCategory.DOMAIN_SPOOFING,
                    severity=IndicatorSeverity.HIGH,
                    score=self._weight("punycode_domain"),
                    title="Punycode domain detected",
                    description=(
                        "The domain contains internationalized punycode that "
                        "may be used for visual impersonation."
                    ),
                    evidence=domain,
                    source="url",
                    confidence=0.78,
                )
            )

        if domain in self.config.suspicious_url_shorteners:
            indicators.append(
                FraudIndicator(
                    code="url_shortener",
                    category=FraudCategory.PHISHING,
                    severity=IndicatorSeverity.MEDIUM,
                    score=self._weight("url_shortener"),
                    title="Shortened URL hides final destination",
                    description=(
                        "The link uses a URL-shortening service, preventing "
                        "the visible link from showing the true destination."
                    ),
                    evidence=domain,
                    source="url",
                    confidence=0.75,
                )
            )

        tld = self._top_level_domain(domain)

        if tld in self.config.risky_top_level_domains:
            indicators.append(
                FraudIndicator(
                    code="risky_tld",
                    category=FraudCategory.PHISHING,
                    severity=IndicatorSeverity.MEDIUM,
                    score=self._weight("risky_tld"),
                    title="Higher-risk top-level domain",
                    description=(
                        "The domain uses a top-level domain frequently seen in "
                        "temporary or deceptive campaigns. This alone does not "
                        "prove fraud."
                    ),
                    evidence=tld,
                    source="url",
                    confidence=0.56,
                )
            )

        if is_login_context and parsed.scheme.lower() != "https":
            indicators.append(
                FraudIndicator(
                    code="non_https_login",
                    category=FraudCategory.FAKE_LOGIN_PAGE,
                    severity=IndicatorSeverity.HIGH,
                    score=self._weight("non_https_login"),
                    title="Login page is not using HTTPS",
                    description=(
                        "A page requesting credentials is not protected by an "
                        "HTTPS URL."
                    ),
                    evidence=self._redact_url(normalized_url),
                    source="url",
                    confidence=0.92,
                )
            )

        subdomain_count = self._subdomain_count(domain)

        if subdomain_count >= 4:
            indicators.append(
                FraudIndicator(
                    code="excessive_subdomains",
                    category=FraudCategory.PHISHING,
                    severity=IndicatorSeverity.MEDIUM,
                    score=self._weight(
                        "excessive_subdomains"
                    ),
                    title="Excessive subdomain nesting",
                    description=(
                        "The URL uses many nested subdomains, potentially to "
                        "place a trusted brand name before the true domain."
                    ),
                    evidence=domain,
                    source="url",
                    confidence=0.68,
                )
            )

        if "%" in normalized_url or len(unquote(normalized_url)) != len(
            normalized_url
        ):
            encoded_count = normalized_url.count("%")

            if encoded_count >= 2:
                indicators.append(
                    FraudIndicator(
                        code="encoded_url",
                        category=FraudCategory.PHISHING,
                        severity=IndicatorSeverity.LOW,
                        score=self._weight("encoded_url"),
                        title="Encoded URL components",
                        description=(
                            "The URL contains multiple encoded characters that "
                            "may obscure its destination or parameters."
                        ),
                        evidence=self._redact_url(normalized_url),
                        source="url",
                        confidence=0.58,
                    )
                )

        query_keys = {
            key.lower()
            for key in parse_qs(
                parsed.query,
                keep_blank_values=True,
            ).keys()
        }

        suspicious_query_keys = {
            "password",
            "passwd",
            "token",
            "auth",
            "session",
            "otp",
            "pin",
            "credential",
            "login",
            "redirect",
            "return",
            "continue",
        }

        matched_query_keys = sorted(
            query_keys & suspicious_query_keys
        )

        if matched_query_keys:
            indicators.append(
                FraudIndicator(
                    code="suspicious_query",
                    category=FraudCategory.PHISHING,
                    severity=IndicatorSeverity.MEDIUM,
                    score=self._weight("suspicious_query"),
                    title="Suspicious authentication-related URL parameters",
                    description=(
                        "The URL contains authentication, redirect, or "
                        "credential-related parameters."
                    ),
                    evidence=", ".join(matched_query_keys),
                    source="url",
                    confidence=0.62,
                )
            )

        expected_domains = self._collect_expected_domains(
            request
        )

        for expected_domain in expected_domains:
            if not self._domain_matches_expected(
                domain,
                expected_domain,
            ):
                if self._is_lookalike_domain(
                    domain,
                    expected_domain,
                ):
                    indicators.append(
                        FraudIndicator(
                            code="lookalike_domain",
                            category=FraudCategory.DOMAIN_SPOOFING,
                            severity=IndicatorSeverity.CRITICAL,
                            score=self._weight(
                                "lookalike_domain"
                            ),
                            title="Lookalike domain detected",
                            description=(
                                "The observed domain closely resembles the "
                                "expected domain but is not controlled as the "
                                "same domain."
                            ),
                            evidence=(
                                f"observed={domain}; "
                                f"expected={expected_domain}"
                            ),
                            source="url",
                            confidence=0.94,
                        )
                    )
                else:
                    indicators.append(
                        FraudIndicator(
                            code="domain_mismatch",
                            category=FraudCategory.BRAND_IMPERSONATION,
                            severity=IndicatorSeverity.HIGH,
                            score=self._weight(
                                "brand_impersonation"
                            ),
                            title="Domain does not match expected organization",
                            description=(
                                "The page domain is unrelated to the expected "
                                "brand or organization domain."
                            ),
                            evidence=(
                                f"observed={domain}; "
                                f"expected={expected_domain}"
                            ),
                            source="url",
                            confidence=0.84,
                        )
                    )

        claimed_brands = self._find_claimed_brands(
            " ".join(
                filter(
                    None,
                    [
                        request.expected_brand,
                        request.page_title,
                        request.text[:3_000],
                        domain,
                    ],
                )
            )
        )

        for brand in claimed_brands:
            trusted_domains = (
                self.config.protected_brand_domains.get(
                    brand,
                    (),
                )
            )

            if trusted_domains and not any(
                self._domain_matches_expected(
                    domain,
                    trusted,
                )
                for trusted in trusted_domains
            ):
                indicators.append(
                    FraudIndicator(
                        code="brand_impersonation",
                        category=FraudCategory.BRAND_IMPERSONATION,
                        severity=IndicatorSeverity.HIGH,
                        score=self._weight(
                            "brand_impersonation"
                        ),
                        title="Protected brand appears on unrelated domain",
                        description=(
                            "The content references a known brand while the "
                            "page is hosted on an unrelated domain."
                        ),
                        evidence=(
                            f"brand={brand}; domain={domain}"
                        ),
                        source="url_and_content",
                        confidence=0.86,
                    )
                )

        return indicators

    # =========================================================================
    # HTML and fake-login-page analysis
    # =========================================================================

    def _analyze_html_indicators(
        self,
        request: FraudAnalysisRequest,
    ) -> List[FraudIndicator]:
        """
        Analyze supplied HTML source without executing scripts.
        """

        html = request.html or ""
        lowered = html.lower()
        indicators: List[FraudIndicator] = []

        if not html:
            return indicators

        if re.search(
            r"<input[^>]+type\s*=\s*['\"]?password",
            lowered,
        ):
            indicators.append(
                FraudIndicator(
                    code="credential_form",
                    category=FraudCategory.CREDENTIAL_THEFT,
                    severity=IndicatorSeverity.HIGH,
                    score=self._weight("credential_form"),
                    title="Password field detected",
                    description=(
                        "The supplied page contains a password input field."
                    ),
                    evidence="<input type=\"password\">",
                    source="html",
                    confidence=0.92,
                )
            )

        hidden_password = bool(
            re.search(
                r"<input[^>]+type\s*=\s*['\"]?password[^>]+"
                r"(?:display\s*:\s*none|visibility\s*:\s*hidden)",
                lowered,
            )
        )

        hidden_form = bool(
            re.search(
                r"<form[^>]+(?:display\s*:\s*none|"
                r"visibility\s*:\s*hidden)",
                lowered,
            )
        )

        if hidden_password or hidden_form:
            indicators.append(
                FraudIndicator(
                    code="hidden_form",
                    category=FraudCategory.CREDENTIAL_THEFT,
                    severity=IndicatorSeverity.HIGH,
                    score=self._weight("hidden_form"),
                    title="Hidden credential or form element",
                    description=(
                        "The page contains a hidden form or password field."
                    ),
                    evidence="Hidden form styling detected",
                    source="html",
                    confidence=0.84,
                )
            )

        obfuscation_patterns = (
            r"\beval\s*\(",
            r"\bfromcharcode\s*\(",
            r"\bunescape\s*\(",
            r"\batob\s*\(",
            r"\\x[0-9a-f]{2}",
            r"\\u[0-9a-f]{4}",
            r"document\.write\s*\(",
        )

        obfuscation_hits = sum(
            len(re.findall(pattern, lowered))
            for pattern in obfuscation_patterns
        )

        if obfuscation_hits >= 3:
            indicators.append(
                FraudIndicator(
                    code="script_obfuscation",
                    category=FraudCategory.MALWARE_DELIVERY,
                    severity=IndicatorSeverity.HIGH,
                    score=self._weight(
                        "script_obfuscation"
                    ),
                    title="Obfuscated script behavior",
                    description=(
                        "The HTML contains repeated script-obfuscation "
                        "constructs commonly used to hide page behavior."
                    ),
                    evidence=(
                        f"obfuscation_hits={obfuscation_hits}"
                    ),
                    source="html",
                    confidence=0.76,
                )
            )

        if re.search(
            r"navigator\.clipboard|clipboard\.writeText",
            lowered,
        ):
            indicators.append(
                FraudIndicator(
                    code="clipboard_manipulation",
                    category=FraudCategory.MALWARE_DELIVERY,
                    severity=IndicatorSeverity.HIGH,
                    score=self._weight(
                        "clipboard_manipulation"
                    ),
                    title="Clipboard manipulation detected",
                    description=(
                        "The page attempts to read or replace clipboard "
                        "content."
                    ),
                    evidence="navigator.clipboard",
                    source="html",
                    confidence=0.78,
                )
            )

        redirect_matches = re.findall(
            r"(?:window\.location|location\.href|"
            r"location\.replace)\s*[=(]",
            lowered,
        )

        if redirect_matches:
            indicators.append(
                FraudIndicator(
                    code="window_location_redirect",
                    category=FraudCategory.PHISHING,
                    severity=IndicatorSeverity.MEDIUM,
                    score=self._weight(
                        "window_location_redirect"
                    ),
                    title="Script-based redirect detected",
                    description=(
                        "The page contains script-based redirect behavior."
                    ),
                    evidence=(
                        f"redirect_constructs={len(redirect_matches)}"
                    ),
                    source="html",
                    confidence=0.65,
                )
            )

        if (
            "<iframe" in lowered
            and (
                "opacity:0" in lowered.replace(" ", "")
                or "display:none" in lowered.replace(" ", "")
            )
        ):
            indicators.append(
                FraudIndicator(
                    code="hidden_iframe",
                    category=FraudCategory.MALWARE_DELIVERY,
                    severity=IndicatorSeverity.HIGH,
                    score=18.0,
                    title="Hidden iframe detected",
                    description=(
                        "The page contains an iframe hidden from the user."
                    ),
                    evidence="<iframe> with hidden styling",
                    source="html",
                    confidence=0.79,
                )
            )

        html_forms = self._extract_html_form_actions(html)

        for form_action in html_forms:
            indicators.extend(
                self._analyze_form_action(
                    form_action=form_action,
                    request=request,
                )
            )

        return indicators

    def _analyze_login_form_indicators(
        self,
        request: FraudAnalysisRequest,
    ) -> List[FraudIndicator]:
        """
        Analyze form fields and actions associated with a login page.
        """

        indicators: List[FraudIndicator] = []

        normalized_fields = {
            self._normalize_field_name(item)
            for item in request.form_fields
            if item
        }

        credential_fields = normalized_fields & {
            self._normalize_field_name(item)
            for item in self.config.credential_field_names
        }

        if credential_fields:
            indicators.append(
                FraudIndicator(
                    code="credential_form",
                    category=FraudCategory.CREDENTIAL_THEFT,
                    severity=IndicatorSeverity.HIGH,
                    score=self._weight("credential_form"),
                    title="Sensitive credential fields detected",
                    description=(
                        "The page requests credentials or verification secrets."
                    ),
                    evidence=", ".join(
                        sorted(credential_fields)
                    ),
                    source="form_fields",
                    confidence=0.94,
                )
            )

        if (
            request.url
            and credential_fields
            and urlparse(
                self._normalize_url(request.url)
            ).scheme.lower()
            != "https"
        ):
            indicators.append(
                FraudIndicator(
                    code="password_and_external_domain",
                    category=FraudCategory.FAKE_LOGIN_PAGE,
                    severity=IndicatorSeverity.CRITICAL,
                    score=self._weight(
                        "password_and_external_domain"
                    ),
                    title="Credentials requested through insecure page",
                    description=(
                        "The page requests credentials without an HTTPS URL."
                    ),
                    evidence=self._redact_url(request.url),
                    source="form_and_url",
                    confidence=0.96,
                )
            )

        for form_action in request.form_actions:
            indicators.extend(
                self._analyze_form_action(
                    form_action=form_action,
                    request=request,
                )
            )

        return indicators

    def _analyze_form_action(
        self,
        *,
        form_action: str,
        request: FraudAnalysisRequest,
    ) -> List[FraudIndicator]:
        """
        Check whether a form submits data to an unrelated domain.
        """

        indicators: List[FraudIndicator] = []

        page_domain = self._url_domain(
            request.final_url or request.url
        )
        action_domain = self._url_domain(form_action)

        if (
            page_domain
            and action_domain
            and not self._same_organizational_domain(
                page_domain,
                action_domain,
            )
        ):
            indicators.append(
                FraudIndicator(
                    code="external_form_action",
                    category=FraudCategory.CREDENTIAL_THEFT,
                    severity=IndicatorSeverity.CRITICAL,
                    score=self._weight(
                        "external_form_action"
                    ),
                    title="Form submits data to an unrelated domain",
                    description=(
                        "The page form sends entered data to a different "
                        "organization domain."
                    ),
                    evidence=(
                        f"page_domain={page_domain}; "
                        f"action_domain={action_domain}"
                    ),
                    source="form_action",
                    confidence=0.95,
                )
            )

        return indicators

    # =========================================================================
    # Attachment analysis
    # =========================================================================

    def _analyze_attachment_indicators(
        self,
        attachments: Sequence[AttachmentMetadata],
    ) -> List[FraudIndicator]:
        """
        Analyze attachment names and metadata without opening files.
        """

        indicators: List[FraudIndicator] = []

        for attachment in attachments:
            filename = attachment.filename.strip()
            lowered = filename.lower()
            suffixes = [
                suffix.lower()
                for suffix in PurePath(lowered).suffixes
            ]
            final_suffix = suffixes[-1] if suffixes else ""

            if final_suffix in self.config.suspicious_attachment_extensions:
                indicators.append(
                    FraudIndicator(
                        code="suspicious_attachment",
                        category=FraudCategory.MALWARE_DELIVERY,
                        severity=IndicatorSeverity.CRITICAL,
                        score=self._weight(
                            "suspicious_attachment"
                        ),
                        title="Executable or script attachment",
                        description=(
                            "The attachment type can execute commands or code."
                        ),
                        evidence=self._redact_filename(filename),
                        source="attachment",
                        confidence=0.96,
                        metadata={
                            "extension": final_suffix,
                            "sha256": attachment.sha256,
                        },
                    )
                )

            if final_suffix in self.config.macro_document_extensions:
                indicators.append(
                    FraudIndicator(
                        code="macro_attachment",
                        category=FraudCategory.MALWARE_DELIVERY,
                        severity=IndicatorSeverity.HIGH,
                        score=self._weight(
                            "macro_attachment"
                        ),
                        title="Macro-enabled document attachment",
                        description=(
                            "The document format can contain executable macros."
                        ),
                        evidence=self._redact_filename(filename),
                        source="attachment",
                        confidence=0.88,
                        metadata={
                            "extension": final_suffix,
                            "sha256": attachment.sha256,
                        },
                    )
                )

            if self._has_dangerous_double_extension(
                lowered
            ):
                indicators.append(
                    FraudIndicator(
                        code="double_extension",
                        category=FraudCategory.MALWARE_DELIVERY,
                        severity=IndicatorSeverity.CRITICAL,
                        score=self._weight(
                            "double_extension"
                        ),
                        title="Misleading double-extension attachment",
                        description=(
                            "The filename appears to disguise an executable "
                            "type as a document or image."
                        ),
                        evidence=self._redact_filename(filename),
                        source="attachment",
                        confidence=0.95,
                        metadata={
                            "suffixes": suffixes,
                            "sha256": attachment.sha256,
                        },
                    )
                )

            if final_suffix in self.config.archive_extensions:
                indicators.append(
                    FraudIndicator(
                        code="archive_attachment",
                        category=FraudCategory.MALWARE_DELIVERY,
                        severity=IndicatorSeverity.MEDIUM,
                        score=self._weight(
                            "archive_attachment"
                        ),
                        title="Archive or disk-image attachment",
                        description=(
                            "The attachment is an archive or disk image that "
                            "may hide its internal file type."
                        ),
                        evidence=self._redact_filename(filename),
                        source="attachment",
                        confidence=0.58,
                        metadata={
                            "password_protected": (
                                attachment.password_protected
                            ),
                            "sha256": attachment.sha256,
                        },
                    )
                )

            if (
                attachment.password_protected
                and final_suffix
                in self.config.archive_extensions
            ):
                indicators.append(
                    FraudIndicator(
                        code="password_protected_archive",
                        category=FraudCategory.MALWARE_DELIVERY,
                        severity=IndicatorSeverity.HIGH,
                        score=15.0,
                        title="Password-protected archive",
                        description=(
                            "The archive is password protected, which can "
                            "prevent normal security scanning."
                        ),
                        evidence=self._redact_filename(filename),
                        source="attachment",
                        confidence=0.76,
                        metadata={"sha256": attachment.sha256},
                    )
                )

            if attachment.extracted_text:
                attachment_text = attachment.extracted_text[
                    : self.config.maximum_text_characters
                ]

                text_indicators = self._analyze_language_patterns(
                    attachment_text,
                    FraudAnalysisRequest(
                        context=TaskContext(
                            user_id="internal_analysis",
                            workspace_id="internal_analysis",
                        ),
                        input_type=FraudInputType.DOCUMENT,
                    ),
                )

                for indicator in text_indicators:
                    indicator.source = "attachment_text"
                    indicator.metadata["filename"] = (
                        self._redact_filename(filename)
                    )
                    indicators.append(indicator)

        return indicators

    # =========================================================================
    # Invoice analysis
    # =========================================================================

    def _analyze_invoice_indicators(
        self,
        request: FraudAnalysisRequest,
    ) -> List[FraudIndicator]:
        """
        Detect suspicious invoice changes and inconsistencies.
        """

        invoice = request.invoice_data
        history = request.historical_data
        indicators: List[FraudIndicator] = []

        vendor_name = self._first_non_empty(
            invoice.get("vendor_name"),
            invoice.get("supplier_name"),
            invoice.get("company_name"),
        )

        vendor_email = self._first_non_empty(
            invoice.get("vendor_email"),
            invoice.get("sender_email"),
            request.sender,
        )

        vendor_domain = self._email_domain(
            self._extract_email_address(vendor_email)
        )

        expected_domains = {
            self._normalize_domain(item)
            for item in request.known_vendor_domains
            if self._normalize_domain(item)
        }

        if (
            vendor_domain
            and expected_domains
            and not any(
                self._domain_matches_expected(
                    vendor_domain,
                    expected,
                )
                for expected in expected_domains
            )
        ):
            indicators.append(
                FraudIndicator(
                    code="invoice_vendor_domain_mismatch",
                    category=FraudCategory.INVOICE_FRAUD,
                    severity=IndicatorSeverity.HIGH,
                    score=self._weight("invoice_mismatch"),
                    title="Invoice sender domain differs from known vendor",
                    description=(
                        "The invoice email domain is not among the known "
                        "domains for this vendor."
                    ),
                    evidence=(
                        f"observed={vendor_domain}; "
                        f"known={','.join(sorted(expected_domains))}"
                    ),
                    source="invoice",
                    confidence=0.9,
                )
            )

        account_identifier = self._extract_account_identifier(
            invoice
        )

        normalized_known_accounts = {
            self._normalize_account_identifier(item)
            for item in request.known_bank_accounts
            if item
        }

        if (
            account_identifier
            and normalized_known_accounts
            and self._normalize_account_identifier(
                account_identifier
            )
            not in normalized_known_accounts
        ):
            indicators.append(
                FraudIndicator(
                    code="invoice_bank_account_changed",
                    category=FraudCategory.PAYMENT_REDIRECTION,
                    severity=IndicatorSeverity.CRITICAL,
                    score=self._weight("bank_change"),
                    title="Invoice uses an unknown bank account",
                    description=(
                        "The payment destination does not match known bank "
                        "accounts for the vendor."
                    ),
                    evidence=self._redact_account_identifier(
                        account_identifier
                    ),
                    source="invoice",
                    confidence=0.94,
                )
            )

        previous_account = self._first_non_empty(
            history.get("previous_bank_account"),
            history.get("bank_account"),
            history.get("iban"),
            history.get("account_number"),
        )

        if (
            account_identifier
            and previous_account
            and self._normalize_account_identifier(
                account_identifier
            )
            != self._normalize_account_identifier(
                previous_account
            )
        ):
            indicators.append(
                FraudIndicator(
                    code="invoice_bank_account_changed",
                    category=FraudCategory.PAYMENT_REDIRECTION,
                    severity=IndicatorSeverity.CRITICAL,
                    score=self._weight("bank_change"),
                    title="Bank account changed from previous invoice",
                    description=(
                        "The invoice payment destination differs from the "
                        "historical account."
                    ),
                    evidence=(
                        "current="
                        f"{self._redact_account_identifier(account_identifier)}; "
                        "previous="
                        f"{self._redact_account_identifier(previous_account)}"
                    ),
                    source="invoice_history",
                    confidence=0.96,
                )
            )

        amount = self._to_decimal(
            self._first_non_empty(
                invoice.get("total"),
                invoice.get("amount_due"),
                invoice.get("amount"),
                invoice.get("invoice_total"),
            )
        )

        expected_amount = self._to_decimal(
            self._first_non_empty(
                history.get("expected_amount"),
                history.get("average_amount"),
                history.get("previous_amount"),
            )
        )

        if amount is not None and amount < Decimal("0"):
            indicators.append(
                FraudIndicator(
                    code="negative_invoice_amount",
                    category=FraudCategory.SUSPICIOUS_INVOICE,
                    severity=IndicatorSeverity.MEDIUM,
                    score=10.0,
                    title="Negative invoice amount",
                    description=(
                        "The invoice total is negative and requires manual "
                        "verification."
                    ),
                    evidence=str(amount),
                    source="invoice",
                    confidence=0.8,
                )
            )

        if (
            amount is not None
            and expected_amount is not None
            and expected_amount > 0
        ):
            deviation = abs(
                amount - expected_amount
            ) / expected_amount

            if deviation >= Decimal("1.0"):
                indicators.append(
                    FraudIndicator(
                        code="invoice_amount_extreme_deviation",
                        category=FraudCategory.SUSPICIOUS_INVOICE,
                        severity=IndicatorSeverity.HIGH,
                        score=18.0,
                        title="Invoice amount is far outside historical range",
                        description=(
                            "The invoice amount differs by at least 100% from "
                            "the supplied expected or historical amount."
                        ),
                        evidence=(
                            f"current={amount}; "
                            f"reference={expected_amount}; "
                            f"deviation={round(float(deviation) * 100, 2)}%"
                        ),
                        source="invoice_history",
                        confidence=0.82,
                    )
                )
            elif deviation >= Decimal("0.35"):
                indicators.append(
                    FraudIndicator(
                        code="invoice_amount_deviation",
                        category=FraudCategory.SUSPICIOUS_INVOICE,
                        severity=IndicatorSeverity.MEDIUM,
                        score=10.0,
                        title="Invoice amount differs from historical pattern",
                        description=(
                            "The invoice amount is materially different from "
                            "the supplied historical reference."
                        ),
                        evidence=(
                            f"current={amount}; "
                            f"reference={expected_amount}; "
                            f"deviation={round(float(deviation) * 100, 2)}%"
                        ),
                        source="invoice_history",
                        confidence=0.7,
                    )
                )

        invoice_number = self._first_non_empty(
            invoice.get("invoice_number"),
            invoice.get("invoice_no"),
            invoice.get("number"),
        )

        previous_invoice_numbers = {
            str(item).strip().lower()
            for item in (
                history.get("previous_invoice_numbers")
                or []
            )
            if item is not None
        }

        if (
            invoice_number
            and str(invoice_number).strip().lower()
            in previous_invoice_numbers
        ):
            indicators.append(
                FraudIndicator(
                    code="duplicate_invoice_number",
                    category=FraudCategory.SUSPICIOUS_INVOICE,
                    severity=IndicatorSeverity.HIGH,
                    score=18.0,
                    title="Duplicate invoice number",
                    description=(
                        "The invoice number already exists in the supplied "
                        "historical records."
                    ),
                    evidence=str(invoice_number)[:100],
                    source="invoice_history",
                    confidence=0.9,
                )
            )

        currency = str(
            self._first_non_empty(
                invoice.get("currency"),
                invoice.get("currency_code"),
            )
            or ""
        ).upper()

        expected_currency = str(
            self._first_non_empty(
                history.get("expected_currency"),
                history.get("currency"),
            )
            or ""
        ).upper()

        if (
            currency
            and expected_currency
            and currency != expected_currency
        ):
            indicators.append(
                FraudIndicator(
                    code="invoice_currency_changed",
                    category=FraudCategory.SUSPICIOUS_INVOICE,
                    severity=IndicatorSeverity.MEDIUM,
                    score=10.0,
                    title="Invoice currency differs from expected currency",
                    description=(
                        "The invoice requests payment in a different currency "
                        "than the supplied vendor history."
                    ),
                    evidence=(
                        f"current={currency}; "
                        f"expected={expected_currency}"
                    ),
                    source="invoice_history",
                    confidence=0.8,
                )
            )

        if request.known_vendor and vendor_name:
            similarity = self._string_similarity(
                self._normalize_company_name(vendor_name),
                self._normalize_company_name(
                    request.known_vendor
                ),
            )

            if similarity < 0.72:
                indicators.append(
                    FraudIndicator(
                        code="invoice_vendor_name_mismatch",
                        category=FraudCategory.INVOICE_FRAUD,
                        severity=IndicatorSeverity.HIGH,
                        score=self._weight("invoice_mismatch"),
                        title="Vendor name differs from known vendor",
                        description=(
                            "The invoice vendor name does not closely match "
                            "the expected vendor."
                        ),
                        evidence=(
                            f"observed={self._redact_name(vendor_name)}; "
                            f"expected={self._redact_name(request.known_vendor)}"
                        ),
                        source="invoice",
                        confidence=0.8,
                    )
                )

        if self._invoice_requests_urgent_payment(
            request.text,
            invoice,
        ):
            indicators.append(
                FraudIndicator(
                    code="invoice_urgency",
                    category=FraudCategory.INVOICE_FRAUD,
                    severity=IndicatorSeverity.MEDIUM,
                    score=self._weight("invoice_urgency"),
                    title="Invoice uses unusual urgency",
                    description=(
                        "The invoice or message pressures the recipient to pay "
                        "immediately or bypass normal review."
                    ),
                    evidence=self._first_matching_sentence(
                        request.text,
                        (
                            "urgent",
                            "immediately",
                            "today",
                            "overdue",
                            "final notice",
                        ),
                    ),
                    source="invoice_text",
                    confidence=0.7,
                )
            )

        return indicators

    # =========================================================================
    # Payment request analysis
    # =========================================================================

    def _analyze_payment_indicators(
        self,
        request: FraudAnalysisRequest,
    ) -> List[FraudIndicator]:
        """
        Analyze payment instructions for redirection and scam patterns.
        """

        payment = request.payment_data
        history = request.historical_data
        indicators: List[FraudIndicator] = []

        method = str(
            self._first_non_empty(
                payment.get("method"),
                payment.get("payment_method"),
                payment.get("type"),
            )
            or ""
        ).lower()

        high_risk_methods = {
            "gift card",
            "gift_card",
            "cryptocurrency",
            "crypto",
            "bitcoin",
            "cash app",
            "cashapp",
            "western union",
            "moneygram",
            "prepaid card",
            "voucher",
            "wire to personal account",
        }

        if method in high_risk_methods:
            category = (
                FraudCategory.GIFT_CARD_SCAM
                if "gift" in method or "voucher" in method
                else FraudCategory.CRYPTO_SCAM
                if method
                in {
                    "cryptocurrency",
                    "crypto",
                    "bitcoin",
                }
                else FraudCategory.SUSPICIOUS_PAYMENT
            )

            indicators.append(
                FraudIndicator(
                    code="unusual_payment_method",
                    category=category,
                    severity=IndicatorSeverity.HIGH,
                    score=self._weight(
                        "unusual_payment_method"
                    ),
                    title="High-risk or irreversible payment method",
                    description=(
                        "The request uses a payment method frequently chosen "
                        "by scammers because it is difficult to reverse."
                    ),
                    evidence=method,
                    source="payment",
                    confidence=0.84,
                )
            )

        account_identifier = self._extract_account_identifier(
            payment
        )

        known_accounts = {
            self._normalize_account_identifier(item)
            for item in request.known_bank_accounts
            if item
        }

        if (
            account_identifier
            and known_accounts
            and self._normalize_account_identifier(
                account_identifier
            )
            not in known_accounts
        ):
            indicators.append(
                FraudIndicator(
                    code="payment_destination_unknown",
                    category=FraudCategory.PAYMENT_REDIRECTION,
                    severity=IndicatorSeverity.CRITICAL,
                    score=self._weight("bank_change"),
                    title="Payment destination is not recognized",
                    description=(
                        "The destination account is not in the supplied list "
                        "of known payment accounts."
                    ),
                    evidence=self._redact_account_identifier(
                        account_identifier
                    ),
                    source="payment",
                    confidence=0.95,
                )
            )

        previous_account = self._first_non_empty(
            history.get("previous_bank_account"),
            history.get("payment_account"),
            history.get("iban"),
            history.get("account_number"),
        )

        if (
            account_identifier
            and previous_account
            and self._normalize_account_identifier(
                account_identifier
            )
            != self._normalize_account_identifier(
                previous_account
            )
        ):
            indicators.append(
                FraudIndicator(
                    code="payment_destination_changed",
                    category=FraudCategory.PAYMENT_REDIRECTION,
                    severity=IndicatorSeverity.CRITICAL,
                    score=self._weight("bank_change"),
                    title="Payment destination changed",
                    description=(
                        "The supplied payment destination differs from the "
                        "historical destination."
                    ),
                    evidence=(
                        "current="
                        f"{self._redact_account_identifier(account_identifier)}; "
                        "previous="
                        f"{self._redact_account_identifier(previous_account)}"
                    ),
                    source="payment_history",
                    confidence=0.96,
                )
            )

        beneficiary = self._first_non_empty(
            payment.get("beneficiary"),
            payment.get("account_name"),
            payment.get("recipient_name"),
        )

        expected_beneficiary = self._first_non_empty(
            history.get("expected_beneficiary"),
            history.get("account_name"),
            request.known_vendor,
        )

        if beneficiary and expected_beneficiary:
            similarity = self._string_similarity(
                self._normalize_company_name(beneficiary),
                self._normalize_company_name(
                    expected_beneficiary
                ),
            )

            if similarity < 0.7:
                indicators.append(
                    FraudIndicator(
                        code="beneficiary_name_mismatch",
                        category=FraudCategory.PAYMENT_REDIRECTION,
                        severity=IndicatorSeverity.HIGH,
                        score=20.0,
                        title="Beneficiary name does not match expected recipient",
                        description=(
                            "The named payment recipient differs from the "
                            "expected vendor or account holder."
                        ),
                        evidence=(
                            f"observed={self._redact_name(beneficiary)}; "
                            "expected="
                            f"{self._redact_name(expected_beneficiary)}"
                        ),
                        source="payment",
                        confidence=0.86,
                    )
                )

        qr_payload = self._first_non_empty(
            payment.get("qr_payload"),
            payment.get("qr_code_data"),
            payment.get("payment_qr"),
        )

        if qr_payload:
            indicators.append(
                FraudIndicator(
                    code="qr_payment",
                    category=FraudCategory.QR_CODE_SCAM,
                    severity=IndicatorSeverity.MEDIUM,
                    score=self._weight("qr_payment"),
                    title="QR-based payment instruction",
                    description=(
                        "The payment request relies on a QR payload. The "
                        "destination should be verified independently."
                    ),
                    evidence=self._redact_qr_payload(
                        str(qr_payload)
                    ),
                    source="payment",
                    confidence=0.68,
                )
            )

        return indicators

    # =========================================================================
    # Risk calculation
    # =========================================================================

    def _calculate_risk_score(
        self,
        indicators: Sequence[FraudIndicator],
    ) -> float:
        """
        Calculate a bounded risk score.

        Repeated weak indicators have diminishing returns. Critical indicators
        still carry significant weight.
        """

        if not indicators:
            return 0.0

        severity_multiplier = {
            IndicatorSeverity.INFO: 0.25,
            IndicatorSeverity.LOW: 0.55,
            IndicatorSeverity.MEDIUM: 0.8,
            IndicatorSeverity.HIGH: 1.0,
            IndicatorSeverity.CRITICAL: 1.15,
        }

        weighted_values: List[float] = []

        for indicator in indicators:
            base = max(0.0, float(indicator.score))
            multiplier = severity_multiplier[
                indicator.severity
            ]
            confidence = min(
                max(float(indicator.confidence), 0.0),
                1.0,
            )

            weighted_values.append(
                base * multiplier * (0.65 + 0.35 * confidence)
            )

        weighted_values.sort(reverse=True)

        diminishing_factors = (
            1.0,
            0.85,
            0.72,
            0.60,
            0.50,
            0.42,
            0.35,
            0.30,
            0.25,
            0.20,
        )

        total = 0.0

        for index, value in enumerate(weighted_values):
            factor = (
                diminishing_factors[index]
                if index < len(diminishing_factors)
                else 0.15
            )
            total += value * factor

        category_count = len(
            {indicator.category for indicator in indicators}
        )

        if category_count >= 3:
            total += min(8.0, category_count * 1.5)

        critical_count = sum(
            1
            for indicator in indicators
            if indicator.severity == IndicatorSeverity.CRITICAL
        )

        if critical_count >= 2:
            total += 8.0

        return round(min(max(total, 0.0), 100.0), 2)

    def _score_to_risk_level(
        self,
        score: float,
    ) -> RiskLevel:
        """
        Convert numeric score to risk level.
        """

        if score >= self.config.critical_risk_threshold:
            return RiskLevel.CRITICAL

        if score >= self.config.high_risk_threshold:
            return RiskLevel.HIGH

        if score >= self.config.medium_risk_threshold:
            return RiskLevel.MEDIUM

        if score >= self.config.low_risk_threshold:
            return RiskLevel.LOW

        return RiskLevel.NONE

    def _calculate_confidence(
        self,
        *,
        request: FraudAnalysisRequest,
        indicators: Sequence[FraudIndicator],
    ) -> ConfidenceLevel:
        """
        Estimate confidence from evidence coverage and indicator strength.
        """

        if not indicators:
            return ConfidenceLevel.MEDIUM

        evidence_sources = {
            item.source
            for item in indicators
            if item.source
        }

        average_confidence = sum(
            item.confidence for item in indicators
        ) / len(indicators)

        high_count = sum(
            1
            for item in indicators
            if item.severity
            in {
                IndicatorSeverity.HIGH,
                IndicatorSeverity.CRITICAL,
            }
        )

        data_coverage = sum(
            bool(value)
            for value in (
                request.text,
                request.url,
                request.html,
                request.sender,
                request.invoice_data,
                request.payment_data,
                request.historical_data,
                request.form_fields,
                request.attachments,
            )
        )

        confidence_score = (
            average_confidence * 0.55
            + min(len(evidence_sources), 4) / 4 * 0.20
            + min(high_count, 3) / 3 * 0.15
            + min(data_coverage, 4) / 4 * 0.10
        )

        if confidence_score >= 0.78:
            return ConfidenceLevel.HIGH

        if confidence_score >= 0.55:
            return ConfidenceLevel.MEDIUM

        return ConfidenceLevel.LOW

    def _rank_categories(
        self,
        indicators: Sequence[FraudIndicator],
    ) -> List[str]:
        """
        Rank categories by total indicator score.
        """

        scores: Counter[str] = Counter()

        for indicator in indicators:
            scores[indicator.category.value] += (
                indicator.score
                * max(indicator.confidence, 0.1)
            )

        return [
            category
            for category, _ in scores.most_common()
        ]

    # =========================================================================
    # Recommendations and explanations
    # =========================================================================

    def _build_recommendations(
        self,
        *,
        risk_score: float,
        risk_level: RiskLevel,
        categories: Sequence[str],
        indicators: Sequence[FraudIndicator],
        request: FraudAnalysisRequest,
    ) -> List[str]:
        """
        Build safe, non-destructive recommendations.
        """

        recommendations: List[str] = []

        category_set = set(categories)
        indicator_codes = {
            indicator.code for indicator in indicators
        }

        if risk_level in {
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        }:
            recommendations.extend(
                [
                    RecommendedAction.ESCALATE_TO_SECURITY.value,
                    RecommendedAction.REQUIRE_HUMAN_REVIEW.value,
                    RecommendedAction.PRESERVE_EVIDENCE.value,
                ]
            )
        elif risk_level == RiskLevel.MEDIUM:
            recommendations.append(
                RecommendedAction.VERIFY_INDEPENDENTLY.value
            )
        else:
            recommendations.append(
                RecommendedAction.ALLOW_WITH_CAUTION.value
            )

        if self._has_payment_context(request):
            if (
                risk_score
                >= self.config.payment_hold_threshold
            ):
                recommendations.append(
                    RecommendedAction.HOLD_PAYMENT.value
                )

            recommendations.append(
                "verify_payment_instructions_using_a_known_contact_channel"
            )

            recommendations.append(
                "confirm_bank_account_changes_with_an_existing_authorized_contact"
            )

        if (
            FraudCategory.CREDENTIAL_THEFT.value
            in category_set
            or FraudCategory.FAKE_LOGIN_PAGE.value
            in category_set
        ):
            recommendations.append(
                RecommendedAction.DO_NOT_ENTER_CREDENTIALS.value
            )

        if self._collect_urls(
            request,
            self._build_combined_text(request),
        ):
            if risk_score >= self.config.medium_risk_threshold:
                recommendations.append(
                    RecommendedAction.DO_NOT_CLICK_LINK.value
                )

        if indicator_codes & {
            "suspicious_attachment",
            "double_extension",
            "macro_attachment",
            "password_protected_archive",
        }:
            recommendations.append(
                RecommendedAction.DO_NOT_OPEN_ATTACHMENT.value
            )

        if (
            risk_score
            >= self.config.high_risk_approval_threshold
        ):
            recommendations.append(
                RecommendedAction.REQUIRE_SECURITY_APPROVAL.value
            )

        if (
            FraudCategory.BUSINESS_EMAIL_COMPROMISE.value
            in category_set
            or FraudCategory.IMPERSONATION.value
            in category_set
        ):
            recommendations.append(
                "contact_the_claimed_sender_using_previously_verified_details"
            )

        if FraudCategory.PHISHING.value in category_set:
            recommendations.append(
                "inspect_the_full_sender_address_and_destination_domain"
            )

        return self._unique_keep_order(
            recommendations,
            maximum=self.config.maximum_recommendations,
        )

    def _build_explanation(
        self,
        *,
        risk_score: float,
        risk_level: RiskLevel,
        categories: Sequence[str],
        indicators: Sequence[FraudIndicator],
    ) -> str:
        """
        Create a concise human-readable explanation.
        """

        if not indicators:
            return (
                "No strong fraud indicators were detected in the supplied "
                "content. This does not prove the content is legitimate; "
                "independent verification may still be appropriate."
            )

        strongest = sorted(
            indicators,
            key=lambda item: (
                self._severity_rank(item.severity),
                item.score,
                item.confidence,
            ),
            reverse=True,
        )[:3]

        strongest_titles = ", ".join(
            item.title for item in strongest
        )

        category_text = (
            ", ".join(categories[:4])
            if categories
            else "unclassified suspicious activity"
        )

        return (
            f"The analysis produced a {risk_level.value} fraud-risk score of "
            f"{risk_score:.2f}/100. Primary detected patterns include "
            f"{category_text}. The strongest indicators were: "
            f"{strongest_titles}. This is a risk assessment rather than proof "
            f"of criminal activity, so high-impact decisions should be "
            f"independently verified."
        )

    def _build_limitations(
        self,
        request: FraudAnalysisRequest,
    ) -> List[str]:
        """
        State analysis limitations accurately.
        """

        limitations = [
            (
                "This detector performs passive heuristic analysis and does "
                "not establish legal proof of fraud."
            ),
            (
                "No URL was visited and no external reputation, certificate, "
                "WHOIS, DNS, or threat-intelligence service was queried."
            ),
        ]

        if request.url and not request.html:
            limitations.append(
                "Page HTML and live browser behavior were not supplied."
            )

        if request.input_type == FraudInputType.EMAIL:
            limitations.append(
                "Email authentication results such as SPF, DKIM, and DMARC "
                "were not independently verified unless supplied in metadata."
            )

        if request.invoice_data and not request.historical_data:
            limitations.append(
                "No historical invoice baseline was supplied for comparison."
            )

        if (
            request.invoice_data or request.payment_data
        ) and not request.known_bank_accounts:
            limitations.append(
                "No verified bank-account allowlist was supplied."
            )

        if request.attachments:
            limitations.append(
                "Attachments were not opened, executed, or malware-scanned; "
                "only supplied metadata and extracted text were analyzed."
            )

        return limitations

    # =========================================================================
    # Entity extraction and source preparation
    # =========================================================================

    def _extract_entities(
        self,
        request: FraudAnalysisRequest,
        urls: Sequence[str],
    ) -> Dict[str, Any]:
        """
        Extract redacted entities for dashboard display.
        """

        domains = sorted(
            {
                domain
                for domain in (
                    self._url_domain(url) for url in urls
                )
                if domain
            }
        )

        emails = sorted(
            {
                email
                for email in self._extract_emails(
                    self._build_combined_text(request)
                )
                if email
            }
        )

        sender_email = self._extract_email_address(
            request.sender
        )

        if sender_email:
            emails.append(sender_email)

        reply_email = self._extract_email_address(
            request.reply_to
        )

        if reply_email:
            emails.append(reply_email)

        emails = self._unique_keep_order(
            emails,
            maximum=self.config.maximum_entities,
        )

        redacted_emails = [
            self._redact_email(item) for item in emails
        ]

        bank_account = self._first_non_empty(
            self._extract_account_identifier(
                request.invoice_data
            ),
            self._extract_account_identifier(
                request.payment_data
            ),
        )

        amounts = self._extract_money_mentions(
            self._build_combined_text(request)
        )

        return {
            "domains": domains[: self.config.maximum_entities],
            "emails": redacted_emails[
                : self.config.maximum_entities
            ],
            "brands": self._find_claimed_brands(
                self._build_combined_text(request)
            )[: self.config.maximum_entities],
            "payment_account": (
                self._redact_account_identifier(bank_account)
                if bank_account
                else None
            ),
            "money_mentions": amounts[
                : self.config.maximum_entities
            ],
            "attachment_names": [
                self._redact_filename(item.filename)
                for item in request.attachments[
                    : self.config.maximum_entities
                ]
            ],
        }

    def _build_combined_text(
        self,
        request: FraudAnalysisRequest,
    ) -> str:
        """
        Build normalized analysis text from safe text-bearing fields.
        """

        parts = [
            request.subject or "",
            request.page_title or "",
            request.text or "",
        ]

        if request.invoice_data:
            parts.append(
                self._safe_mapping_to_text(
                    request.invoice_data
                )
            )

        if request.payment_data:
            parts.append(
                self._safe_mapping_to_text(
                    request.payment_data
                )
            )

        for attachment in request.attachments:
            if attachment.extracted_text:
                parts.append(attachment.extracted_text)

        combined = "\n".join(
            part for part in parts if part
        )

        return combined[: self.config.maximum_text_characters]

    def _build_source_hash(
        self,
        request: FraudAnalysisRequest,
    ) -> str:
        """
        Build deterministic hash without exposing source content.
        """

        payload = {
            "input_type": request.input_type.value,
            "text": request.text,
            "subject": request.subject,
            "sender": request.sender,
            "reply_to": request.reply_to,
            "url": request.url,
            "visible_url": request.visible_url,
            "final_url": request.final_url,
            "redirect_chain": request.redirect_chain,
            "html": request.html,
            "page_title": request.page_title,
            "form_actions": request.form_actions,
            "form_fields": request.form_fields,
            "attachments": [
                {
                    "filename": item.filename,
                    "content_type": item.content_type,
                    "size_bytes": item.size_bytes,
                    "sha256": item.sha256,
                    "password_protected": (
                        item.password_protected
                    ),
                }
                for item in request.attachments
            ],
            "invoice_data": request.invoice_data,
            "payment_data": request.payment_data,
        }

        serialized = json.dumps(
            payload,
            sort_keys=True,
            default=str,
            ensure_ascii=False,
        )

        return hashlib.sha256(
            serialized.encode("utf-8")
        ).hexdigest()

    def _build_redacted_preview(
        self,
        request: FraudAnalysisRequest,
    ) -> Optional[str]:
        """
        Build a short privacy-safe source preview.
        """

        source = self._build_combined_text(request).strip()

        if not source:
            source = request.url or request.sender or ""

        if not source:
            return None

        preview = source[
            : max(self.config.evidence_snippet_length * 2, 300)
        ]

        return self._redact_sensitive_text(preview)

    # =========================================================================
    # Parsing helpers
    # =========================================================================

    def _collect_urls(
        self,
        request: FraudAnalysisRequest,
        text: str,
    ) -> List[str]:
        """
        Collect unique URLs from structured fields and text.
        """

        candidates: List[str] = []

        for value in (
            request.url,
            request.visible_url,
            request.final_url,
        ):
            if value:
                candidates.append(value)

        candidates.extend(request.redirect_chain)
        candidates.extend(request.form_actions)
        candidates.extend(self._extract_urls(text))

        if request.html:
            candidates.extend(
                self._extract_urls_from_html(request.html)
            )

        normalized = []

        for candidate in candidates:
            value = self._normalize_url(candidate)

            if value:
                normalized.append(value)

        return self._unique_keep_order(
            normalized,
            maximum=200,
        )

    def _collect_expected_domains(
        self,
        request: FraudAnalysisRequest,
    ) -> List[str]:
        """
        Collect domains the source is expected to belong to.
        """

        domains: List[str] = []

        for domain in (
            request.expected_domain,
            request.expected_sender_domain,
            *request.known_vendor_domains,
        ):
            normalized = self._normalize_domain(domain)

            if normalized:
                domains.append(normalized)

        if request.expected_brand:
            brand_key = request.expected_brand.lower().strip()

            for known_brand, known_domains in (
                self.config.protected_brand_domains.items()
            ):
                if (
                    known_brand in brand_key
                    or brand_key in known_brand
                ):
                    domains.extend(known_domains)

        return self._unique_keep_order(
            domains,
            maximum=50,
        )

    def _extract_urls(self, text: str) -> List[str]:
        """
        Extract HTTP(S) and www URLs from text.
        """

        if not text:
            return []

        pattern = re.compile(
            r"(?i)\b("
            r"(?:https?://|www\.)"
            r"[^\s<>'\"\]\[(){}]+"
            r")"
        )

        results = []

        for match in pattern.findall(text):
            cleaned = match.rstrip(
                ".,;:!?)]}'\""
            )
            results.append(cleaned)

        return results

    def _extract_urls_from_html(
        self,
        html: str,
    ) -> List[str]:
        """
        Extract href, src, and action URLs from raw HTML.
        """

        decoded = unescape(html)
        pattern = re.compile(
            r"""(?is)\b(?:href|src|action)\s*=\s*
            (?:
                ["']([^"']+)["']
                |
                ([^\s>]+)
            )
            """,
            re.VERBOSE,
        )

        urls: List[str] = []

        for quoted, unquoted_value in pattern.findall(decoded):
            value = quoted or unquoted_value

            if value:
                urls.append(value.strip())

        return urls

    def _extract_html_form_actions(
        self,
        html: str,
    ) -> List[str]:
        """
        Extract form action attributes.
        """

        pattern = re.compile(
            r"""(?is)<form\b[^>]*\baction\s*=\s*
            (?:
                ["']([^"']*)["']
                |
                ([^\s>]+)
            )
            """,
            re.VERBOSE,
        )

        actions = []

        for quoted, unquoted_value in pattern.findall(html):
            value = quoted or unquoted_value

            if value:
                actions.append(value.strip())

        return self._unique_keep_order(
            actions,
            maximum=100,
        )

    def _extract_emails(self, text: str) -> List[str]:
        """
        Extract email addresses from text.
        """

        if not text:
            return []

        return re.findall(
            r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,63}\b",
            text,
            flags=re.IGNORECASE,
        )

    def _extract_email_address(
        self,
        value: Optional[str],
    ) -> Optional[str]:
        """
        Extract email address from a display-name header.
        """

        if not value:
            return None

        matches = self._extract_emails(value)

        if matches:
            return matches[0].lower()

        candidate = value.strip().lower()

        if "@" in candidate and " " not in candidate:
            return candidate.strip("<>")

        return None

    def _email_domain(
        self,
        email: Optional[str],
    ) -> Optional[str]:
        """
        Extract normalized domain from email address.
        """

        if not email or "@" not in email:
            return None

        return self._normalize_domain(
            email.rsplit("@", 1)[-1]
        )

    def _url_domain(
        self,
        value: Optional[str],
    ) -> Optional[str]:
        """
        Extract normalized domain from URL.
        """

        if not value:
            return None

        normalized = self._normalize_url(value)

        if not normalized:
            return None

        return self._normalize_domain(
            urlparse(normalized).hostname
        )

    # =========================================================================
    # Domain helpers
    # =========================================================================

    def _normalize_url(
        self,
        value: Optional[str],
    ) -> Optional[str]:
        """
        Normalize a URL for syntax analysis.
        """

        if not value:
            return None

        candidate = unescape(str(value)).strip()

        if not candidate:
            return None

        if candidate.startswith("//"):
            candidate = f"https:{candidate}"

        if not re.match(
            r"^[a-zA-Z][a-zA-Z0-9+.\-]*://",
            candidate,
        ):
            if candidate.lower().startswith("www."):
                candidate = f"https://{candidate}"
            elif re.match(
                r"^[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}(?:[:/]|$)",
                candidate,
            ):
                candidate = f"https://{candidate}"

        parsed = urlparse(candidate)

        if parsed.scheme.lower() not in {
            "http",
            "https",
            "ftp",
        }:
            return None

        return candidate[
            : self.config.maximum_url_characters
        ]

    def _normalize_domain(
        self,
        value: Optional[str],
    ) -> Optional[str]:
        """
        Normalize hostname or domain input.
        """

        if not value:
            return None

        candidate = str(value).strip().lower()
        candidate = candidate.strip(".")

        if "://" in candidate:
            candidate = (
                urlparse(candidate).hostname or ""
            ).lower()

        if "@" in candidate:
            candidate = candidate.rsplit("@", 1)[-1]

        candidate = candidate.split(":", 1)[0]
        candidate = candidate.strip(".")

        if candidate.startswith("www."):
            candidate = candidate[4:]

        return candidate or None

    def _domain_matches_expected(
        self,
        observed: str,
        expected: str,
    ) -> bool:
        """
        Check exact domain or legitimate subdomain relation.
        """

        observed = self._normalize_domain(observed) or ""
        expected = self._normalize_domain(expected) or ""

        if not observed or not expected:
            return False

        return (
            observed == expected
            or observed.endswith(f".{expected}")
        )

    def _same_organizational_domain(
        self,
        left: str,
        right: str,
    ) -> bool:
        """
        Approximate organizational-domain comparison.

        Uses a conservative built-in suffix heuristic without external public
        suffix dependencies.
        """

        left_normalized = self._normalize_domain(left)
        right_normalized = self._normalize_domain(right)

        if not left_normalized or not right_normalized:
            return False

        return (
            left_normalized == right_normalized
            or left_normalized.endswith(
                f".{right_normalized}"
            )
            or right_normalized.endswith(
                f".{left_normalized}"
            )
            or self._approximate_registered_domain(
                left_normalized
            )
            == self._approximate_registered_domain(
                right_normalized
            )
        )

    def _approximate_registered_domain(
        self,
        domain: str,
    ) -> str:
        """
        Approximate registrable domain without external dependencies.
        """

        labels = domain.split(".")

        if len(labels) <= 2:
            return domain

        common_second_level_suffixes = {
            "co.uk",
            "org.uk",
            "gov.uk",
            "ac.uk",
            "com.au",
            "net.au",
            "org.au",
            "co.nz",
            "com.pk",
            "com.br",
            "co.jp",
            "co.in",
            "co.za",
            "com.sg",
            "com.my",
            "com.tr",
            "com.mx",
            "com.cn",
            "com.hk",
            "com.ae",
            "co.kr",
        }

        suffix2 = ".".join(labels[-2:])

        if (
            suffix2 in common_second_level_suffixes
            and len(labels) >= 3
        ):
            return ".".join(labels[-3:])

        return ".".join(labels[-2:])

    def _is_lookalike_domain(
        self,
        observed: str,
        expected: str,
    ) -> bool:
        """
        Detect typo, insertion, hyphen, and homoglyph lookalike domains.
        """

        observed = self._normalize_domain(observed) or ""
        expected = self._normalize_domain(expected) or ""

        if not observed or not expected:
            return False

        if self._domain_matches_expected(
            observed,
            expected,
        ):
            return False

        observed_label = self._registrable_label(observed)
        expected_label = self._registrable_label(expected)

        if not observed_label or not expected_label:
            return False

        distance = self._levenshtein_distance(
            observed_label,
            expected_label,
        )

        similarity = self._string_similarity(
            observed_label,
            expected_label,
        )

        compact_observed = observed_label.replace("-", "")
        compact_expected = expected_label.replace("-", "")

        return bool(
            distance <= 2
            or similarity >= 0.82
            or compact_observed == compact_expected
            or self._contains_homoglyph_pattern(
                observed_label,
                expected_label,
            )
        )

    def _contains_homoglyph_pattern(
        self,
        observed: str,
        expected: str,
    ) -> bool:
        """
        Detect common ASCII/Unicode visual substitutions.
        """

        mapping = str.maketrans(
            {
                "0": "o",
                "1": "l",
                "3": "e",
                "5": "s",
                "7": "t",
                "|": "l",
                "@": "a",
                "$": "s",
            }
        )

        observed_ascii = self._ascii_fold(
            observed
        ).translate(mapping)
        expected_ascii = self._ascii_fold(
            expected
        ).translate(mapping)

        return (
            observed_ascii != expected_ascii
            and self._string_similarity(
                observed_ascii,
                expected_ascii,
            )
            >= 0.9
        )

    def _registrable_label(
        self,
        domain: str,
    ) -> str:
        """
        Return main registrable-domain label.
        """

        registered = self._approximate_registered_domain(
            domain
        )
        labels = registered.split(".")

        return labels[0] if labels else registered

    def _subdomain_count(
        self,
        domain: str,
    ) -> int:
        """
        Approximate subdomain count.
        """

        registered = self._approximate_registered_domain(
            domain
        )

        domain_labels = domain.split(".")
        registered_labels = registered.split(".")

        return max(
            0,
            len(domain_labels) - len(registered_labels),
        )

    def _top_level_domain(
        self,
        domain: str,
    ) -> str:
        labels = domain.split(".")
        return labels[-1] if labels else ""

    def _is_ip_address(
        self,
        value: str,
    ) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    # =========================================================================
    # Fraud pattern helpers
    # =========================================================================

    def _detect_job_scam_pattern(
        self,
        text: str,
    ) -> bool:
        job_markers = (
            "job offer",
            "you are hired",
            "work from home",
            "remote position",
            "employment opportunity",
            "interview on telegram",
            "interview on whatsapp",
        )

        payment_markers = (
            "deposit the check",
            "buy equipment",
            "send money back",
            "purchase gift cards",
            "processing fee",
            "training fee",
            "registration fee",
        )

        return (
            any(marker in text for marker in job_markers)
            and any(
                marker in text for marker in payment_markers
            )
        )

    def _detect_romance_scam_pattern(
        self,
        text: str,
    ) -> bool:
        relationship_markers = (
            "my love",
            "dear love",
            "soulmate",
            "love you",
            "future together",
            "marry you",
        )

        money_markers = (
            "send money",
            "wire money",
            "emergency",
            "hospital bill",
            "travel ticket",
            "customs fee",
            "stuck abroad",
        )

        return (
            any(
                marker in text
                for marker in relationship_markers
            )
            and any(
                marker in text for marker in money_markers
            )
        )

    def _detect_charity_scam_pattern(
        self,
        text: str,
    ) -> bool:
        charity_markers = (
            "donate now",
            "charity",
            "disaster relief",
            "help the victims",
            "emergency relief",
        )

        risky_payment_markers = (
            "gift card",
            "crypto",
            "bitcoin",
            "wire transfer",
            "personal account",
        )

        return (
            any(
                marker in text for marker in charity_markers
            )
            and any(
                marker in text
                for marker in risky_payment_markers
            )
        )

    def _invoice_requests_urgent_payment(
        self,
        text: str,
        invoice: Mapping[str, Any],
    ) -> bool:
        combined = (
            text
            + "\n"
            + self._safe_mapping_to_text(invoice)
        ).lower()

        markers = (
            "pay immediately",
            "urgent payment",
            "payment today",
            "same day payment",
            "final notice",
            "avoid service interruption",
            "bypass approval",
        )

        return any(marker in combined for marker in markers)

    def _has_credential_context(
        self,
        request: FraudAnalysisRequest,
        indicators: Sequence[FraudIndicator],
    ) -> bool:
        fields = {
            self._normalize_field_name(item)
            for item in request.form_fields
        }

        configured_fields = {
            self._normalize_field_name(item)
            for item in self.config.credential_field_names
        }

        if fields & configured_fields:
            return True

        if request.html and self._html_has_login_form(
            request.html
        ):
            return True

        return any(
            item.category
            in {
                FraudCategory.CREDENTIAL_THEFT,
                FraudCategory.FAKE_LOGIN_PAGE,
                FraudCategory.IDENTITY_VERIFICATION_SCAM,
            }
            for item in indicators
        )

    def _has_payment_context(
        self,
        request: FraudAnalysisRequest,
    ) -> bool:
        return bool(
            request.invoice_data
            or request.payment_data
            or request.input_type
            in {
                FraudInputType.INVOICE,
                FraudInputType.PAYMENT_REQUEST,
                FraudInputType.QR_PAYMENT,
            }
        )

    def _html_has_login_form(
        self,
        html: str,
    ) -> bool:
        lowered = html.lower()

        return bool(
            "<form" in lowered
            and (
                'type="password"' in lowered
                or "type='password'" in lowered
                or "name=\"password\"" in lowered
                or "name='password'" in lowered
            )
        )

    # =========================================================================
    # Data comparison helpers
    # =========================================================================

    def _extract_account_identifier(
        self,
        data: Mapping[str, Any],
    ) -> Optional[str]:
        """
        Extract payment-account identifier from structured data.
        """

        for key in (
            "iban",
            "account_number",
            "bank_account",
            "beneficiary_account",
            "routing_account",
            "wallet_address",
            "crypto_address",
            "payment_address",
        ):
            value = data.get(key)

            if value is not None and str(value).strip():
                return str(value).strip()

        routing = self._first_non_empty(
            data.get("routing_number"),
            data.get("sort_code"),
            data.get("swift"),
            data.get("bic"),
        )

        account = self._first_non_empty(
            data.get("account_number"),
            data.get("account"),
        )

        if routing and account:
            return f"{routing}:{account}"

        return None

    def _normalize_account_identifier(
        self,
        value: str,
    ) -> str:
        """
        Normalize account identifier for comparison.
        """

        return re.sub(
            r"[^A-Za-z0-9]",
            "",
            str(value),
        ).upper()

    def _to_decimal(
        self,
        value: Any,
    ) -> Optional[Decimal]:
        """
        Safely parse currency-like numeric values.
        """

        if value is None:
            return None

        if isinstance(value, Decimal):
            return value

        if isinstance(value, (int, float)):
            try:
                return Decimal(str(value))
            except InvalidOperation:
                return None

        cleaned = re.sub(
            r"[^0-9.\-]",
            "",
            str(value),
        )

        if not cleaned or cleaned in {"-", ".", "-."}:
            return None

        try:
            return Decimal(cleaned)
        except InvalidOperation:
            return None

    # =========================================================================
    # Redaction and privacy helpers
    # =========================================================================

    def _redact_sensitive_text(
        self,
        text: str,
    ) -> str:
        """
        Redact common credentials, card numbers, bank details, and secrets.
        """

        if not self.config.redact_sensitive_data:
            return text

        redacted = text

        redacted = re.sub(
            r"(?i)\b(password|passwd|passcode|pin|otp|"
            r"verification code|security code|api key|token|"
            r"private key|seed phrase|recovery phrase)"
            r"\s*[:=]\s*\S+",
            lambda match: (
                f"{match.group(1)}=[REDACTED]"
            ),
            redacted,
        )

        redacted = re.sub(
            r"\b(?:\d[ -]*?){13,19}\b",
            "[REDACTED_PAYMENT_NUMBER]",
            redacted,
        )

        redacted = re.sub(
            r"(?i)\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b",
            "[REDACTED_IBAN]",
            redacted,
        )

        redacted = re.sub(
            r"(?i)\b(?:0x)?[A-F0-9]{40,64}\b",
            "[REDACTED_KEY_OR_WALLET]",
            redacted,
        )

        return redacted

    def _contains_obvious_secret(
        self,
        text: str,
    ) -> bool:
        """
        Check whether an output preview still appears to contain a secret.
        """

        patterns = (
            r"(?i)\bpassword\s*[:=]\s*\S+",
            r"(?i)\bapi[_ ]?key\s*[:=]\s*\S+",
            r"(?i)\bprivate[_ ]?key\s*[:=]\s*\S+",
            r"\b(?:\d[ -]*?){13,19}\b",
        )

        return any(
            re.search(pattern, text)
            for pattern in patterns
        )

    def _redact_email(
        self,
        email: str,
    ) -> str:
        """
        Partially redact email local part.
        """

        if "@" not in email:
            return self._redact_name(email)

        local, domain = email.rsplit("@", 1)

        if len(local) <= 2:
            masked = local[:1] + "*"
        else:
            masked = local[:2] + "*" * min(
                len(local) - 2,
                6,
            )

        return f"{masked}@{domain}"

    def _redact_account_identifier(
        self,
        value: Optional[str],
    ) -> Optional[str]:
        """
        Preserve only final account characters.
        """

        if not value:
            return None

        normalized = re.sub(
            r"\s+",
            "",
            str(value),
        )

        if len(normalized) <= 4:
            return "*" * len(normalized)

        return (
            "*" * min(len(normalized) - 4, 16)
            + normalized[-4:]
        )

    def _redact_filename(
        self,
        filename: str,
    ) -> str:
        """
        Return filename without path traversal components.
        """

        return PurePath(filename).name[:255]

    def _redact_url(
        self,
        url: Optional[str],
    ) -> Optional[str]:
        """
        Remove sensitive query values and user information.
        """

        if not url:
            return None

        normalized = self._normalize_url(url)

        if not normalized:
            return str(url)[:300]

        parsed = urlparse(normalized)
        hostname = parsed.hostname or ""
        port = (
            f":{parsed.port}"
            if parsed.port is not None
            else ""
        )

        path = parsed.path[:200]
        query_keys = sorted(
            parse_qs(
                parsed.query,
                keep_blank_values=True,
            ).keys()
        )

        query_text = (
            "?" + "&".join(f"{key}=[REDACTED]" for key in query_keys)
            if query_keys
            else ""
        )

        return (
            f"{parsed.scheme}://{hostname}{port}"
            f"{path}{query_text}"
        )[:500]

    def _redact_qr_payload(
        self,
        value: str,
    ) -> str:
        """
        Redact payment payload while preserving classification context.
        """

        digest = hashlib.sha256(
            value.encode("utf-8")
        ).hexdigest()[:16]

        return (
            f"[QR_PAYLOAD_REDACTED sha256_prefix={digest}]"
        )

    def _redact_name(
        self,
        value: Optional[str],
    ) -> str:
        """
        Partially redact a person or company name.
        """

        if not value:
            return ""

        value = str(value).strip()

        if len(value) <= 2:
            return value[:1] + "*"

        return value[:2] + "*" * min(
            len(value) - 2,
            8,
        )

    # =========================================================================
    # General utility methods
    # =========================================================================

    def _indicator_to_dict(
        self,
        indicator: FraudIndicator,
    ) -> Dict[str, Any]:
        """
        Serialize FraudIndicator with enum values.
        """

        return {
            "code": indicator.code,
            "category": indicator.category.value,
            "severity": indicator.severity.value,
            "score": round(indicator.score, 2),
            "title": indicator.title,
            "description": indicator.description,
            "evidence": indicator.evidence,
            "source": indicator.source,
            "confidence": round(
                indicator.confidence,
                4,
            ),
            "metadata": indicator.metadata,
        }

    def _deduplicate_indicators(
        self,
        indicators: Sequence[FraudIndicator],
    ) -> List[FraudIndicator]:
        """
        Deduplicate indicators while preserving strongest evidence.
        """

        strongest: Dict[
            Tuple[str, str, Optional[str]],
            FraudIndicator,
        ] = {}

        for indicator in indicators:
            evidence_key = (
                self._fingerprint(indicator.evidence or "")
                if indicator.evidence
                else None
            )

            key = (
                indicator.code,
                indicator.category.value,
                evidence_key,
            )

            existing = strongest.get(key)

            if existing is None:
                strongest[key] = indicator
                continue

            existing_strength = (
                self._severity_rank(existing.severity),
                existing.score,
                existing.confidence,
            )

            candidate_strength = (
                self._severity_rank(indicator.severity),
                indicator.score,
                indicator.confidence,
            )

            if candidate_strength > existing_strength:
                strongest[key] = indicator

        return sorted(
            strongest.values(),
            key=lambda item: (
                self._severity_rank(item.severity),
                item.score,
                item.confidence,
            ),
            reverse=True,
        )

    def _weight(
        self,
        key: str,
    ) -> float:
        """
        Safely obtain configured score weight.
        """

        try:
            return float(
                self.config.score_weights.get(key, 10.0)
            )
        except Exception:
            return 10.0

    def _severity_confidence(
        self,
        severity: IndicatorSeverity,
    ) -> float:
        """
        Default confidence by severity.
        """

        return {
            IndicatorSeverity.INFO: 0.5,
            IndicatorSeverity.LOW: 0.55,
            IndicatorSeverity.MEDIUM: 0.68,
            IndicatorSeverity.HIGH: 0.82,
            IndicatorSeverity.CRITICAL: 0.92,
        }[severity]

    def _severity_rank(
        self,
        severity: IndicatorSeverity,
    ) -> int:
        return {
            IndicatorSeverity.INFO: 0,
            IndicatorSeverity.LOW: 1,
            IndicatorSeverity.MEDIUM: 2,
            IndicatorSeverity.HIGH: 3,
            IndicatorSeverity.CRITICAL: 4,
        }[severity]

    def _find_first_pattern(
        self,
        text: str,
        patterns: Sequence[str],
    ) -> Optional[re.Match[str]]:
        """
        Return first regex match across patterns.
        """

        for pattern in patterns:
            match = re.search(
                pattern,
                text,
                flags=re.IGNORECASE | re.DOTALL,
            )

            if match:
                return match

        return None

    def _evidence_snippet(
        self,
        text: str,
        start: int,
        end: int,
    ) -> Optional[str]:
        """
        Build redacted evidence snippet.
        """

        if not self.config.include_evidence_snippets:
            return None

        radius = self.config.evidence_snippet_length // 2

        snippet = text[
            max(0, start - radius):
            min(len(text), end + radius)
        ]

        snippet = re.sub(r"\s+", " ", snippet).strip()

        return self._redact_sensitive_text(snippet)

    def _first_matching_sentence(
        self,
        text: str,
        markers: Sequence[str],
    ) -> Optional[str]:
        """
        Return first redacted sentence containing a marker.
        """

        if not text:
            return None

        sentences = re.split(
            r"(?<=[.!?])\s+|\n+",
            text,
        )

        for sentence in sentences:
            lowered = sentence.lower()

            if any(marker in lowered for marker in markers):
                return self._redact_sensitive_text(
                    sentence.strip()[
                        : self.config.evidence_snippet_length
                    ]
                )

        return None

    def _normalize_text(
        self,
        text: str,
    ) -> str:
        """
        Normalize text while retaining semantic content.
        """

        text = unescape(text)
        text = unicodedata.normalize("NFKC", text)
        text = re.sub(r"\s+", " ", text)

        return text.strip().lower()

    def _normalize_field_name(
        self,
        value: str,
    ) -> str:
        """
        Normalize form-field name.
        """

        return re.sub(
            r"[^a-z0-9]+",
            "_",
            value.lower(),
        ).strip("_")

    def _normalize_company_name(
        self,
        value: str,
    ) -> str:
        """
        Normalize company name for comparison.
        """

        value = self._ascii_fold(value.lower())

        removable = (
            " limited",
            " ltd",
            " llc",
            " inc",
            " incorporated",
            " corporation",
            " corp",
            " company",
            " co",
            " plc",
            " pvt",
            " private",
            " gmbh",
        )

        for suffix in removable:
            if value.endswith(suffix):
                value = value[: -len(suffix)]

        return re.sub(
            r"[^a-z0-9]",
            "",
            value,
        )

    def _find_claimed_brand(
        self,
        text: str,
    ) -> Optional[str]:
        """
        Return first protected brand claimed in text.
        """

        brands = self._find_claimed_brands(text)

        return brands[0] if brands else None

    def _find_claimed_brands(
        self,
        text: str,
    ) -> List[str]:
        """
        Identify configured protected brands mentioned in text.
        """

        lowered = text.lower()
        found = []

        for brand in self.config.protected_brand_domains:
            if re.search(
                rf"\b{re.escape(brand)}\b",
                lowered,
            ):
                found.append(brand)

        return found

    def _has_dangerous_double_extension(
        self,
        filename: str,
    ) -> bool:
        """
        Detect file.pdf.exe or image.jpg.scr patterns.
        """

        suffixes = [
            suffix.lower()
            for suffix in PurePath(filename).suffixes
        ]

        if len(suffixes) < 2:
            return False

        harmless_decoys = {
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".txt",
            ".rtf",
        }

        return bool(
            suffixes[-1]
            in self.config.suspicious_attachment_extensions
            and suffixes[-2] in harmless_decoys
        )

    def _extract_money_mentions(
        self,
        text: str,
    ) -> List[str]:
        """
        Extract bounded, redacted monetary mentions.
        """

        patterns = re.findall(
            r"(?i)(?:USD|EUR|GBP|PKR|AED|CAD|AUD|\$|€|£)"
            r"\s?\d[\d,]*(?:\.\d{1,2})?",
            text,
        )

        return self._unique_keep_order(
            patterns,
            maximum=50,
        )

    def _safe_mapping_to_text(
        self,
        data: Mapping[str, Any],
    ) -> str:
        """
        Convert safe primitive mapping values to analysis text.
        """

        excluded_keys = {
            "password",
            "passwd",
            "pin",
            "otp",
            "token",
            "api_key",
            "secret",
            "private_key",
            "cvv",
            "cvc",
        }

        parts: List[str] = []

        for key, value in data.items():
            normalized_key = str(key).lower()

            if normalized_key in excluded_keys:
                continue

            if isinstance(
                value,
                (str, int, float, Decimal, bool),
            ):
                parts.append(f"{key}: {value}")

        return self._redact_sensitive_text(
            "\n".join(parts)
        )

    def _sanitize_log_payload(
        self,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Remove sensitive fields from events and audit logs.
        """

        blocked_keys = {
            "text",
            "html",
            "body",
            "password",
            "token",
            "secret",
            "private_key",
            "seed_phrase",
            "card_number",
            "cvv",
            "cvc",
            "bank_account",
            "account_number",
            "iban",
            "qr_payload",
            "payment_data",
            "invoice_data",
        }

        def sanitize(value: Any, key: Optional[str] = None) -> Any:
            if (
                key
                and key.lower() in blocked_keys
            ):
                return "[REDACTED]"

            if isinstance(value, dict):
                return {
                    str(inner_key): sanitize(
                        inner_value,
                        str(inner_key),
                    )
                    for inner_key, inner_value in value.items()
                }

            if isinstance(value, list):
                return [
                    sanitize(item)
                    for item in value[:100]
                ]

            if isinstance(value, tuple):
                return [
                    sanitize(item)
                    for item in value[:100]
                ]

            if isinstance(value, str):
                return self._redact_sensitive_text(
                    value[:2_000]
                )

            if isinstance(
                value,
                (int, float, bool, type(None)),
            ):
                return value

            return str(value)[:500]

        return sanitize(payload)

    def _parse_attachments(
        self,
        attachments: Sequence[
            Union[AttachmentMetadata, Dict[str, Any]]
        ],
    ) -> List[AttachmentMetadata]:
        """
        Normalize attachment metadata.
        """

        parsed: List[AttachmentMetadata] = []

        for item in attachments:
            if isinstance(item, AttachmentMetadata):
                parsed.append(item)
                continue

            if not isinstance(item, dict):
                continue

            filename = str(
                item.get("filename")
                or item.get("name")
                or "unnamed_attachment"
            )

            size_value = item.get("size_bytes")

            try:
                size_bytes = (
                    int(size_value)
                    if size_value is not None
                    else None
                )
            except (TypeError, ValueError):
                size_bytes = None

            parsed.append(
                AttachmentMetadata(
                    filename=filename,
                    content_type=self._optional_string(
                        item.get("content_type")
                        or item.get("mime_type")
                    ),
                    size_bytes=size_bytes,
                    sha256=self._optional_string(
                        item.get("sha256")
                    ),
                    password_protected=bool(
                        item.get("password_protected", False)
                    ),
                    extracted_text=self._optional_string(
                        item.get("extracted_text")
                    ),
                    metadata=self._safe_dict(
                        item.get("metadata")
                    ),
                )
            )

        return parsed[
            : self.config.maximum_attachments
        ]

    def _safe_dict(
        self,
        value: Any,
    ) -> Dict[str, Any]:
        """
        Return a shallow dictionary copy or an empty dictionary.
        """

        if isinstance(value, dict):
            return dict(value)

        return {}

    def _normalize_string_list(
        self,
        value: Any,
    ) -> List[str]:
        """
        Normalize string/list/tuple input to list[str].
        """

        if value is None:
            return []

        if isinstance(value, str):
            return [value]

        if isinstance(value, (list, tuple, set)):
            return [
                str(item)
                for item in value
                if item is not None
                and str(item).strip()
            ]

        return [str(value)]

    def _optional_string(
        self,
        value: Any,
    ) -> Optional[str]:
        """
        Normalize optional scalar to stripped string.
        """

        if value is None:
            return None

        text = str(value).strip()

        return text or None

    def _coerce_enum(
        self,
        enum_class: Any,
        value: Any,
        default: Any,
    ) -> Any:
        """
        Safely coerce input to enum.
        """

        if isinstance(value, enum_class):
            return value

        if value is None:
            return default

        try:
            return enum_class(str(value).lower())
        except (TypeError, ValueError):
            return default

    def _first_non_empty(
        self,
        *values: Any,
    ) -> Any:
        """
        Return first non-empty value.
        """

        for value in values:
            if value is None:
                continue

            if isinstance(value, str):
                if value.strip():
                    return value.strip()
                continue

            return value

        return None

    def _unique_keep_order(
        self,
        items: Iterable[str],
        *,
        maximum: int,
    ) -> List[str]:
        """
        Deduplicate strings while preserving order.
        """

        seen: Set[str] = set()
        output: List[str] = []

        for item in items:
            value = str(item).strip()

            if not value:
                continue

            key = value.lower()

            if key in seen:
                continue

            seen.add(key)
            output.append(value)

            if len(output) >= maximum:
                break

        return output

    def _string_similarity(
        self,
        left: str,
        right: str,
    ) -> float:
        """
        Normalized Levenshtein similarity.
        """

        if left == right:
            return 1.0

        if not left or not right:
            return 0.0

        distance = self._levenshtein_distance(
            left,
            right,
        )

        return max(
            0.0,
            1.0 - distance / max(len(left), len(right)),
        )

    def _levenshtein_distance(
        self,
        left: str,
        right: str,
    ) -> int:
        """
        Memory-efficient Levenshtein edit distance.
        """

        if left == right:
            return 0

        if not left:
            return len(right)

        if not right:
            return len(left)

        if len(left) < len(right):
            left, right = right, left

        previous = list(range(len(right) + 1))

        for left_index, left_char in enumerate(
            left,
            start=1,
        ):
            current = [left_index]

            for right_index, right_char in enumerate(
                right,
                start=1,
            ):
                insert_cost = current[right_index - 1] + 1
                delete_cost = previous[right_index] + 1
                substitute_cost = (
                    previous[right_index - 1]
                    + (left_char != right_char)
                )

                current.append(
                    min(
                        insert_cost,
                        delete_cost,
                        substitute_cost,
                    )
                )

            previous = current

        return previous[-1]

    def _ascii_fold(
        self,
        value: str,
    ) -> str:
        """
        Fold Unicode text to approximate ASCII.
        """

        normalized = unicodedata.normalize(
            "NFKD",
            value,
        )

        return "".join(
            character
            for character in normalized
            if not unicodedata.combining(character)
        ).lower()

    def _fingerprint(
        self,
        value: str,
    ) -> str:
        """
        Build short content fingerprint.
        """

        normalized = re.sub(
            r"\W+",
            "",
            value.lower(),
        )[:1_000]

        return hashlib.sha1(
            normalized.encode("utf-8")
        ).hexdigest()

    def _utc_now(self) -> str:
        """
        Return ISO 8601 UTC timestamp.
        """

        return datetime.now(timezone.utc).isoformat()


# =============================================================================
# Module-level factories and registry hooks
# =============================================================================

def create_fraud_detector(
    config: Optional[FraudDetectorConfig] = None,
    **kwargs: Any,
) -> FraudDetector:
    """
    Factory function for Agent Loader and dependency injection.
    """

    return FraudDetector(
        config=config,
        **kwargs,
    )


def get_agent_metadata() -> Dict[str, Any]:
    """
    Module-level metadata hook for registries that inspect modules directly.
    """

    return FraudDetector().get_registry_metadata()


def health_check() -> Dict[str, Any]:
    """
    Module-level health-check hook.
    """

    return FraudDetector().health_check()


__all__ = [
    "FraudDetector",
    "FraudDetectorConfig",
    "FraudAnalysisRequest",
    "FraudAnalysisData",
    "FraudIndicator",
    "AttachmentMetadata",
    "TaskContext",
    "FraudInputType",
    "FraudCategory",
    "RiskLevel",
    "ConfidenceLevel",
    "RecommendedAction",
    "IndicatorSeverity",
    "AnalysisStatus",
    "create_fraud_detector",
    "get_agent_metadata",
    "health_check",
]