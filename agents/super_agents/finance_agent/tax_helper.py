"""
agents/super_agents/finance_agent/receipt_reader.py

Purpose:
    OCR/parse receipts and invoice documents with privacy for the William / Jarvis
    Multi-Agent AI SaaS System by Digital Promotix.

This module is designed to be:
    - Import-safe even if the full William/Jarvis framework is not present yet.
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router, and Master Agent routing.
    - Privacy-first for receipt/invoice OCR and parsing.
    - SaaS-safe with user_id/workspace_id validation and isolation.
    - Ready for FastAPI/dashboard integration.
    - Compatible with Security Agent, Verification Agent, Memory Agent, audit logs, and analytics.

Important safety behavior:
    - This file does NOT submit payments, transfers, refunds, messages, browser actions, or destructive actions.
    - It only extracts and structures data from receipt/invoice text or supported files.
    - Sensitive financial/payment identifiers are redacted by default.
"""

from __future__ import annotations

import hashlib
import json
import logging
import mimetypes
import os
import re
import tempfile
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional imports
# ---------------------------------------------------------------------------

try:
    from PIL import Image  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    Image = None  # type: ignore

try:
    import pytesseract  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    pytesseract = None  # type: ignore

try:
    import pdfplumber  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    pdfplumber = None  # type: ignore


# ---------------------------------------------------------------------------
# Optional William/Jarvis BaseAgent import with fallback
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import safety

    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe before the real William/Jarvis BaseAgent
        exists. The real BaseAgent should provide richer event, audit, registry,
        permission, and routing features.
        """

        agent_name: str = "base_agent"
        agent_type: str = "fallback"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.logger = logging.getLogger(self.__class__.__name__)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_name, payload)

        def log_audit(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.info("Fallback audit: %s %s", event_name, payload)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants and patterns
# ---------------------------------------------------------------------------

DEFAULT_MAX_FILE_BYTES = 15 * 1024 * 1024
DEFAULT_MAX_TEXT_CHARS = 120_000

SUPPORTED_TEXT_EXTENSIONS = {".txt", ".csv", ".md", ".json"}
SUPPORTED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff", ".tif"}
SUPPORTED_PDF_EXTENSIONS = {".pdf"}

RECEIPT_DOCUMENT_TYPES = {
    "receipt",
    "invoice",
    "bill",
    "statement",
    "expense_document",
    "purchase_order",
    "quote",
    "unknown",
}

SENSITIVE_ACTIONS = {
    "extract_receipt",
    "parse_receipt",
    "parse_invoice",
    "read_receipt_file",
    "read_invoice_file",
}

CURRENCY_SYMBOLS = {
    "$": "USD",
    "€": "EUR",
    "£": "GBP",
    "¥": "JPY",
    "₹": "INR",
    "₨": "PKR",
    "Rs": "PKR",
    "AED": "AED",
    "SAR": "SAR",
    "CAD": "CAD",
    "AUD": "AUD",
    "USD": "USD",
    "EUR": "EUR",
    "GBP": "GBP",
    "PKR": "PKR",
}

EMAIL_PATTERN = re.compile(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b")
PHONE_PATTERN = re.compile(
    r"(?x)(?<!\d)(?:\+?\d{1,3}[\s.\-()]*)?(?:\(?\d{2,4}\)?[\s.\-()]*){2,5}\d{2,4}(?!\d)"
)
CARD_PATTERN = re.compile(
    r"(?i)\b(?:card|visa|mastercard|amex|american express|discover)?\s*(?:ending|ends|last\s*4|xxxx|x{2,}|[*]{2,})?\s*[:#\-]?\s*(?:\d[\s\-]*){12,19}\b"
)
CARD_LAST4_PATTERN = re.compile(r"(?i)\b(?:ending|ends|last\s*4|xxxx|x{2,}|[*]{2,})\s*[:#\-]?\s*(\d{4})\b")
IBAN_PATTERN = re.compile(r"(?i)\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
BANK_ACCOUNT_PATTERN = re.compile(r"(?i)\b(?:account|acct|iban|routing|sort code)\s*[:#\-]?\s*[A-Z0-9\- ]{6,34}\b")
TAX_ID_PATTERN = re.compile(r"(?i)\b(?:tax\s*id|vat|gst|ein|ssn|ntn|trn)\s*[:#\-]?\s*[A-Z0-9\-]{4,25}\b")
INVOICE_NUMBER_PATTERN = re.compile(
    r"(?i)\b(?:invoice|inv|bill|receipt|order|transaction|txn|ref|reference|po)\s*(?:number|no|#|id)?\s*[:#\-]?\s*([A-Z0-9][A-Z0-9\-_/]{2,40})\b"
)
DATE_PATTERN = re.compile(
    r"(?ix)\b("
    r"\d{4}[-/]\d{1,2}[-/]\d{1,2}"
    r"|"
    r"\d{1,2}[-/]\d{1,2}[-/]\d{2,4}"
    r"|"
    r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?\s+\d{1,2},?\s+\d{2,4}"
    r"|"
    r"\d{1,2}\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?,?\s+\d{2,4}"
    r")\b"
)
AMOUNT_PATTERN = re.compile(
    r"(?ix)(?<![A-Z0-9])("
    r"(?:USD|EUR|GBP|PKR|AED|SAR|CAD|AUD|INR|Rs\.?|US\$|C\$|A\$)?\s*"
    r"[$€£¥₹₨]?\s*"
    r"-?\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?"
    r"|"
    r"(?:USD|EUR|GBP|PKR|AED|SAR|CAD|AUD|INR|Rs\.?)\s*-?\d+(?:\.\d{1,2})?"
    r")(?![A-Z0-9])"
)

TOTAL_KEYWORDS = (
    "total",
    "amount due",
    "balance due",
    "grand total",
    "invoice total",
    "net total",
    "paid",
    "payment",
)
SUBTOTAL_KEYWORDS = ("subtotal", "sub total", "net amount")
TAX_KEYWORDS = ("tax", "vat", "gst", "sales tax", "service tax")
DISCOUNT_KEYWORDS = ("discount", "coupon", "promo")
TIP_KEYWORDS = ("tip", "gratuity")
SHIPPING_KEYWORDS = ("shipping", "delivery", "freight")


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ReceiptReaderConfig:
    """
    Configuration for ReceiptReader.

    The defaults are privacy-friendly:
        - Redaction is enabled.
        - Raw text is not returned unless explicitly requested.
        - No external OCR API is called.
    """

    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_text_chars: int = DEFAULT_MAX_TEXT_CHARS
    redact_sensitive: bool = True
    include_raw_text_default: bool = False
    allow_ocr: bool = True
    allow_pdf_text_extraction: bool = True
    allow_local_temp_files: bool = True
    audit_enabled: bool = True
    emit_events_enabled: bool = True
    memory_payload_enabled: bool = True
    verification_payload_enabled: bool = True
    strict_context_validation: bool = True
    default_currency: Optional[str] = None
    min_confidence_for_auto_fields: float = 0.35


@dataclass
class ParsedLineItem:
    """
    A parsed receipt or invoice line item.
    """

    description: str
    quantity: Optional[float] = None
    unit_price: Optional[str] = None
    amount: Optional[str] = None
    currency: Optional[str] = None
    confidence: float = 0.4


@dataclass
class ParsedReceiptDocument:
    """
    Structured receipt/invoice extraction result.
    """

    document_type: str = "unknown"
    merchant_name: Optional[str] = None
    vendor_name: Optional[str] = None
    invoice_number: Optional[str] = None
    receipt_number: Optional[str] = None
    transaction_id: Optional[str] = None
    purchase_order_number: Optional[str] = None
    issue_date: Optional[str] = None
    due_date: Optional[str] = None
    paid_date: Optional[str] = None
    currency: Optional[str] = None
    subtotal: Optional[str] = None
    tax: Optional[str] = None
    discount: Optional[str] = None
    tip: Optional[str] = None
    shipping: Optional[str] = None
    total: Optional[str] = None
    amount_due: Optional[str] = None
    payment_method: Optional[str] = None
    card_last4: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    address_lines: List[str] = field(default_factory=list)
    line_items: List[ParsedLineItem] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class FileReadResult:
    """
    Internal file extraction result.
    """

    text: str
    source_type: str
    mime_type: Optional[str]
    file_name: Optional[str]
    file_size: Optional[int]
    sha256: Optional[str]
    pages_processed: Optional[int] = None
    warnings: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def _safe_decimal_string(value: Any) -> Optional[str]:
    if value is None:
        return None

    raw = str(value).strip()
    if not raw:
        return None

    cleaned = (
        raw.replace(",", "")
        .replace("$", "")
        .replace("€", "")
        .replace("£", "")
        .replace("¥", "")
        .replace("₹", "")
        .replace("₨", "")
        .replace("Rs.", "")
        .replace("Rs", "")
        .strip()
    )

    cleaned = re.sub(r"(?i)\b(USD|EUR|GBP|PKR|AED|SAR|CAD|AUD|INR)\b", "", cleaned).strip()

    try:
        number = Decimal(cleaned)
    except (InvalidOperation, ValueError):
        return None

    return format(number.quantize(Decimal("0.01")), "f")


def _hash_text(value: Union[str, bytes]) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8", errors="ignore")
    return hashlib.sha256(value).hexdigest()


def _guess_mime_type(path: Optional[Union[str, Path]]) -> Optional[str]:
    if not path:
        return None
    guessed, _ = mimetypes.guess_type(str(path))
    return guessed


def _extension_from_path(path: Optional[Union[str, Path]]) -> str:
    if not path:
        return ""
    return Path(path).suffix.lower()


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _dedupe_preserve_order(values: Iterable[str]) -> List[str]:
    seen = set()
    output: List[str] = []
    for value in values:
        normalized = _normalize_whitespace(value)
        key = normalized.lower()
        if normalized and key not in seen:
            seen.add(key)
            output.append(normalized)
    return output


# ---------------------------------------------------------------------------
# ReceiptReader
# ---------------------------------------------------------------------------

class ReceiptReader(BaseAgent):
    """
    OCR/parse receipts and invoice documents with privacy.

    Master Agent:
        Routes receipt/invoice parsing tasks to this class when the user asks to
        read a receipt, invoice, bill, statement, or expense document.

    Security Agent:
        This file treats receipt/invoice parsing as privacy-sensitive because
        documents may contain payment cards, bank details, addresses, tax IDs,
        emails, phone numbers, and vendor data. It provides hooks for security
        approval before processing sensitive documents.

    Memory Agent:
        This file prepares a privacy-safe memory payload with structured expense
        metadata only. Raw OCR text is excluded by default.

    Verification Agent:
        This file prepares a verification payload so another agent can review
        extracted fields, confidence, warnings, and document hash.

    Dashboard/API:
        All public methods return structured dict results with:
            success, message, data, error, metadata
    """

    agent_name = "receipt_reader"
    agent_type = "finance_agent_helper"
    agent_module = "Finance Agent"
    registry_name = "ReceiptReader"
    public_methods = (
        "read_document",
        "parse_text",
        "parse_receipt",
        "parse_invoice_document",
        "extract_text_from_file",
        "redact_sensitive_text",
        "health_check",
    )

    def __init__(
        self,
        config: Optional[ReceiptReaderConfig] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_emitter: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.config = config or ReceiptReaderConfig()
        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        """
        Return module health and optional dependency availability.
        """

        data = {
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "module": self.agent_module,
            "status": "ready",
            "optional_dependencies": {
                "Pillow": Image is not None,
                "pytesseract": pytesseract is not None,
                "pdfplumber": pdfplumber is not None,
            },
            "supported_extensions": sorted(
                SUPPORTED_TEXT_EXTENSIONS | SUPPORTED_IMAGE_EXTENSIONS | SUPPORTED_PDF_EXTENSIONS
            ),
            "privacy_defaults": {
                "redact_sensitive": self.config.redact_sensitive,
                "include_raw_text_default": self.config.include_raw_text_default,
                "no_external_ocr_api": True,
            },
        }

        return self._safe_result(
            message="ReceiptReader health check completed.",
            data=data,
            metadata={"timestamp": _utc_now_iso()},
        )

    def read_document(
        self,
        *,
        user_id: str,
        workspace_id: str,
        file_path: Optional[Union[str, Path]] = None,
        file_bytes: Optional[bytes] = None,
        file_name: Optional[str] = None,
        mime_type: Optional[str] = None,
        raw_text: Optional[str] = None,
        document_type: str = "unknown",
        include_raw_text: Optional[bool] = None,
        redact_sensitive: Optional[bool] = None,
        task_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Read and parse a receipt/invoice document from file path, file bytes, or raw text.

        Exactly one of file_path, file_bytes, or raw_text should normally be supplied.

        Args:
            user_id: SaaS user identifier.
            workspace_id: SaaS workspace identifier.
            file_path: Local file path to parse.
            file_bytes: Uploaded file bytes.
            file_name: Original file name for uploaded bytes.
            mime_type: Optional MIME type.
            raw_text: Already-extracted text.
            document_type: receipt, invoice, bill, statement, etc.
            include_raw_text: Whether to include extracted raw text in output.
            redact_sensitive: Whether to redact sensitive values.
            task_context: Optional Master Agent routing/task context.

        Returns:
            Structured result dict.
        """

        action = "read_invoice_file" if document_type == "invoice" else "read_receipt_file"
        context = self._build_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            action=action,
            task_context=task_context,
        )

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        if self._requires_security_check(action=action, task_context=context):
            approval = self._request_security_approval(
                action=action,
                task_context=context,
                reason="Receipt/invoice documents may contain private financial or payment information.",
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval was not granted for document parsing.",
                    error={
                        "code": "SECURITY_APPROVAL_REQUIRED",
                        "details": approval,
                    },
                    metadata=self._base_metadata(context),
                )

        try:
            include_text = (
                self.config.include_raw_text_default
                if include_raw_text is None
                else bool(include_raw_text)
            )
            should_redact = (
                self.config.redact_sensitive
                if redact_sensitive is None
                else bool(redact_sensitive)
            )

            if raw_text is not None:
                read_result = FileReadResult(
                    text=self._limit_text(raw_text),
                    source_type="raw_text",
                    mime_type="text/plain",
                    file_name=file_name,
                    file_size=len(raw_text.encode("utf-8", errors="ignore")),
                    sha256=_hash_text(raw_text),
                    warnings=[],
                )
            else:
                read_result = self.extract_text_from_file(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    file_path=file_path,
                    file_bytes=file_bytes,
                    file_name=file_name,
                    mime_type=mime_type,
                    task_context=context,
                )
                if not read_result["success"]:
                    return read_result
                read_result = FileReadResult(**read_result["data"]["file_read_result"])

            parse_result = self.parse_text(
                user_id=user_id,
                workspace_id=workspace_id,
                text=read_result.text,
                document_type=document_type,
                include_raw_text=include_text,
                redact_sensitive=should_redact,
                task_context=context,
                source_metadata={
                    "source_type": read_result.source_type,
                    "mime_type": read_result.mime_type,
                    "file_name": read_result.file_name,
                    "file_size": read_result.file_size,
                    "sha256": read_result.sha256,
                    "pages_processed": read_result.pages_processed,
                    "read_warnings": read_result.warnings,
                },
            )

            if parse_result["success"]:
                self._emit_agent_event("finance.receipt_reader.document_parsed", parse_result)
                self._log_audit_event(
                    event_name="receipt_reader.document_parsed",
                    payload={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "document_type": document_type,
                        "source_type": read_result.source_type,
                        "file_name": read_result.file_name,
                        "sha256": read_result.sha256,
                        "raw_text_returned": include_text,
                        "sensitive_redaction": should_redact,
                    },
                )

            return parse_result

        except Exception as exc:
            self.logger.exception("Failed to read document.")
            return self._error_result(
                message="Failed to read and parse receipt/invoice document.",
                error={
                    "code": "DOCUMENT_READ_FAILED",
                    "details": str(exc),
                },
                metadata=self._base_metadata(context),
            )

    def parse_receipt(
        self,
        *,
        user_id: str,
        workspace_id: str,
        text: str,
        include_raw_text: Optional[bool] = None,
        redact_sensitive: Optional[bool] = None,
        task_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Parse receipt text into structured receipt fields.
        """

        return self.parse_text(
            user_id=user_id,
            workspace_id=workspace_id,
            text=text,
            document_type="receipt",
            include_raw_text=include_raw_text,
            redact_sensitive=redact_sensitive,
            task_context=task_context,
        )

    def parse_invoice_document(
        self,
        *,
        user_id: str,
        workspace_id: str,
        text: str,
        include_raw_text: Optional[bool] = None,
        redact_sensitive: Optional[bool] = None,
        task_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Parse invoice text into structured invoice fields.
        """

        return self.parse_text(
            user_id=user_id,
            workspace_id=workspace_id,
            text=text,
            document_type="invoice",
            include_raw_text=include_raw_text,
            redact_sensitive=redact_sensitive,
            task_context=task_context,
        )

    def parse_text(
        self,
        *,
        user_id: str,
        workspace_id: str,
        text: str,
        document_type: str = "unknown",
        include_raw_text: Optional[bool] = None,
        redact_sensitive: Optional[bool] = None,
        task_context: Optional[Mapping[str, Any]] = None,
        source_metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Parse raw text from a receipt, invoice, bill, or statement.

        This method does not call external OCR APIs and does not perform any
        financial action. It only extracts data.
        """

        action = "parse_invoice" if document_type == "invoice" else "parse_receipt"
        context = self._build_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            action=action,
            task_context=task_context,
        )

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        if self._requires_security_check(action=action, task_context=context):
            approval = self._request_security_approval(
                action=action,
                task_context=context,
                reason="Parsing receipt/invoice text may expose private financial details.",
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval was not granted for receipt/invoice parsing.",
                    error={
                        "code": "SECURITY_APPROVAL_REQUIRED",
                        "details": approval,
                    },
                    metadata=self._base_metadata(context),
                )

        try:
            if not isinstance(text, str) or not text.strip():
                return self._error_result(
                    message="No receipt/invoice text was provided.",
                    error={"code": "EMPTY_TEXT", "details": "Text must be a non-empty string."},
                    metadata=self._base_metadata(context),
                )

            normalized_document_type = self._normalize_document_type(document_type)
            include_text = (
                self.config.include_raw_text_default
                if include_raw_text is None
                else bool(include_raw_text)
            )
            should_redact = (
                self.config.redact_sensitive
                if redact_sensitive is None
                else bool(redact_sensitive)
            )

            limited_text = self._limit_text(text)
            original_sha256 = _hash_text(limited_text)
            parsing_text = self.redact_sensitive_text(limited_text) if should_redact else limited_text

            parsed = self._parse_receipt_like_text(
                text=parsing_text,
                requested_document_type=normalized_document_type,
            )

            parsed_dict = self._parsed_document_to_dict(parsed)

            data: Dict[str, Any] = {
                "parsed_document": parsed_dict,
                "privacy": {
                    "redacted_sensitive": should_redact,
                    "raw_text_included": include_text,
                    "external_ocr_api_used": False,
                    "document_sha256": original_sha256,
                },
                "extraction": {
                    "document_type_requested": normalized_document_type,
                    "document_type_detected": parsed.document_type,
                    "confidence": parsed.confidence,
                    "warnings": parsed.warnings,
                    "source_metadata": dict(source_metadata or {}),
                },
            }

            if include_text:
                data["raw_text"] = parsing_text if should_redact else limited_text

            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                action=action,
                parsed_document=parsed_dict,
                metadata={
                    "document_sha256": original_sha256,
                    "redacted_sensitive": should_redact,
                    "raw_text_included": include_text,
                    "source_metadata": dict(source_metadata or {}),
                },
            )

            memory_payload = self._prepare_memory_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                parsed_document=parsed_dict,
                metadata={
                    "document_sha256": original_sha256,
                    "document_type": parsed.document_type,
                },
            )

            data["verification_payload"] = verification_payload
            data["memory_payload"] = memory_payload

            result = self._safe_result(
                message="Receipt/invoice text parsed successfully.",
                data=data,
                metadata={
                    **self._base_metadata(context),
                    "document_sha256": original_sha256,
                    "parser_version": "1.0.0",
                },
            )

            self._emit_agent_event("finance.receipt_reader.text_parsed", result)
            self._log_audit_event(
                event_name="receipt_reader.text_parsed",
                payload={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "document_type": parsed.document_type,
                    "document_sha256": original_sha256,
                    "redacted_sensitive": should_redact,
                    "raw_text_returned": include_text,
                    "confidence": parsed.confidence,
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("Failed to parse receipt/invoice text.")
            return self._error_result(
                message="Failed to parse receipt/invoice text.",
                error={
                    "code": "TEXT_PARSE_FAILED",
                    "details": str(exc),
                },
                metadata=self._base_metadata(context),
            )

    def extract_text_from_file(
        self,
        *,
        user_id: str,
        workspace_id: str,
        file_path: Optional[Union[str, Path]] = None,
        file_bytes: Optional[bytes] = None,
        file_name: Optional[str] = None,
        mime_type: Optional[str] = None,
        task_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Extract text from supported local files or uploaded bytes.

        Supported:
            - Text: .txt, .csv, .md, .json
            - PDF: .pdf using pdfplumber when installed
            - Images: .png, .jpg, .jpeg, .webp, .bmp, .tiff using pytesseract/Pillow when installed

        No external OCR service is called.
        """

        context = self._build_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            action="extract_receipt",
            task_context=task_context,
        )

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        if self._requires_security_check(action="extract_receipt", task_context=context):
            approval = self._request_security_approval(
                action="extract_receipt",
                task_context=context,
                reason="OCR extraction can expose private financial document contents.",
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval was not granted for OCR extraction.",
                    error={
                        "code": "SECURITY_APPROVAL_REQUIRED",
                        "details": approval,
                    },
                    metadata=self._base_metadata(context),
                )

        temp_path: Optional[Path] = None

        try:
            if file_path is None and file_bytes is None:
                return self._error_result(
                    message="No file was provided for text extraction.",
                    error={
                        "code": "NO_FILE_PROVIDED",
                        "details": "Provide either file_path or file_bytes.",
                    },
                    metadata=self._base_metadata(context),
                )

            if file_path is not None and file_bytes is not None:
                return self._error_result(
                    message="Ambiguous file input.",
                    error={
                        "code": "AMBIGUOUS_FILE_INPUT",
                        "details": "Provide only one of file_path or file_bytes.",
                    },
                    metadata=self._base_metadata(context),
                )

            actual_path: Optional[Path] = None
            file_size: Optional[int] = None
            sha256: Optional[str] = None

            if file_bytes is not None:
                if not isinstance(file_bytes, (bytes, bytearray)):
                    return self._error_result(
                        message="Invalid file bytes.",
                        error={
                            "code": "INVALID_FILE_BYTES",
                            "details": "file_bytes must be bytes.",
                        },
                        metadata=self._base_metadata(context),
                    )

                file_size = len(file_bytes)
                if file_size > self.config.max_file_bytes:
                    return self._error_result(
                        message="File is too large for safe receipt OCR.",
                        error={
                            "code": "FILE_TOO_LARGE",
                            "details": f"Maximum allowed bytes: {self.config.max_file_bytes}",
                        },
                        metadata=self._base_metadata(context),
                    )

                sha256 = _hash_text(bytes(file_bytes))

                if not self.config.allow_local_temp_files:
                    return self._error_result(
                        message="Temporary local file use is disabled.",
                        error={
                            "code": "TEMP_FILE_DISABLED",
                            "details": "Enable allow_local_temp_files to process uploaded bytes.",
                        },
                        metadata=self._base_metadata(context),
                    )

                safe_suffix = _extension_from_path(file_name) or self._extension_from_mime(mime_type) or ".bin"
                fd, temp_file = tempfile.mkstemp(prefix="william_receipt_", suffix=safe_suffix)
                os.close(fd)
                temp_path = Path(temp_file)
                temp_path.write_bytes(bytes(file_bytes))
                actual_path = temp_path

            else:
                actual_path = Path(str(file_path)).expanduser().resolve()
                if not actual_path.exists() or not actual_path.is_file():
                    return self._error_result(
                        message="File does not exist or is not a file.",
                        error={
                            "code": "FILE_NOT_FOUND",
                            "details": str(actual_path),
                        },
                        metadata=self._base_metadata(context),
                    )

                file_size = actual_path.stat().st_size
                if file_size > self.config.max_file_bytes:
                    return self._error_result(
                        message="File is too large for safe receipt OCR.",
                        error={
                            "code": "FILE_TOO_LARGE",
                            "details": f"Maximum allowed bytes: {self.config.max_file_bytes}",
                        },
                        metadata=self._base_metadata(context),
                    )

                sha256 = _hash_text(actual_path.read_bytes())

            assert actual_path is not None

            resolved_file_name = file_name or actual_path.name
            resolved_mime_type = mime_type or _guess_mime_type(actual_path)
            extension = actual_path.suffix.lower()
            warnings: List[str] = []
            pages_processed: Optional[int] = None

            if extension in SUPPORTED_TEXT_EXTENSIONS:
                text = self._extract_text_from_text_file(actual_path)
                source_type = "text_file"

            elif extension in SUPPORTED_PDF_EXTENSIONS:
                if not self.config.allow_pdf_text_extraction:
                    return self._error_result(
                        message="PDF text extraction is disabled.",
                        error={"code": "PDF_EXTRACTION_DISABLED", "details": "Configuration disabled PDF parsing."},
                        metadata=self._base_metadata(context),
                    )
                text, pages_processed, pdf_warnings = self._extract_text_from_pdf(actual_path)
                warnings.extend(pdf_warnings)
                source_type = "pdf"

            elif extension in SUPPORTED_IMAGE_EXTENSIONS:
                if not self.config.allow_ocr:
                    return self._error_result(
                        message="OCR is disabled.",
                        error={"code": "OCR_DISABLED", "details": "Configuration disabled OCR."},
                        metadata=self._base_metadata(context),
                    )
                text, image_warnings = self._extract_text_from_image(actual_path)
                warnings.extend(image_warnings)
                source_type = "image_ocr"

            else:
                return self._error_result(
                    message="Unsupported file type for receipt/invoice extraction.",
                    error={
                        "code": "UNSUPPORTED_FILE_TYPE",
                        "details": {
                            "extension": extension,
                            "supported_extensions": sorted(
                                SUPPORTED_TEXT_EXTENSIONS | SUPPORTED_IMAGE_EXTENSIONS | SUPPORTED_PDF_EXTENSIONS
                            ),
                        },
                    },
                    metadata=self._base_metadata(context),
                )

            text = self._limit_text(text)

            if not text.strip():
                warnings.append("No readable text was extracted from the document.")

            file_read_result = FileReadResult(
                text=text,
                source_type=source_type,
                mime_type=resolved_mime_type,
                file_name=resolved_file_name,
                file_size=file_size,
                sha256=sha256,
                pages_processed=pages_processed,
                warnings=warnings,
            )

            result = self._safe_result(
                message="Text extracted from receipt/invoice file successfully.",
                data={"file_read_result": asdict(file_read_result)},
                metadata={
                    **self._base_metadata(context),
                    "file_name": resolved_file_name,
                    "file_size": file_size,
                    "sha256": sha256,
                    "source_type": source_type,
                },
            )

            self._emit_agent_event("finance.receipt_reader.text_extracted", result)
            self._log_audit_event(
                event_name="receipt_reader.text_extracted",
                payload={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "file_name": resolved_file_name,
                    "file_size": file_size,
                    "sha256": sha256,
                    "source_type": source_type,
                    "warnings": warnings,
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("Failed to extract text from file.")
            return self._error_result(
                message="Failed to extract text from receipt/invoice file.",
                error={
                    "code": "FILE_TEXT_EXTRACTION_FAILED",
                    "details": str(exc),
                },
                metadata=self._base_metadata(context),
            )

        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except Exception:
                    self.logger.warning("Could not remove temporary receipt file: %s", temp_path)

    def redact_sensitive_text(self, text: str) -> str:
        """
        Redact sensitive values from receipt/invoice text.

        Redacted:
            - Email addresses
            - Phone numbers
            - Full payment card-like numbers
            - IBAN-like values
            - Bank account/routing/sort-code-like values
            - Tax IDs/VAT/GST/EIN/SSN/NTN/TRN values
        """

        if not isinstance(text, str):
            return ""

        redacted = text

        redacted = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", redacted)
        redacted = CARD_PATTERN.sub("[REDACTED_CARD]", redacted)
        redacted = IBAN_PATTERN.sub("[REDACTED_IBAN]", redacted)
        redacted = BANK_ACCOUNT_PATTERN.sub("[REDACTED_BANK_ACCOUNT]", redacted)
        redacted = TAX_ID_PATTERN.sub("[REDACTED_TAX_ID]", redacted)

        # Phone redaction can create false positives on amounts/dates, so keep it conservative.
        redacted = self._redact_probable_phones(redacted)

        return redacted

    # -----------------------------------------------------------------------
    # Parsing internals
    # -----------------------------------------------------------------------

    def _parse_receipt_like_text(
        self,
        *,
        text: str,
        requested_document_type: str,
    ) -> ParsedReceiptDocument:
        lines = self._clean_lines(text)
        lower_text = text.lower()

        parsed = ParsedReceiptDocument()
        parsed.document_type = self._detect_document_type(lower_text, requested_document_type)
        parsed.currency = self._detect_currency(text) or self.config.default_currency

        parsed.invoice_number = self._extract_reference_number(text, preferred="invoice")
        parsed.receipt_number = self._extract_reference_number(text, preferred="receipt")
        parsed.transaction_id = self._extract_reference_number(text, preferred="transaction")
        parsed.purchase_order_number = self._extract_reference_number(text, preferred="po")

        parsed.issue_date = self._extract_labeled_date(lines, labels=("invoice date", "date", "issued", "issue date"))
        parsed.due_date = self._extract_labeled_date(lines, labels=("due date", "payment due"))
        parsed.paid_date = self._extract_labeled_date(lines, labels=("paid date", "payment date"))

        all_dates = DATE_PATTERN.findall(text)
        if not parsed.issue_date and all_dates:
            parsed.issue_date = _normalize_whitespace(all_dates[0])

        parsed.email = self._extract_first(EMAIL_PATTERN, text)
        parsed.phone = self._extract_probable_phone(text)

        parsed.card_last4 = self._extract_card_last4(text)
        parsed.payment_method = self._extract_payment_method(lines)

        parsed.subtotal = self._extract_labeled_amount(lines, SUBTOTAL_KEYWORDS)
        parsed.tax = self._extract_labeled_amount(lines, TAX_KEYWORDS)
        parsed.discount = self._extract_labeled_amount(lines, DISCOUNT_KEYWORDS)
        parsed.tip = self._extract_labeled_amount(lines, TIP_KEYWORDS)
        parsed.shipping = self._extract_labeled_amount(lines, SHIPPING_KEYWORDS)
        parsed.total = self._extract_total_amount(lines)
        parsed.amount_due = self._extract_labeled_amount(lines, ("amount due", "balance due", "due"))

        parsed.line_items = self._extract_line_items(lines, parsed.currency)
        parsed.merchant_name = self._extract_merchant_name(lines, parsed.document_type)
        parsed.vendor_name = parsed.merchant_name
        parsed.address_lines = self._extract_address_lines(lines)

        parsed.warnings = self._build_warnings(parsed, text)
        parsed.confidence = self._calculate_confidence(parsed)

        return parsed

    def _clean_lines(self, text: str) -> List[str]:
        raw_lines = text.splitlines()
        cleaned = []
        for line in raw_lines:
            value = _normalize_whitespace(line)
            if value:
                cleaned.append(value)
        return cleaned

    def _detect_document_type(self, lower_text: str, requested: str) -> str:
        if requested and requested != "unknown":
            return requested

        if any(word in lower_text for word in ("invoice", "amount due", "due date", "bill to", "invoice no")):
            return "invoice"
        if any(word in lower_text for word in ("receipt", "transaction", "cashier", "change", "paid")):
            return "receipt"
        if "statement" in lower_text:
            return "statement"
        if "purchase order" in lower_text or re.search(r"\bpo\s*(?:number|#|no)\b", lower_text):
            return "purchase_order"
        if "quote" in lower_text or "quotation" in lower_text:
            return "quote"
        return "unknown"

    def _detect_currency(self, text: str) -> Optional[str]:
        for token, currency in CURRENCY_SYMBOLS.items():
            if re.search(rf"(?i)(?<![A-Z]){re.escape(token)}(?![A-Z])", text):
                return currency
        return None

    def _extract_reference_number(self, text: str, preferred: str) -> Optional[str]:
        preferred_patterns = {
            "invoice": re.compile(r"(?i)\b(?:invoice|inv)\s*(?:number|no|#|id)?\s*[:#\-]?\s*([A-Z0-9][A-Z0-9\-_/]{2,40})\b"),
            "receipt": re.compile(r"(?i)\b(?:receipt)\s*(?:number|no|#|id)?\s*[:#\-]?\s*([A-Z0-9][A-Z0-9\-_/]{2,40})\b"),
            "transaction": re.compile(r"(?i)\b(?:transaction|txn|trans)\s*(?:number|no|#|id)?\s*[:#\-]?\s*([A-Z0-9][A-Z0-9\-_/]{2,40})\b"),
            "po": re.compile(r"(?i)\b(?:po|purchase\s*order)\s*(?:number|no|#|id)?\s*[:#\-]?\s*([A-Z0-9][A-Z0-9\-_/]{2,40})\b"),
        }
        pattern = preferred_patterns.get(preferred, INVOICE_NUMBER_PATTERN)
        match = pattern.search(text)
        if not match:
            return None
        return _normalize_whitespace(match.group(1)).strip(".,;:")

    def _extract_labeled_date(self, lines: Sequence[str], labels: Sequence[str]) -> Optional[str]:
        for line in lines:
            lower = line.lower()
            if any(label in lower for label in labels):
                match = DATE_PATTERN.search(line)
                if match:
                    return _normalize_whitespace(match.group(1))
        return None

    def _extract_first(self, pattern: re.Pattern[str], text: str) -> Optional[str]:
        match = pattern.search(text)
        if not match:
            return None
        return _normalize_whitespace(match.group(0))

    def _extract_probable_phone(self, text: str) -> Optional[str]:
        for match in PHONE_PATTERN.finditer(text):
            value = _normalize_whitespace(match.group(0))
            digits = re.sub(r"\D", "", value)
            if 7 <= len(digits) <= 15 and not self._looks_like_amount_or_date(value):
                return value
        return None

    def _extract_card_last4(self, text: str) -> Optional[str]:
        last4_match = CARD_LAST4_PATTERN.search(text)
        if last4_match:
            return last4_match.group(1)

        card_match = CARD_PATTERN.search(text)
        if not card_match:
            return None

        digits = re.sub(r"\D", "", card_match.group(0))
        if len(digits) >= 4:
            return digits[-4:]
        return None

    def _extract_payment_method(self, lines: Sequence[str]) -> Optional[str]:
        keywords = (
            "visa",
            "mastercard",
            "amex",
            "american express",
            "discover",
            "card",
            "cash",
            "bank transfer",
            "paypal",
            "stripe",
            "apple pay",
            "google pay",
            "credit",
            "debit",
        )

        for line in lines:
            lower = line.lower()
            if any(keyword in lower for keyword in keywords):
                return _normalize_whitespace(line)
        return None

    def _extract_labeled_amount(self, lines: Sequence[str], labels: Sequence[str]) -> Optional[str]:
        candidates: List[Tuple[int, str]] = []

        for index, line in enumerate(lines):
            lower = line.lower()
            if any(label in lower for label in labels):
                amounts = self._amounts_from_line(line)
                if amounts:
                    candidates.append((index, amounts[-1]))

        if not candidates:
            return None

        # Prefer the last matching line because receipts often repeat totals near the bottom.
        _, amount = candidates[-1]
        return amount

    def _extract_total_amount(self, lines: Sequence[str]) -> Optional[str]:
        strong_candidates: List[Tuple[int, str, int]] = []

        for index, line in enumerate(lines):
            lower = line.lower()

            if any(keyword in lower for keyword in TOTAL_KEYWORDS):
                amounts = self._amounts_from_line(line)
                if amounts:
                    score = 3
                    if "grand total" in lower or "amount due" in lower or "balance due" in lower:
                        score = 5
                    elif re.search(r"(?i)\btotal\b", line):
                        score = 4
                    strong_candidates.append((score, amounts[-1], index))

        if strong_candidates:
            strong_candidates.sort(key=lambda item: (item[0], item[2]))
            return strong_candidates[-1][1]

        # Fallback: use largest plausible amount if no total line is labeled.
        amounts = []
        for line in lines:
            for amount in self._amounts_from_line(line):
                decimal_amount = _safe_decimal_string(amount)
                if decimal_amount is not None:
                    try:
                        amounts.append(Decimal(decimal_amount))
                    except InvalidOperation:
                        pass

        if not amounts:
            return None

        return format(max(amounts).quantize(Decimal("0.01")), "f")

    def _amounts_from_line(self, line: str) -> List[str]:
        amounts = []
        for match in AMOUNT_PATTERN.finditer(line):
            raw = _normalize_whitespace(match.group(1))
            amount = _safe_decimal_string(raw)
            if amount is not None:
                amounts.append(amount)
        return amounts

    def _extract_line_items(self, lines: Sequence[str], currency: Optional[str]) -> List[ParsedLineItem]:
        items: List[ParsedLineItem] = []

        skip_keywords = {
            "total",
            "subtotal",
            "tax",
            "vat",
            "gst",
            "discount",
            "amount due",
            "balance due",
            "invoice",
            "receipt",
            "payment",
            "change",
            "cash",
            "card",
            "date",
            "phone",
            "email",
            "address",
            "bill to",
            "ship to",
        }

        for line in lines:
            lower = line.lower()
            if any(keyword in lower for keyword in skip_keywords):
                continue

            amounts = self._amounts_from_line(line)
            if not amounts:
                continue

            amount = amounts[-1]
            description = AMOUNT_PATTERN.sub("", line).strip(" -:\t")
            description = _normalize_whitespace(description)

            if not description:
                continue

            if len(description) < 2 or len(description) > 120:
                continue

            quantity = self._extract_quantity_from_line(line)

            item = ParsedLineItem(
                description=description,
                quantity=quantity,
                unit_price=None,
                amount=amount,
                currency=currency,
                confidence=0.45 if quantity else 0.35,
            )
            items.append(item)

            if len(items) >= 100:
                break

        return items

    def _extract_quantity_from_line(self, line: str) -> Optional[float]:
        patterns = [
            re.compile(r"(?i)\bqty\s*[:x]?\s*(\d+(?:\.\d+)?)\b"),
            re.compile(r"(?i)\b(\d+(?:\.\d+)?)\s*x\s*"),
        ]
        for pattern in patterns:
            match = pattern.search(line)
            if match:
                try:
                    return float(match.group(1))
                except ValueError:
                    return None
        return None

    def _extract_merchant_name(self, lines: Sequence[str], document_type: str) -> Optional[str]:
        if not lines:
            return None

        ignored = {
            "invoice",
            "receipt",
            "tax invoice",
            "cash receipt",
            "sales receipt",
            "bill",
            "statement",
        }

        for line in lines[:8]:
            normalized = _normalize_whitespace(line)
            lower = normalized.lower()

            if not normalized:
                continue
            if lower in ignored:
                continue
            if DATE_PATTERN.search(normalized):
                continue
            if EMAIL_PATTERN.search(normalized):
                continue
            if PHONE_PATTERN.search(normalized):
                continue
            if len(normalized) > 80:
                continue
            if self._amounts_from_line(normalized):
                continue

            return normalized

        return None

    def _extract_address_lines(self, lines: Sequence[str]) -> List[str]:
        candidates: List[str] = []

        address_indicators = (
            "street",
            "st.",
            "road",
            "rd.",
            "avenue",
            "ave",
            "suite",
            "floor",
            "building",
            "city",
            "state",
            "zip",
            "postal",
            "pakistan",
            "usa",
            "uk",
            "united kingdom",
            "canada",
            "australia",
            "uae",
            "saudi",
        )

        for line in lines[:25]:
            lower = line.lower()
            if any(indicator in lower for indicator in address_indicators):
                if not EMAIL_PATTERN.search(line) and not self._amounts_from_line(line):
                    candidates.append(line)

        return _dedupe_preserve_order(candidates)[:6]

    def _build_warnings(self, parsed: ParsedReceiptDocument, text: str) -> List[str]:
        warnings: List[str] = []

        if not parsed.total and not parsed.amount_due:
            warnings.append("No clear total or amount due was detected.")

        if not parsed.issue_date:
            warnings.append("No clear document date was detected.")

        if not parsed.merchant_name:
            warnings.append("No clear merchant/vendor name was detected.")

        if parsed.document_type == "invoice" and not parsed.invoice_number:
            warnings.append("Invoice number was not detected.")

        if "[REDACTED_" in text:
            warnings.append("Sensitive information was redacted before parsing.")

        if len(text.strip()) < 30:
            warnings.append("Extracted text is very short; OCR quality may be low.")

        return warnings

    def _calculate_confidence(self, parsed: ParsedReceiptDocument) -> float:
        score = 0.0
        total_weight = 0.0

        checks = [
            (parsed.document_type != "unknown", 0.10),
            (bool(parsed.merchant_name), 0.15),
            (bool(parsed.issue_date), 0.15),
            (bool(parsed.total or parsed.amount_due), 0.25),
            (bool(parsed.currency), 0.08),
            (bool(parsed.invoice_number or parsed.receipt_number or parsed.transaction_id), 0.10),
            (bool(parsed.line_items), 0.10),
            (bool(parsed.tax or parsed.subtotal), 0.07),
        ]

        for passed, weight in checks:
            total_weight += weight
            if passed:
                score += weight

        if total_weight <= 0:
            return 0.0

        return round(min(score / total_weight, 1.0), 3)

    # -----------------------------------------------------------------------
    # File extraction internals
    # -----------------------------------------------------------------------

    def _extract_text_from_text_file(self, path: Path) -> str:
        for encoding in ("utf-8", "utf-8-sig", "latin-1"):
            try:
                return path.read_text(encoding=encoding, errors="ignore")
            except Exception:
                continue
        return path.read_bytes().decode("utf-8", errors="ignore")

    def _extract_text_from_pdf(self, path: Path) -> Tuple[str, int, List[str]]:
        warnings: List[str] = []

        if pdfplumber is None:
            return (
                "",
                0,
                [
                    "pdfplumber is not installed. Install pdfplumber to extract text from PDFs.",
                ],
            )

        pages_text: List[str] = []
        pages_processed = 0

        try:
            with pdfplumber.open(str(path)) as pdf:
                for page in pdf.pages:
                    pages_processed += 1
                    try:
                        page_text = page.extract_text() or ""
                    except Exception as exc:
                        warnings.append(f"Failed to extract text from PDF page {pages_processed}: {exc}")
                        page_text = ""
                    if page_text:
                        pages_text.append(page_text)

            if not pages_text:
                warnings.append(
                    "No embedded text was found in the PDF. Scanned PDFs may require image OCR preprocessing."
                )

            return "\n".join(pages_text), pages_processed, warnings

        except Exception as exc:
            return "", pages_processed, [f"PDF extraction failed: {exc}"]

    def _extract_text_from_image(self, path: Path) -> Tuple[str, List[str]]:
        warnings: List[str] = []

        if Image is None:
            return "", ["Pillow is not installed. Install Pillow to open image receipts."]

        if pytesseract is None:
            return "", ["pytesseract is not installed. Install pytesseract and Tesseract OCR to read images."]

        try:
            with Image.open(str(path)) as img:
                text = pytesseract.image_to_string(img)
            return text or "", warnings

        except Exception as exc:
            return "", [f"Image OCR failed: {exc}"]

    # -----------------------------------------------------------------------
    # Privacy helpers
    # -----------------------------------------------------------------------

    def _redact_probable_phones(self, text: str) -> str:
        def replace(match: re.Match[str]) -> str:
            value = _normalize_whitespace(match.group(0))
            digits = re.sub(r"\D", "", value)
            if 7 <= len(digits) <= 15 and not self._looks_like_amount_or_date(value):
                return "[REDACTED_PHONE]"
            return value

        return PHONE_PATTERN.sub(replace, text)

    def _looks_like_amount_or_date(self, value: str) -> bool:
        cleaned = value.strip()
        if DATE_PATTERN.fullmatch(cleaned):
            return True
        if _safe_decimal_string(cleaned) is not None and len(re.sub(r"\D", "", cleaned)) <= 6:
            return True
        if re.search(r"\d{1,2}[:/.-]\d{1,2}([:/.-]\d{2,4})?", cleaned):
            return True
        return False

    def _limit_text(self, text: str) -> str:
        if len(text) <= self.config.max_text_chars:
            return text
        return text[: self.config.max_text_chars]

    # -----------------------------------------------------------------------
    # Structured payload helpers
    # -----------------------------------------------------------------------

    def _parsed_document_to_dict(self, parsed: ParsedReceiptDocument) -> Dict[str, Any]:
        data = asdict(parsed)
        data["line_items"] = [asdict(item) for item in parsed.line_items]
        return data

    def _prepare_verification_payload(
        self,
        *,
        user_id: str,
        workspace_id: str,
        action: str,
        parsed_document: Mapping[str, Any],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a payload for Verification Agent.

        This does not call the Verification Agent directly by default. It gives
        Master Agent/API a structured handoff object.
        """

        payload = {
            "handoff_id": str(uuid.uuid4()),
            "target_agent": "verification_agent",
            "source_agent": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "action": action,
            "verification_type": "finance_document_extraction_review",
            "requires_human_review": self._needs_human_review(parsed_document),
            "summary": {
                "document_type": parsed_document.get("document_type"),
                "merchant_name": parsed_document.get("merchant_name"),
                "invoice_number": parsed_document.get("invoice_number"),
                "receipt_number": parsed_document.get("receipt_number"),
                "total": parsed_document.get("total"),
                "amount_due": parsed_document.get("amount_due"),
                "currency": parsed_document.get("currency"),
                "confidence": parsed_document.get("confidence"),
                "warnings": parsed_document.get("warnings", []),
            },
            "metadata": dict(metadata or {}),
            "created_at": _utc_now_iso(),
        }

        return payload if self.config.verification_payload_enabled else {}

    def _prepare_memory_payload(
        self,
        *,
        user_id: str,
        workspace_id: str,
        parsed_document: Mapping[str, Any],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a privacy-safe payload for Memory Agent.

        Raw OCR text is intentionally excluded. The Memory Agent can choose
        whether to remember vendor/category preferences or recurring merchant
        information, but should not store private card/bank/tax details.
        """

        if not self.config.memory_payload_enabled:
            return {}

        payload = {
            "handoff_id": str(uuid.uuid4()),
            "target_agent": "memory_agent",
            "source_agent": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "memory_type": "finance_document_summary",
            "safe_to_store": True,
            "contains_raw_document_text": False,
            "contains_payment_card": False,
            "contains_bank_account": False,
            "summary": {
                "document_type": parsed_document.get("document_type"),
                "merchant_name": parsed_document.get("merchant_name"),
                "vendor_name": parsed_document.get("vendor_name"),
                "currency": parsed_document.get("currency"),
                "subtotal": parsed_document.get("subtotal"),
                "tax": parsed_document.get("tax"),
                "total": parsed_document.get("total"),
                "amount_due": parsed_document.get("amount_due"),
                "issue_date": parsed_document.get("issue_date"),
                "due_date": parsed_document.get("due_date"),
            },
            "metadata": dict(metadata or {}),
            "created_at": _utc_now_iso(),
        }

        return payload

    def _needs_human_review(self, parsed_document: Mapping[str, Any]) -> bool:
        confidence = parsed_document.get("confidence")
        warnings = parsed_document.get("warnings") or []

        try:
            confidence_value = float(confidence)
        except (TypeError, ValueError):
            confidence_value = 0.0

        if confidence_value < self.config.min_confidence_for_auto_fields:
            return True

        if warnings:
            return True

        return False

    # -----------------------------------------------------------------------
    # Compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(self, task_context: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace context.

        This protects isolation between users and workspaces. Every user-specific
        execution must include both user_id and workspace_id.
        """

        user_id = str(task_context.get("user_id") or "").strip()
        workspace_id = str(task_context.get("workspace_id") or "").strip()

        if self.config.strict_context_validation:
            if not user_id:
                return self._error_result(
                    message="Missing required user_id for Finance Agent receipt reading.",
                    error={
                        "code": "MISSING_USER_ID",
                        "details": "ReceiptReader requires user_id for SaaS isolation.",
                    },
                    metadata={"timestamp": _utc_now_iso(), "agent": self.agent_name},
                )

            if not workspace_id:
                return self._error_result(
                    message="Missing required workspace_id for Finance Agent receipt reading.",
                    error={
                        "code": "MISSING_WORKSPACE_ID",
                        "details": "ReceiptReader requires workspace_id for SaaS isolation.",
                    },
                    metadata={"timestamp": _utc_now_iso(), "agent": self.agent_name},
                )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "valid": True,
            },
            metadata={"timestamp": _utc_now_iso(), "agent": self.agent_name},
        )

    def _requires_security_check(
        self,
        *,
        action: str,
        task_context: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Decide whether Security Agent approval is required.

        Receipt and invoice parsing is privacy-sensitive, but not financially
        destructive. By default, this hook returns True for sensitive parsing
        actions unless task_context explicitly says security already approved.
        """

        context = dict(task_context or {})

        if _coerce_bool(context.get("security_approved"), default=False):
            return False

        if action in SENSITIVE_ACTIONS:
            return True

        return False

    def _request_security_approval(
        self,
        *,
        action: str,
        task_context: Mapping[str, Any],
        reason: str,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent when available.

        Fallback behavior:
            - Does not block imports.
            - Allows local parsing with a clear simulated approval marker.
            - Production systems can replace this by injecting security_agent.
        """

        request_payload = {
            "request_id": str(uuid.uuid4()),
            "source_agent": self.agent_name,
            "target_agent": "security_agent",
            "action": action,
            "reason": reason,
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "risk_level": "medium",
            "data_classification": "private_financial_document",
            "requested_at": _utc_now_iso(),
        }

        if self.security_agent is not None:
            try:
                if hasattr(self.security_agent, "approve_action"):
                    response = self.security_agent.approve_action(request_payload)
                    if isinstance(response, Mapping):
                        return dict(response)

                if hasattr(self.security_agent, "request_approval"):
                    response = self.security_agent.request_approval(request_payload)
                    if isinstance(response, Mapping):
                        return dict(response)

            except Exception as exc:
                self.logger.exception("Security approval request failed.")
                return {
                    "approved": False,
                    "reason": "Security Agent request failed.",
                    "error": str(exc),
                    "request": request_payload,
                }

        # Safe fallback for development/import safety. This is intentionally explicit.
        return {
            "approved": True,
            "mode": "fallback_local_approval",
            "reason": "No Security Agent injected; non-destructive local parsing allowed.",
            "request": request_payload,
        }

    def _prepare_memory_payload_public(
        self,
        user_id: str,
        workspace_id: str,
        parsed_document: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Public-style compatibility wrapper for callers that expect a named hook.
        """

        return self._prepare_memory_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            parsed_document=parsed_document,
            metadata={},
        )

    def _emit_agent_event(self, event_name: str, payload: Mapping[str, Any]) -> None:
        """
        Emit an event for dashboard analytics, task history, or agent observability.
        """

        if not self.config.emit_events_enabled:
            return

        safe_payload = self._event_safe_payload(payload)

        try:
            if self.event_emitter is not None:
                if hasattr(self.event_emitter, "emit"):
                    self.event_emitter.emit(event_name, safe_payload)
                    return
                if callable(self.event_emitter):
                    self.event_emitter(event_name, safe_payload)
                    return

            if hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_name, safe_payload)  # type: ignore[attr-defined]
                    return
                except Exception:
                    pass

            self.logger.debug("Agent event emitted: %s %s", event_name, safe_payload)

        except Exception:
            self.logger.exception("Failed to emit agent event: %s", event_name)

    def _log_audit_event(self, event_name: str, payload: Mapping[str, Any]) -> None:
        """
        Log a privacy-safe audit event.

        Raw document text should never be sent here.
        """

        if not self.config.audit_enabled:
            return

        audit_payload = {
            "audit_id": str(uuid.uuid4()),
            "event_name": event_name,
            "source_agent": self.agent_name,
            "module": self.agent_module,
            "timestamp": _utc_now_iso(),
            "payload": self._event_safe_payload(payload),
        }

        try:
            if self.audit_logger is not None:
                if hasattr(self.audit_logger, "log"):
                    self.audit_logger.log(audit_payload)
                    return
                if callable(self.audit_logger):
                    self.audit_logger(audit_payload)
                    return

            if hasattr(super(), "log_audit"):
                try:
                    super().log_audit(event_name, audit_payload)  # type: ignore[attr-defined]
                    return
                except Exception:
                    pass

            self.logger.info("Audit event: %s", json.dumps(audit_payload, default=str))

        except Exception:
            self.logger.exception("Failed to log audit event: %s", event_name)

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success response shape for dashboard/API/Master Agent.
        """

        return {
            "success": True,
            "message": message,
            "data": dict(data or {}),
            "error": None,
            "metadata": dict(metadata or {}),
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error response shape for dashboard/API/Master Agent.
        """

        return {
            "success": False,
            "message": message,
            "data": dict(data or {}),
            "error": dict(error or {"code": "UNKNOWN_ERROR", "details": message}),
            "metadata": dict(metadata or {}),
        }

    # -----------------------------------------------------------------------
    # Misc internals
    # -----------------------------------------------------------------------

    def _build_task_context(
        self,
        *,
        user_id: str,
        workspace_id: str,
        action: str,
        task_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        context = dict(task_context or {})
        context["user_id"] = user_id
        context["workspace_id"] = workspace_id
        context["action"] = action
        context.setdefault("agent", self.agent_name)
        context.setdefault("module", self.agent_module)
        context.setdefault("request_id", str(uuid.uuid4()))
        context.setdefault("created_at", _utc_now_iso())
        return context

    def _base_metadata(self, task_context: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "module": self.agent_module,
            "request_id": task_context.get("request_id"),
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "timestamp": _utc_now_iso(),
        }

    def _normalize_document_type(self, document_type: str) -> str:
        value = (document_type or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
        if value not in RECEIPT_DOCUMENT_TYPES:
            return "unknown"
        return value

    def _extension_from_mime(self, mime_type: Optional[str]) -> Optional[str]:
        if not mime_type:
            return None
        mapping = {
            "text/plain": ".txt",
            "text/csv": ".csv",
            "application/json": ".json",
            "application/pdf": ".pdf",
            "image/png": ".png",
            "image/jpeg": ".jpg",
            "image/webp": ".webp",
            "image/bmp": ".bmp",
            "image/tiff": ".tiff",
        }
        return mapping.get(mime_type.lower())

    def _event_safe_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Remove raw document text and obviously sensitive fields before event/audit logging.
        """

        blocked_keys = {
            "raw_text",
            "text",
            "file_bytes",
            "body",
            "content",
            "email",
            "phone",
            "card_last4",
            "payment_method",
            "address_lines",
        }

        def sanitize(value: Any) -> Any:
            if isinstance(value, Mapping):
                clean = {}
                for key, inner_value in value.items():
                    key_str = str(key)
                    if key_str in blocked_keys:
                        clean[key_str] = "[REDACTED_FOR_EVENT]"
                    else:
                        clean[key_str] = sanitize(inner_value)
                return clean

            if isinstance(value, list):
                return [sanitize(item) for item in value[:50]]

            if isinstance(value, str) and len(value) > 500:
                return value[:500] + "...[TRUNCATED]"

            return value

        return sanitize(dict(payload))

    def to_registry_descriptor(self) -> Dict[str, Any]:
        """
        Descriptor that Agent Registry / Agent Loader can use.
        """

        return {
            "agent_name": self.agent_name,
            "registry_name": self.registry_name,
            "agent_type": self.agent_type,
            "module": self.agent_module,
            "class_name": self.__class__.__name__,
            "public_methods": list(self.public_methods),
            "supports_user_workspace_isolation": True,
            "requires_security_for_sensitive_actions": True,
            "supports_verification_payload": True,
            "supports_memory_payload": True,
            "safe_to_import": True,
            "description": "OCR/parse receipts and invoice documents with privacy.",
        }


# ---------------------------------------------------------------------------
# Module-level factory helpers
# ---------------------------------------------------------------------------

def create_receipt_reader(
    config: Optional[ReceiptReaderConfig] = None,
    **kwargs: Any,
) -> ReceiptReader:
    """
    Factory helper for Agent Loader / Registry / FastAPI dependency injection.
    """

    return ReceiptReader(config=config, **kwargs)


def get_agent_descriptor() -> Dict[str, Any]:
    """
    Lightweight module descriptor without needing full app initialization.
    """

    return {
        "agent_name": ReceiptReader.agent_name,
        "registry_name": ReceiptReader.registry_name,
        "agent_type": ReceiptReader.agent_type,
        "module": ReceiptReader.agent_module,
        "class_name": "ReceiptReader",
        "file_path": "agents/super_agents/finance_agent/receipt_reader.py",
        "purpose": "OCR/parse receipts and invoice documents with privacy.",
        "public_methods": list(ReceiptReader.public_methods),
        "safe_to_import": True,
        "supports_user_workspace_isolation": True,
        "supports_security_agent_handoff": True,
        "supports_verification_agent_payload": True,
        "supports_memory_agent_payload": True,
    }


__all__ = [
    "ReceiptReader",
    "ReceiptReaderConfig",
    "ParsedReceiptDocument",
    "ParsedLineItem",
    "FileReadResult",
    "create_receipt_reader",
    "get_agent_descriptor",
]


# ---------------------------------------------------------------------------
# Safe manual smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    reader = ReceiptReader()
    sample_text = """
    Digital Promotix
    Receipt No: RCPT-1001
    Date: 2026-06-24
    Web Design Package      99.99
    Tax                      5.00
    Total                  $104.99
    Paid by Visa ending 4242
    support@example.com
    """

    result = reader.parse_receipt(
        user_id="demo_user",
        workspace_id="demo_workspace",
        text=sample_text,
        include_raw_text=False,
        redact_sensitive=True,
        task_context={"security_approved": True},
    )

    print(json.dumps(result, indent=2, default=str))