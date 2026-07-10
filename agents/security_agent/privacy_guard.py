"""
agents/security_agent/privacy_guard.py

Security privacy protection layer for the William / Jarvis Multi-Agent AI SaaS
System by Digital Promotix.

Primary responsibilities:
    - Protect private messages.
    - Inspect and protect file metadata and supported text content.
    - Protect screenshots through OCR/text metadata inspection interfaces.
    - Detect passwords, API keys, tokens, private keys, financial data,
      personal identifiers, confidential content, and authentication material.
    - Sanitize logs, exceptions, request metadata, URLs, headers, and payloads.
    - Prevent cross-user and cross-workspace data exposure.
    - Require Security Agent approval for high-risk access, sharing, exporting,
      unredacted viewing, or external transmission.
    - Prepare Verification Agent payloads after completed privacy operations.
    - Prepare privacy-safe Memory Agent payloads.
    - Emit registry/event-bus compatible events and audit records.
    - Remain import-safe when future William modules are unavailable.

Architecture integration:
    Master Agent:
        Routes privacy-sensitive tasks through this guard before execution.

    Security Agent:
        Uses this helper to classify and protect private content. High-risk
        operations can be routed through approval_manager.py or security_agent.py.

    Memory Agent:
        Receives only sanitized, scoped, privacy-compatible memory payloads.

    Verification Agent:
        Receives verification payloads describing what was inspected, blocked,
        redacted, approved, or permitted.

    Dashboard / FastAPI:
        Public methods return JSON-compatible dictionaries and can be exposed
        through API routes without changing their interfaces.

    Agent Registry / Loader / Router:
        The class exposes stable metadata and execute/handle_task interfaces and
        is safe to import during partial project construction.

Security priorities:
    1. Safety and authorization.
    2. User/workspace isolation.
    3. BaseAgent compatibility.
    4. Master Agent and Registry compatibility.
    5. Privacy protection functionality.
"""

from __future__ import annotations

import base64
import copy
import dataclasses
import enum
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import mimetypes
import os
import re
import secrets
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any,
    Callable,
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
# Optional William/Jarvis imports with safe fallbacks
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Import-safe fallback used until the real William BaseAgent exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get(
                "agent_name",
                kwargs.get("name", self.__class__.__name__),
            )

        def emit_event(
            self,
            event_name: str,
            payload: Mapping[str, Any],
        ) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback BaseAgent event emitted.",
                "data": {
                    "event_name": event_name,
                    "payload": dict(payload),
                },
                "error": None,
                "metadata": {
                    "fallback": True,
                },
            }


try:
    from agents.security_agent.approval_manager import ApprovalManager  # type: ignore
except Exception:  # pragma: no cover
    ApprovalManager = None  # type: ignore


try:
    from agents.security_agent.audit_logger import AuditLogger  # type: ignore
except Exception:  # pragma: no cover
    AuditLogger = None  # type: ignore


try:
    from agents.verification_agent.verification_agent import (  # type: ignore
        VerificationAgent,
    )
except Exception:  # pragma: no cover
    VerificationAgent = None  # type: ignore


try:
    from agents.memory_agent.memory_agent import MemoryAgent  # type: ignore
except Exception:  # pragma: no cover
    MemoryAgent = None  # type: ignore


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# =============================================================================
# Enums
# =============================================================================

class PrivacyRiskLevel(str, enum.Enum):
    """Normalized privacy risk levels."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PrivacyDecisionType(str, enum.Enum):
    """Possible decisions after privacy inspection."""

    ALLOW = "allow"
    ALLOW_REDACTED = "allow_redacted"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


class PrivacyContentType(str, enum.Enum):
    """Content types supported by this privacy guard."""

    MESSAGE = "message"
    FILE = "file"
    SCREENSHOT = "screenshot"
    LOG = "log"
    SECRET = "secret"
    METADATA = "metadata"
    REQUEST = "request"
    RESPONSE = "response"
    MEMORY = "memory"
    UNKNOWN = "unknown"


class SensitiveCategory(str, enum.Enum):
    """Sensitive content categories detected by the guard."""

    PASSWORD = "password"
    API_KEY = "api_key"
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    SESSION_TOKEN = "session_token"
    AUTHORIZATION_HEADER = "authorization_header"
    COOKIE = "cookie"
    PRIVATE_KEY = "private_key"
    CERTIFICATE = "certificate"
    DATABASE_URL = "database_url"
    CONNECTION_STRING = "connection_string"
    WEBHOOK_SECRET = "webhook_secret"
    OAUTH_SECRET = "oauth_secret"
    JWT = "jwt"
    CREDIT_CARD = "credit_card"
    BANK_ACCOUNT = "bank_account"
    IBAN = "iban"
    ROUTING_NUMBER = "routing_number"
    CRYPTO_PRIVATE_KEY = "crypto_private_key"
    SEED_PHRASE = "seed_phrase"
    SSN = "ssn"
    NATIONAL_ID = "national_id"
    PASSPORT = "passport"
    DRIVER_LICENSE = "driver_license"
    EMAIL = "email"
    PHONE = "phone"
    PHYSICAL_ADDRESS = "physical_address"
    PRECISE_LOCATION = "precise_location"
    IP_ADDRESS = "ip_address"
    HEALTH = "health"
    BIOMETRIC = "biometric"
    POLITICAL = "political"
    RELIGIOUS = "religious"
    ETHNICITY = "ethnicity"
    SEXUAL_ORIENTATION = "sexual_orientation"
    CRIMINAL_RECORD = "criminal_record"
    CHILD_DATA = "child_data"
    LEGAL_PRIVILEGED = "legal_privileged"
    CLIENT_CONFIDENTIAL = "client_confidential"
    BUSINESS_CONFIDENTIAL = "business_confidential"
    SOURCE_CODE_SECRET = "source_code_secret"
    PRIVATE_MESSAGE = "private_message"
    PRIVATE_FILE = "private_file"
    PRIVATE_SCREENSHOT = "private_screenshot"
    LOG_SECRET = "log_secret"
    UNKNOWN_SENSITIVE = "unknown_sensitive"


class ApprovalStatus(str, enum.Enum):
    """Approval state for privacy-sensitive actions."""

    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class PrivacyOperation(str, enum.Enum):
    """Actions evaluated by SecurityPrivacyGuard."""

    INSPECT = "inspect"
    STORE = "store"
    READ = "read"
    DISPLAY = "display"
    SHARE = "share"
    EXPORT = "export"
    DOWNLOAD = "download"
    TRANSMIT = "transmit"
    LOG = "log"
    MEMORY_WRITE = "memory_write"
    DELETE = "delete"
    UNREDACT = "unredact"


# =============================================================================
# Data classes
# =============================================================================

@dataclasses.dataclass(frozen=True)
class SensitiveFinding:
    """One detected privacy or secret finding."""

    finding_id: str
    category: SensitiveCategory
    risk_level: PrivacyRiskLevel
    field_path: str
    start: Optional[int]
    end: Optional[int]
    masked_preview: str
    confidence: float
    detector: str
    reason: str
    requires_redaction: bool = True
    requires_approval: bool = False
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class PrivacyInspection:
    """Complete inspection result before conversion to public result format."""

    inspection_id: str
    allowed: bool
    decision: PrivacyDecisionType
    risk_level: PrivacyRiskLevel
    content_type: PrivacyContentType
    operation: PrivacyOperation
    findings: List[SensitiveFinding]
    sanitized_content: Any
    approval_status: ApprovalStatus
    approval_id: Optional[str]
    message: str
    original_fingerprint: str
    sanitized_fingerprint: str
    created_at: str


@dataclasses.dataclass
class PrivacyApprovalRecord:
    """Import-safe local approval record."""

    approval_id: str
    user_id: str
    workspace_id: str
    requester_id: Optional[str]
    operation: PrivacyOperation
    content_type: PrivacyContentType
    risk_level: PrivacyRiskLevel
    reason: str
    content_fingerprint: str
    status: ApprovalStatus
    created_at: str
    expires_at_epoch: float
    metadata: Dict[str, Any]


@dataclasses.dataclass(frozen=True)
class FileInspectionPolicy:
    """File privacy inspection limits and rules."""

    max_file_size_bytes: int = 25 * 1024 * 1024
    max_text_inspection_bytes: int = 2 * 1024 * 1024
    block_executable_files: bool = True
    block_encrypted_archives_without_approval: bool = True
    inspect_filename: bool = True
    inspect_metadata: bool = True
    inspect_text_content: bool = True


# =============================================================================
# SecurityPrivacyGuard
# =============================================================================

class SecurityPrivacyGuard(BaseAgent):
    """
    Security Agent privacy guard.

    Protects private messages, files, screenshots, secrets, logs, request
    metadata, and private payloads while preserving strict SaaS tenant isolation.

    Public methods are intentionally framework-neutral so they can be called by:
        - MasterAgent
        - SecurityAgent
        - BrowserAgent
        - VisualAgent
        - MemoryAgent
        - CodeAgent
        - WorkflowAgent
        - FastAPI routes
        - Dashboard services
    """

    AGENT_NAME = "SecurityPrivacyGuard"
    AGENT_TYPE = "security_privacy_guard"
    AGENT_VERSION = "1.0.0"

    DEFAULT_APPROVAL_TTL_SECONDS = 60 * 60
    MAX_RECURSION_DEPTH = 20
    MAX_CONTAINER_ITEMS = 10_000
    MAX_TEXT_LENGTH = 5_000_000

    REDACTION_TEXT = "[REDACTED]"
    PRIVATE_TEXT = "[PRIVATE]"
    SECRET_TEXT = "[SECRET]"
    BINARY_TEXT = "[BINARY CONTENT PROTECTED]"

    SAFE_IMAGE_MIME_TYPES: Set[str] = {
        "image/png",
        "image/jpeg",
        "image/webp",
        "image/gif",
        "image/bmp",
        "image/tiff",
        "image/heic",
        "image/heif",
    }

    SAFE_TEXT_MIME_TYPES: Set[str] = {
        "text/plain",
        "text/csv",
        "text/html",
        "text/xml",
        "text/markdown",
        "application/json",
        "application/xml",
        "application/yaml",
        "application/x-yaml",
        "application/javascript",
        "application/sql",
    }

    BLOCKED_EXECUTABLE_EXTENSIONS: Set[str] = {
        ".exe",
        ".dll",
        ".com",
        ".scr",
        ".msi",
        ".msp",
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
        ".jar",
        ".apk",
        ".app",
        ".dmg",
        ".pkg",
        ".deb",
        ".rpm",
        ".bin",
        ".run",
        ".elf",
    }

    ARCHIVE_EXTENSIONS: Set[str] = {
        ".zip",
        ".rar",
        ".7z",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".tgz",
    }

    SECRET_FIELD_NAMES: Set[str] = {
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "secret",
        "client_secret",
        "api_key",
        "apikey",
        "access_key",
        "secret_key",
        "private_key",
        "token",
        "access_token",
        "refresh_token",
        "session_token",
        "session_id",
        "auth_token",
        "authorization",
        "cookie",
        "set_cookie",
        "set-cookie",
        "jwt",
        "bearer",
        "webhook_secret",
        "signing_secret",
        "database_url",
        "db_url",
        "connection_string",
        "dsn",
        "smtp_password",
        "ftp_password",
        "ssh_key",
        "encryption_key",
        "master_key",
        "recovery_code",
        "backup_code",
        "otp",
        "pin",
        "cvv",
        "cvc",
    }

    PRIVATE_FIELD_NAMES: Set[str] = {
        "private_message",
        "direct_message",
        "dm",
        "private_note",
        "confidential",
        "internal_only",
        "private_file",
        "private_screenshot",
        "medical_record",
        "legal_note",
        "client_secret_data",
    }

    SAFE_LOG_HEADER_ALLOWLIST: Set[str] = {
        "content-type",
        "content-length",
        "accept",
        "accept-language",
        "user-agent",
        "cache-control",
        "pragma",
        "x-request-id",
        "x-correlation-id",
        "traceparent",
    }

    def __init__(
        self,
        agent_name: str = AGENT_NAME,
        security_agent: Optional[Any] = None,
        approval_manager: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], Any]] = None,
        strict_mode: bool = True,
        default_redaction: bool = True,
        approval_ttl_seconds: int = DEFAULT_APPROVAL_TTL_SECONDS,
        file_policy: Optional[FileInspectionPolicy] = None,
        fingerprint_key: Optional[Union[str, bytes]] = None,
    ) -> None:
        """
        Initialize the SecurityPrivacyGuard.

        Args:
            agent_name:
                Registry-friendly agent name.
            security_agent:
                Optional parent Security Agent instance.
            approval_manager:
                Optional ApprovalManager instance.
            verification_agent:
                Optional Verification Agent instance.
            memory_agent:
                Optional Memory Agent instance.
            audit_logger:
                Optional AuditLogger instance or callable.
            event_emitter:
                Optional event bus callable.
            strict_mode:
                Blocks critical content and requires approval for high-risk
                unredacted operations.
            default_redaction:
                Redacts sensitive values by default.
            approval_ttl_seconds:
                Expiry time for local approval requests.
            file_policy:
                Optional file inspection policy.
            fingerprint_key:
                Optional HMAC key used only for fingerprints. Never logged.
        """
        try:
            super().__init__(agent_name=agent_name)
        except TypeError:
            try:
                super().__init__(name=agent_name)
            except TypeError:
                super().__init__()

        self.agent_name = agent_name
        self.security_agent = security_agent
        self.approval_manager = approval_manager
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter
        self.strict_mode = bool(strict_mode)
        self.default_redaction = bool(default_redaction)
        self.approval_ttl_seconds = max(300, int(approval_ttl_seconds))
        self.file_policy = file_policy or FileInspectionPolicy()

        if fingerprint_key is None:
            self._fingerprint_key = secrets.token_bytes(32)
        elif isinstance(fingerprint_key, bytes):
            self._fingerprint_key = fingerprint_key
        else:
            self._fingerprint_key = fingerprint_key.encode("utf-8")

        self._local_approvals: Dict[str, PrivacyApprovalRecord] = {}
        self._patterns = self._build_patterns()
        self._keyword_rules = self._build_keyword_rules()

    # =========================================================================
    # Registry / routing compatibility
    # =========================================================================

    @property
    def registry_metadata(self) -> Dict[str, Any]:
        """Return Agent Registry compatible metadata."""
        return {
            "name": self.agent_name,
            "type": self.AGENT_TYPE,
            "version": self.AGENT_VERSION,
            "module": "agents.security_agent.privacy_guard",
            "class_name": self.__class__.__name__,
            "capabilities": [
                "inspect_private_messages",
                "inspect_files",
                "inspect_screenshots",
                "detect_secrets",
                "sanitize_logs",
                "redact_sensitive_content",
                "tenant_isolation",
                "privacy_approval",
                "verification_payloads",
                "memory_payloads",
            ],
            "requires_user_context": True,
            "requires_workspace_context": True,
            "safe_to_import": True,
        }

    def get_capabilities(self) -> Dict[str, Any]:
        """Return structured capabilities for Agent Loader or dashboard."""
        return self._safe_result(
            message="Security privacy capabilities retrieved.",
            data=self.registry_metadata,
        )

    def execute(
        self,
        task: Mapping[str, Any],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generic BaseAgent/MasterAgent execution entry point.

        Supported task actions:
            inspect_message
            inspect_file
            inspect_screenshot
            sanitize_log
            detect_secrets
            inspect_payload
            request_approval
            approval_status
        """
        return self.handle_task(task=task, context=context)

    def handle_task(
        self,
        task: Mapping[str, Any],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Route a structured task to the correct public method."""
        if not isinstance(task, Mapping):
            return self._error_result(
                message="Privacy guard task must be a mapping.",
                error="invalid_task_type",
            )

        merged_context = self._merge_context(task, context)
        validation = self._validate_task_context(merged_context)
        if not validation["success"]:
            return validation

        action = str(task.get("action") or task.get("operation") or "").strip().lower()

        try:
            if action in {"inspect_message", "protect_message"}:
                return self.inspect_message(
                    message=task.get("message", task.get("content", "")),
                    context=merged_context,
                    operation=task.get("privacy_operation", PrivacyOperation.DISPLAY.value),
                    redact=task.get("redact"),
                    destination=task.get("destination"),
                )

            if action in {"inspect_file", "protect_file"}:
                return self.inspect_file(
                    file_info=task.get("file", task.get("file_info", {})),
                    context=merged_context,
                    operation=task.get("privacy_operation", PrivacyOperation.READ.value),
                    text_content=task.get("text_content"),
                    allow_executable=bool(task.get("allow_executable", False)),
                )

            if action in {"inspect_screenshot", "protect_screenshot"}:
                return self.inspect_screenshot(
                    screenshot=task.get("screenshot", {}),
                    context=merged_context,
                    operation=task.get("privacy_operation", PrivacyOperation.DISPLAY.value),
                    extracted_text=task.get("extracted_text"),
                    metadata=task.get("metadata"),
                )

            if action in {"sanitize_log", "protect_log"}:
                return self.sanitize_log(
                    log_data=task.get("log", task.get("content", {})),
                    context=merged_context,
                    log_level=str(task.get("log_level", "INFO")),
                )

            if action in {"detect_secrets", "scan_secrets"}:
                return self.detect_secrets(
                    content=task.get("content"),
                    context=merged_context,
                    content_type=task.get("content_type", PrivacyContentType.SECRET.value),
                )

            if action in {"inspect_payload", "protect_payload"}:
                return self.inspect_payload(
                    payload=task.get("payload", {}),
                    context=merged_context,
                    content_type=task.get("content_type", PrivacyContentType.UNKNOWN.value),
                    operation=task.get("privacy_operation", PrivacyOperation.INSPECT.value),
                    redact=task.get("redact"),
                )

            if action == "request_approval":
                return self.request_privacy_approval(
                    context=merged_context,
                    operation=task.get("privacy_operation", PrivacyOperation.SHARE.value),
                    content_type=task.get("content_type", PrivacyContentType.UNKNOWN.value),
                    risk_level=task.get("risk_level", PrivacyRiskLevel.HIGH.value),
                    content_fingerprint=str(task.get("content_fingerprint", "")),
                    reason=str(task.get("reason", "Privacy-sensitive action.")),
                    metadata=task.get("metadata"),
                )

            if action == "approval_status":
                return self.get_approval_status(
                    approval_id=str(task.get("approval_id", "")),
                    context=merged_context,
                )

            return self._error_result(
                message="Unsupported SecurityPrivacyGuard task action.",
                error="unsupported_action",
                data={
                    "action": action,
                    "supported_actions": [
                        "inspect_message",
                        "inspect_file",
                        "inspect_screenshot",
                        "sanitize_log",
                        "detect_secrets",
                        "inspect_payload",
                        "request_approval",
                        "approval_status",
                    ],
                },
            )
        except Exception as exc:
            logger.exception("SecurityPrivacyGuard task execution failed.")
            return self._error_result(
                message="Security privacy task failed safely.",
                error=str(exc),
                metadata={
                    "agent": self.agent_name,
                    "action": action,
                },
            )

    # =========================================================================
    # Public privacy inspection methods
    # =========================================================================

    def inspect_message(
        self,
        message: Any,
        context: Mapping[str, Any],
        operation: Union[str, PrivacyOperation] = PrivacyOperation.DISPLAY,
        redact: Optional[bool] = None,
        destination: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Inspect and protect private message content.

        The destination may describe whether the message is being sent to:
            - same workspace
            - another workspace
            - external recipient
            - public output

        External/public transmission raises the approval threshold.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        normalized_operation = self._normalize_operation(operation)
        should_redact = self.default_redaction if redact is None else bool(redact)

        message_payload = {
            "message": message,
            "destination": self._json_safe(destination or {}),
        }

        destination_risk = self._evaluate_destination_risk(destination, context)

        result = self._inspect_content(
            content=message_payload,
            context=context,
            content_type=PrivacyContentType.MESSAGE,
            operation=normalized_operation,
            redact=should_redact,
            additional_risk=destination_risk,
        )

        if result.get("success"):
            self._emit_agent_event(
                "security.privacy.message.inspected",
                {
                    "inspection_id": result["data"].get("inspection_id"),
                    "user_id": str(context.get("user_id")),
                    "workspace_id": str(context.get("workspace_id")),
                    "decision": result["data"].get("decision"),
                    "risk_level": result["data"].get("risk_level"),
                },
            )

        return result

    def inspect_file(
        self,
        file_info: Mapping[str, Any],
        context: Mapping[str, Any],
        operation: Union[str, PrivacyOperation] = PrivacyOperation.READ,
        text_content: Optional[Any] = None,
        allow_executable: bool = False,
    ) -> Dict[str, Any]:
        """
        Inspect file metadata and optional extracted text content.

        This method does not execute, open, upload, download, or modify a file.
        File bytes should be processed by a dedicated file service. This guard
        evaluates privacy and policy information only.

        Expected file_info fields may include:
            filename
            path
            size_bytes
            mime_type
            extension
            checksum
            owner_user_id
            owner_workspace_id
            is_encrypted
            is_archive
            metadata
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        if not isinstance(file_info, Mapping):
            return self._error_result(
                message="file_info must be a mapping.",
                error="invalid_file_info",
            )

        scope_check = self._validate_resource_scope(file_info, context)
        if not scope_check["success"]:
            return scope_check

        normalized_operation = self._normalize_operation(operation)
        safe_file_info = self._json_safe(file_info)

        filename = str(
            safe_file_info.get("filename")
            or safe_file_info.get("name")
            or Path(str(safe_file_info.get("path", ""))).name
            or "unnamed_file"
        )

        extension = str(safe_file_info.get("extension") or Path(filename).suffix).lower()
        mime_type = str(
            safe_file_info.get("mime_type")
            or mimetypes.guess_type(filename)[0]
            or "application/octet-stream"
        ).lower()

        size_bytes = self._safe_int(safe_file_info.get("size_bytes"), default=0)
        is_encrypted = bool(safe_file_info.get("is_encrypted", False))
        is_archive = bool(
            safe_file_info.get("is_archive", False)
            or extension in self.ARCHIVE_EXTENSIONS
        )
        executable = extension in self.BLOCKED_EXECUTABLE_EXTENSIONS

        policy_findings: List[SensitiveFinding] = []
        additional_risk = PrivacyRiskLevel.NONE

        if size_bytes < 0:
            return self._error_result(
                message="File size cannot be negative.",
                error="invalid_file_size",
            )

        if size_bytes > self.file_policy.max_file_size_bytes:
            policy_findings.append(
                self._make_finding(
                    category=SensitiveCategory.PRIVATE_FILE,
                    risk=PrivacyRiskLevel.HIGH,
                    field_path="file.size_bytes",
                    preview=str(size_bytes),
                    confidence=1.0,
                    detector="file_policy",
                    reason="File exceeds the privacy inspection size limit.",
                    requires_approval=True,
                    metadata={
                        "maximum_size_bytes": self.file_policy.max_file_size_bytes,
                    },
                )
            )
            additional_risk = PrivacyRiskLevel.HIGH

        if executable and self.file_policy.block_executable_files and not allow_executable:
            policy_findings.append(
                self._make_finding(
                    category=SensitiveCategory.PRIVATE_FILE,
                    risk=PrivacyRiskLevel.CRITICAL,
                    field_path="file.extension",
                    preview=extension,
                    confidence=1.0,
                    detector="file_policy",
                    reason="Executable file type is blocked by default.",
                    requires_approval=True,
                )
            )
            additional_risk = PrivacyRiskLevel.CRITICAL

        if is_archive and is_encrypted and self.file_policy.block_encrypted_archives_without_approval:
            policy_findings.append(
                self._make_finding(
                    category=SensitiveCategory.PRIVATE_FILE,
                    risk=PrivacyRiskLevel.HIGH,
                    field_path="file.is_encrypted",
                    preview="encrypted archive",
                    confidence=1.0,
                    detector="file_policy",
                    reason="Encrypted archive content cannot be privacy-inspected.",
                    requires_approval=True,
                )
            )
            additional_risk = self._max_risk(
                additional_risk,
                PrivacyRiskLevel.HIGH,
            )

        file_payload: Dict[str, Any] = {
            "filename": filename,
            "extension": extension,
            "mime_type": mime_type,
            "size_bytes": size_bytes,
            "is_encrypted": is_encrypted,
            "is_archive": is_archive,
            "metadata": safe_file_info.get("metadata", {}),
            "owner_user_id": safe_file_info.get("owner_user_id"),
            "owner_workspace_id": safe_file_info.get("owner_workspace_id"),
        }

        if text_content is not None and self.file_policy.inspect_text_content:
            encoded_size = len(self._stringify(text_content).encode("utf-8", errors="ignore"))
            if encoded_size <= self.file_policy.max_text_inspection_bytes:
                file_payload["text_content"] = text_content
            else:
                file_payload["text_content"] = "[CONTENT TOO LARGE FOR INLINE INSPECTION]"
                policy_findings.append(
                    self._make_finding(
                        category=SensitiveCategory.PRIVATE_FILE,
                        risk=PrivacyRiskLevel.MEDIUM,
                        field_path="file.text_content",
                        preview="content exceeds inline inspection limit",
                        confidence=1.0,
                        detector="file_policy",
                        reason="Text extraction exceeded the configured privacy inspection limit.",
                        requires_approval=False,
                    )
                )
                additional_risk = self._max_risk(
                    additional_risk,
                    PrivacyRiskLevel.MEDIUM,
                )

        result = self._inspect_content(
            content=file_payload,
            context=context,
            content_type=PrivacyContentType.FILE,
            operation=normalized_operation,
            redact=True,
            additional_risk=additional_risk,
            preexisting_findings=policy_findings,
        )

        if result.get("success"):
            result["data"]["file_policy"] = {
                "filename": filename,
                "extension": extension,
                "mime_type": mime_type,
                "size_bytes": size_bytes,
                "executable": executable,
                "encrypted": is_encrypted,
                "archive": is_archive,
                "file_was_opened": False,
                "file_was_executed": False,
                "file_was_modified": False,
            }

            self._emit_agent_event(
                "security.privacy.file.inspected",
                {
                    "inspection_id": result["data"].get("inspection_id"),
                    "user_id": str(context.get("user_id")),
                    "workspace_id": str(context.get("workspace_id")),
                    "decision": result["data"].get("decision"),
                    "risk_level": result["data"].get("risk_level"),
                    "extension": extension,
                    "mime_type": mime_type,
                },
            )

        return result

    def inspect_screenshot(
        self,
        screenshot: Any,
        context: Mapping[str, Any],
        operation: Union[str, PrivacyOperation] = PrivacyOperation.DISPLAY,
        extracted_text: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Inspect screenshot metadata and OCR/extracted text.

        This method does not perform OCR itself. VisualAgent or an OCR service
        should provide extracted_text. Binary screenshot data is fingerprinted
        and replaced with a protected marker to prevent accidental log exposure.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        normalized_operation = self._normalize_operation(operation)
        safe_metadata = self._json_safe(metadata or {})

        if isinstance(screenshot, Mapping):
            scope_check = self._validate_resource_scope(screenshot, context)
            if not scope_check["success"]:
                return scope_check

        screenshot_fingerprint = self._fingerprint(screenshot)

        screenshot_payload: Dict[str, Any] = {
            "screenshot_fingerprint": screenshot_fingerprint,
            "metadata": safe_metadata,
            "extracted_text": extracted_text or "",
            "binary_content": self.BINARY_TEXT,
        }

        if isinstance(screenshot, Mapping):
            screenshot_payload["source"] = {
                "filename": screenshot.get("filename"),
                "mime_type": screenshot.get("mime_type"),
                "width": screenshot.get("width"),
                "height": screenshot.get("height"),
                "owner_user_id": screenshot.get("owner_user_id"),
                "owner_workspace_id": screenshot.get("owner_workspace_id"),
            }

        result = self._inspect_content(
            content=screenshot_payload,
            context=context,
            content_type=PrivacyContentType.SCREENSHOT,
            operation=normalized_operation,
            redact=True,
            additional_risk=(
                PrivacyRiskLevel.MEDIUM
                if extracted_text
                else PrivacyRiskLevel.LOW
            ),
        )

        if result.get("success"):
            result["data"]["screenshot_protection"] = {
                "binary_content_returned": False,
                "binary_content_logged": False,
                "fingerprint": screenshot_fingerprint,
                "ocr_text_inspected": bool(extracted_text),
            }

            self._emit_agent_event(
                "security.privacy.screenshot.inspected",
                {
                    "inspection_id": result["data"].get("inspection_id"),
                    "user_id": str(context.get("user_id")),
                    "workspace_id": str(context.get("workspace_id")),
                    "decision": result["data"].get("decision"),
                    "risk_level": result["data"].get("risk_level"),
                },
            )

        return result

    def sanitize_log(
        self,
        log_data: Any,
        context: Mapping[str, Any],
        log_level: str = "INFO",
    ) -> Dict[str, Any]:
        """
        Sanitize logs, exceptions, headers, URLs, and nested payloads.

        Original log content is never included in the returned metadata.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        sanitized = self._sanitize_recursive(
            value=log_data,
            path="log",
            findings=[],
            depth=0,
            force_log_mode=True,
        )

        findings = sanitized[1]
        protected_log = sanitized[0]
        risk_level = self._calculate_overall_risk(findings)

        self._log_audit_event(
            event_type="security_privacy_log_sanitized",
            context=context,
            data={
                "log_level": str(log_level).upper(),
                "risk_level": risk_level.value,
                "finding_count": len(findings),
                "original_fingerprint": self._fingerprint(log_data),
                "sanitized_fingerprint": self._fingerprint(protected_log),
            },
        )

        verification_payload = self._prepare_verification_payload(
            action="sanitize_log",
            context=context,
            success=True,
            data={
                "risk_level": risk_level.value,
                "finding_count": len(findings),
                "sanitized": True,
            },
        )

        return self._safe_result(
            message="Log data sanitized successfully.",
            data={
                "sanitized_log": protected_log,
                "risk_level": risk_level.value,
                "finding_count": len(findings),
                "findings": [self._finding_to_dict(item) for item in findings],
                "verification_payload": verification_payload,
            },
            metadata={
                "agent": self.agent_name,
                "content_type": PrivacyContentType.LOG.value,
                "log_level": str(log_level).upper(),
                "original_content_returned": False,
            },
        )

    def detect_secrets(
        self,
        content: Any,
        context: Mapping[str, Any],
        content_type: Union[str, PrivacyContentType] = PrivacyContentType.SECRET,
    ) -> Dict[str, Any]:
        """
        Detect secrets without returning raw secret values.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        normalized_content_type = self._normalize_content_type(content_type)
        findings = self._find_sensitive_data(content)
        risk_level = self._calculate_overall_risk(findings)

        critical_count = sum(
            1 for item in findings
            if item.risk_level == PrivacyRiskLevel.CRITICAL
        )

        self._log_audit_event(
            event_type="security_privacy_secret_scan",
            context=context,
            data={
                "content_type": normalized_content_type.value,
                "risk_level": risk_level.value,
                "finding_count": len(findings),
                "critical_count": critical_count,
                "content_fingerprint": self._fingerprint(content),
            },
        )

        return self._safe_result(
            message=(
                "Secret scan completed. Sensitive content was detected."
                if findings
                else "Secret scan completed. No supported secret pattern was detected."
            ),
            data={
                "contains_secrets": bool(findings),
                "risk_level": risk_level.value,
                "finding_count": len(findings),
                "critical_count": critical_count,
                "findings": [self._finding_to_dict(item) for item in findings],
                "content_fingerprint": self._fingerprint(content),
            },
            metadata={
                "agent": self.agent_name,
                "content_type": normalized_content_type.value,
                "raw_content_returned": False,
            },
        )

    def inspect_payload(
        self,
        payload: Any,
        context: Mapping[str, Any],
        content_type: Union[str, PrivacyContentType] = PrivacyContentType.UNKNOWN,
        operation: Union[str, PrivacyOperation] = PrivacyOperation.INSPECT,
        redact: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Inspect any structured or unstructured payload."""
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        normalized_content_type = self._normalize_content_type(content_type)
        normalized_operation = self._normalize_operation(operation)
        should_redact = self.default_redaction if redact is None else bool(redact)

        return self._inspect_content(
            content=payload,
            context=context,
            content_type=normalized_content_type,
            operation=normalized_operation,
            redact=should_redact,
        )

    def protect_private_content(
        self,
        content: Any,
        context: Mapping[str, Any],
        content_type: Union[str, PrivacyContentType],
        operation: Union[str, PrivacyOperation],
    ) -> Dict[str, Any]:
        """Convenience wrapper for generic privacy protection."""
        return self.inspect_payload(
            payload=content,
            context=context,
            content_type=content_type,
            operation=operation,
            redact=True,
        )

    def redact_sensitive_content(
        self,
        content: Any,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Redact detected sensitive content without requiring a specific type."""
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        findings: List[SensitiveFinding] = []
        sanitized, findings = self._sanitize_recursive(
            value=content,
            path="content",
            findings=findings,
            depth=0,
            force_log_mode=False,
        )

        return self._safe_result(
            message="Sensitive content redacted.",
            data={
                "sanitized_content": sanitized,
                "finding_count": len(findings),
                "risk_level": self._calculate_overall_risk(findings).value,
                "findings": [self._finding_to_dict(item) for item in findings],
            },
            metadata={
                "agent": self.agent_name,
                "original_content_returned": False,
            },
        )

    # =========================================================================
    # Approval controls
    # =========================================================================

    def request_privacy_approval(
        self,
        context: Mapping[str, Any],
        operation: Union[str, PrivacyOperation],
        content_type: Union[str, PrivacyContentType],
        risk_level: Union[str, PrivacyRiskLevel],
        content_fingerprint: str,
        reason: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval for privacy-sensitive access or transmission.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        normalized_operation = self._normalize_operation(operation)
        normalized_content_type = self._normalize_content_type(content_type)
        normalized_risk = self._normalize_risk(risk_level)

        return self._request_security_approval(
            context=context,
            operation=normalized_operation,
            content_type=normalized_content_type,
            risk_level=normalized_risk,
            content_fingerprint=content_fingerprint,
            reason=reason,
            metadata=metadata,
        )

    def approve_privacy_action(
        self,
        approval_id: str,
        context: Mapping[str, Any],
        approved_by: Optional[str] = None,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Approve a local privacy request.

        A production deployment may delegate this operation to ApprovalManager.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        record = self._local_approvals.get(approval_id)
        if record is None:
            return self._error_result(
                message="Privacy approval request was not found.",
                error="approval_not_found",
            )

        isolation = self._validate_approval_scope(record, context)
        if not isolation["success"]:
            return isolation

        if self._approval_expired(record):
            record.status = ApprovalStatus.EXPIRED
            return self._error_result(
                message="Privacy approval request has expired.",
                error="approval_expired",
                data={
                    "approval_id": approval_id,
                    "status": record.status.value,
                },
            )

        record.status = ApprovalStatus.APPROVED

        self._log_audit_event(
            event_type="security_privacy_approval_approved",
            context=context,
            data={
                "approval_id": approval_id,
                "approved_by": approved_by,
                "note_present": bool(note),
                "operation": record.operation.value,
                "content_type": record.content_type.value,
                "risk_level": record.risk_level.value,
            },
        )

        self._emit_agent_event(
            "security.privacy.approval.approved",
            {
                "approval_id": approval_id,
                "user_id": record.user_id,
                "workspace_id": record.workspace_id,
                "approved_by": approved_by,
            },
        )

        return self._safe_result(
            message="Privacy action approved.",
            data={
                "approval_id": approval_id,
                "status": record.status.value,
                "approved_by": approved_by,
                "note": note,
            },
        )

    def reject_privacy_action(
        self,
        approval_id: str,
        context: Mapping[str, Any],
        rejected_by: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Reject a local privacy approval request."""
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        record = self._local_approvals.get(approval_id)
        if record is None:
            return self._error_result(
                message="Privacy approval request was not found.",
                error="approval_not_found",
            )

        isolation = self._validate_approval_scope(record, context)
        if not isolation["success"]:
            return isolation

        record.status = ApprovalStatus.REJECTED

        self._log_audit_event(
            event_type="security_privacy_approval_rejected",
            context=context,
            data={
                "approval_id": approval_id,
                "rejected_by": rejected_by,
                "reason_present": bool(reason),
                "operation": record.operation.value,
                "content_type": record.content_type.value,
            },
        )

        self._emit_agent_event(
            "security.privacy.approval.rejected",
            {
                "approval_id": approval_id,
                "user_id": record.user_id,
                "workspace_id": record.workspace_id,
                "rejected_by": rejected_by,
            },
        )

        return self._safe_result(
            message="Privacy action rejected.",
            data={
                "approval_id": approval_id,
                "status": record.status.value,
                "rejected_by": rejected_by,
                "reason": reason,
            },
        )

    def get_approval_status(
        self,
        approval_id: str,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Get a scoped privacy approval status."""
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        if not approval_id:
            return self._error_result(
                message="approval_id is required.",
                error="missing_approval_id",
            )

        record = self._local_approvals.get(approval_id)
        if record is None:
            return self._error_result(
                message="Privacy approval request was not found.",
                error="approval_not_found",
            )

        isolation = self._validate_approval_scope(record, context)
        if not isolation["success"]:
            return isolation

        if self._approval_expired(record):
            record.status = ApprovalStatus.EXPIRED

        return self._safe_result(
            message="Privacy approval status retrieved.",
            data={
                "approval_id": record.approval_id,
                "status": record.status.value,
                "operation": record.operation.value,
                "content_type": record.content_type.value,
                "risk_level": record.risk_level.value,
                "reason": record.reason,
                "created_at": record.created_at,
                "expires_at_epoch": record.expires_at_epoch,
                "metadata": self._json_safe(record.metadata),
            },
        )

    def list_pending_approvals(
        self,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """List pending approvals for one user/workspace only."""
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        user_id = str(context.get("user_id"))
        workspace_id = str(context.get("workspace_id"))

        approvals: List[Dict[str, Any]] = []

        for record in self._local_approvals.values():
            if record.user_id != user_id or record.workspace_id != workspace_id:
                continue

            if self._approval_expired(record):
                record.status = ApprovalStatus.EXPIRED

            if record.status != ApprovalStatus.PENDING:
                continue

            approvals.append(
                {
                    "approval_id": record.approval_id,
                    "status": record.status.value,
                    "operation": record.operation.value,
                    "content_type": record.content_type.value,
                    "risk_level": record.risk_level.value,
                    "reason": record.reason,
                    "created_at": record.created_at,
                    "expires_at_epoch": record.expires_at_epoch,
                    "metadata": self._json_safe(record.metadata),
                }
            )

        return self._safe_result(
            message="Pending privacy approvals retrieved.",
            data={
                "approvals": approvals,
                "count": len(approvals),
            },
        )

    def purge_expired_approvals(self) -> Dict[str, Any]:
        """Remove expired local approval records."""
        expired_ids = [
            approval_id
            for approval_id, record in self._local_approvals.items()
            if self._approval_expired(record)
        ]

        for approval_id in expired_ids:
            self._local_approvals.pop(approval_id, None)

        return self._safe_result(
            message="Expired privacy approvals purged.",
            data={
                "purged_count": len(expired_ids),
                "purged_ids": expired_ids,
            },
        )

    # =========================================================================
    # Required compatibility hooks
    # =========================================================================

    def _validate_task_context(
        self,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Validate required SaaS tenant context.

        Required:
            user_id
            workspace_id
        """
        if not isinstance(context, Mapping):
            return self._error_result(
                message="Task context must be a mapping.",
                error="invalid_context_type",
            )

        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")

        if user_id is None or not str(user_id).strip():
            return self._error_result(
                message="Task context is missing user_id.",
                error="missing_user_id",
            )

        if workspace_id is None or not str(workspace_id).strip():
            return self._error_result(
                message="Task context is missing workspace_id.",
                error="missing_workspace_id",
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "tenant_isolation_ready": True,
            },
        )

    def _requires_security_check(
        self,
        operation: Union[str, PrivacyOperation],
        risk_level: Union[str, PrivacyRiskLevel],
        content_type: Union[str, PrivacyContentType],
        destination: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """Determine whether Security approval is required."""
        normalized_operation = self._normalize_operation(operation)
        normalized_risk = self._normalize_risk(risk_level)
        normalized_type = self._normalize_content_type(content_type)

        if normalized_risk == PrivacyRiskLevel.CRITICAL:
            return True

        if normalized_risk == PrivacyRiskLevel.HIGH and normalized_operation in {
            PrivacyOperation.READ,
            PrivacyOperation.DISPLAY,
            PrivacyOperation.SHARE,
            PrivacyOperation.EXPORT,
            PrivacyOperation.DOWNLOAD,
            PrivacyOperation.TRANSMIT,
            PrivacyOperation.UNREDACT,
        }:
            return True

        if normalized_operation in {
            PrivacyOperation.SHARE,
            PrivacyOperation.EXPORT,
            PrivacyOperation.TRANSMIT,
            PrivacyOperation.UNREDACT,
        } and normalized_risk in {
            PrivacyRiskLevel.MEDIUM,
            PrivacyRiskLevel.HIGH,
            PrivacyRiskLevel.CRITICAL,
        }:
            return True

        if normalized_type in {
            PrivacyContentType.FILE,
            PrivacyContentType.SCREENSHOT,
            PrivacyContentType.MESSAGE,
        } and destination:
            if bool(destination.get("external")) or bool(destination.get("public")):
                return normalized_risk != PrivacyRiskLevel.NONE

        return False

    def _request_security_approval(
        self,
        context: Mapping[str, Any],
        operation: PrivacyOperation,
        content_type: PrivacyContentType,
        risk_level: PrivacyRiskLevel,
        content_fingerprint: str,
        reason: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request privacy approval through ApprovalManager or local fallback.
        """
        approval_id = self._new_id("privacy_approval")
        now_epoch = time.time()

        record = PrivacyApprovalRecord(
            approval_id=approval_id,
            user_id=str(context.get("user_id")),
            workspace_id=str(context.get("workspace_id")),
            requester_id=(
                str(context.get("requester_id"))
                if context.get("requester_id") is not None
                else None
            ),
            operation=operation,
            content_type=content_type,
            risk_level=risk_level,
            reason=reason,
            content_fingerprint=content_fingerprint,
            status=ApprovalStatus.PENDING,
            created_at=self._utc_now(),
            expires_at_epoch=now_epoch + self.approval_ttl_seconds,
            metadata=self._json_safe(metadata or {}),
        )

        self._local_approvals[approval_id] = record

        approval_payload = {
            "approval_id": approval_id,
            "source_agent": self.agent_name,
            "target_agent": "SecurityAgent",
            "approval_type": "privacy_sensitive_action",
            "user_id": record.user_id,
            "workspace_id": record.workspace_id,
            "requester_id": record.requester_id,
            "operation": operation.value,
            "content_type": content_type.value,
            "risk_level": risk_level.value,
            "reason": reason,
            "content_fingerprint": content_fingerprint,
            "created_at": record.created_at,
            "expires_at_epoch": record.expires_at_epoch,
            "metadata": record.metadata,
        }

        manager_response = self._call_approval_manager(approval_payload)

        self._log_audit_event(
            event_type="security_privacy_approval_requested",
            context=context,
            data={
                "approval_id": approval_id,
                "operation": operation.value,
                "content_type": content_type.value,
                "risk_level": risk_level.value,
                "content_fingerprint": content_fingerprint,
                "approval_manager_available": self.approval_manager is not None,
            },
        )

        self._emit_agent_event(
            "security.privacy.approval.requested",
            {
                "approval_id": approval_id,
                "user_id": record.user_id,
                "workspace_id": record.workspace_id,
                "operation": operation.value,
                "risk_level": risk_level.value,
            },
        )

        return self._safe_result(
            message="Privacy-sensitive action requires approval.",
            data={
                "approval_required": True,
                "approval_id": approval_id,
                "approval_status": ApprovalStatus.PENDING.value,
                "approval_payload": approval_payload,
                "approval_manager_response": manager_response,
            },
            metadata={
                "agent": self.agent_name,
                "approval_manager_available": self.approval_manager is not None,
            },
        )

    def _prepare_verification_payload(
        self,
        action: str,
        context: Mapping[str, Any],
        success: bool,
        data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare Verification Agent compatible payload."""
        return {
            "verification_id": self._new_id("privacy_verify"),
            "source_agent": self.agent_name,
            "source_module": "agents.security_agent.privacy_guard",
            "target_agent": "VerificationAgent",
            "action": action,
            "success": bool(success),
            "user_id": str(context.get("user_id")),
            "workspace_id": str(context.get("workspace_id")),
            "timestamp": self._utc_now(),
            "checks": {
                "task_context_validated": True,
                "tenant_isolation_checked": True,
                "privacy_inspection_completed": True,
                "secret_values_excluded_from_verification": True,
                "security_approval_considered": True,
            },
            "data": self._json_safe(data or {}),
        }

    def _prepare_memory_payload(
        self,
        content: Any,
        context: Mapping[str, Any],
        inspection: Optional[PrivacyInspection] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Memory Agent compatible privacy-safe payload.

        Raw sensitive content is not included when an inspection provides a
        sanitized version.
        """
        safe_content = (
            inspection.sanitized_content
            if inspection is not None
            else self._sanitize_recursive(
                value=content,
                path="memory",
                findings=[],
                depth=0,
                force_log_mode=False,
            )[0]
        )

        return {
            "user_id": str(context.get("user_id")),
            "workspace_id": str(context.get("workspace_id")),
            "source_agent": self.agent_name,
            "memory_type": "security_privacy_context",
            "content": safe_content,
            "privacy": {
                "sanitized": True,
                "inspection_id": inspection.inspection_id if inspection else None,
                "decision": inspection.decision.value if inspection else None,
                "risk_level": inspection.risk_level.value if inspection else None,
                "approval_status": (
                    inspection.approval_status.value
                    if inspection
                    else ApprovalStatus.NOT_REQUIRED.value
                ),
                "original_content_included": False,
            },
            "created_at": self._utc_now(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Emit privacy events without exposing secret content."""
        safe_payload = self._sanitize_recursive(
            value=payload,
            path="event",
            findings=[],
            depth=0,
            force_log_mode=True,
        )[0]

        try:
            if self.event_emitter is not None:
                response = self.event_emitter(event_name, safe_payload)
                return self._safe_result(
                    message="Agent event emitted.",
                    data={
                        "event_name": event_name,
                        "response": self._json_safe(response),
                    },
                )

            parent_emit = getattr(super(), "emit_event", None)
            if callable(parent_emit):
                try:
                    response = parent_emit(event_name, safe_payload)
                    return self._safe_result(
                        message="Agent event emitted through BaseAgent.",
                        data={
                            "event_name": event_name,
                            "response": self._json_safe(response),
                        },
                    )
                except Exception:
                    pass

            logger.debug(
                "Privacy event emitted locally: %s %s",
                event_name,
                safe_payload,
            )
            return self._safe_result(
                message="Agent event recorded locally.",
                data={
                    "event_name": event_name,
                },
                metadata={
                    "local_only": True,
                },
            )
        except Exception as exc:
            logger.warning("Privacy event emission failed: %s", exc)
            return self._error_result(
                message="Privacy event emission failed.",
                error=str(exc),
            )

    def _log_audit_event(
        self,
        event_type: str,
        context: Mapping[str, Any],
        data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Emit an audit-safe record.

        Audit content is sanitized again before it reaches an external logger.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        sanitized_data = self._sanitize_recursive(
            value=data or {},
            path="audit.data",
            findings=[],
            depth=0,
            force_log_mode=True,
        )[0]

        event = {
            "audit_id": self._new_id("privacy_audit"),
            "event_type": event_type,
            "source_agent": self.agent_name,
            "user_id": str(context.get("user_id")),
            "workspace_id": str(context.get("workspace_id")),
            "request_id": context.get("request_id"),
            "session_id": self._mask_identifier(context.get("session_id")),
            "timestamp": self._utc_now(),
            "data": sanitized_data,
        }

        try:
            if self.audit_logger is None:
                logger.info("Privacy audit event: %s", json.dumps(event, default=str))
                return self._safe_result(
                    message="Privacy audit event logged locally.",
                    data={
                        "audit_id": event["audit_id"],
                    },
                )

            if callable(self.audit_logger):
                response = self.audit_logger(event)
                return self._safe_result(
                    message="Privacy audit event logged.",
                    data={
                        "audit_id": event["audit_id"],
                        "response": self._json_safe(response),
                    },
                )

            for method_name in (
                "log_event",
                "write",
                "record",
                "create_event",
                "log",
            ):
                method = getattr(self.audit_logger, method_name, None)
                if callable(method):
                    try:
                        response = method(event)
                    except TypeError:
                        response = method(**event)

                    return self._safe_result(
                        message="Privacy audit event logged.",
                        data={
                            "audit_id": event["audit_id"],
                            "response": self._json_safe(response),
                        },
                    )

            logger.info("Privacy audit event: %s", json.dumps(event, default=str))
            return self._safe_result(
                message="Audit logger had no compatible method; event logged locally.",
                data={
                    "audit_id": event["audit_id"],
                },
                metadata={
                    "fallback": True,
                },
            )
        except Exception as exc:
            logger.warning("Privacy audit logging failed: %s", exc)
            return self._error_result(
                message="Privacy audit logging failed.",
                error=str(exc),
                data={
                    "audit_id": event["audit_id"],
                },
            )

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis success response."""
        return {
            "success": True,
            "message": message,
            "data": self._json_safe(data or {}),
            "error": None,
            "metadata": self._json_safe(
                {
                    "agent": self.agent_name,
                    "agent_type": self.AGENT_TYPE,
                    "version": self.AGENT_VERSION,
                    **dict(metadata or {}),
                }
            ),
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception]] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis error response."""
        return {
            "success": False,
            "message": message,
            "data": self._json_safe(data or {}),
            "error": str(error) if error is not None else "privacy_guard_error",
            "metadata": self._json_safe(
                {
                    "agent": self.agent_name,
                    "agent_type": self.AGENT_TYPE,
                    "version": self.AGENT_VERSION,
                    **dict(metadata or {}),
                }
            ),
        }

    # =========================================================================
    # Internal inspection engine
    # =========================================================================

    def _inspect_content(
        self,
        content: Any,
        context: Mapping[str, Any],
        content_type: PrivacyContentType,
        operation: PrivacyOperation,
        redact: bool,
        additional_risk: PrivacyRiskLevel = PrivacyRiskLevel.NONE,
        preexisting_findings: Optional[List[SensitiveFinding]] = None,
    ) -> Dict[str, Any]:
        """Core privacy inspection workflow."""
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        original_fingerprint = self._fingerprint(content)
        findings = list(preexisting_findings or [])

        detected = self._find_sensitive_data(content)
        findings.extend(detected)
        findings = self._deduplicate_findings(findings)

        sanitized_content = content
        if redact:
            sanitized_content, redaction_findings = self._sanitize_recursive(
                value=content,
                path="content",
                findings=[],
                depth=0,
                force_log_mode=False,
            )
            findings.extend(redaction_findings)
            findings = self._deduplicate_findings(findings)
        else:
            sanitized_content = self._json_safe(content)

        risk_level = self._max_risk(
            self._calculate_overall_risk(findings),
            additional_risk,
        )

        decision = self._decide(
            risk_level=risk_level,
            operation=operation,
            content_type=content_type,
            redact=redact,
        )

        approval_status = ApprovalStatus.NOT_REQUIRED
        approval_id: Optional[str] = None

        if decision == PrivacyDecisionType.REQUIRE_APPROVAL:
            approval = self._request_security_approval(
                context=context,
                operation=operation,
                content_type=content_type,
                risk_level=risk_level,
                content_fingerprint=original_fingerprint,
                reason=(
                    f"{operation.value} of {content_type.value} content with "
                    f"{risk_level.value} privacy risk requires approval."
                ),
                metadata={
                    "finding_count": len(findings),
                    "categories": sorted(
                        {finding.category.value for finding in findings}
                    ),
                    "redaction_available": redact,
                },
            )
            approval_status = ApprovalStatus.PENDING
            approval_id = approval.get("data", {}).get("approval_id")

        allowed = decision in {
            PrivacyDecisionType.ALLOW,
            PrivacyDecisionType.ALLOW_REDACTED,
        }

        inspection = PrivacyInspection(
            inspection_id=self._new_id("privacy_inspection"),
            allowed=allowed,
            decision=decision,
            risk_level=risk_level,
            content_type=content_type,
            operation=operation,
            findings=findings,
            sanitized_content=sanitized_content,
            approval_status=approval_status,
            approval_id=approval_id,
            message=self._decision_message(decision, risk_level),
            original_fingerprint=original_fingerprint,
            sanitized_fingerprint=self._fingerprint(sanitized_content),
            created_at=self._utc_now(),
        )

        verification_payload = self._prepare_verification_payload(
            action=f"inspect_{content_type.value}",
            context=context,
            success=True,
            data={
                "inspection_id": inspection.inspection_id,
                "decision": inspection.decision.value,
                "risk_level": inspection.risk_level.value,
                "operation": inspection.operation.value,
                "finding_count": len(findings),
                "approval_status": inspection.approval_status.value,
                "approval_id": inspection.approval_id,
                "original_fingerprint": inspection.original_fingerprint,
                "sanitized_fingerprint": inspection.sanitized_fingerprint,
            },
        )

        memory_payload = self._prepare_memory_payload(
            content=content,
            context=context,
            inspection=inspection,
        )

        self._log_audit_event(
            event_type="security_privacy_content_inspected",
            context=context,
            data={
                "inspection_id": inspection.inspection_id,
                "content_type": content_type.value,
                "operation": operation.value,
                "decision": decision.value,
                "risk_level": risk_level.value,
                "finding_count": len(findings),
                "approval_status": approval_status.value,
                "approval_id": approval_id,
                "original_fingerprint": original_fingerprint,
                "sanitized_fingerprint": inspection.sanitized_fingerprint,
            },
        )

        return self._safe_result(
            message=inspection.message,
            data={
                "inspection_id": inspection.inspection_id,
                "allowed": inspection.allowed,
                "decision": inspection.decision.value,
                "risk_level": inspection.risk_level.value,
                "content_type": inspection.content_type.value,
                "operation": inspection.operation.value,
                "approval_status": inspection.approval_status.value,
                "approval_id": inspection.approval_id,
                "finding_count": len(inspection.findings),
                "findings": [
                    self._finding_to_dict(item)
                    for item in inspection.findings
                ],
                "sanitized_content": inspection.sanitized_content,
                "original_fingerprint": inspection.original_fingerprint,
                "sanitized_fingerprint": inspection.sanitized_fingerprint,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
                "created_at": inspection.created_at,
            },
            metadata={
                "strict_mode": self.strict_mode,
                "redaction_enabled": redact,
                "original_content_returned": False,
            },
        )

    def _decide(
        self,
        risk_level: PrivacyRiskLevel,
        operation: PrivacyOperation,
        content_type: PrivacyContentType,
        redact: bool,
    ) -> PrivacyDecisionType:
        """Choose allow, redact, approval, or block."""
        if risk_level == PrivacyRiskLevel.NONE:
            return PrivacyDecisionType.ALLOW

        if risk_level == PrivacyRiskLevel.LOW:
            return (
                PrivacyDecisionType.ALLOW_REDACTED
                if redact
                else PrivacyDecisionType.ALLOW
            )

        if risk_level == PrivacyRiskLevel.MEDIUM:
            if operation in {
                PrivacyOperation.SHARE,
                PrivacyOperation.EXPORT,
                PrivacyOperation.TRANSMIT,
                PrivacyOperation.UNREDACT,
            }:
                return PrivacyDecisionType.REQUIRE_APPROVAL

            return (
                PrivacyDecisionType.ALLOW_REDACTED
                if redact
                else PrivacyDecisionType.REQUIRE_APPROVAL
            )

        if risk_level == PrivacyRiskLevel.HIGH:
            if redact and operation in {
                PrivacyOperation.INSPECT,
                PrivacyOperation.LOG,
                PrivacyOperation.STORE,
                PrivacyOperation.MEMORY_WRITE,
            }:
                return PrivacyDecisionType.ALLOW_REDACTED

            return PrivacyDecisionType.REQUIRE_APPROVAL

        if risk_level == PrivacyRiskLevel.CRITICAL:
            if operation in {
                PrivacyOperation.LOG,
                PrivacyOperation.STORE,
                PrivacyOperation.MEMORY_WRITE,
            } and redact:
                return PrivacyDecisionType.ALLOW_REDACTED

            if operation == PrivacyOperation.INSPECT and redact:
                return PrivacyDecisionType.ALLOW_REDACTED

            return (
                PrivacyDecisionType.BLOCK
                if self.strict_mode
                else PrivacyDecisionType.REQUIRE_APPROVAL
            )

        return PrivacyDecisionType.BLOCK

    def _decision_message(
        self,
        decision: PrivacyDecisionType,
        risk_level: PrivacyRiskLevel,
    ) -> str:
        if decision == PrivacyDecisionType.ALLOW:
            return "Privacy inspection passed."

        if decision == PrivacyDecisionType.ALLOW_REDACTED:
            return (
                f"Privacy inspection detected {risk_level.value}-risk content. "
                "Sensitive values were redacted."
            )

        if decision == PrivacyDecisionType.REQUIRE_APPROVAL:
            return (
                f"Privacy inspection detected {risk_level.value}-risk content. "
                "Security approval is required."
            )

        return (
            f"Privacy inspection detected {risk_level.value}-risk content. "
            "The requested action was blocked."
        )

    # =========================================================================
    # Detection and sanitization
    # =========================================================================

    def _build_patterns(
        self,
    ) -> Dict[
        SensitiveCategory,
        List[Tuple[re.Pattern[str], PrivacyRiskLevel, str, float]],
    ]:
        """Build compiled privacy and secret patterns."""
        flags = re.IGNORECASE | re.MULTILINE

        return {
            SensitiveCategory.EMAIL: [
                (
                    re.compile(
                        r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b",
                        re.IGNORECASE,
                    ),
                    PrivacyRiskLevel.LOW,
                    "Email address detected.",
                    0.96,
                )
            ],
            SensitiveCategory.PHONE: [
                (
                    re.compile(
                        r"(?<!\d)(?:\+?\d{1,3}[\s.\-]?)?"
                        r"(?:\(?\d{2,4}\)?[\s.\-]?)?"
                        r"\d{3,4}[\s.\-]?\d{4}(?!\d)"
                    ),
                    PrivacyRiskLevel.LOW,
                    "Phone number-like value detected.",
                    0.72,
                )
            ],
            SensitiveCategory.SSN: [
                (
                    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
                    PrivacyRiskLevel.CRITICAL,
                    "US Social Security number-like value detected.",
                    0.99,
                )
            ],
            SensitiveCategory.CREDIT_CARD: [
                (
                    re.compile(r"(?<!\d)(?:\d[ \-]*?){13,19}(?!\d)"),
                    PrivacyRiskLevel.CRITICAL,
                    "Payment card number-like value detected.",
                    0.90,
                )
            ],
            SensitiveCategory.IBAN: [
                (
                    re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", re.IGNORECASE),
                    PrivacyRiskLevel.CRITICAL,
                    "IBAN-like value detected.",
                    0.92,
                )
            ],
            SensitiveCategory.JWT: [
                (
                    re.compile(
                        r"\beyJ[A-Za-z0-9_\-]{5,}\."
                        r"[A-Za-z0-9_\-]{5,}\."
                        r"[A-Za-z0-9_\-]{5,}\b"
                    ),
                    PrivacyRiskLevel.CRITICAL,
                    "JWT token detected.",
                    0.99,
                )
            ],
            SensitiveCategory.PRIVATE_KEY: [
                (
                    re.compile(
                        r"-----BEGIN "
                        r"(?:RSA |EC |DSA |OPENSSH |PGP )?"
                        r"PRIVATE KEY-----",
                        flags,
                    ),
                    PrivacyRiskLevel.CRITICAL,
                    "Private key material detected.",
                    1.0,
                )
            ],
            SensitiveCategory.CERTIFICATE: [
                (
                    re.compile(r"-----BEGIN CERTIFICATE-----", flags),
                    PrivacyRiskLevel.HIGH,
                    "Certificate material detected.",
                    1.0,
                )
            ],
            SensitiveCategory.AUTHORIZATION_HEADER: [
                (
                    re.compile(
                        r"(?i)\bauthorization\s*[:=]\s*"
                        r"(?:bearer|basic|token)\s+[A-Za-z0-9+/=_\-.:]{6,}"
                    ),
                    PrivacyRiskLevel.CRITICAL,
                    "Authorization credential detected.",
                    0.99,
                )
            ],
            SensitiveCategory.PASSWORD: [
                (
                    re.compile(
                        r"(?i)\b(?:password|passwd|pwd|passphrase)\b"
                        r"\s*[:=]\s*[\"']?[^\"'\s,;}{]{4,}"
                    ),
                    PrivacyRiskLevel.CRITICAL,
                    "Password assignment detected.",
                    0.98,
                )
            ],
            SensitiveCategory.API_KEY: [
                (
                    re.compile(
                        r"(?i)\b(?:api[_\- ]?key|access[_\- ]?key|secret[_\- ]?key)"
                        r"\b\s*[:=]\s*[\"']?[A-Za-z0-9_\-/.+=]{8,}"
                    ),
                    PrivacyRiskLevel.CRITICAL,
                    "API or access key assignment detected.",
                    0.97,
                ),
                (
                    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b"),
                    PrivacyRiskLevel.CRITICAL,
                    "Secret-key-like token detected.",
                    0.96,
                ),
                (
                    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
                    PrivacyRiskLevel.CRITICAL,
                    "AWS access-key-like identifier detected.",
                    0.99,
                ),
                (
                    re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"),
                    PrivacyRiskLevel.CRITICAL,
                    "Google API-key-like value detected.",
                    0.97,
                ),
                (
                    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
                    PrivacyRiskLevel.CRITICAL,
                    "GitHub token-like value detected.",
                    0.98,
                ),
            ],
            SensitiveCategory.OAUTH_SECRET: [
                (
                    re.compile(
                        r"(?i)\bclient[_\- ]?secret\b"
                        r"\s*[:=]\s*[\"']?[A-Za-z0-9_\-/.+=]{8,}"
                    ),
                    PrivacyRiskLevel.CRITICAL,
                    "OAuth client secret detected.",
                    0.98,
                )
            ],
            SensitiveCategory.WEBHOOK_SECRET: [
                (
                    re.compile(
                        r"(?i)\b(?:webhook|signing)[_\- ]?secret\b"
                        r"\s*[:=]\s*[\"']?[A-Za-z0-9_\-/.+=]{8,}"
                    ),
                    PrivacyRiskLevel.CRITICAL,
                    "Webhook signing secret detected.",
                    0.98,
                )
            ],
            SensitiveCategory.DATABASE_URL: [
                (
                    re.compile(
                        r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|"
                        r"redis|amqp|mssql)://"
                        r"[^:\s/]+:[^@\s]+@[^\s]+"
                    ),
                    PrivacyRiskLevel.CRITICAL,
                    "Credential-bearing database URL detected.",
                    0.99,
                )
            ],
            SensitiveCategory.COOKIE: [
                (
                    re.compile(
                        r"(?i)\b(?:cookie|set-cookie)\s*[:=]\s*[^\r\n]{8,}"
                    ),
                    PrivacyRiskLevel.HIGH,
                    "Cookie or session material detected.",
                    0.90,
                )
            ],
            SensitiveCategory.PRECISE_LOCATION: [
                (
                    re.compile(
                        r"(?<!\d)-?\d{1,2}\.\d{5,}\s*,\s*"
                        r"-?\d{1,3}\.\d{5,}(?!\d)"
                    ),
                    PrivacyRiskLevel.HIGH,
                    "Precise geographic coordinates detected.",
                    0.95,
                )
            ],
            SensitiveCategory.IP_ADDRESS: [
                (
                    re.compile(
                        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
                    ),
                    PrivacyRiskLevel.LOW,
                    "IP-address-like value detected.",
                    0.70,
                )
            ],
            SensitiveCategory.SEED_PHRASE: [
                (
                    re.compile(
                        r"(?i)\b(?:seed phrase|recovery phrase|mnemonic)\b"
                        r"\s*[:=]\s*(?:[a-z]{3,12}\s+){11,23}[a-z]{3,12}\b"
                    ),
                    PrivacyRiskLevel.CRITICAL,
                    "Cryptocurrency recovery phrase detected.",
                    0.98,
                )
            ],
            SensitiveCategory.SOURCE_CODE_SECRET: [
                (
                    re.compile(
                        r"(?i)\b(?:secret|token|key)\b"
                        r"\s*[:=]\s*[\"'][A-Za-z0-9_\-/.+=]{16,}[\"']"
                    ),
                    PrivacyRiskLevel.CRITICAL,
                    "Hardcoded source-code secret detected.",
                    0.90,
                )
            ],
        }

    def _build_keyword_rules(
        self,
    ) -> Dict[
        SensitiveCategory,
        Tuple[Sequence[str], PrivacyRiskLevel, str, float],
    ]:
        """Build semantic keyword detection rules."""
        return {
            SensitiveCategory.HEALTH: (
                (
                    "medical diagnosis",
                    "mental health",
                    "therapy notes",
                    "patient record",
                    "prescription medication",
                    "medical condition",
                    "blood test result",
                ),
                PrivacyRiskLevel.HIGH,
                "Health-related private information detected.",
                0.75,
            ),
            SensitiveCategory.BIOMETRIC: (
                (
                    "fingerprint template",
                    "face embedding",
                    "facial recognition vector",
                    "retina scan",
                    "iris scan",
                    "voice biometric",
                ),
                PrivacyRiskLevel.CRITICAL,
                "Biometric information detected.",
                0.85,
            ),
            SensitiveCategory.POLITICAL: (
                (
                    "political affiliation",
                    "voting preference",
                    "party membership",
                    "political donation",
                ),
                PrivacyRiskLevel.HIGH,
                "Political private information detected.",
                0.75,
            ),
            SensitiveCategory.RELIGIOUS: (
                (
                    "religious belief",
                    "religious affiliation",
                    "church membership",
                    "mosque membership",
                    "temple membership",
                    "synagogue membership",
                ),
                PrivacyRiskLevel.HIGH,
                "Religious private information detected.",
                0.75,
            ),
            SensitiveCategory.ETHNICITY: (
                (
                    "racial background",
                    "ethnic background",
                    "ethnicity",
                    "caste",
                    "tribal affiliation",
                ),
                PrivacyRiskLevel.HIGH,
                "Race or ethnicity information detected.",
                0.78,
            ),
            SensitiveCategory.SEXUAL_ORIENTATION: (
                (
                    "sexual orientation",
                    "gender identity",
                    "sex life",
                ),
                PrivacyRiskLevel.HIGH,
                "Highly private identity information detected.",
                0.78,
            ),
            SensitiveCategory.CRIMINAL_RECORD: (
                (
                    "criminal record",
                    "arrest record",
                    "criminal conviction",
                    "probation record",
                    "parole record",
                ),
                PrivacyRiskLevel.HIGH,
                "Criminal-record information detected.",
                0.80,
            ),
            SensitiveCategory.CHILD_DATA: (
                (
                    "minor child",
                    "under thirteen",
                    "child passport",
                    "student medical record",
                    "school identification number",
                ),
                PrivacyRiskLevel.CRITICAL,
                "Child-related private information detected.",
                0.82,
            ),
            SensitiveCategory.LEGAL_PRIVILEGED: (
                (
                    "attorney-client privileged",
                    "legal privileged",
                    "confidential legal advice",
                    "settlement negotiation",
                ),
                PrivacyRiskLevel.HIGH,
                "Legally privileged information detected.",
                0.82,
            ),
            SensitiveCategory.CLIENT_CONFIDENTIAL: (
                (
                    "client confidential",
                    "confidential client",
                    "under nda",
                    "non-disclosure agreement",
                    "private client brief",
                ),
                PrivacyRiskLevel.HIGH,
                "Client-confidential information detected.",
                0.76,
            ),
            SensitiveCategory.BUSINESS_CONFIDENTIAL: (
                (
                    "trade secret",
                    "confidential strategy",
                    "unreleased financials",
                    "internal only",
                    "confidential roadmap",
                ),
                PrivacyRiskLevel.HIGH,
                "Business-confidential information detected.",
                0.76,
            ),
            SensitiveCategory.PRIVATE_MESSAGE: (
                (
                    "private message",
                    "direct message",
                    "do not share",
                    "for your eyes only",
                    "private conversation",
                ),
                PrivacyRiskLevel.MEDIUM,
                "Private-message indicator detected.",
                0.72,
            ),
        }

    def _find_sensitive_data(self, content: Any) -> List[SensitiveFinding]:
        """Find sensitive data in nested content."""
        findings: List[SensitiveFinding] = []
        self._scan_recursive(
            value=content,
            path="content",
            findings=findings,
            depth=0,
        )
        return self._deduplicate_findings(findings)

    def _scan_recursive(
        self,
        value: Any,
        path: str,
        findings: List[SensitiveFinding],
        depth: int,
    ) -> None:
        """Recursively inspect content without mutating it."""
        if depth > self.MAX_RECURSION_DEPTH:
            findings.append(
                self._make_finding(
                    category=SensitiveCategory.UNKNOWN_SENSITIVE,
                    risk=PrivacyRiskLevel.MEDIUM,
                    field_path=path,
                    preview="maximum recursion depth exceeded",
                    confidence=1.0,
                    detector="structure_limit",
                    reason="Nested content exceeded privacy inspection depth.",
                )
            )
            return

        if isinstance(value, Mapping):
            if len(value) > self.MAX_CONTAINER_ITEMS:
                findings.append(
                    self._make_finding(
                        category=SensitiveCategory.UNKNOWN_SENSITIVE,
                        risk=PrivacyRiskLevel.MEDIUM,
                        field_path=path,
                        preview=f"{len(value)} mapping items",
                        confidence=1.0,
                        detector="structure_limit",
                        reason="Mapping exceeded the privacy inspection item limit.",
                    )
                )

            for index, (key, item) in enumerate(value.items()):
                if index >= self.MAX_CONTAINER_ITEMS:
                    break

                key_text = str(key)
                child_path = f"{path}.{key_text}"
                normalized_key = self._normalize_field_name(key_text)

                if normalized_key in self.SECRET_FIELD_NAMES:
                    findings.append(
                        self._make_finding(
                            category=self._category_for_field(normalized_key),
                            risk=PrivacyRiskLevel.CRITICAL,
                            field_path=child_path,
                            preview=self._stringify(item),
                            confidence=0.99,
                            detector="sensitive_field_name",
                            reason="Secret-bearing field name detected.",
                            requires_approval=True,
                        )
                    )
                    continue

                if normalized_key in self.PRIVATE_FIELD_NAMES:
                    findings.append(
                        self._make_finding(
                            category=SensitiveCategory.PRIVATE_MESSAGE,
                            risk=PrivacyRiskLevel.HIGH,
                            field_path=child_path,
                            preview=self._stringify(item),
                            confidence=0.92,
                            detector="private_field_name",
                            reason="Explicitly private field detected.",
                            requires_approval=True,
                        )
                    )

                self._scan_recursive(
                    value=item,
                    path=child_path,
                    findings=findings,
                    depth=depth + 1,
                )
            return

        if isinstance(value, (list, tuple, set)):
            sequence = list(value)
            if len(sequence) > self.MAX_CONTAINER_ITEMS:
                findings.append(
                    self._make_finding(
                        category=SensitiveCategory.UNKNOWN_SENSITIVE,
                        risk=PrivacyRiskLevel.MEDIUM,
                        field_path=path,
                        preview=f"{len(sequence)} sequence items",
                        confidence=1.0,
                        detector="structure_limit",
                        reason="Sequence exceeded the privacy inspection item limit.",
                    )
                )

            for index, item in enumerate(sequence[: self.MAX_CONTAINER_ITEMS]):
                self._scan_recursive(
                    value=item,
                    path=f"{path}.{index}",
                    findings=findings,
                    depth=depth + 1,
                )
            return

        if isinstance(value, (bytes, bytearray, memoryview)):
            findings.append(
                self._make_finding(
                    category=SensitiveCategory.PRIVATE_FILE,
                    risk=PrivacyRiskLevel.MEDIUM,
                    field_path=path,
                    preview=f"{len(bytes(value))} binary bytes",
                    confidence=0.85,
                    detector="binary_content",
                    reason="Binary content cannot be safely represented in logs.",
                )
            )
            return

        text = self._stringify(value)
        if not text:
            return

        self._scan_text(
            text=text,
            path=path,
            findings=findings,
        )

    def _scan_text(
        self,
        text: str,
        path: str,
        findings: List[SensitiveFinding],
    ) -> None:
        """Scan text using patterns, validation, and keyword rules."""
        limited_text = text[: self.MAX_TEXT_LENGTH]

        for category, rules in self._patterns.items():
            for pattern, risk, reason, confidence in rules:
                for match in pattern.finditer(limited_text):
                    raw = match.group(0)

                    if category == SensitiveCategory.CREDIT_CARD:
                        if not self._looks_like_card_number(raw):
                            continue

                    if category == SensitiveCategory.IP_ADDRESS:
                        if not self._valid_ip(raw):
                            continue

                    findings.append(
                        self._make_finding(
                            category=category,
                            risk=risk,
                            field_path=path,
                            preview=raw,
                            confidence=confidence,
                            detector="regex",
                            reason=reason,
                            start=match.start(),
                            end=match.end(),
                            requires_approval=risk in {
                                PrivacyRiskLevel.HIGH,
                                PrivacyRiskLevel.CRITICAL,
                            },
                        )
                    )

        lowered = limited_text.lower()
        for category, (keywords, risk, reason, confidence) in self._keyword_rules.items():
            for keyword in keywords:
                position = lowered.find(keyword)
                if position < 0:
                    continue

                findings.append(
                    self._make_finding(
                        category=category,
                        risk=risk,
                        field_path=path,
                        preview=keyword,
                        confidence=confidence,
                        detector="keyword",
                        reason=reason,
                        start=position,
                        end=position + len(keyword),
                        requires_approval=risk in {
                            PrivacyRiskLevel.HIGH,
                            PrivacyRiskLevel.CRITICAL,
                        },
                    )
                )
                break

        entropy_tokens = re.findall(
            r"(?<![A-Za-z0-9])[A-Za-z0-9_\-+/=]{24,}(?![A-Za-z0-9])",
            limited_text,
        )
        for token in entropy_tokens[:100]:
            if self._looks_like_high_entropy_secret(token):
                findings.append(
                    self._make_finding(
                        category=SensitiveCategory.ACCESS_TOKEN,
                        risk=PrivacyRiskLevel.HIGH,
                        field_path=path,
                        preview=token,
                        confidence=0.68,
                        detector="entropy",
                        reason="High-entropy token-like value detected.",
                        requires_approval=True,
                    )
                )

    def _sanitize_recursive(
        self,
        value: Any,
        path: str,
        findings: List[SensitiveFinding],
        depth: int,
        force_log_mode: bool,
    ) -> Tuple[Any, List[SensitiveFinding]]:
        """Recursively create a privacy-safe representation."""
        if depth > self.MAX_RECURSION_DEPTH:
            findings.append(
                self._make_finding(
                    category=SensitiveCategory.UNKNOWN_SENSITIVE,
                    risk=PrivacyRiskLevel.MEDIUM,
                    field_path=path,
                    preview="maximum recursion depth exceeded",
                    confidence=1.0,
                    detector="structure_limit",
                    reason="Nested content was truncated for privacy safety.",
                )
            )
            return "[TRUNCATED NESTED CONTENT]", findings

        if value is None or isinstance(value, (bool, int, float)):
            return value, findings

        if dataclasses.is_dataclass(value):
            value = dataclasses.asdict(value)

        if isinstance(value, Mapping):
            sanitized_mapping: Dict[str, Any] = {}

            for index, (key, item) in enumerate(value.items()):
                if index >= self.MAX_CONTAINER_ITEMS:
                    sanitized_mapping["__truncated__"] = (
                        f"Exceeded {self.MAX_CONTAINER_ITEMS} items."
                    )
                    break

                key_text = str(key)
                normalized_key = self._normalize_field_name(key_text)
                child_path = f"{path}.{key_text}"

                if normalized_key in self.SECRET_FIELD_NAMES:
                    category = self._category_for_field(normalized_key)
                    findings.append(
                        self._make_finding(
                            category=category,
                            risk=PrivacyRiskLevel.CRITICAL,
                            field_path=child_path,
                            preview=self._stringify(item),
                            confidence=0.99,
                            detector="sensitive_field_name",
                            reason="Secret-bearing field was redacted.",
                            requires_approval=True,
                        )
                    )
                    sanitized_mapping[key_text] = self.SECRET_TEXT
                    continue

                if force_log_mode and self._looks_like_sensitive_header(normalized_key):
                    findings.append(
                        self._make_finding(
                            category=SensitiveCategory.AUTHORIZATION_HEADER,
                            risk=PrivacyRiskLevel.CRITICAL,
                            field_path=child_path,
                            preview=self._stringify(item),
                            confidence=0.98,
                            detector="log_header",
                            reason="Sensitive request/response header was redacted.",
                            requires_approval=True,
                        )
                    )
                    sanitized_mapping[key_text] = self.SECRET_TEXT
                    continue

                if normalized_key in self.PRIVATE_FIELD_NAMES:
                    findings.append(
                        self._make_finding(
                            category=SensitiveCategory.PRIVATE_MESSAGE,
                            risk=PrivacyRiskLevel.HIGH,
                            field_path=child_path,
                            preview=self._stringify(item),
                            confidence=0.92,
                            detector="private_field_name",
                            reason="Explicitly private field was redacted.",
                            requires_approval=True,
                        )
                    )
                    sanitized_mapping[key_text] = self.PRIVATE_TEXT
                    continue

                protected_item, findings = self._sanitize_recursive(
                    value=item,
                    path=child_path,
                    findings=findings,
                    depth=depth + 1,
                    force_log_mode=force_log_mode,
                )
                sanitized_mapping[key_text] = protected_item

            return sanitized_mapping, findings

        if isinstance(value, (list, tuple, set)):
            protected_sequence: List[Any] = []

            for index, item in enumerate(list(value)[: self.MAX_CONTAINER_ITEMS]):
                protected_item, findings = self._sanitize_recursive(
                    value=item,
                    path=f"{path}.{index}",
                    findings=findings,
                    depth=depth + 1,
                    force_log_mode=force_log_mode,
                )
                protected_sequence.append(protected_item)

            if len(value) > self.MAX_CONTAINER_ITEMS:
                protected_sequence.append(
                    f"[TRUNCATED AFTER {self.MAX_CONTAINER_ITEMS} ITEMS]"
                )

            return protected_sequence, findings

        if isinstance(value, (bytes, bytearray, memoryview)):
            binary_bytes = bytes(value)
            findings.append(
                self._make_finding(
                    category=SensitiveCategory.PRIVATE_FILE,
                    risk=PrivacyRiskLevel.MEDIUM,
                    field_path=path,
                    preview=f"{len(binary_bytes)} binary bytes",
                    confidence=0.90,
                    detector="binary_content",
                    reason="Binary content was replaced with a protected marker.",
                )
            )
            return {
                "protected_binary": True,
                "size_bytes": len(binary_bytes),
                "fingerprint": self._fingerprint(binary_bytes),
                "content": self.BINARY_TEXT,
            }, findings

        text = self._stringify(value)
        sanitized_text, text_findings = self._sanitize_text(text, path)
        findings.extend(text_findings)

        return sanitized_text, findings

    def _sanitize_text(
        self,
        text: str,
        path: str,
    ) -> Tuple[str, List[SensitiveFinding]]:
        """Redact sensitive matches from a string."""
        if not text:
            return text, []

        limited_text = text[: self.MAX_TEXT_LENGTH]
        findings: List[SensitiveFinding] = []
        replacements: List[Tuple[int, int, str]] = []

        for category, rules in self._patterns.items():
            for pattern, risk, reason, confidence in rules:
                for match in pattern.finditer(limited_text):
                    raw = match.group(0)

                    if category == SensitiveCategory.CREDIT_CARD:
                        if not self._looks_like_card_number(raw):
                            continue

                    if category == SensitiveCategory.IP_ADDRESS:
                        if not self._valid_ip(raw):
                            continue

                    finding = self._make_finding(
                        category=category,
                        risk=risk,
                        field_path=path,
                        preview=raw,
                        confidence=confidence,
                        detector="regex",
                        reason=reason,
                        start=match.start(),
                        end=match.end(),
                        requires_approval=risk in {
                            PrivacyRiskLevel.HIGH,
                            PrivacyRiskLevel.CRITICAL,
                        },
                    )
                    findings.append(finding)
                    replacements.append(
                        (
                            match.start(),
                            match.end(),
                            self._replacement_for_category(category),
                        )
                    )

        lowered = limited_text.lower()
        for category, (keywords, risk, reason, confidence) in self._keyword_rules.items():
            for keyword in keywords:
                start = lowered.find(keyword)
                if start < 0:
                    continue

                end = start + len(keyword)
                findings.append(
                    self._make_finding(
                        category=category,
                        risk=risk,
                        field_path=path,
                        preview=keyword,
                        confidence=confidence,
                        detector="keyword",
                        reason=reason,
                        start=start,
                        end=end,
                        requires_approval=risk in {
                            PrivacyRiskLevel.HIGH,
                            PrivacyRiskLevel.CRITICAL,
                        },
                    )
                )

                if category in {
                    SensitiveCategory.PRIVATE_MESSAGE,
                    SensitiveCategory.HEALTH,
                    SensitiveCategory.BIOMETRIC,
                    SensitiveCategory.POLITICAL,
                    SensitiveCategory.RELIGIOUS,
                    SensitiveCategory.ETHNICITY,
                    SensitiveCategory.SEXUAL_ORIENTATION,
                    SensitiveCategory.CRIMINAL_RECORD,
                    SensitiveCategory.CHILD_DATA,
                    SensitiveCategory.LEGAL_PRIVILEGED,
                    SensitiveCategory.CLIENT_CONFIDENTIAL,
                    SensitiveCategory.BUSINESS_CONFIDENTIAL,
                }:
                    replacements.append((start, end, self.PRIVATE_TEXT))
                break

        sanitized = limited_text

        for start, end, replacement in sorted(
            replacements,
            key=lambda item: (item[0], item[1]),
            reverse=True,
        ):
            sanitized = sanitized[:start] + replacement + sanitized[end:]

        if len(text) > self.MAX_TEXT_LENGTH:
            sanitized += "\n[TRUNCATED FOR PRIVACY INSPECTION]"

        return sanitized, self._deduplicate_findings(findings)

    # =========================================================================
    # Scope, destination, and approval helpers
    # =========================================================================

    def _validate_resource_scope(
        self,
        resource: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Prevent cross-tenant access to files, screenshots, and resources."""
        expected_user_id = str(context.get("user_id"))
        expected_workspace_id = str(context.get("workspace_id"))

        resource_user_id = (
            resource.get("owner_user_id")
            or resource.get("user_id")
            or resource.get("created_by_user_id")
        )
        resource_workspace_id = (
            resource.get("owner_workspace_id")
            or resource.get("workspace_id")
            or resource.get("tenant_id")
        )

        if (
            resource_user_id is not None
            and str(resource_user_id) != expected_user_id
        ):
            self._log_audit_event(
                event_type="security_privacy_user_isolation_violation",
                context=context,
                data={
                    "expected_user_id": expected_user_id,
                    "resource_user_fingerprint": self._fingerprint(resource_user_id),
                },
            )
            return self._error_result(
                message="Resource does not belong to the current user.",
                error="user_isolation_violation",
            )

        if (
            resource_workspace_id is not None
            and str(resource_workspace_id) != expected_workspace_id
        ):
            self._log_audit_event(
                event_type="security_privacy_workspace_isolation_violation",
                context=context,
                data={
                    "expected_workspace_id": expected_workspace_id,
                    "resource_workspace_fingerprint": self._fingerprint(
                        resource_workspace_id
                    ),
                },
            )
            return self._error_result(
                message="Resource does not belong to the current workspace.",
                error="workspace_isolation_violation",
            )

        return self._safe_result(
            message="Resource scope validated.",
            data={
                "tenant_isolation_passed": True,
            },
        )

    def _evaluate_destination_risk(
        self,
        destination: Optional[Mapping[str, Any]],
        context: Mapping[str, Any],
    ) -> PrivacyRiskLevel:
        """Evaluate cross-workspace, external, or public destination risk."""
        if not destination:
            return PrivacyRiskLevel.NONE

        destination_workspace_id = destination.get("workspace_id")
        destination_user_id = destination.get("user_id")
        external = bool(destination.get("external", False))
        public = bool(destination.get("public", False))

        if public:
            return PrivacyRiskLevel.HIGH

        if external:
            return PrivacyRiskLevel.HIGH

        if (
            destination_workspace_id is not None
            and str(destination_workspace_id) != str(context.get("workspace_id"))
        ):
            return PrivacyRiskLevel.HIGH

        if (
            destination_user_id is not None
            and str(destination_user_id) != str(context.get("user_id"))
        ):
            return PrivacyRiskLevel.MEDIUM

        return PrivacyRiskLevel.NONE

    def _validate_approval_scope(
        self,
        record: PrivacyApprovalRecord,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Enforce user/workspace isolation on approval records."""
        if record.user_id != str(context.get("user_id")):
            return self._error_result(
                message="Approval request does not belong to this user.",
                error="approval_user_isolation_violation",
            )

        if record.workspace_id != str(context.get("workspace_id")):
            return self._error_result(
                message="Approval request does not belong to this workspace.",
                error="approval_workspace_isolation_violation",
            )

        return self._safe_result(
            message="Approval scope validated.",
            data={
                "approval_id": record.approval_id,
            },
        )

    def _call_approval_manager(
        self,
        approval_payload: Mapping[str, Any],
    ) -> Optional[Any]:
        """Call a compatible ApprovalManager method if available."""
        manager = self.approval_manager

        if manager is None and self.security_agent is not None:
            manager = getattr(self.security_agent, "approval_manager", None)

        if manager is None:
            return None

        for method_name in (
            "request_approval",
            "create_approval",
            "submit_request",
            "request_action_approval",
            "handle_approval_request",
        ):
            method = getattr(manager, method_name, None)
            if not callable(method):
                continue

            try:
                return self._json_safe(method(dict(approval_payload)))
            except TypeError:
                try:
                    return self._json_safe(method(**dict(approval_payload)))
                except Exception as exc:
                    logger.warning(
                        "ApprovalManager method %s failed: %s",
                        method_name,
                        exc,
                    )
            except Exception as exc:
                logger.warning(
                    "ApprovalManager method %s failed: %s",
                    method_name,
                    exc,
                )

        return {
            "success": False,
            "message": "ApprovalManager has no compatible request method.",
            "error": "approval_manager_method_missing",
        }

    # =========================================================================
    # Utility helpers
    # =========================================================================

    def _merge_context(
        self,
        task: Mapping[str, Any],
        context: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        merged: Dict[str, Any] = {}

        task_context = task.get("context")
        if isinstance(task_context, Mapping):
            merged.update(task_context)

        if context:
            merged.update(context)

        for key in (
            "user_id",
            "workspace_id",
            "requester_id",
            "request_id",
            "session_id",
            "role",
        ):
            if key in task and key not in merged:
                merged[key] = task[key]

        return merged

    def _normalize_content_type(
        self,
        value: Union[str, PrivacyContentType],
    ) -> PrivacyContentType:
        if isinstance(value, PrivacyContentType):
            return value

        normalized = str(value).strip().lower()
        for item in PrivacyContentType:
            if item.value == normalized:
                return item

        return PrivacyContentType.UNKNOWN

    def _normalize_operation(
        self,
        value: Union[str, PrivacyOperation],
    ) -> PrivacyOperation:
        if isinstance(value, PrivacyOperation):
            return value

        normalized = str(value).strip().lower()
        for item in PrivacyOperation:
            if item.value == normalized:
                return item

        return PrivacyOperation.INSPECT

    def _normalize_risk(
        self,
        value: Union[str, PrivacyRiskLevel],
    ) -> PrivacyRiskLevel:
        if isinstance(value, PrivacyRiskLevel):
            return value

        normalized = str(value).strip().lower()
        for item in PrivacyRiskLevel:
            if item.value == normalized:
                return item

        return PrivacyRiskLevel.MEDIUM

    def _normalize_field_name(self, value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")

    def _category_for_field(self, normalized_key: str) -> SensitiveCategory:
        mapping = {
            "password": SensitiveCategory.PASSWORD,
            "passwd": SensitiveCategory.PASSWORD,
            "pwd": SensitiveCategory.PASSWORD,
            "passphrase": SensitiveCategory.PASSWORD,
            "api_key": SensitiveCategory.API_KEY,
            "apikey": SensitiveCategory.API_KEY,
            "access_key": SensitiveCategory.API_KEY,
            "secret_key": SensitiveCategory.API_KEY,
            "private_key": SensitiveCategory.PRIVATE_KEY,
            "token": SensitiveCategory.ACCESS_TOKEN,
            "access_token": SensitiveCategory.ACCESS_TOKEN,
            "refresh_token": SensitiveCategory.REFRESH_TOKEN,
            "session_token": SensitiveCategory.SESSION_TOKEN,
            "session_id": SensitiveCategory.SESSION_TOKEN,
            "authorization": SensitiveCategory.AUTHORIZATION_HEADER,
            "cookie": SensitiveCategory.COOKIE,
            "set_cookie": SensitiveCategory.COOKIE,
            "jwt": SensitiveCategory.JWT,
            "client_secret": SensitiveCategory.OAUTH_SECRET,
            "webhook_secret": SensitiveCategory.WEBHOOK_SECRET,
            "signing_secret": SensitiveCategory.WEBHOOK_SECRET,
            "database_url": SensitiveCategory.DATABASE_URL,
            "db_url": SensitiveCategory.DATABASE_URL,
            "connection_string": SensitiveCategory.CONNECTION_STRING,
            "dsn": SensitiveCategory.CONNECTION_STRING,
            "recovery_code": SensitiveCategory.ACCESS_TOKEN,
            "backup_code": SensitiveCategory.ACCESS_TOKEN,
            "otp": SensitiveCategory.ACCESS_TOKEN,
            "pin": SensitiveCategory.PASSWORD,
            "cvv": SensitiveCategory.CREDIT_CARD,
            "cvc": SensitiveCategory.CREDIT_CARD,
        }
        return mapping.get(normalized_key, SensitiveCategory.UNKNOWN_SENSITIVE)

    def _replacement_for_category(
        self,
        category: SensitiveCategory,
    ) -> str:
        if category in {
            SensitiveCategory.EMAIL,
            SensitiveCategory.PHONE,
            SensitiveCategory.IP_ADDRESS,
            SensitiveCategory.PHYSICAL_ADDRESS,
            SensitiveCategory.PRECISE_LOCATION,
        }:
            return self.REDACTION_TEXT

        if category in {
            SensitiveCategory.PRIVATE_MESSAGE,
            SensitiveCategory.PRIVATE_FILE,
            SensitiveCategory.PRIVATE_SCREENSHOT,
            SensitiveCategory.HEALTH,
            SensitiveCategory.BIOMETRIC,
            SensitiveCategory.POLITICAL,
            SensitiveCategory.RELIGIOUS,
            SensitiveCategory.ETHNICITY,
            SensitiveCategory.SEXUAL_ORIENTATION,
            SensitiveCategory.CRIMINAL_RECORD,
            SensitiveCategory.CHILD_DATA,
            SensitiveCategory.LEGAL_PRIVILEGED,
            SensitiveCategory.CLIENT_CONFIDENTIAL,
            SensitiveCategory.BUSINESS_CONFIDENTIAL,
        }:
            return self.PRIVATE_TEXT

        return self.SECRET_TEXT

    def _make_finding(
        self,
        category: SensitiveCategory,
        risk: PrivacyRiskLevel,
        field_path: str,
        preview: str,
        confidence: float,
        detector: str,
        reason: str,
        start: Optional[int] = None,
        end: Optional[int] = None,
        requires_approval: bool = False,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> SensitiveFinding:
        return SensitiveFinding(
            finding_id=self._new_id("privacy_finding"),
            category=category,
            risk_level=risk,
            field_path=field_path,
            start=start,
            end=end,
            masked_preview=self._mask_value(preview),
            confidence=max(0.0, min(1.0, float(confidence))),
            detector=detector,
            reason=reason,
            requires_redaction=True,
            requires_approval=requires_approval,
            metadata=self._json_safe(metadata or {}),
        )

    def _finding_to_dict(
        self,
        finding: SensitiveFinding,
    ) -> Dict[str, Any]:
        return {
            "finding_id": finding.finding_id,
            "category": finding.category.value,
            "risk_level": finding.risk_level.value,
            "field_path": finding.field_path,
            "start": finding.start,
            "end": finding.end,
            "masked_preview": finding.masked_preview,
            "confidence": finding.confidence,
            "detector": finding.detector,
            "reason": finding.reason,
            "requires_redaction": finding.requires_redaction,
            "requires_approval": finding.requires_approval,
            "metadata": self._json_safe(finding.metadata),
        }

    def _deduplicate_findings(
        self,
        findings: Iterable[SensitiveFinding],
    ) -> List[SensitiveFinding]:
        unique: List[SensitiveFinding] = []
        seen: Set[Tuple[str, str, Optional[int], Optional[int], str]] = set()

        for finding in findings:
            key = (
                finding.category.value,
                finding.field_path,
                finding.start,
                finding.end,
                finding.masked_preview,
            )
            if key in seen:
                continue

            seen.add(key)
            unique.append(finding)

        return unique

    def _calculate_overall_risk(
        self,
        findings: Sequence[SensitiveFinding],
    ) -> PrivacyRiskLevel:
        if not findings:
            return PrivacyRiskLevel.NONE

        highest = PrivacyRiskLevel.NONE
        critical_count = 0
        high_count = 0

        for finding in findings:
            highest = self._max_risk(highest, finding.risk_level)

            if finding.risk_level == PrivacyRiskLevel.CRITICAL:
                critical_count += 1
            elif finding.risk_level == PrivacyRiskLevel.HIGH:
                high_count += 1

        if critical_count > 0:
            return PrivacyRiskLevel.CRITICAL

        if high_count >= 2:
            return PrivacyRiskLevel.CRITICAL if self.strict_mode else PrivacyRiskLevel.HIGH

        return highest

    def _max_risk(
        self,
        first: PrivacyRiskLevel,
        second: PrivacyRiskLevel,
    ) -> PrivacyRiskLevel:
        rank = {
            PrivacyRiskLevel.NONE: 0,
            PrivacyRiskLevel.LOW: 1,
            PrivacyRiskLevel.MEDIUM: 2,
            PrivacyRiskLevel.HIGH: 3,
            PrivacyRiskLevel.CRITICAL: 4,
        }
        return first if rank[first] >= rank[second] else second

    def _looks_like_card_number(self, value: str) -> bool:
        digits = re.sub(r"\D", "", value)
        if len(digits) < 13 or len(digits) > 19:
            return False
        return self._luhn_valid(digits)

    def _luhn_valid(self, digits: str) -> bool:
        try:
            total = 0
            parity = len(digits) % 2

            for index, character in enumerate(digits):
                number = int(character)
                if index % 2 == parity:
                    number *= 2
                    if number > 9:
                        number -= 9
                total += number

            return total % 10 == 0
        except (TypeError, ValueError):
            return False

    def _valid_ip(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _looks_like_high_entropy_secret(self, token: str) -> bool:
        if len(token) < 24:
            return False

        if token.isdigit():
            return False

        unique_characters = len(set(token))
        if unique_characters < 10:
            return False

        character_classes = sum(
            [
                any(character.islower() for character in token),
                any(character.isupper() for character in token),
                any(character.isdigit() for character in token),
                any(not character.isalnum() for character in token),
            ]
        )

        if character_classes < 2:
            return False

        entropy = self._shannon_entropy(token)
        return entropy >= 3.5

    def _shannon_entropy(self, value: str) -> float:
        if not value:
            return 0.0

        frequencies: Dict[str, int] = {}
        for character in value:
            frequencies[character] = frequencies.get(character, 0) + 1

        length = len(value)
        entropy = 0.0

        for count in frequencies.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _looks_like_sensitive_header(self, normalized_key: str) -> bool:
        if normalized_key in {
            self._normalize_field_name(item)
            for item in self.SAFE_LOG_HEADER_ALLOWLIST
        }:
            return False

        sensitive_header_names = {
            "authorization",
            "proxy_authorization",
            "cookie",
            "set_cookie",
            "x_api_key",
            "x_auth_token",
            "x_access_token",
            "x_csrf_token",
            "x_xsrf_token",
        }
        return normalized_key in sensitive_header_names

    def _mask_value(self, value: Any) -> str:
        text = self._stringify(value).replace("\n", " ").replace("\r", " ").strip()

        if not text:
            return ""

        if len(text) <= 4:
            return "*" * len(text)

        if len(text) <= 8:
            return f"{text[0]}{'*' * (len(text) - 2)}{text[-1]}"

        visible_prefix = text[:2]
        visible_suffix = text[-2:]
        hidden_length = min(max(len(text) - 4, 6), 16)

        return f"{visible_prefix}{'*' * hidden_length}{visible_suffix}"

    def _mask_identifier(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        return self._mask_value(value)

    def _fingerprint(self, value: Any) -> str:
        serialized = self._stable_serialize(value)
        digest = hmac.new(
            self._fingerprint_key,
            serialized,
            hashlib.sha256,
        ).hexdigest()
        return f"sha256:{digest}"

    def _stable_serialize(self, value: Any) -> bytes:
        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value)

        try:
            normalized = self._json_safe(value)
            return json.dumps(
                normalized,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                default=str,
            ).encode("utf-8")
        except Exception:
            return repr(value).encode("utf-8", errors="replace")

    def _json_safe(self, value: Any, depth: int = 0) -> Any:
        """Convert arbitrary values into JSON-compatible safe structures."""
        if depth > self.MAX_RECURSION_DEPTH:
            return "[MAX DEPTH]"

        if value is None or isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, enum.Enum):
            return value.value

        if dataclasses.is_dataclass(value):
            return self._json_safe(dataclasses.asdict(value), depth + 1)

        if isinstance(value, Mapping):
            result: Dict[str, Any] = {}
            for index, (key, item) in enumerate(value.items()):
                if index >= self.MAX_CONTAINER_ITEMS:
                    result["__truncated__"] = True
                    break
                result[str(key)] = self._json_safe(item, depth + 1)
            return result

        if isinstance(value, (list, tuple, set)):
            sequence = list(value)
            result = [
                self._json_safe(item, depth + 1)
                for item in sequence[: self.MAX_CONTAINER_ITEMS]
            ]
            if len(sequence) > self.MAX_CONTAINER_ITEMS:
                result.append("[TRUNCATED]")
            return result

        if isinstance(value, (bytes, bytearray, memoryview)):
            binary = bytes(value)
            return {
                "protected_binary": True,
                "size_bytes": len(binary),
                "fingerprint": self._fingerprint(binary),
            }

        if isinstance(value, Path):
            return str(value)

        if isinstance(value, BaseException):
            return {
                "type": value.__class__.__name__,
                "message": self._sanitize_text(str(value), "exception.message")[0],
            }

        return str(value)

    def _stringify(self, value: Any) -> str:
        if value is None:
            return ""

        if isinstance(value, str):
            return value

        if isinstance(value, (bytes, bytearray, memoryview)):
            return f"<binary:{len(bytes(value))} bytes>"

        try:
            return json.dumps(
                self._json_safe(value),
                ensure_ascii=False,
                default=str,
            )
        except Exception:
            return str(value)

    def _safe_int(self, value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _approval_expired(self, record: PrivacyApprovalRecord) -> bool:
        return time.time() > record.expires_at_epoch

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _new_id(self, prefix: str) -> str:
        return f"{prefix}_{uuid.uuid4().hex}"


# =============================================================================
# Import-safe module exports
# =============================================================================

__all__ = [
    "SecurityPrivacyGuard",
    "PrivacyRiskLevel",
    "PrivacyDecisionType",
    "PrivacyContentType",
    "PrivacyOperation",
    "SensitiveCategory",
    "ApprovalStatus",
    "SensitiveFinding",
    "PrivacyInspection",
    "PrivacyApprovalRecord",
    "FileInspectionPolicy",
]


# =============================================================================
# Standalone smoke test
# =============================================================================

def _self_test() -> Dict[str, Any]:
    """
    Run a non-destructive smoke test.

    No file is opened, no message is sent, and no external action is executed.
    """
    guard = SecurityPrivacyGuard()

    context = {
        "user_id": "test_user_001",
        "workspace_id": "test_workspace_001",
        "request_id": "test_request_001",
    }

    message_test = guard.inspect_message(
        message={
            "text": "Please keep this private.",
            "email": "client@example.com",
            "password": "<redacted_demo_password>",
            "api_key": "<redacted_demo_api_key>",
        },
        context=context,
        operation=PrivacyOperation.DISPLAY,
    )

    log_test = guard.sanitize_log(
        log_data={
            "method": "POST",
            "url": "https://example.test/login",
            "headers": {
                "Content-Type": "application/json",
                "Authorization": "Bearer <redacted_demo_token>",
            },
            "body": {
                "username": "client@example.com",
                "password": "<redacted_demo_password>",
            },
        },
        context=context,
    )

    screenshot_test = guard.inspect_screenshot(
        screenshot={
            "filename": "private-dashboard.png",
            "mime_type": "image/png",
            "owner_user_id": "test_user_001",
            "owner_workspace_id": "test_workspace_001",
            "width": 1080,
            "height": 1920,
        },
        extracted_text=(
            "Dashboard API key: "
            "<redacted_demo_secret_key>"
        ),
        context=context,
    )

    return {
        "message_test": message_test,
        "log_test": log_test,
        "screenshot_test": screenshot_test,
    }


if __name__ == "__main__":
    print(json.dumps(_self_test(), indent=2, ensure_ascii=False, default=str))