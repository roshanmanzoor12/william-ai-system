"""
agents/workflow_agent/email_connector.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Workflow Agent - Email Connector

Purpose:
    Sends approved emails, auto-replies, follow-ups, and workflow reports.

Architecture Compatibility:
    - Safe to import even if BaseAgent or other William modules are not created yet.
    - Compatible with Master Agent routing, Agent Registry, Agent Loader, Agent Router.
    - Enforces SaaS user/workspace isolation.
    - Supports Security Agent approval before sensitive outbound email actions.
    - Prepares Verification Agent payloads after completed actions.
    - Prepares Memory Agent payloads for useful workflow context.
    - Emits audit/dashboard-friendly structured events.
    - Returns structured dict results with:
        success, message, data, error, metadata

Important Safety Design:
    - This connector does NOT hardcode secrets.
    - Real email sending is blocked by default unless:
        1. task context is valid,
        2. security approval is granted or not required,
        3. dry_run is False,
        4. SMTP configuration is supplied securely.
    - Default mode is dry-run safe for development and dashboard testing.
"""

from __future__ import annotations

import copy
import dataclasses
import email.utils
import hashlib
import hmac
import json
import logging
import re
import smtplib
import ssl
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for incomplete future project

    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe while the William/Jarvis architecture
        is still being generated file-by-file.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
            raise NotImplementedError("Fallback BaseAgent does not implement run().")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("William.WorkflowAgent.EmailConnector")
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EMAIL_REGEX = re.compile(
    r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+"
    r"(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*"
    r'|^"([^"\r\\]|\\["\r\\])*")@'
    r"([A-Z0-9-]+\.)+[A-Z]{2,63}$",
    re.IGNORECASE,
)

DEFAULT_AGENT_NAME = "workflow_email_connector"
DEFAULT_AGENT_VERSION = "1.0.0"

MAX_SUBJECT_LENGTH = 180
MAX_EMAIL_BODY_LENGTH = 150_000
MAX_RECIPIENTS_PER_EMAIL = 50
MAX_ATTACHMENTS = 10
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024

SENSITIVE_PLACEHOLDER = "[REDACTED]"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EmailAction(str, Enum):
    """Supported email connector actions."""

    SEND_EMAIL = "send_email"
    AUTO_REPLY = "auto_reply"
    FOLLOW_UP = "follow_up"
    REPORT = "report"
    PREVIEW = "preview"
    VALIDATE = "validate"


class EmailPriority(str, Enum):
    """Supported email priority levels."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"


class EmailFormat(str, Enum):
    """Supported email content formats."""

    TEXT = "text"
    HTML = "html"


class DeliveryStatus(str, Enum):
    """Internal delivery status values."""

    DRAFTED = "drafted"
    APPROVAL_REQUIRED = "approval_required"
    DRY_RUN = "dry_run"
    SENT = "sent"
    FAILED = "failed"
    VALIDATED = "validated"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class EmailAttachment:
    """
    Represents a safe email attachment.

    Notes:
        - This connector accepts attachment bytes only if provided by a trusted
          upstream workflow.
        - File reading from arbitrary paths is intentionally not performed here
          to avoid unsafe file access and workspace leakage.
    """

    filename: str
    content: bytes
    mime_type: str = "application/octet-stream"

    def validate(self) -> Tuple[bool, Optional[str]]:
        if not self.filename or not isinstance(self.filename, str):
            return False, "Attachment filename is required."
        if "/" in self.filename or "\\" in self.filename:
            return False, "Attachment filename must not contain path separators."
        if not isinstance(self.content, (bytes, bytearray)):
            return False, "Attachment content must be bytes."
        if len(self.content) > MAX_ATTACHMENT_BYTES:
            return False, f"Attachment exceeds maximum size of {MAX_ATTACHMENT_BYTES} bytes."
        if not self.mime_type or "/" not in self.mime_type:
            return False, "Attachment mime_type must be valid."
        return True, None


@dataclass
class EmailMessagePayload:
    """
    Normalized outbound email message.

    This data object is used internally after task validation and before the
    provider-specific send operation.
    """

    to: List[str]
    subject: str
    body: str
    from_email: Optional[str] = None
    from_name: Optional[str] = None
    cc: List[str] = field(default_factory=list)
    bcc: List[str] = field(default_factory=list)
    reply_to: Optional[str] = None
    format: EmailFormat = EmailFormat.TEXT
    priority: EmailPriority = EmailPriority.NORMAL
    headers: Dict[str, str] = field(default_factory=dict)
    attachments: List[EmailAttachment] = field(default_factory=list)
    template_id: Optional[str] = None
    template_variables: Dict[str, Any] = field(default_factory=dict)
    idempotency_key: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SMTPConfig:
    """
    SMTP configuration.

    Secrets should be injected from environment/config services at runtime.
    Do not hardcode username/password in source code.
    """

    host: str
    port: int = 587
    username: Optional[str] = None
    password: Optional[str] = None
    use_tls: bool = True
    use_ssl: bool = False
    timeout_seconds: int = 30
    default_from_email: Optional[str] = None
    default_from_name: Optional[str] = None

    @classmethod
    def from_mapping(cls, config: Optional[Mapping[str, Any]]) -> Optional["SMTPConfig"]:
        if not config:
            return None

        host = str(config.get("host") or "").strip()
        if not host:
            return None

        return cls(
            host=host,
            port=int(config.get("port", 587)),
            username=config.get("username"),
            password=config.get("password"),
            use_tls=bool(config.get("use_tls", True)),
            use_ssl=bool(config.get("use_ssl", False)),
            timeout_seconds=int(config.get("timeout_seconds", 30)),
            default_from_email=config.get("default_from_email"),
            default_from_name=config.get("default_from_name"),
        )


@dataclass
class EmailConnectorConfig:
    """
    Runtime config for EmailConnector.

    dry_run:
        If True, emails are not sent. Structured preview/simulation results
        are returned instead.

    require_approval:
        If True, outbound email actions require Security Agent approval.

    allowed_domains:
        Optional allowlist for recipient domains. Empty list means no allowlist.

    blocked_domains:
        Optional blocklist for recipient domains.

    block_role_accounts:
        If True, blocks high-risk role accounts like abuse@, postmaster@.

    allow_attachments:
        If False, attachment sending is blocked.

    provider:
        Currently supports "smtp" and "dry_run".
    """

    provider: str = "smtp"
    dry_run: bool = True
    require_approval: bool = True
    allowed_domains: List[str] = field(default_factory=list)
    blocked_domains: List[str] = field(default_factory=list)
    block_role_accounts: bool = False
    allow_attachments: bool = True
    default_format: EmailFormat = EmailFormat.TEXT
    smtp: Optional[SMTPConfig] = None
    audit_enabled: bool = True
    event_emit_enabled: bool = True
    memory_enabled: bool = True
    verification_enabled: bool = True

    @classmethod
    def from_mapping(cls, config: Optional[Mapping[str, Any]]) -> "EmailConnectorConfig":
        if not config:
            return cls()

        smtp_config = SMTPConfig.from_mapping(config.get("smtp") or config.get("smtp_config"))

        default_format = config.get("default_format", EmailFormat.TEXT.value)
        if isinstance(default_format, EmailFormat):
            parsed_format = default_format
        else:
            parsed_format = EmailFormat(str(default_format).lower())

        return cls(
            provider=str(config.get("provider", "smtp")).lower(),
            dry_run=bool(config.get("dry_run", True)),
            require_approval=bool(config.get("require_approval", True)),
            allowed_domains=list(config.get("allowed_domains", []) or []),
            blocked_domains=list(config.get("blocked_domains", []) or []),
            block_role_accounts=bool(config.get("block_role_accounts", False)),
            allow_attachments=bool(config.get("allow_attachments", True)),
            default_format=parsed_format,
            smtp=smtp_config,
            audit_enabled=bool(config.get("audit_enabled", True)),
            event_emit_enabled=bool(config.get("event_emit_enabled", True)),
            memory_enabled=bool(config.get("memory_enabled", True)),
            verification_enabled=bool(config.get("verification_enabled", True)),
        )


# ---------------------------------------------------------------------------
# Email Connector
# ---------------------------------------------------------------------------

class EmailConnector(BaseAgent):
    """
    Workflow Agent Email Connector.

    Main Responsibilities:
        - Send approved outbound emails.
        - Send auto-replies.
        - Send follow-up emails.
        - Send workflow reports.
        - Validate and preview email payloads.
        - Enforce user_id/workspace_id isolation.
        - Request Security Agent approval for sensitive email actions.
        - Prepare Verification Agent and Memory Agent payloads.
        - Emit dashboard/API/audit-friendly events.

    Master Agent / Router Usage:
        The Master Agent or Workflow Action Router can call:
            connector.execute(task)

        Example task:
            {
                "action": "send_email",
                "user_id": "user_123",
                "workspace_id": "workspace_456",
                "payload": {
                    "to": ["client@example.com"],
                    "subject": "Your Report",
                    "body": "Hello, your report is ready.",
                    "format": "text"
                },
                "permissions": {
                    "approved": true,
                    "approved_by": "security_agent"
                },
                "config": {
                    "dry_run": true
                }
            }
    """

    ROLE_ACCOUNT_PREFIXES = {
        "abuse",
        "admin",
        "administrator",
        "billing",
        "compliance",
        "devnull",
        "dns",
        "help",
        "hostmaster",
        "info",
        "legal",
        "mail",
        "marketing",
        "newsletter",
        "no-reply",
        "noreply",
        "postmaster",
        "privacy",
        "root",
        "sales",
        "security",
        "support",
        "webmaster",
    }

    def __init__(
        self,
        config: Optional[Mapping[str, Any]] = None,
        *,
        security_approval_callback: Optional[Callable[[Mapping[str, Any]], Union[bool, Mapping[str, Any]]]] = None,
        audit_callback: Optional[Callable[[Mapping[str, Any]], None]] = None,
        event_callback: Optional[Callable[[Mapping[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=DEFAULT_AGENT_NAME, **kwargs)

        self.config = EmailConnectorConfig.from_mapping(config)
        self.security_approval_callback = security_approval_callback
        self.audit_callback = audit_callback
        self.event_callback = event_callback
        self.logger = logger or LOGGER

        self.agent_name = DEFAULT_AGENT_NAME
        self.agent_version = DEFAULT_AGENT_VERSION
        self.agent_type = "workflow_connector"
        self.capabilities = [
            "send_email",
            "auto_reply",
            "follow_up",
            "report",
            "preview_email",
            "validate_email",
            "security_approval",
            "audit_logging",
            "verification_payload",
            "memory_payload",
        ]

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible async entrypoint.

        This allows Agent Loader / Agent Router / Master Agent to call this
        file using a standard BaseAgent style interface.
        """
        return self.execute(task)

    def execute(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Main router for workflow email actions.

        Args:
            task: Structured task dict from Master Agent or Workflow Agent.

        Returns:
            Structured result dict.
        """
        started_at = self._utc_now_iso()
        correlation_id = self._get_correlation_id(task)

        try:
            context_result = self._validate_task_context(task)
            if not context_result["success"]:
                return context_result

            action = self._parse_action(task.get("action"))
            payload = task.get("payload") or {}

            self._emit_agent_event(
                event_type="email_connector.action_started",
                task=task,
                data={
                    "action": action.value,
                    "correlation_id": correlation_id,
                    "started_at": started_at,
                },
            )

            if action == EmailAction.SEND_EMAIL:
                result = self.send_email(task, payload)
            elif action == EmailAction.AUTO_REPLY:
                result = self.send_auto_reply(task, payload)
            elif action == EmailAction.FOLLOW_UP:
                result = self.send_follow_up(task, payload)
            elif action == EmailAction.REPORT:
                result = self.send_report(task, payload)
            elif action == EmailAction.PREVIEW:
                result = self.preview_email(task, payload)
            elif action == EmailAction.VALIDATE:
                result = self.validate_email_payload(task, payload)
            else:
                result = self._error_result(
                    message=f"Unsupported email action: {action}",
                    error_code="unsupported_action",
                    metadata={"correlation_id": correlation_id},
                )

            self._emit_agent_event(
                event_type="email_connector.action_finished",
                task=task,
                data={
                    "action": action.value,
                    "correlation_id": correlation_id,
                    "success": result.get("success", False),
                    "finished_at": self._utc_now_iso(),
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("EmailConnector execute failed.")
            error_result = self._error_result(
                message="Email connector execution failed.",
                error_code="email_connector_execute_failed",
                exception=exc,
                metadata={
                    "correlation_id": correlation_id,
                    "started_at": started_at,
                    "finished_at": self._utc_now_iso(),
                },
            )
            self._log_audit_event(
                event_type="email_connector.error",
                task=task,
                data=error_result,
            )
            return error_result

    def send_email(self, task: Mapping[str, Any], payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Send a standard approved outbound email.

        This method validates message fields, checks security approval, sends
        through configured provider or dry-run simulation, then prepares
        verification/memory payloads.
        """
        return self._process_email_action(
            task=task,
            payload=payload,
            action=EmailAction.SEND_EMAIL,
            default_tags=["workflow", "outbound_email"],
        )

    def send_auto_reply(self, task: Mapping[str, Any], payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Send an approved auto-reply.

        Typical use cases:
            - Form submission acknowledgement.
            - Ticket received acknowledgement.
            - CRM lead auto-response.
        """
        enriched_payload = dict(payload)
        enriched_payload.setdefault("headers", {})
        enriched_payload["headers"] = {
            **dict(enriched_payload.get("headers") or {}),
            "X-William-Email-Type": "auto-reply",
            "Auto-Submitted": "auto-replied",
        }

        enriched_payload.setdefault("tags", [])
        enriched_payload["tags"] = list(enriched_payload["tags"]) + ["auto_reply"]

        return self._process_email_action(
            task=task,
            payload=enriched_payload,
            action=EmailAction.AUTO_REPLY,
            default_tags=["workflow", "auto_reply"],
        )

    def send_follow_up(self, task: Mapping[str, Any], payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Send an approved follow-up email.

        This connector sends only the provided follow-up now. Scheduling should
        be handled by workflow_agent/scheduler.py when that file is generated.
        """
        enriched_payload = dict(payload)
        enriched_payload.setdefault("headers", {})
        enriched_payload["headers"] = {
            **dict(enriched_payload.get("headers") or {}),
            "X-William-Email-Type": "follow-up",
        }

        enriched_payload.setdefault("tags", [])
        enriched_payload["tags"] = list(enriched_payload["tags"]) + ["follow_up"]

        return self._process_email_action(
            task=task,
            payload=enriched_payload,
            action=EmailAction.FOLLOW_UP,
            default_tags=["workflow", "follow_up"],
        )

    def send_report(self, task: Mapping[str, Any], payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Send an approved workflow report email.

        Supports report-style payloads:
            {
                "to": [...],
                "subject": "Daily Workflow Report",
                "report": {
                    "title": "...",
                    "summary": "...",
                    "metrics": {...},
                    "sections": [...]
                }
            }

        If body is not supplied, a readable report body is generated.
        """
        enriched_payload = dict(payload)

        if not enriched_payload.get("body") and enriched_payload.get("report"):
            report = enriched_payload.get("report") or {}
            fmt = str(enriched_payload.get("format", self.config.default_format.value)).lower()
            enriched_payload["body"] = self._render_report_body(report, fmt)

        enriched_payload.setdefault("headers", {})
        enriched_payload["headers"] = {
            **dict(enriched_payload.get("headers") or {}),
            "X-William-Email-Type": "workflow-report",
        }

        enriched_payload.setdefault("tags", [])
        enriched_payload["tags"] = list(enriched_payload["tags"]) + ["workflow_report"]

        return self._process_email_action(
            task=task,
            payload=enriched_payload,
            action=EmailAction.REPORT,
            default_tags=["workflow", "report"],
        )

    def preview_email(self, task: Mapping[str, Any], payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate and return a safe preview of an email without sending it.
        """
        context_result = self._validate_task_context(task)
        if not context_result["success"]:
            return context_result

        normalized_result = self._normalize_email_payload(payload)
        if not normalized_result["success"]:
            return normalized_result

        message_payload: EmailMessagePayload = normalized_result["data"]["email"]

        preview = self._message_preview(message_payload)
        result = self._safe_result(
            message="Email preview generated successfully.",
            data={
                "status": DeliveryStatus.DRAFTED.value,
                "preview": preview,
                "verification_payload": self._prepare_verification_payload(
                    task=task,
                    action=EmailAction.PREVIEW,
                    status=DeliveryStatus.DRAFTED,
                    provider_response={"preview": True},
                    email_payload=message_payload,
                ),
                "memory_payload": self._prepare_memory_payload(
                    task=task,
                    action=EmailAction.PREVIEW,
                    status=DeliveryStatus.DRAFTED,
                    email_payload=message_payload,
                ),
            },
            metadata={
                "agent": self.agent_name,
                "version": self.agent_version,
                "correlation_id": self._get_correlation_id(task),
                "dry_run": True,
            },
        )

        self._log_audit_event(
            event_type="email_connector.preview",
            task=task,
            data={"preview": preview},
        )
        return result

    def validate_email_payload(self, task: Mapping[str, Any], payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate an email payload without sending.
        """
        context_result = self._validate_task_context(task)
        if not context_result["success"]:
            return context_result

        normalized_result = self._normalize_email_payload(payload)
        if not normalized_result["success"]:
            return normalized_result

        message_payload: EmailMessagePayload = normalized_result["data"]["email"]

        return self._safe_result(
            message="Email payload is valid.",
            data={
                "status": DeliveryStatus.VALIDATED.value,
                "recipient_count": self._recipient_count(message_payload),
                "subject": message_payload.subject,
                "format": message_payload.format.value,
                "has_attachments": bool(message_payload.attachments),
                "attachment_count": len(message_payload.attachments),
                "idempotency_key": message_payload.idempotency_key,
            },
            metadata={
                "agent": self.agent_name,
                "version": self.agent_version,
                "correlation_id": self._get_correlation_id(task),
            },
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Dashboard/API health check for this connector.
        """
        smtp_ready = bool(self.config.smtp and self.config.smtp.host)

        return self._safe_result(
            message="EmailConnector is import-safe and ready.",
            data={
                "agent": self.agent_name,
                "version": self.agent_version,
                "provider": self.config.provider,
                "dry_run": self.config.dry_run,
                "smtp_configured": smtp_ready,
                "capabilities": self.capabilities,
            },
            metadata={
                "checked_at": self._utc_now_iso(),
            },
        )

    def registry_manifest(self) -> Dict[str, Any]:
        """
        Agent Registry / Agent Loader manifest.

        This lets future registry code discover the connector's capabilities
        without executing email actions.
        """
        return {
            "agent_name": self.agent_name,
            "class_name": self.__class__.__name__,
            "module": "agents.workflow_agent.email_connector",
            "version": self.agent_version,
            "type": self.agent_type,
            "capabilities": self.capabilities,
            "actions": [action.value for action in EmailAction],
            "requires_user_context": True,
            "requires_workspace_context": True,
            "requires_security_for": [
                EmailAction.SEND_EMAIL.value,
                EmailAction.AUTO_REPLY.value,
                EmailAction.FOLLOW_UP.value,
                EmailAction.REPORT.value,
            ],
            "safe_import": True,
        }

    # -----------------------------------------------------------------------
    # Main processing
    # -----------------------------------------------------------------------

    def _process_email_action(
        self,
        *,
        task: Mapping[str, Any],
        payload: Mapping[str, Any],
        action: EmailAction,
        default_tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        context_result = self._validate_task_context(task)
        if not context_result["success"]:
            return context_result

        normalized_result = self._normalize_email_payload(payload)
        if not normalized_result["success"]:
            self._log_audit_event(
                event_type="email_connector.validation_failed",
                task=task,
                data=normalized_result,
            )
            return normalized_result

        email_payload: EmailMessagePayload = normalized_result["data"]["email"]

        if default_tags:
            merged_tags = list(dict.fromkeys(default_tags + email_payload.tags))
            email_payload.tags = merged_tags

        security_result = self._request_security_approval(
            task=task,
            action=action,
            email_payload=email_payload,
        )
        if not security_result["success"]:
            return security_result

        if self.config.dry_run or self.config.provider == "dry_run":
            provider_response = self._simulate_send(email_payload)
            status = DeliveryStatus.DRY_RUN
        else:
            provider_response = self._send_via_provider(email_payload)
            status = DeliveryStatus.SENT if provider_response.get("success") else DeliveryStatus.FAILED

        verification_payload = self._prepare_verification_payload(
            task=task,
            action=action,
            status=status,
            provider_response=provider_response,
            email_payload=email_payload,
        )

        memory_payload = self._prepare_memory_payload(
            task=task,
            action=action,
            status=status,
            email_payload=email_payload,
        )

        audit_data = {
            "action": action.value,
            "status": status.value,
            "provider_response": self._sanitize_dict(provider_response),
            "recipient_hashes": [self._hash_value(addr) for addr in self._all_recipients(email_payload)],
            "subject_hash": self._hash_value(email_payload.subject),
            "verification_payload": verification_payload,
            "memory_payload": memory_payload,
        }
        self._log_audit_event(
            event_type="email_connector.email_processed",
            task=task,
            data=audit_data,
        )

        if not provider_response.get("success"):
            return self._error_result(
                message=provider_response.get("message", "Email delivery failed."),
                error_code=provider_response.get("error_code", "email_delivery_failed"),
                metadata={
                    "agent": self.agent_name,
                    "version": self.agent_version,
                    "status": status.value,
                    "correlation_id": self._get_correlation_id(task),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
            )

        return self._safe_result(
            message=self._status_message(action, status),
            data={
                "status": status.value,
                "action": action.value,
                "message_id": provider_response.get("message_id"),
                "provider": provider_response.get("provider", self.config.provider),
                "dry_run": status == DeliveryStatus.DRY_RUN,
                "recipient_count": self._recipient_count(email_payload),
                "preview": self._message_preview(email_payload),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent": self.agent_name,
                "version": self.agent_version,
                "correlation_id": self._get_correlation_id(task),
                "workspace_id": task.get("workspace_id"),
                "user_id": task.get("user_id"),
                "processed_at": self._utc_now_iso(),
            },
        )

    def _send_via_provider(self, email_payload: EmailMessagePayload) -> Dict[str, Any]:
        provider = self.config.provider.lower().strip()

        if provider == "smtp":
            return self._send_via_smtp(email_payload)

        return {
            "success": False,
            "message": f"Unsupported email provider: {provider}",
            "error_code": "unsupported_email_provider",
            "provider": provider,
        }

    def _send_via_smtp(self, email_payload: EmailMessagePayload) -> Dict[str, Any]:
        smtp_config = self.config.smtp
        if not smtp_config:
            return {
                "success": False,
                "message": "SMTP configuration is missing.",
                "error_code": "smtp_config_missing",
                "provider": "smtp",
            }

        if not smtp_config.host:
            return {
                "success": False,
                "message": "SMTP host is missing.",
                "error_code": "smtp_host_missing",
                "provider": "smtp",
            }

        from_email = email_payload.from_email or smtp_config.default_from_email
        if not from_email:
            return {
                "success": False,
                "message": "Sender email is missing.",
                "error_code": "sender_missing",
                "provider": "smtp",
            }

        try:
            message = self._build_email_message(email_payload, smtp_config)

            recipients = self._all_recipients(email_payload)
            if smtp_config.use_ssl:
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(
                    smtp_config.host,
                    smtp_config.port,
                    timeout=smtp_config.timeout_seconds,
                    context=context,
                ) as smtp:
                    self._smtp_login_if_needed(smtp, smtp_config)
                    smtp.send_message(message, from_addr=from_email, to_addrs=recipients)
            else:
                with smtplib.SMTP(
                    smtp_config.host,
                    smtp_config.port,
                    timeout=smtp_config.timeout_seconds,
                ) as smtp:
                    smtp.ehlo()
                    if smtp_config.use_tls:
                        context = ssl.create_default_context()
                        smtp.starttls(context=context)
                        smtp.ehlo()
                    self._smtp_login_if_needed(smtp, smtp_config)
                    smtp.send_message(message, from_addr=from_email, to_addrs=recipients)

            return {
                "success": True,
                "message": "Email sent successfully via SMTP.",
                "provider": "smtp",
                "message_id": message["Message-ID"],
                "sent_at": self._utc_now_iso(),
            }

        except smtplib.SMTPAuthenticationError as exc:
            return {
                "success": False,
                "message": "SMTP authentication failed.",
                "error_code": "smtp_auth_failed",
                "provider": "smtp",
                "details": str(exc),
            }
        except smtplib.SMTPRecipientsRefused as exc:
            return {
                "success": False,
                "message": "SMTP recipients refused.",
                "error_code": "smtp_recipients_refused",
                "provider": "smtp",
                "details": self._safe_str(exc),
            }
        except smtplib.SMTPException as exc:
            return {
                "success": False,
                "message": "SMTP delivery failed.",
                "error_code": "smtp_delivery_failed",
                "provider": "smtp",
                "details": self._safe_str(exc),
            }
        except Exception as exc:
            self.logger.exception("Unexpected SMTP send failure.")
            return {
                "success": False,
                "message": "Unexpected email provider failure.",
                "error_code": "smtp_unexpected_failure",
                "provider": "smtp",
                "details": self._safe_str(exc),
            }

    def _simulate_send(self, email_payload: EmailMessagePayload) -> Dict[str, Any]:
        message_id = email_payload.idempotency_key or f"dryrun-{uuid.uuid4().hex}"
        return {
            "success": True,
            "message": "Dry-run enabled. Email was validated and simulated, not sent.",
            "provider": "dry_run",
            "message_id": message_id,
            "sent_at": self._utc_now_iso(),
        }

    # -----------------------------------------------------------------------
    # Payload normalization and validation
    # -----------------------------------------------------------------------

    def _normalize_email_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        if not isinstance(payload, Mapping):
            return self._error_result(
                message="Email payload must be a mapping/dict.",
                error_code="invalid_payload_type",
            )

        subject = str(payload.get("subject") or "").strip()
        body = str(payload.get("body") or "").strip()

        if not subject:
            return self._error_result("Email subject is required.", "subject_required")
        if len(subject) > MAX_SUBJECT_LENGTH:
            return self._error_result(
                f"Email subject exceeds {MAX_SUBJECT_LENGTH} characters.",
                "subject_too_long",
            )

        if not body:
            return self._error_result("Email body is required.", "body_required")
        if len(body) > MAX_EMAIL_BODY_LENGTH:
            return self._error_result(
                f"Email body exceeds {MAX_EMAIL_BODY_LENGTH} characters.",
                "body_too_long",
            )

        fmt = self._parse_email_format(payload.get("format") or self.config.default_format.value)
        priority = self._parse_priority(payload.get("priority") or EmailPriority.NORMAL.value)

        to_list = self._normalize_email_list(payload.get("to"))
        cc_list = self._normalize_email_list(payload.get("cc"))
        bcc_list = self._normalize_email_list(payload.get("bcc"))

        if not to_list:
            return self._error_result("At least one recipient is required.", "recipient_required")

        all_recipient_count = len(to_list) + len(cc_list) + len(bcc_list)
        if all_recipient_count > MAX_RECIPIENTS_PER_EMAIL:
            return self._error_result(
                f"Too many recipients. Maximum allowed is {MAX_RECIPIENTS_PER_EMAIL}.",
                "too_many_recipients",
            )

        email_validation_error = self._validate_recipient_policy(to_list + cc_list + bcc_list)
        if email_validation_error:
            return self._error_result(email_validation_error, "recipient_policy_failed")

        from_email = self._optional_str(payload.get("from_email"))
        if from_email and not self._is_valid_email(from_email):
            return self._error_result("from_email is not valid.", "invalid_from_email")

        reply_to = self._optional_str(payload.get("reply_to"))
        if reply_to and not self._is_valid_email(reply_to):
            return self._error_result("reply_to is not valid.", "invalid_reply_to")

        headers = self._normalize_headers(payload.get("headers") or {})
        tags = self._normalize_string_list(payload.get("tags") or [])
        metadata = self._normalize_metadata(payload.get("metadata") or {})

        attachments_result = self._normalize_attachments(payload.get("attachments") or [])
        if not attachments_result["success"]:
            return attachments_result

        template_variables = payload.get("template_variables") or {}
        if not isinstance(template_variables, Mapping):
            return self._error_result(
                "template_variables must be a mapping/dict.",
                "invalid_template_variables",
            )

        idempotency_key = self._optional_str(payload.get("idempotency_key"))
        if not idempotency_key:
            idempotency_key = self._generate_idempotency_key(
                to=to_list,
                subject=subject,
                body=body,
            )

        email_payload = EmailMessagePayload(
            to=to_list,
            cc=cc_list,
            bcc=bcc_list,
            subject=subject,
            body=body,
            from_email=from_email,
            from_name=self._optional_str(payload.get("from_name")),
            reply_to=reply_to,
            format=fmt,
            priority=priority,
            headers=headers,
            attachments=attachments_result["data"]["attachments"],
            template_id=self._optional_str(payload.get("template_id")),
            template_variables=dict(template_variables),
            idempotency_key=idempotency_key,
            tags=tags,
            metadata=metadata,
        )

        return self._safe_result(
            message="Email payload normalized successfully.",
            data={"email": email_payload},
        )

    def _normalize_email_list(self, value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            raw_items = [item.strip() for item in value.split(",")]
        elif isinstance(value, Iterable):
            raw_items = [str(item).strip() for item in value]
        else:
            raw_items = []

        normalized: List[str] = []
        seen = set()
        for item in raw_items:
            if not item:
                continue

            _, parsed_email = email.utils.parseaddr(item)
            parsed_email = parsed_email.strip().lower()

            if parsed_email and self._is_valid_email(parsed_email) and parsed_email not in seen:
                normalized.append(parsed_email)
                seen.add(parsed_email)

        return normalized

    def _normalize_headers(self, headers: Mapping[str, Any]) -> Dict[str, str]:
        safe_headers: Dict[str, str] = {}
        blocked = {"bcc", "cc", "to", "from", "subject", "content-type", "content-transfer-encoding"}

        if not isinstance(headers, Mapping):
            return safe_headers

        for key, value in headers.items():
            clean_key = str(key).strip()
            clean_value = str(value).strip()

            if not clean_key or not clean_value:
                continue
            if "\n" in clean_key or "\r" in clean_key:
                continue
            if "\n" in clean_value or "\r" in clean_value:
                continue
            if clean_key.lower() in blocked:
                continue

            safe_headers[clean_key] = clean_value[:500]

        return safe_headers

    def _normalize_string_list(self, value: Any) -> List[str]:
        if not value:
            return []
        if isinstance(value, str):
            items = [value]
        elif isinstance(value, Iterable):
            items = list(value)
        else:
            return []

        normalized: List[str] = []
        seen = set()
        for item in items:
            clean = str(item).strip()
            if not clean:
                continue
            clean = re.sub(r"[^a-zA-Z0-9_\-:.]", "_", clean)[:80]
            if clean not in seen:
                normalized.append(clean)
                seen.add(clean)
        return normalized

    def _normalize_metadata(self, metadata: Mapping[str, Any]) -> Dict[str, Any]:
        if not isinstance(metadata, Mapping):
            return {}

        safe: Dict[str, Any] = {}
        for key, value in metadata.items():
            clean_key = str(key).strip()[:80]
            if not clean_key:
                continue

            if isinstance(value, (str, int, float, bool)) or value is None:
                safe[clean_key] = value
            else:
                safe[clean_key] = self._safe_json(value)[:2_000]

        return safe

    def _normalize_attachments(self, attachments: Any) -> Dict[str, Any]:
        if not attachments:
            return self._safe_result(
                message="No attachments.",
                data={"attachments": []},
            )

        if not self.config.allow_attachments:
            return self._error_result(
                "Attachments are disabled for this connector configuration.",
                "attachments_disabled",
            )

        if not isinstance(attachments, Sequence) or isinstance(attachments, (str, bytes, bytearray)):
            return self._error_result(
                "attachments must be a list of attachment objects.",
                "invalid_attachments",
            )

        if len(attachments) > MAX_ATTACHMENTS:
            return self._error_result(
                f"Too many attachments. Maximum allowed is {MAX_ATTACHMENTS}.",
                "too_many_attachments",
            )

        normalized: List[EmailAttachment] = []

        for item in attachments:
            if isinstance(item, EmailAttachment):
                attachment = item
            elif isinstance(item, Mapping):
                filename = str(item.get("filename") or "").strip()
                content = item.get("content", b"")
                mime_type = str(item.get("mime_type") or "application/octet-stream").strip()

                if isinstance(content, str):
                    content = content.encode("utf-8")

                attachment = EmailAttachment(
                    filename=filename,
                    content=bytes(content),
                    mime_type=mime_type,
                )
            else:
                return self._error_result(
                    "Each attachment must be EmailAttachment or mapping.",
                    "invalid_attachment_item",
                )

            valid, error = attachment.validate()
            if not valid:
                return self._error_result(error or "Invalid attachment.", "invalid_attachment")

            normalized.append(attachment)

        return self._safe_result(
            message="Attachments normalized successfully.",
            data={"attachments": normalized},
        )

    def _validate_recipient_policy(self, recipients: Sequence[str]) -> Optional[str]:
        for email_address in recipients:
            if not self._is_valid_email(email_address):
                return f"Invalid recipient email: {email_address}"

            local_part, domain = email_address.rsplit("@", 1)
            domain = domain.lower().strip()
            local_part = local_part.lower().strip()

            if self.config.allowed_domains:
                allowed = {d.lower().strip() for d in self.config.allowed_domains}
                if domain not in allowed:
                    return f"Recipient domain is not allowed: {domain}"

            if self.config.blocked_domains:
                blocked = {d.lower().strip() for d in self.config.blocked_domains}
                if domain in blocked:
                    return f"Recipient domain is blocked: {domain}"

            if self.config.block_role_accounts:
                role_prefix = local_part.split("+", 1)[0]
                if role_prefix in self.ROLE_ACCOUNT_PREFIXES:
                    return f"Role account recipient is blocked by policy: {email_address}"

        return None

    # -----------------------------------------------------------------------
    # Message building
    # -----------------------------------------------------------------------

    def _build_email_message(
        self,
        email_payload: EmailMessagePayload,
        smtp_config: SMTPConfig,
    ) -> EmailMessage:
        message = EmailMessage()

        from_email = email_payload.from_email or smtp_config.default_from_email
        from_name = email_payload.from_name or smtp_config.default_from_name

        if from_name:
            message["From"] = email.utils.formataddr((from_name, from_email or ""))
        else:
            message["From"] = from_email or ""

        message["To"] = ", ".join(email_payload.to)
        if email_payload.cc:
            message["Cc"] = ", ".join(email_payload.cc)

        message["Subject"] = email_payload.subject
        message["Date"] = email.utils.formatdate(localtime=False)
        message["Message-ID"] = email.utils.make_msgid(domain="william-jarvis.local")

        if email_payload.reply_to:
            message["Reply-To"] = email_payload.reply_to

        if email_payload.priority == EmailPriority.HIGH:
            message["X-Priority"] = "1"
            message["Priority"] = "urgent"
        elif email_payload.priority == EmailPriority.LOW:
            message["X-Priority"] = "5"
            message["Priority"] = "non-urgent"

        for key, value in email_payload.headers.items():
            message[key] = value

        if email_payload.format == EmailFormat.HTML:
            text_fallback = self._html_to_text(email_payload.body)
            message.set_content(text_fallback)
            message.add_alternative(email_payload.body, subtype="html")
        else:
            message.set_content(email_payload.body)

        for attachment in email_payload.attachments:
            maintype, subtype = attachment.mime_type.split("/", 1)
            message.add_attachment(
                attachment.content,
                maintype=maintype,
                subtype=subtype,
                filename=attachment.filename,
            )

        return message

    def _smtp_login_if_needed(self, smtp: smtplib.SMTP, config: SMTPConfig) -> None:
        if config.username:
            smtp.login(config.username, config.password or "")

    def _render_report_body(self, report: Mapping[str, Any], fmt: str = "text") -> str:
        title = str(report.get("title") or "Workflow Report")
        summary = str(report.get("summary") or "")
        metrics = report.get("metrics") or {}
        sections = report.get("sections") or []

        if fmt == EmailFormat.HTML.value:
            parts = [
                f"<h2>{self._escape_html(title)}</h2>",
                f"<p>{self._escape_html(summary)}</p>" if summary else "",
            ]

            if isinstance(metrics, Mapping) and metrics:
                parts.append("<h3>Metrics</h3><ul>")
                for key, value in metrics.items():
                    parts.append(f"<li><strong>{self._escape_html(str(key))}:</strong> {self._escape_html(str(value))}</li>")
                parts.append("</ul>")

            if isinstance(sections, Sequence):
                for section in sections:
                    if not isinstance(section, Mapping):
                        continue
                    heading = self._escape_html(str(section.get("heading") or "Section"))
                    content = self._escape_html(str(section.get("content") or ""))
                    parts.append(f"<h3>{heading}</h3><p>{content}</p>")

            parts.append("<p>Generated by William / Jarvis Workflow Agent.</p>")
            return "\n".join(part for part in parts if part)

        lines = [
            title,
            "=" * len(title),
            "",
        ]

        if summary:
            lines.extend(["Summary:", summary, ""])

        if isinstance(metrics, Mapping) and metrics:
            lines.append("Metrics:")
            for key, value in metrics.items():
                lines.append(f"- {key}: {value}")
            lines.append("")

        if isinstance(sections, Sequence):
            for section in sections:
                if not isinstance(section, Mapping):
                    continue
                heading = str(section.get("heading") or "Section")
                content = str(section.get("content") or "")
                lines.extend([heading, "-" * len(heading), content, ""])

        lines.append("Generated by William / Jarvis Workflow Agent.")
        return "\n".join(lines)

    # -----------------------------------------------------------------------
    # Compatibility hooks required by prompt
    # -----------------------------------------------------------------------

    def _validate_task_context(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation context.

        Required:
            - user_id
            - workspace_id

        Recommended:
            - task_id or correlation_id
            - actor/role metadata
        """
        if not isinstance(task, Mapping):
            return self._error_result(
                message="Task must be a mapping/dict.",
                error_code="invalid_task_type",
            )

        user_id = self._optional_str(task.get("user_id"))
        workspace_id = self._optional_str(task.get("workspace_id"))

        if not user_id:
            return self._error_result(
                message="user_id is required for EmailConnector tasks.",
                error_code="missing_user_id",
            )

        if not workspace_id:
            return self._error_result(
                message="workspace_id is required for EmailConnector tasks.",
                error_code="missing_workspace_id",
            )

        return self._safe_result(
            message="Task context is valid.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "correlation_id": self._get_correlation_id(task),
            },
        )

    def _requires_security_check(
        self,
        *,
        task: Mapping[str, Any],
        action: EmailAction,
        email_payload: Optional[EmailMessagePayload] = None,
    ) -> bool:
        """
        Decide whether Security Agent approval is required.

        Outbound sending actions are sensitive and approval is enabled by
        default. Preview/validate actions do not require approval.
        """
        if action in {EmailAction.PREVIEW, EmailAction.VALIDATE}:
            return False

        if not self.config.require_approval:
            return False

        if task.get("skip_security_check") is True:
            return False

        return True

    def _request_security_approval(
        self,
        *,
        task: Mapping[str, Any],
        action: EmailAction,
        email_payload: EmailMessagePayload,
    ) -> Dict[str, Any]:
        """
        Security Agent approval hook.

        Approval can come from:
            - task["permissions"]["approved"] == True
            - task["security"]["approved"] == True
            - external security_approval_callback returning True or success dict

        This method does not directly import Security Agent to keep this file
        import-safe while the full project is still being generated.
        """
        if not self._requires_security_check(task=task, action=action, email_payload=email_payload):
            return self._safe_result(
                message="Security check not required for this email action.",
                data={"approved": True, "source": "not_required"},
            )

        security_payload = {
            "agent": self.agent_name,
            "action": action.value,
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "correlation_id": self._get_correlation_id(task),
            "recipient_count": self._recipient_count(email_payload),
            "recipient_hashes": [self._hash_value(addr) for addr in self._all_recipients(email_payload)],
            "subject_hash": self._hash_value(email_payload.subject),
            "has_attachments": bool(email_payload.attachments),
            "attachment_count": len(email_payload.attachments),
            "requested_at": self._utc_now_iso(),
        }

        permissions = task.get("permissions") or {}
        security = task.get("security") or {}

        if isinstance(permissions, Mapping) and permissions.get("approved") is True:
            return self._safe_result(
                message="Email action approved by task permissions.",
                data={
                    "approved": True,
                    "source": "task.permissions",
                    "approved_by": permissions.get("approved_by"),
                    "security_payload": security_payload,
                },
            )

        if isinstance(security, Mapping) and security.get("approved") is True:
            return self._safe_result(
                message="Email action approved by task security context.",
                data={
                    "approved": True,
                    "source": "task.security",
                    "approved_by": security.get("approved_by"),
                    "security_payload": security_payload,
                },
            )

        if self.security_approval_callback:
            callback_response = self.security_approval_callback(security_payload)

            if callback_response is True:
                return self._safe_result(
                    message="Email action approved by Security Agent callback.",
                    data={
                        "approved": True,
                        "source": "security_callback",
                        "security_payload": security_payload,
                    },
                )

            if isinstance(callback_response, Mapping) and callback_response.get("success") is True:
                return self._safe_result(
                    message="Email action approved by Security Agent callback.",
                    data={
                        "approved": True,
                        "source": "security_callback",
                        "security_payload": security_payload,
                        "approval_response": self._sanitize_dict(callback_response),
                    },
                )

        result = self._error_result(
            message="Email action requires Security Agent approval before sending.",
            error_code="security_approval_required",
            data={
                "status": DeliveryStatus.APPROVAL_REQUIRED.value,
                "approved": False,
                "security_payload": security_payload,
            },
            metadata={
                "agent": self.agent_name,
                "correlation_id": self._get_correlation_id(task),
            },
        )

        self._log_audit_event(
            event_type="email_connector.security_approval_required",
            task=task,
            data=result,
        )

        return result

    def _prepare_verification_payload(
        self,
        *,
        task: Mapping[str, Any],
        action: EmailAction,
        status: DeliveryStatus,
        provider_response: Mapping[str, Any],
        email_payload: EmailMessagePayload,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload after email action.

        Verification Agent can use this to confirm:
            - action attempted,
            - delivery provider response,
            - dry-run vs real send,
            - user/workspace isolation,
            - recipient hashes without exposing raw PII.
        """
        return {
            "verification_type": "workflow_email_delivery",
            "agent": self.agent_name,
            "agent_version": self.agent_version,
            "action": action.value,
            "status": status.value,
            "success": bool(provider_response.get("success")),
            "message_id": provider_response.get("message_id"),
            "provider": provider_response.get("provider", self.config.provider),
            "dry_run": status == DeliveryStatus.DRY_RUN,
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "task_id": task.get("task_id"),
            "correlation_id": self._get_correlation_id(task),
            "recipient_count": self._recipient_count(email_payload),
            "recipient_hashes": [self._hash_value(addr) for addr in self._all_recipients(email_payload)],
            "subject_hash": self._hash_value(email_payload.subject),
            "has_attachments": bool(email_payload.attachments),
            "attachment_count": len(email_payload.attachments),
            "provider_response": self._sanitize_dict(provider_response),
            "created_at": self._utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        *,
        task: Mapping[str, Any],
        action: EmailAction,
        status: DeliveryStatus,
        email_payload: EmailMessagePayload,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Raw body and raw recipient addresses are intentionally not included.
        This supports future workflow recall without leaking sensitive PII.
        """
        return {
            "memory_type": "workflow_email_context",
            "agent": self.agent_name,
            "action": action.value,
            "status": status.value,
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "task_id": task.get("task_id"),
            "correlation_id": self._get_correlation_id(task),
            "summary": {
                "subject": email_payload.subject,
                "subject_hash": self._hash_value(email_payload.subject),
                "format": email_payload.format.value,
                "priority": email_payload.priority.value,
                "recipient_count": self._recipient_count(email_payload),
                "recipient_hashes": [self._hash_value(addr) for addr in self._all_recipients(email_payload)],
                "tags": email_payload.tags,
                "template_id": email_payload.template_id,
                "body_preview": self._safe_preview(email_payload.body, 240),
            },
            "metadata": {
                "email_metadata": self._sanitize_dict(email_payload.metadata),
                "created_at": self._utc_now_iso(),
            },
        }

    def _emit_agent_event(
        self,
        *,
        event_type: str,
        task: Mapping[str, Any],
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit dashboard/API/agent event.

        Future Notification Engine or Workflow Monitor can subscribe to this
        event shape.
        """
        if not self.config.event_emit_enabled:
            return

        event = {
            "event_id": f"evt_{uuid.uuid4().hex}",
            "event_type": event_type,
            "agent": self.agent_name,
            "agent_version": self.agent_version,
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "task_id": task.get("task_id"),
            "correlation_id": self._get_correlation_id(task),
            "data": self._sanitize_dict(data or {}),
            "created_at": self._utc_now_iso(),
        }

        if self.event_callback:
            try:
                self.event_callback(event)
                return
            except Exception:
                self.logger.exception("EmailConnector event callback failed.")

        self.logger.info("Agent event: %s", self._safe_json(event))

    def _log_audit_event(
        self,
        *,
        event_type: str,
        task: Mapping[str, Any],
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Audit logging hook.

        Keeps records workspace-scoped and PII-minimized. Future audit log
        storage can consume this event via audit_callback.
        """
        if not self.config.audit_enabled:
            return

        audit_event = {
            "audit_id": f"audit_{uuid.uuid4().hex}",
            "event_type": event_type,
            "agent": self.agent_name,
            "agent_version": self.agent_version,
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "task_id": task.get("task_id"),
            "correlation_id": self._get_correlation_id(task),
            "data": self._sanitize_dict(data or {}),
            "created_at": self._utc_now_iso(),
        }

        if self.audit_callback:
            try:
                self.audit_callback(audit_event)
                return
            except Exception:
                self.logger.exception("EmailConnector audit callback failed.")

        self.logger.info("Audit event: %s", self._safe_json(audit_event))

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success result.
        """
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
        error_code: str = "error",
        *,
        exception: Optional[BaseException] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result.
        """
        error: Dict[str, Any] = {
            "code": error_code,
            "message": message,
        }
        if exception is not None:
            error["exception_type"] = exception.__class__.__name__
            error["exception"] = self._safe_str(exception)

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _parse_action(self, action: Any) -> EmailAction:
        if isinstance(action, EmailAction):
            return action
        if not action:
            return EmailAction.SEND_EMAIL
        try:
            return EmailAction(str(action).lower().strip())
        except ValueError as exc:
            raise ValueError(f"Unsupported EmailConnector action: {action}") from exc

    def _parse_email_format(self, value: Any) -> EmailFormat:
        if isinstance(value, EmailFormat):
            return value
        try:
            return EmailFormat(str(value).lower().strip())
        except ValueError:
            return self.config.default_format

    def _parse_priority(self, value: Any) -> EmailPriority:
        if isinstance(value, EmailPriority):
            return value
        try:
            return EmailPriority(str(value).lower().strip())
        except ValueError:
            return EmailPriority.NORMAL

    def _is_valid_email(self, value: str) -> bool:
        if not value or not isinstance(value, str):
            return False
        if len(value) > 254:
            return False
        return bool(EMAIL_REGEX.match(value.strip()))

    def _all_recipients(self, payload: EmailMessagePayload) -> List[str]:
        return list(payload.to) + list(payload.cc) + list(payload.bcc)

    def _recipient_count(self, payload: EmailMessagePayload) -> int:
        return len(self._all_recipients(payload))

    def _optional_str(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        clean = str(value).strip()
        return clean or None

    def _get_correlation_id(self, task: Mapping[str, Any]) -> str:
        for key in ("correlation_id", "request_id", "run_id", "task_id"):
            value = task.get(key)
            if value:
                return str(value)
        return f"corr_{uuid.uuid4().hex}"

    def _generate_idempotency_key(self, *, to: Sequence[str], subject: str, body: str) -> str:
        normalized = json.dumps(
            {
                "to": sorted([addr.lower() for addr in to]),
                "subject": subject,
                "body_hash": self._hash_value(body),
            },
            sort_keys=True,
        )
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        return f"email_{digest[:32]}"

    def _hash_value(self, value: Any) -> str:
        """
        Stable hash for audit/memory without exposing raw PII.
        """
        text = str(value or "")
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return f"sha256:{digest}"

    def _safe_preview(self, text: str, limit: int = 180) -> str:
        clean = re.sub(r"\s+", " ", str(text or "")).strip()
        if len(clean) <= limit:
            return clean
        return clean[: max(0, limit - 3)] + "..."

    def _message_preview(self, payload: EmailMessagePayload) -> Dict[str, Any]:
        """
        Safe preview for dashboard/API.

        Raw BCC is intentionally not displayed.
        """
        return {
            "to": payload.to,
            "cc": payload.cc,
            "bcc_count": len(payload.bcc),
            "subject": payload.subject,
            "body_preview": self._safe_preview(payload.body, 500),
            "format": payload.format.value,
            "priority": payload.priority.value,
            "from_email": payload.from_email,
            "from_name": payload.from_name,
            "reply_to": payload.reply_to,
            "tags": payload.tags,
            "template_id": payload.template_id,
            "attachment_count": len(payload.attachments),
            "attachments": [
                {
                    "filename": attachment.filename,
                    "mime_type": attachment.mime_type,
                    "size_bytes": len(attachment.content),
                }
                for attachment in payload.attachments
            ],
            "idempotency_key": payload.idempotency_key,
        }

    def _status_message(self, action: EmailAction, status: DeliveryStatus) -> str:
        if status == DeliveryStatus.DRY_RUN:
            return f"{action.value} validated successfully in dry-run mode. No email was sent."
        if status == DeliveryStatus.SENT:
            return f"{action.value} completed successfully."
        if status == DeliveryStatus.FAILED:
            return f"{action.value} failed."
        return f"{action.value} processed with status {status.value}."

    def _sanitize_dict(self, value: Any) -> Any:
        """
        Recursively sanitize sensitive values from dict/list structures.
        """
        sensitive_keys = {
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "auth",
            "smtp_password",
            "access_token",
            "refresh_token",
        }

        if dataclasses.is_dataclass(value):
            value = dataclasses.asdict(value)

        if isinstance(value, Mapping):
            sanitized: Dict[str, Any] = {}
            for key, item in value.items():
                key_str = str(key)
                if key_str.lower() in sensitive_keys or any(s in key_str.lower() for s in sensitive_keys):
                    sanitized[key_str] = SENSITIVE_PLACEHOLDER
                else:
                    sanitized[key_str] = self._sanitize_dict(item)
            return sanitized

        if isinstance(value, list):
            return [self._sanitize_dict(item) for item in value]

        if isinstance(value, tuple):
            return tuple(self._sanitize_dict(item) for item in value)

        if isinstance(value, bytes):
            return f"<bytes:{len(value)}>"

        return value

    def _safe_json(self, value: Any) -> str:
        try:
            return json.dumps(self._sanitize_dict(value), default=str, ensure_ascii=False)
        except Exception:
            return str(value)

    def _safe_str(self, value: Any) -> str:
        text = str(value)
        return text[:2_000]

    def _utc_now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _html_to_text(self, html: str) -> str:
        text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", html)
        text = re.sub(r"(?s)<br\s*/?>", "\n", text)
        text = re.sub(r"(?s)</p\s*>", "\n\n", text)
        text = re.sub(r"(?s)<.*?>", "", text)
        text = (
            text.replace("&nbsp;", " ")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", '"')
            .replace("&#39;", "'")
        )
        return re.sub(r"\n{3,}", "\n\n", text).strip()

    def _escape_html(self, value: str) -> str:
        return (
            value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def build_email_connector(config: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> EmailConnector:
    """
    Factory for Agent Loader / FastAPI dependency injection.

    Example:
        connector = build_email_connector({
            "dry_run": True,
            "require_approval": True
        })
    """
    return EmailConnector(config=config, **kwargs)


# ---------------------------------------------------------------------------
# Minimal self-test helper
# ---------------------------------------------------------------------------

def _self_test() -> Dict[str, Any]:
    """
    Lightweight import-safe test.

    This does not send a real email because dry_run=True.
    """
    connector = EmailConnector(config={"dry_run": True, "require_approval": False})
    task = {
        "action": "send_email",
        "user_id": "test_user",
        "workspace_id": "test_workspace",
        "task_id": "test_task_email_connector",
        "payload": {
            "to": ["client@example.com"],
            "subject": "William Email Connector Test",
            "body": "This is a dry-run test email from William / Jarvis Workflow Agent.",
            "format": "text",
        },
    }
    return connector.execute(task)


if __name__ == "__main__":
    print(json.dumps(_self_test(), indent=2, default=str))