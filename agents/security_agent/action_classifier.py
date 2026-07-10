"""
agents/security_agent/action_classifier.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Classify an action request by:

    - Action type
    - Target resource type
    - Source agent
    - Sensitivity level
    - Required permission level
    - Risk indicators
    - Approval requirements
    - Security review requirements
    - Verification requirements
    - Audit requirements
    - SaaS user/workspace scope

This module does not execute actions, approve actions, access resources, make
payments, send messages, place calls, browse websites, modify files, or run
system commands.

It prepares deterministic, structured security classification results for:

    - Security Agent
    - Master Agent
    - Agent Router
    - Agent Registry
    - Agent Loader
    - Permission Checker
    - Risk Engine
    - Approval Manager
    - Audit Logger
    - Verification Agent
    - Memory Agent
    - Dashboard/API integrations

Safety priorities:

    1. Safety and permission enforcement
    2. User/workspace isolation
    3. BaseAgent compatibility
    4. Master Agent and Registry compatibility
    5. Action classification
    6. Future extensibility

The file is import-safe even when other William modules are not yet available.
"""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
)


# =============================================================================
# Optional William imports with safe fallbacks
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Minimal import-safe BaseAgent fallback.

        The production William BaseAgent can replace this automatically once
        available.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get(
                "agent_id",
                self.__class__.__name__.lower(),
            )
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(
            self,
            event_name: str,
            payload: Dict[str, Any],
        ) -> None:
            self.logger.debug(
                "Fallback event emitted: %s | %s",
                event_name,
                payload,
            )

        def log_audit(
            self,
            event_name: str,
            payload: Dict[str, Any],
        ) -> None:
            self.logger.debug(
                "Fallback audit event: %s | %s",
                event_name,
                payload,
            )


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# =============================================================================
# Enums
# =============================================================================

class ActionType(str, Enum):
    """Canonical action types recognized by the Security Agent."""

    READ = "read"
    SEARCH = "search"
    LIST = "list"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    START = "start"
    STOP = "stop"
    RESTART = "restart"
    INSTALL = "install"
    UNINSTALL = "uninstall"
    UPLOAD = "upload"
    DOWNLOAD = "download"
    COPY = "copy"
    MOVE = "move"
    RENAME = "rename"
    EXPORT = "export"
    IMPORT = "import"
    SEND = "send"
    RECEIVE = "receive"
    CALL = "call"
    MESSAGE = "message"
    EMAIL = "email"
    PUBLISH = "publish"
    DEPLOY = "deploy"
    ROLLBACK = "rollback"
    LOGIN = "login"
    LOGOUT = "logout"
    AUTHENTICATE = "authenticate"
    AUTHORIZE = "authorize"
    GRANT_PERMISSION = "grant_permission"
    REVOKE_PERMISSION = "revoke_permission"
    CHANGE_ROLE = "change_role"
    CHANGE_SETTINGS = "change_settings"
    ACCESS_SECRET = "access_secret"
    ROTATE_SECRET = "rotate_secret"
    PAYMENT = "payment"
    REFUND = "refund"
    TRANSFER_FUNDS = "transfer_funds"
    PURCHASE = "purchase"
    SUBSCRIBE = "subscribe"
    CANCEL_SUBSCRIPTION = "cancel_subscription"
    BROWSER_NAVIGATION = "browser_navigation"
    BROWSER_INTERACTION = "browser_interaction"
    SYSTEM_COMMAND = "system_command"
    FILE_OPERATION = "file_operation"
    DATABASE_OPERATION = "database_operation"
    API_REQUEST = "api_request"
    WORKFLOW_RUN = "workflow_run"
    MEMORY_STORE = "memory_store"
    MEMORY_READ = "memory_read"
    MEMORY_DELETE = "memory_delete"
    SECURITY_OPERATION = "security_operation"
    BIOMETRIC_OPERATION = "biometric_operation"
    DEVICE_OPERATION = "device_operation"
    UNKNOWN = "unknown"


class ResourceType(str, Enum):
    """Resources that an action may target."""

    NONE = "none"
    USER = "user"
    WORKSPACE = "workspace"
    ROLE = "role"
    PERMISSION = "permission"
    SUBSCRIPTION = "subscription"
    BILLING = "billing"
    PAYMENT = "payment"
    FINANCIAL_ACCOUNT = "financial_account"
    FILE = "file"
    DIRECTORY = "directory"
    DATABASE = "database"
    DATABASE_RECORD = "database_record"
    MEMORY = "memory"
    AUDIT_LOG = "audit_log"
    TASK = "task"
    WORKFLOW = "workflow"
    AGENT = "agent"
    AGENT_CONFIGURATION = "agent_configuration"
    SYSTEM = "system"
    PROCESS = "process"
    SERVICE = "service"
    APPLICATION = "application"
    DEVICE = "device"
    SESSION = "session"
    SECRET = "secret"
    API_KEY = "api_key"
    TOKEN = "token"
    CREDENTIAL = "credential"
    EMAIL = "email"
    MESSAGE = "message"
    CALL = "call"
    CONTACT = "contact"
    BROWSER = "browser"
    WEBSITE = "website"
    URL = "url"
    CLOUD_RESOURCE = "cloud_resource"
    DEPLOYMENT = "deployment"
    SOURCE_CODE = "source_code"
    REPOSITORY = "repository"
    CLIENT_DATA = "client_data"
    PROJECT_DATA = "project_data"
    TEAM_DATA = "team_data"
    ANALYTICS = "analytics"
    REPORT = "report"
    MEDIA = "media"
    DOCUMENT = "document"
    BIOMETRIC_DATA = "biometric_data"
    SECURITY_POLICY = "security_policy"
    UNKNOWN = "unknown"


class SensitivityLevel(str, Enum):
    """Sensitivity of the requested action and resource."""

    PUBLIC = "public"
    LOW = "low"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    CRITICAL = "critical"


class PermissionLevel(str, Enum):
    """Minimum permission level recommended for an action."""

    NONE = "none"
    PUBLIC = "public"
    AUTHENTICATED = "authenticated"
    USER = "user"
    WORKSPACE_MEMBER = "workspace_member"
    CONTRIBUTOR = "contributor"
    OPERATOR = "operator"
    MANAGER = "manager"
    ADMIN = "admin"
    WORKSPACE_OWNER = "workspace_owner"
    SECURITY_ADMIN = "security_admin"
    SYSTEM_ADMIN = "system_admin"
    SUPER_ADMIN = "super_admin"
    EXPLICIT_APPROVAL = "explicit_approval"
    DENY = "deny"


class ApprovalType(str, Enum):
    """Approval mechanisms recommended by the classifier."""

    NONE = "none"
    USER_CONFIRMATION = "user_confirmation"
    WORKSPACE_ADMIN = "workspace_admin"
    WORKSPACE_OWNER = "workspace_owner"
    SECURITY_AGENT = "security_agent"
    SECURITY_ADMIN = "security_admin"
    SYSTEM_ADMIN = "system_admin"
    BIOMETRIC = "biometric"
    MULTI_FACTOR = "multi_factor"
    DUAL_APPROVAL = "dual_approval"
    FINANCE_APPROVAL = "finance_approval"
    MANUAL_REVIEW = "manual_review"
    DENIED = "denied"


class ClassificationDecision(str, Enum):
    """Recommended handling outcome."""

    ALLOW_CLASSIFICATION = "allow_classification"
    REQUIRE_PERMISSION_CHECK = "require_permission_check"
    REQUIRE_APPROVAL = "require_approval"
    REQUIRE_SECURITY_REVIEW = "require_security_review"
    REQUIRE_BIOMETRIC = "require_biometric"
    DENY = "deny"


class SourceAgentTrust(str, Enum):
    """Baseline trust assigned to an action source."""

    SYSTEM_TRUSTED = "system_trusted"
    HIGH = "high"
    STANDARD = "standard"
    LIMITED = "limited"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


# =============================================================================
# Data models
# =============================================================================

@dataclass
class ActionClassificationInput:
    """Normalized request consumed by ActionClassifier."""

    action: str
    user_id: Optional[str] = None
    workspace_id: Optional[str] = None
    source_agent: Optional[str] = None
    resource: Optional[str] = None
    resource_id: Optional[str] = None
    description: Optional[str] = None
    target_user_id: Optional[str] = None
    target_workspace_id: Optional[str] = None
    task_id: Optional[str] = None
    conversation_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    parameters: Dict[str, Any] = field(default_factory=dict)
    explicit_action_type: Optional[Union[str, ActionType]] = None
    explicit_resource_type: Optional[Union[str, ResourceType]] = None
    explicit_sensitivity: Optional[
        Union[str, SensitivityLevel]
    ] = None
    explicit_permission_level: Optional[
        Union[str, PermissionLevel]
    ] = None
    dry_run: bool = True


@dataclass
class ActionClassification:
    """Final normalized security classification."""

    classification_id: str
    action_fingerprint: str
    action_type: ActionType
    resource_type: ResourceType
    source_agent: str
    source_agent_trust: SourceAgentTrust
    sensitivity: SensitivityLevel
    permission_level: PermissionLevel
    decision: ClassificationDecision
    approval_types: List[ApprovalType]
    risk_score: float
    risk_indicators: List[str]
    reasons: List[str]
    requires_security_check: bool
    requires_permission_check: bool
    requires_explicit_approval: bool
    requires_biometric: bool
    requires_verification: bool
    requires_audit_log: bool
    destructive: bool
    external_side_effect: bool
    financial: bool
    cross_user_scope: bool
    cross_workspace_scope: bool
    created_at: str


EnumType = TypeVar("EnumType", bound=Enum)


# =============================================================================
# ActionClassifier
# =============================================================================

class ActionClassifier(BaseAgent):
    """
    Production action classifier for William's Security Agent.

    The classifier determines the security profile of an action. It never
    performs the action itself.

    Public methods:

        classify_action()
        classify_batch()
        determine_action_type()
        determine_resource_type()
        determine_source_agent()
        determine_source_agent_trust()
        determine_sensitivity()
        determine_permission_level()
        calculate_risk_score()
        get_agent_manifest()
        health_check()

    Compatibility hooks:

        _validate_task_context()
        _requires_security_check()
        _request_security_approval()
        _prepare_verification_payload()
        _prepare_memory_payload()
        _emit_agent_event()
        _log_audit_event()
        _safe_result()
        _error_result()
    """

    DEFAULT_AGENT_NAME = "ActionClassifier"
    DEFAULT_AGENT_ID = "security_action_classifier"
    VERSION = "1.0.0"

    ACTION_KEYWORDS: Dict[ActionType, Tuple[str, ...]] = {
        ActionType.DELETE: (
            "delete",
            "remove permanently",
            "erase",
            "destroy",
            "purge",
            "wipe",
            "drop",
        ),
        ActionType.TRANSFER_FUNDS: (
            "transfer funds",
            "send money",
            "wire money",
            "bank transfer",
            "move funds",
        ),
        ActionType.PAYMENT: (
            "make payment",
            "pay invoice",
            "charge card",
            "process payment",
            "pay",
        ),
        ActionType.REFUND: (
            "refund",
            "reverse payment",
            "return payment",
        ),
        ActionType.PURCHASE: (
            "purchase",
            "buy",
            "checkout",
            "place order",
        ),
        ActionType.SUBSCRIBE: (
            "subscribe",
            "start subscription",
            "upgrade plan",
        ),
        ActionType.CANCEL_SUBSCRIPTION: (
            "cancel subscription",
            "end subscription",
            "downgrade plan",
        ),
        ActionType.GRANT_PERMISSION: (
            "grant permission",
            "give access",
            "allow access",
            "assign permission",
        ),
        ActionType.REVOKE_PERMISSION: (
            "revoke permission",
            "remove access",
            "deny access",
        ),
        ActionType.CHANGE_ROLE: (
            "change role",
            "assign role",
            "promote user",
            "demote user",
        ),
        ActionType.ACCESS_SECRET: (
            "access secret",
            "read secret",
            "get api key",
            "show token",
            "view password",
            "retrieve credential",
        ),
        ActionType.ROTATE_SECRET: (
            "rotate secret",
            "rotate key",
            "replace token",
            "regenerate api key",
        ),
        ActionType.DEPLOY: (
            "deploy",
            "release to production",
            "publish build",
            "production release",
        ),
        ActionType.ROLLBACK: (
            "rollback",
            "revert deployment",
            "restore release",
        ),
        ActionType.SYSTEM_COMMAND: (
            "run command",
            "execute shell",
            "terminal command",
            "shell command",
            "powershell",
            "bash command",
            "cmd.exe",
        ),
        ActionType.INSTALL: (
            "install",
            "add package",
            "install dependency",
        ),
        ActionType.UNINSTALL: (
            "uninstall",
            "remove package",
        ),
        ActionType.START: (
            "start service",
            "start process",
            "launch application",
            "start worker",
        ),
        ActionType.STOP: (
            "stop service",
            "stop process",
            "kill process",
            "terminate service",
        ),
        ActionType.RESTART: (
            "restart",
            "reboot",
            "restart service",
        ),
        ActionType.SEND: (
            "send",
            "dispatch",
            "deliver",
        ),
        ActionType.EMAIL: (
            "send email",
            "email",
            "reply email",
            "forward email",
        ),
        ActionType.MESSAGE: (
            "send message",
            "message",
            "chat message",
            "whatsapp",
            "sms",
        ),
        ActionType.CALL: (
            "place call",
            "make call",
            "dial",
            "phone call",
        ),
        ActionType.PUBLISH: (
            "publish",
            "post publicly",
            "make public",
        ),
        ActionType.UPLOAD: (
            "upload",
            "attach file",
        ),
        ActionType.DOWNLOAD: (
            "download",
            "retrieve file",
        ),
        ActionType.EXPORT: (
            "export",
            "download report",
            "export csv",
        ),
        ActionType.IMPORT: (
            "import",
            "upload dataset",
            "bulk import",
        ),
        ActionType.MOVE: (
            "move file",
            "move folder",
            "relocate",
        ),
        ActionType.RENAME: (
            "rename",
            "change filename",
        ),
        ActionType.COPY: (
            "copy",
            "duplicate",
            "clone file",
        ),
        ActionType.LOGIN: (
            "login",
            "sign in",
        ),
        ActionType.LOGOUT: (
            "logout",
            "sign out",
        ),
        ActionType.AUTHENTICATE: (
            "authenticate",
            "verify identity",
        ),
        ActionType.AUTHORIZE: (
            "authorize",
            "approve access",
        ),
        ActionType.BROWSER_NAVIGATION: (
            "open website",
            "visit url",
            "navigate browser",
            "browse to",
        ),
        ActionType.BROWSER_INTERACTION: (
            "click button",
            "submit form",
            "fill form",
            "browser interaction",
        ),
        ActionType.DATABASE_OPERATION: (
            "database query",
            "update database",
            "insert record",
            "delete record",
            "sql",
        ),
        ActionType.API_REQUEST: (
            "api request",
            "call endpoint",
            "http request",
            "webhook",
        ),
        ActionType.WORKFLOW_RUN: (
            "run workflow",
            "execute workflow",
            "start automation",
        ),
        ActionType.MEMORY_STORE: (
            "store memory",
            "save memory",
            "remember this",
        ),
        ActionType.MEMORY_READ: (
            "read memory",
            "recall memory",
            "search memory",
        ),
        ActionType.MEMORY_DELETE: (
            "delete memory",
            "forget memory",
            "remove memory",
        ),
        ActionType.CHANGE_SETTINGS: (
            "change settings",
            "update settings",
            "modify configuration",
        ),
        ActionType.CREATE: (
            "create",
            "add",
            "new",
        ),
        ActionType.UPDATE: (
            "update",
            "edit",
            "modify",
            "change",
        ),
        ActionType.SEARCH: (
            "search",
            "find",
            "lookup",
        ),
        ActionType.LIST: (
            "list",
            "show all",
            "enumerate",
        ),
        ActionType.READ: (
            "read",
            "view",
            "get",
            "inspect",
            "show",
        ),
        ActionType.EXECUTE: (
            "execute",
            "run",
            "perform",
        ),
    }

    RESOURCE_KEYWORDS: Dict[ResourceType, Tuple[str, ...]] = {
        ResourceType.API_KEY: (
            "api key",
            "api_key",
        ),
        ResourceType.TOKEN: (
            "access token",
            "refresh token",
            "bearer token",
            "token",
        ),
        ResourceType.CREDENTIAL: (
            "credential",
            "password",
            "login details",
        ),
        ResourceType.SECRET: (
            "secret",
            "private key",
            "encryption key",
        ),
        ResourceType.BIOMETRIC_DATA: (
            "biometric",
            "fingerprint",
            "face id",
            "voice print",
        ),
        ResourceType.FINANCIAL_ACCOUNT: (
            "bank account",
            "financial account",
            "wallet",
        ),
        ResourceType.PAYMENT: (
            "payment",
            "invoice",
            "transaction",
            "refund",
        ),
        ResourceType.BILLING: (
            "billing",
            "billing profile",
        ),
        ResourceType.SUBSCRIPTION: (
            "subscription",
            "plan",
        ),
        ResourceType.PERMISSION: (
            "permission",
            "access control",
            "privilege",
        ),
        ResourceType.ROLE: (
            "role",
            "admin role",
        ),
        ResourceType.SECURITY_POLICY: (
            "security policy",
            "access policy",
            "permission policy",
        ),
        ResourceType.AUDIT_LOG: (
            "audit log",
            "security log",
            "activity log",
        ),
        ResourceType.DATABASE_RECORD: (
            "database record",
            "row",
            "record",
        ),
        ResourceType.DATABASE: (
            "database",
            "postgres",
            "mysql",
            "mongodb",
            "redis",
            "sql",
        ),
        ResourceType.SOURCE_CODE: (
            "source code",
            "code file",
            "python file",
            "javascript file",
        ),
        ResourceType.REPOSITORY: (
            "repository",
            "repo",
            "git",
            "github",
            "gitlab",
        ),
        ResourceType.DEPLOYMENT: (
            "deployment",
            "production",
            "release",
        ),
        ResourceType.FILE: (
            "file",
            "document file",
        ),
        ResourceType.DIRECTORY: (
            "directory",
            "folder",
        ),
        ResourceType.MEMORY: (
            "memory",
            "long-term memory",
            "short-term memory",
        ),
        ResourceType.EMAIL: (
            "email",
            "mailbox",
            "gmail",
        ),
        ResourceType.MESSAGE: (
            "message",
            "sms",
            "whatsapp",
            "chat",
        ),
        ResourceType.CALL: (
            "call",
            "phone",
            "dialer",
        ),
        ResourceType.CONTACT: (
            "contact",
            "recipient",
        ),
        ResourceType.BROWSER: (
            "browser",
            "chrome",
            "firefox",
        ),
        ResourceType.WEBSITE: (
            "website",
            "web page",
            "domain",
        ),
        ResourceType.URL: (
            "url",
            "link",
        ),
        ResourceType.DEVICE: (
            "device",
            "phone",
            "computer",
            "emulator",
        ),
        ResourceType.SESSION: (
            "session",
            "login session",
        ),
        ResourceType.PROCESS: (
            "process",
            "worker",
        ),
        ResourceType.SERVICE: (
            "service",
            "daemon",
        ),
        ResourceType.SYSTEM: (
            "system",
            "operating system",
            "server",
            "terminal",
        ),
        ResourceType.AGENT_CONFIGURATION: (
            "agent config",
            "agent configuration",
            "agent permission",
        ),
        ResourceType.AGENT: (
            "agent",
            "master agent",
            "security agent",
        ),
        ResourceType.WORKFLOW: (
            "workflow",
            "automation",
            "pipeline",
        ),
        ResourceType.TASK: (
            "task",
            "job",
        ),
        ResourceType.CLIENT_DATA: (
            "client data",
            "customer data",
            "lead data",
        ),
        ResourceType.PROJECT_DATA: (
            "project data",
            "project context",
        ),
        ResourceType.TEAM_DATA: (
            "team data",
            "staff data",
        ),
        ResourceType.USER: (
            "user",
            "account",
            "profile",
        ),
        ResourceType.WORKSPACE: (
            "workspace",
            "tenant",
            "organization",
        ),
        ResourceType.ANALYTICS: (
            "analytics",
            "metrics",
            "dashboard data",
        ),
        ResourceType.REPORT: (
            "report",
            "summary",
        ),
        ResourceType.MEDIA: (
            "image",
            "video",
            "audio",
            "media",
        ),
        ResourceType.DOCUMENT: (
            "document",
            "pdf",
            "spreadsheet",
        ),
        ResourceType.APPLICATION: (
            "application",
            "app",
            "software",
        ),
        ResourceType.CLOUD_RESOURCE: (
            "cloud resource",
            "aws",
            "azure",
            "gcp",
            "cloudflare",
        ),
    }

    DESTRUCTIVE_ACTIONS: Set[ActionType] = {
        ActionType.DELETE,
        ActionType.UNINSTALL,
        ActionType.STOP,
        ActionType.ROLLBACK,
        ActionType.REVOKE_PERMISSION,
        ActionType.MEMORY_DELETE,
        ActionType.CANCEL_SUBSCRIPTION,
    }

    FINANCIAL_ACTIONS: Set[ActionType] = {
        ActionType.PAYMENT,
        ActionType.REFUND,
        ActionType.TRANSFER_FUNDS,
        ActionType.PURCHASE,
        ActionType.SUBSCRIBE,
        ActionType.CANCEL_SUBSCRIPTION,
    }

    EXTERNAL_SIDE_EFFECT_ACTIONS: Set[ActionType] = {
        ActionType.SEND,
        ActionType.EMAIL,
        ActionType.MESSAGE,
        ActionType.CALL,
        ActionType.PUBLISH,
        ActionType.DEPLOY,
        ActionType.API_REQUEST,
        ActionType.BROWSER_INTERACTION,
        ActionType.PAYMENT,
        ActionType.REFUND,
        ActionType.TRANSFER_FUNDS,
        ActionType.PURCHASE,
        ActionType.SUBSCRIBE,
        ActionType.CANCEL_SUBSCRIPTION,
    }

    PRIVILEGED_ACTIONS: Set[ActionType] = {
        ActionType.GRANT_PERMISSION,
        ActionType.REVOKE_PERMISSION,
        ActionType.CHANGE_ROLE,
        ActionType.ACCESS_SECRET,
        ActionType.ROTATE_SECRET,
        ActionType.SECURITY_OPERATION,
        ActionType.BIOMETRIC_OPERATION,
        ActionType.CHANGE_SETTINGS,
    }

    CRITICAL_RESOURCES: Set[ResourceType] = {
        ResourceType.SECRET,
        ResourceType.API_KEY,
        ResourceType.TOKEN,
        ResourceType.CREDENTIAL,
        ResourceType.BIOMETRIC_DATA,
        ResourceType.FINANCIAL_ACCOUNT,
        ResourceType.SECURITY_POLICY,
    }

    CONFIDENTIAL_RESOURCES: Set[ResourceType] = {
        ResourceType.CLIENT_DATA,
        ResourceType.PAYMENT,
        ResourceType.BILLING,
        ResourceType.SUBSCRIPTION,
        ResourceType.AUDIT_LOG,
        ResourceType.DATABASE,
        ResourceType.DATABASE_RECORD,
        ResourceType.MEMORY,
        ResourceType.EMAIL,
        ResourceType.MESSAGE,
        ResourceType.CALL,
        ResourceType.CONTACT,
        ResourceType.USER,
        ResourceType.TEAM_DATA,
    }

    TRUSTED_AGENT_NAMES: Dict[str, SourceAgentTrust] = {
        "master_agent": SourceAgentTrust.HIGH,
        "master": SourceAgentTrust.HIGH,
        "security_agent": SourceAgentTrust.SYSTEM_TRUSTED,
        "security": SourceAgentTrust.SYSTEM_TRUSTED,
        "verification_agent": SourceAgentTrust.HIGH,
        "verification": SourceAgentTrust.HIGH,
        "memory_agent": SourceAgentTrust.STANDARD,
        "memory": SourceAgentTrust.STANDARD,
        "system_agent": SourceAgentTrust.HIGH,
        "system": SourceAgentTrust.HIGH,
        "browser_agent": SourceAgentTrust.LIMITED,
        "browser": SourceAgentTrust.LIMITED,
        "code_agent": SourceAgentTrust.STANDARD,
        "code": SourceAgentTrust.STANDARD,
        "voice_agent": SourceAgentTrust.LIMITED,
        "voice": SourceAgentTrust.LIMITED,
        "workflow_agent": SourceAgentTrust.STANDARD,
        "workflow": SourceAgentTrust.STANDARD,
        "call_agent": SourceAgentTrust.LIMITED,
        "call": SourceAgentTrust.LIMITED,
        "finance_agent": SourceAgentTrust.LIMITED,
        "finance": SourceAgentTrust.LIMITED,
        "business_agent": SourceAgentTrust.STANDARD,
        "business": SourceAgentTrust.STANDARD,
        "creator_agent": SourceAgentTrust.STANDARD,
        "creator": SourceAgentTrust.STANDARD,
        "visual_agent": SourceAgentTrust.STANDARD,
        "visual": SourceAgentTrust.STANDARD,
        "hologram_agent": SourceAgentTrust.LIMITED,
        "hologram": SourceAgentTrust.LIMITED,
    }

    SECRET_PATTERNS: Tuple[str, ...] = (
        r"\bpassword\b",
        r"\bpasscode\b",
        r"\bapi[_\s-]?key\b",
        r"\bprivate[_\s-]?key\b",
        r"\bsecret[_\s-]?key\b",
        r"\baccess[_\s-]?token\b",
        r"\brefresh[_\s-]?token\b",
        r"\bbearer\s+[a-z0-9._\-]+\b",
        r"\bssh-rsa\b",
        r"\bBEGIN\s+(RSA|OPENSSH|PRIVATE)\s+KEY\b",
        r"\bcvv\b",
        r"\botp\b",
        r"\b2fa\s+code\b",
    )

    SYSTEM_COMMAND_PATTERNS: Tuple[str, ...] = (
        r"\brm\s+-rf\b",
        r"\bdel\s+/[fsq]\b",
        r"\bformat\s+[a-z]:\b",
        r"\bshutdown\b",
        r"\breboot\b",
        r"\bkill\s+-9\b",
        r"\btaskkill\b",
        r"\bdrop\s+database\b",
        r"\btruncate\s+table\b",
        r"\bchmod\s+777\b",
        r"\bsudo\b",
        r"\bpowershell\b",
        r"\bcmd\.exe\b",
    )

    CROSS_SCOPE_KEYS: Tuple[str, ...] = (
        "target_user_id",
        "target_workspace_id",
        "owner_user_id",
        "owner_workspace_id",
    )

    def __init__(
        self,
        *,
        agent_name: str = DEFAULT_AGENT_NAME,
        agent_id: str = DEFAULT_AGENT_ID,
        strict_context_validation: bool = True,
        workspace_required: bool = True,
        security_approval_callback: Optional[
            Callable[[Dict[str, Any]], Dict[str, Any]]
        ] = None,
        event_callback: Optional[
            Callable[[str, Dict[str, Any]], None]
        ] = None,
        audit_callback: Optional[
            Callable[[str, Dict[str, Any]], None]
        ] = None,
        logger_instance: Optional[logging.Logger] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize ActionClassifier.

        Args:
            agent_name:
                Human-readable component name.

            agent_id:
                Registry-safe component identifier.

            strict_context_validation:
                Require user_id for user-specific classification.

            workspace_required:
                Require workspace_id to guarantee tenant isolation.

            security_approval_callback:
                Optional Security Agent or Approval Manager callback.

            event_callback:
                Optional Dashboard/Registry event callback.

            audit_callback:
                Optional Audit Logger callback.

            logger_instance:
                Optional custom logger.

            config:
                Optional future configuration overrides.
        """

        try:
            super().__init__(
                agent_name=agent_name,
                agent_id=agent_id,
            )
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.agent_id = agent_id
        self.strict_context_validation = strict_context_validation
        self.workspace_required = workspace_required
        self.security_approval_callback = security_approval_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.config = config or {}
        self.logger = logger_instance or logging.getLogger(
            f"{__name__}.{self.__class__.__name__}"
        )

    # =========================================================================
    # Main public interface
    # =========================================================================

    def classify_action(
        self,
        action: str,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        source_agent: Optional[str] = None,
        resource: Optional[str] = None,
        resource_id: Optional[str] = None,
        description: Optional[str] = None,
        target_user_id: Optional[str] = None,
        target_workspace_id: Optional[str] = None,
        task_id: Optional[str] = None,
        conversation_id: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        parameters: Optional[Dict[str, Any]] = None,
        explicit_action_type: Optional[
            Union[str, ActionType]
        ] = None,
        explicit_resource_type: Optional[
            Union[str, ResourceType]
        ] = None,
        explicit_sensitivity: Optional[
            Union[str, SensitivityLevel]
        ] = None,
        explicit_permission_level: Optional[
            Union[str, PermissionLevel]
        ] = None,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """
        Classify one requested action.

        This method performs no external action. It only prepares a structured
        classification and compatibility payloads.
        """

        request = ActionClassificationInput(
            action=action,
            user_id=user_id,
            workspace_id=workspace_id,
            source_agent=source_agent,
            resource=resource,
            resource_id=resource_id,
            description=description,
            target_user_id=target_user_id,
            target_workspace_id=target_workspace_id,
            task_id=task_id,
            conversation_id=conversation_id,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata or {},
            parameters=parameters or {},
            explicit_action_type=explicit_action_type,
            explicit_resource_type=explicit_resource_type,
            explicit_sensitivity=explicit_sensitivity,
            explicit_permission_level=explicit_permission_level,
            dry_run=dry_run,
        )

        validation = self._validate_task_context(request)
        if not validation["success"]:
            self._log_audit_event(
                "security.action_classification.validation_failed",
                {
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "source_agent": source_agent,
                    "request_id": request_id,
                    "error": validation.get("error"),
                },
            )
            return validation

        normalized_action = self._normalize_text(action)
        normalized_resource = self._normalize_text(resource)
        normalized_description = self._normalize_text(description)

        combined_text = " ".join(
            item
            for item in (
                normalized_action,
                normalized_resource,
                normalized_description,
            )
            if item
        )

        action_type = self.determine_action_type(
            normalized_action,
            description=normalized_description,
            explicit_action_type=explicit_action_type,
            metadata=request.metadata,
        )

        resource_type = self.determine_resource_type(
            normalized_resource,
            action=normalized_action,
            description=normalized_description,
            explicit_resource_type=explicit_resource_type,
            metadata=request.metadata,
        )

        normalized_source_agent = self.determine_source_agent(
            source_agent,
            request.metadata,
        )

        source_agent_trust = self.determine_source_agent_trust(
            normalized_source_agent,
            request.metadata,
        )

        cross_user_scope = self._is_cross_user_scope(request)
        cross_workspace_scope = self._is_cross_workspace_scope(request)

        destructive = action_type in self.DESTRUCTIVE_ACTIONS
        financial = action_type in self.FINANCIAL_ACTIONS
        external_side_effect = (
            action_type in self.EXTERNAL_SIDE_EFFECT_ACTIONS
        )

        sensitivity = self.determine_sensitivity(
            action_type=action_type,
            resource_type=resource_type,
            combined_text=combined_text,
            source_agent_trust=source_agent_trust,
            cross_user_scope=cross_user_scope,
            cross_workspace_scope=cross_workspace_scope,
            explicit_sensitivity=explicit_sensitivity,
            metadata=request.metadata,
            parameters=request.parameters,
        )

        permission_level = self.determine_permission_level(
            action_type=action_type,
            resource_type=resource_type,
            sensitivity=sensitivity,
            cross_user_scope=cross_user_scope,
            cross_workspace_scope=cross_workspace_scope,
            explicit_permission_level=explicit_permission_level,
        )

        risk_score, risk_indicators = self.calculate_risk_score(
            action_type=action_type,
            resource_type=resource_type,
            sensitivity=sensitivity,
            source_agent_trust=source_agent_trust,
            destructive=destructive,
            financial=financial,
            external_side_effect=external_side_effect,
            cross_user_scope=cross_user_scope,
            cross_workspace_scope=cross_workspace_scope,
            combined_text=combined_text,
            metadata=request.metadata,
            parameters=request.parameters,
        )

        requires_security_check = self._requires_security_check(
            action_type=action_type,
            resource_type=resource_type,
            sensitivity=sensitivity,
            permission_level=permission_level,
            risk_score=risk_score,
            cross_user_scope=cross_user_scope,
            cross_workspace_scope=cross_workspace_scope,
        )

        approval_types = self._determine_approval_types(
            action_type=action_type,
            resource_type=resource_type,
            sensitivity=sensitivity,
            permission_level=permission_level,
            risk_score=risk_score,
            financial=financial,
            destructive=destructive,
            cross_user_scope=cross_user_scope,
            cross_workspace_scope=cross_workspace_scope,
        )

        requires_explicit_approval = bool(
            approval_types
            and approval_types != [ApprovalType.NONE]
        )

        requires_biometric = (
            ApprovalType.BIOMETRIC in approval_types
        )

        requires_permission_check = (
            permission_level
            not in {
                PermissionLevel.NONE,
                PermissionLevel.PUBLIC,
                PermissionLevel.DENY,
            }
        )

        requires_verification = self._requires_verification(
            action_type=action_type,
            sensitivity=sensitivity,
            destructive=destructive,
            financial=financial,
            external_side_effect=external_side_effect,
            risk_score=risk_score,
        )

        requires_audit_log = self._requires_audit_log(
            action_type=action_type,
            sensitivity=sensitivity,
            requires_security_check=requires_security_check,
            external_side_effect=external_side_effect,
        )

        decision = self._determine_decision(
            permission_level=permission_level,
            sensitivity=sensitivity,
            requires_security_check=requires_security_check,
            requires_explicit_approval=requires_explicit_approval,
            requires_biometric=requires_biometric,
            risk_score=risk_score,
            cross_workspace_scope=cross_workspace_scope,
        )

        reasons = self._build_classification_reasons(
            action_type=action_type,
            resource_type=resource_type,
            source_agent=normalized_source_agent,
            source_agent_trust=source_agent_trust,
            sensitivity=sensitivity,
            permission_level=permission_level,
            decision=decision,
            destructive=destructive,
            financial=financial,
            external_side_effect=external_side_effect,
            cross_user_scope=cross_user_scope,
            cross_workspace_scope=cross_workspace_scope,
            risk_score=risk_score,
        )

        classification = ActionClassification(
            classification_id=self._new_id("actioncls"),
            action_fingerprint=self._build_action_fingerprint(request),
            action_type=action_type,
            resource_type=resource_type,
            source_agent=normalized_source_agent,
            source_agent_trust=source_agent_trust,
            sensitivity=sensitivity,
            permission_level=permission_level,
            decision=decision,
            approval_types=approval_types,
            risk_score=risk_score,
            risk_indicators=risk_indicators,
            reasons=reasons,
            requires_security_check=requires_security_check,
            requires_permission_check=requires_permission_check,
            requires_explicit_approval=requires_explicit_approval,
            requires_biometric=requires_biometric,
            requires_verification=requires_verification,
            requires_audit_log=requires_audit_log,
            destructive=destructive,
            external_side_effect=external_side_effect,
            financial=financial,
            cross_user_scope=cross_user_scope,
            cross_workspace_scope=cross_workspace_scope,
            created_at=self._utc_now(),
        )

        security_request = None
        if requires_security_check:
            security_request = self._request_security_approval(
                request,
                classification,
            )

        verification_payload = self._prepare_verification_payload(
            request=request,
            classification=classification,
            security_request=security_request,
        )

        memory_payload = self._prepare_memory_payload(
            request=request,
            classification=classification,
        )

        event_payload = {
            "classification_id": classification.classification_id,
            "request_id": request.request_id,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "source_agent": classification.source_agent,
            "action_type": classification.action_type.value,
            "resource_type": classification.resource_type.value,
            "sensitivity": classification.sensitivity.value,
            "permission_level": classification.permission_level.value,
            "decision": classification.decision.value,
            "risk_score": classification.risk_score,
            "requires_security_check": (
                classification.requires_security_check
            ),
            "requires_explicit_approval": (
                classification.requires_explicit_approval
            ),
            "dry_run": request.dry_run,
        }

        self._emit_agent_event(
            "security.action_classified",
            event_payload,
        )

        if classification.requires_audit_log:
            self._log_audit_event(
                "security.action_classified",
                event_payload,
            )

        return self._safe_result(
            message="Action classified successfully.",
            data={
                "classification": self._classification_to_dict(
                    classification
                ),
                "security_request": security_request,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
                "execution_allowed": False,
                "classification_only": True,
                "dry_run": request.dry_run,
            },
            metadata=self._base_metadata(request),
        )

    def classify_batch(
        self,
        actions: Sequence[
            Union[str, Mapping[str, Any], ActionClassificationInput]
        ],
        *,
        default_user_id: Optional[str] = None,
        default_workspace_id: Optional[str] = None,
        default_source_agent: Optional[str] = None,
        default_metadata: Optional[Dict[str, Any]] = None,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """Classify multiple action requests safely."""

        results: List[Dict[str, Any]] = []
        failures: List[Dict[str, Any]] = []

        for index, item in enumerate(actions):
            try:
                kwargs = self._normalize_batch_item(
                    item,
                    default_user_id=default_user_id,
                    default_workspace_id=default_workspace_id,
                    default_source_agent=default_source_agent,
                    default_metadata=default_metadata or {},
                    dry_run=dry_run,
                )

                result = self.classify_action(**kwargs)

                results.append(
                    {
                        "index": index,
                        "success": bool(result.get("success")),
                        "result": result,
                    }
                )

            except Exception as exc:
                self.logger.exception(
                    "Action classification batch item failed at index %s.",
                    index,
                )
                failures.append(
                    {
                        "index": index,
                        "error_type": exc.__class__.__name__,
                        "message": str(exc),
                    }
                )

        success_count = sum(
            1 for item in results if item.get("success")
        )

        return self._safe_result(
            message="Batch action classification completed.",
            data={
                "total": len(actions),
                "success_count": success_count,
                "failure_count": len(actions) - success_count,
                "items": results,
                "failures": failures,
            },
            metadata={
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "version": self.VERSION,
                "dry_run": dry_run,
                "created_at": self._utc_now(),
            },
        )

    # =========================================================================
    # Public classification functions
    # =========================================================================

    def determine_action_type(
        self,
        action: str,
        *,
        description: Optional[str] = None,
        explicit_action_type: Optional[
            Union[str, ActionType]
        ] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ActionType:
        """Determine canonical action type."""

        if explicit_action_type is not None:
            return self._safe_enum(
                explicit_action_type,
                ActionType,
                ActionType.UNKNOWN,
            )

        metadata = metadata or {}

        metadata_action_type = (
            metadata.get("action_type")
            or metadata.get("operation_type")
        )

        if metadata_action_type is not None:
            parsed = self._safe_enum(
                metadata_action_type,
                ActionType,
                ActionType.UNKNOWN,
            )
            if parsed != ActionType.UNKNOWN:
                return parsed

        text = " ".join(
            item
            for item in (
                self._normalize_text(action),
                self._normalize_text(description),
            )
            if item
        ).lower()

        if not text:
            return ActionType.UNKNOWN

        scores: Dict[ActionType, int] = {}

        for action_type, keywords in self.ACTION_KEYWORDS.items():
            score = 0

            for keyword in keywords:
                normalized_keyword = keyword.lower()

                if normalized_keyword in text:
                    score += 5 if " " in normalized_keyword else 2

                if text == normalized_keyword:
                    score += 10

            if score:
                scores[action_type] = score

        if self._contains_system_command_pattern(text):
            scores[ActionType.SYSTEM_COMMAND] = (
                scores.get(ActionType.SYSTEM_COMMAND, 0) + 20
            )

        if not scores:
            return ActionType.UNKNOWN

        return max(
            scores.items(),
            key=lambda item: item[1],
        )[0]

    def determine_resource_type(
        self,
        resource: Optional[str],
        *,
        action: Optional[str] = None,
        description: Optional[str] = None,
        explicit_resource_type: Optional[
            Union[str, ResourceType]
        ] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ResourceType:
        """Determine the target resource type."""

        if explicit_resource_type is not None:
            return self._safe_enum(
                explicit_resource_type,
                ResourceType,
                ResourceType.UNKNOWN,
            )

        metadata = metadata or {}

        metadata_resource_type = (
            metadata.get("resource_type")
            or metadata.get("target_type")
        )

        if metadata_resource_type is not None:
            parsed = self._safe_enum(
                metadata_resource_type,
                ResourceType,
                ResourceType.UNKNOWN,
            )
            if parsed != ResourceType.UNKNOWN:
                return parsed

        text = " ".join(
            item
            for item in (
                self._normalize_text(resource),
                self._normalize_text(action),
                self._normalize_text(description),
            )
            if item
        ).lower()

        if not text:
            return ResourceType.NONE

        scores: Dict[ResourceType, int] = {}

        for resource_type, keywords in self.RESOURCE_KEYWORDS.items():
            score = 0

            for keyword in keywords:
                normalized_keyword = keyword.lower()

                if normalized_keyword in text:
                    score += 5 if " " in normalized_keyword else 2

            if score:
                scores[resource_type] = score

        if self._looks_like_file_path(text):
            scores[ResourceType.FILE] = (
                scores.get(ResourceType.FILE, 0) + 8
            )

        if self._looks_like_url(text):
            scores[ResourceType.URL] = (
                scores.get(ResourceType.URL, 0) + 8
            )

        if not scores:
            return ResourceType.UNKNOWN

        return max(
            scores.items(),
            key=lambda item: item[1],
        )[0]

    def determine_source_agent(
        self,
        source_agent: Optional[str],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Normalize the action source agent identifier."""

        metadata = metadata or {}

        raw_source = (
            source_agent
            or metadata.get("source_agent")
            or metadata.get("agent_name")
            or metadata.get("agent_id")
            or "unknown_agent"
        )

        normalized = self._normalize_identifier(str(raw_source))

        return normalized or "unknown_agent"

    def determine_source_agent_trust(
        self,
        source_agent: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SourceAgentTrust:
        """Determine baseline trust for the source agent."""

        metadata = metadata or {}

        explicit_trust = metadata.get("source_agent_trust")

        if explicit_trust is not None:
            return self._safe_enum(
                explicit_trust,
                SourceAgentTrust,
                SourceAgentTrust.UNKNOWN,
            )

        normalized = self._normalize_identifier(source_agent)

        if normalized in self.TRUSTED_AGENT_NAMES:
            return self.TRUSTED_AGENT_NAMES[normalized]

        if normalized.startswith("plugin_"):
            return SourceAgentTrust.LIMITED

        if normalized in {
            "",
            "unknown",
            "unknown_agent",
            "external",
            "third_party",
        }:
            return SourceAgentTrust.UNKNOWN

        return SourceAgentTrust.STANDARD

    def determine_sensitivity(
        self,
        *,
        action_type: ActionType,
        resource_type: ResourceType,
        combined_text: str,
        source_agent_trust: SourceAgentTrust,
        cross_user_scope: bool,
        cross_workspace_scope: bool,
        explicit_sensitivity: Optional[
            Union[str, SensitivityLevel]
        ] = None,
        metadata: Optional[Dict[str, Any]] = None,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> SensitivityLevel:
        """Determine sensitivity using action, resource, text, and scope."""

        if explicit_sensitivity is not None:
            return self._safe_enum(
                explicit_sensitivity,
                SensitivityLevel,
                SensitivityLevel.SENSITIVE,
            )

        metadata = metadata or {}
        parameters = parameters or {}

        metadata_sensitivity = metadata.get("sensitivity")

        if metadata_sensitivity is not None:
            parsed = self._safe_enum(
                metadata_sensitivity,
                SensitivityLevel,
                SensitivityLevel.SENSITIVE,
            )
            return parsed

        score = 1

        if resource_type in self.CRITICAL_RESOURCES:
            score = max(score, 6)

        elif resource_type in self.CONFIDENTIAL_RESOURCES:
            score = max(score, 4)

        elif resource_type in {
            ResourceType.PROJECT_DATA,
            ResourceType.WORKSPACE,
            ResourceType.AGENT_CONFIGURATION,
            ResourceType.SOURCE_CODE,
            ResourceType.REPOSITORY,
            ResourceType.DEPLOYMENT,
            ResourceType.SYSTEM,
        }:
            score = max(score, 3)

        if action_type in self.FINANCIAL_ACTIONS:
            score = max(score, 6)

        if action_type in self.PRIVILEGED_ACTIONS:
            score = max(score, 6)

        if action_type in {
            ActionType.DELETE,
            ActionType.DEPLOY,
            ActionType.ROLLBACK,
            ActionType.SYSTEM_COMMAND,
            ActionType.DATABASE_OPERATION,
            ActionType.MEMORY_DELETE,
        }:
            score = max(score, 5)

        if action_type in {
            ActionType.EMAIL,
            ActionType.MESSAGE,
            ActionType.CALL,
            ActionType.PUBLISH,
            ActionType.EXPORT,
        }:
            score = max(score, 4)

        if self._contains_secret_pattern(combined_text):
            score = max(score, 6)

        if self._mapping_contains_sensitive_values(parameters):
            score = max(score, 6)

        if cross_user_scope:
            score += 1

        if cross_workspace_scope:
            score += 2

        if source_agent_trust in {
            SourceAgentTrust.UNTRUSTED,
            SourceAgentTrust.UNKNOWN,
        }:
            score += 1

        score = min(score, 7)

        mapping = {
            1: SensitivityLevel.PUBLIC,
            2: SensitivityLevel.LOW,
            3: SensitivityLevel.INTERNAL,
            4: SensitivityLevel.SENSITIVE,
            5: SensitivityLevel.CONFIDENTIAL,
            6: SensitivityLevel.RESTRICTED,
            7: SensitivityLevel.CRITICAL,
        }

        return mapping[score]

    def determine_permission_level(
        self,
        *,
        action_type: ActionType,
        resource_type: ResourceType,
        sensitivity: SensitivityLevel,
        cross_user_scope: bool,
        cross_workspace_scope: bool,
        explicit_permission_level: Optional[
            Union[str, PermissionLevel]
        ] = None,
    ) -> PermissionLevel:
        """Determine the minimum permission level."""

        if explicit_permission_level is not None:
            return self._safe_enum(
                explicit_permission_level,
                PermissionLevel,
                PermissionLevel.EXPLICIT_APPROVAL,
            )

        if cross_workspace_scope:
            return PermissionLevel.SUPER_ADMIN

        if action_type in {
            ActionType.GRANT_PERMISSION,
            ActionType.REVOKE_PERMISSION,
            ActionType.CHANGE_ROLE,
        }:
            return PermissionLevel.SECURITY_ADMIN

        if action_type in {
            ActionType.ACCESS_SECRET,
            ActionType.ROTATE_SECRET,
            ActionType.SECURITY_OPERATION,
            ActionType.BIOMETRIC_OPERATION,
        }:
            return PermissionLevel.SECURITY_ADMIN

        if action_type in {
            ActionType.SYSTEM_COMMAND,
            ActionType.INSTALL,
            ActionType.UNINSTALL,
            ActionType.RESTART,
            ActionType.DEPLOY,
            ActionType.ROLLBACK,
        } or resource_type in {
            ResourceType.SYSTEM,
            ResourceType.SERVICE,
            ResourceType.PROCESS,
            ResourceType.DEPLOYMENT,
            ResourceType.CLOUD_RESOURCE,
        }:
            return PermissionLevel.SYSTEM_ADMIN

        if action_type in self.FINANCIAL_ACTIONS:
            return PermissionLevel.EXPLICIT_APPROVAL

        if sensitivity == SensitivityLevel.CRITICAL:
            return PermissionLevel.SUPER_ADMIN

        if sensitivity == SensitivityLevel.RESTRICTED:
            return PermissionLevel.SECURITY_ADMIN

        if cross_user_scope:
            return PermissionLevel.WORKSPACE_OWNER

        if action_type in self.DESTRUCTIVE_ACTIONS:
            return PermissionLevel.ADMIN

        if sensitivity == SensitivityLevel.CONFIDENTIAL:
            return PermissionLevel.ADMIN

        if sensitivity == SensitivityLevel.SENSITIVE:
            return PermissionLevel.MANAGER

        if sensitivity == SensitivityLevel.INTERNAL:
            return PermissionLevel.WORKSPACE_MEMBER

        if sensitivity == SensitivityLevel.LOW:
            return PermissionLevel.AUTHENTICATED

        if sensitivity == SensitivityLevel.PUBLIC:
            if action_type in {
                ActionType.READ,
                ActionType.SEARCH,
                ActionType.LIST,
                ActionType.BROWSER_NAVIGATION,
            }:
                return PermissionLevel.PUBLIC
            return PermissionLevel.AUTHENTICATED

        return PermissionLevel.EXPLICIT_APPROVAL

    def calculate_risk_score(
        self,
        *,
        action_type: ActionType,
        resource_type: ResourceType,
        sensitivity: SensitivityLevel,
        source_agent_trust: SourceAgentTrust,
        destructive: bool,
        financial: bool,
        external_side_effect: bool,
        cross_user_scope: bool,
        cross_workspace_scope: bool,
        combined_text: str,
        metadata: Optional[Dict[str, Any]] = None,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Tuple[float, List[str]]:
        """
        Calculate deterministic normalized risk score from 0.0 to 1.0.
        """

        metadata = metadata or {}
        parameters = parameters or {}

        score = 0.05
        indicators: List[str] = []

        sensitivity_weights = {
            SensitivityLevel.PUBLIC: 0.00,
            SensitivityLevel.LOW: 0.05,
            SensitivityLevel.INTERNAL: 0.12,
            SensitivityLevel.SENSITIVE: 0.22,
            SensitivityLevel.CONFIDENTIAL: 0.35,
            SensitivityLevel.RESTRICTED: 0.48,
            SensitivityLevel.CRITICAL: 0.60,
        }

        score += sensitivity_weights[sensitivity]

        if sensitivity in {
            SensitivityLevel.CONFIDENTIAL,
            SensitivityLevel.RESTRICTED,
            SensitivityLevel.CRITICAL,
        }:
            indicators.append(
                f"High-sensitivity classification: {sensitivity.value}."
            )

        if destructive:
            score += 0.20
            indicators.append("Action is destructive.")

        if financial:
            score += 0.25
            indicators.append("Action has financial impact.")

        if external_side_effect:
            score += 0.12
            indicators.append("Action creates an external side effect.")

        if action_type in self.PRIVILEGED_ACTIONS:
            score += 0.18
            indicators.append("Action modifies or accesses privileged security state.")

        if resource_type in self.CRITICAL_RESOURCES:
            score += 0.20
            indicators.append(
                f"Target resource is critical: {resource_type.value}."
            )

        if cross_user_scope:
            score += 0.12
            indicators.append("Action targets a different user scope.")

        if cross_workspace_scope:
            score += 0.30
            indicators.append("Action targets a different workspace scope.")

        if source_agent_trust == SourceAgentTrust.LIMITED:
            score += 0.07
            indicators.append("Source agent has limited trust.")

        elif source_agent_trust == SourceAgentTrust.UNTRUSTED:
            score += 0.20
            indicators.append("Source agent is untrusted.")

        elif source_agent_trust == SourceAgentTrust.UNKNOWN:
            score += 0.12
            indicators.append("Source agent trust is unknown.")

        if self._contains_secret_pattern(combined_text):
            score += 0.20
            indicators.append("Action text references credentials or secrets.")

        if self._contains_system_command_pattern(combined_text):
            score += 0.20
            indicators.append("Action text contains a system-command indicator.")

        if self._mapping_contains_sensitive_values(parameters):
            score += 0.20
            indicators.append("Action parameters may contain sensitive values.")

        if metadata.get("unattended") is True:
            score += 0.08
            indicators.append("Action is marked as unattended.")

        if metadata.get("production") is True:
            score += 0.12
            indicators.append("Action targets a production environment.")

        if metadata.get("bulk") is True:
            score += 0.10
            indicators.append("Action is marked as a bulk operation.")

        if metadata.get("irreversible") is True:
            score += 0.15
            indicators.append("Action is marked as irreversible.")

        score = max(0.0, min(round(score, 3), 1.0))

        if not indicators:
            indicators.append("No major risk indicators detected.")

        return score, indicators

    # =========================================================================
    # Required architecture hooks
    # =========================================================================

    def _validate_task_context(
        self,
        request: ActionClassificationInput,
    ) -> Dict[str, Any]:
        """
        Validate required SaaS context and safe identifiers.

        Classification must not silently operate without tenant context when
        strict validation is enabled.
        """

        if not self._normalize_text(request.action):
            return self._error_result(
                message="Action is required for classification.",
                code="MISSING_ACTION",
                metadata=self._base_metadata(request),
            )

        if self.strict_context_validation and not request.user_id:
            return self._error_result(
                message=(
                    "user_id is required to prevent cross-user security "
                    "classification and audit mixing."
                ),
                code="MISSING_USER_ID",
                metadata=self._base_metadata(request),
            )

        if self.workspace_required and not request.workspace_id:
            return self._error_result(
                message=(
                    "workspace_id is required to prevent cross-workspace "
                    "security classification and audit mixing."
                ),
                code="MISSING_WORKSPACE_ID",
                metadata=self._base_metadata(request),
            )

        identifiers = {
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "target_user_id": request.target_user_id,
            "target_workspace_id": request.target_workspace_id,
            "task_id": request.task_id,
            "conversation_id": request.conversation_id,
            "session_id": request.session_id,
            "request_id": request.request_id,
            "resource_id": request.resource_id,
        }

        for name, value in identifiers.items():
            if value is not None and not self._is_safe_identifier(
                str(value)
            ):
                return self._error_result(
                    message=f"Invalid {name} format.",
                    code=f"INVALID_{name.upper()}",
                    metadata=self._base_metadata(request),
                )

        if (
            request.target_workspace_id
            and not request.workspace_id
        ):
            return self._error_result(
                message=(
                    "workspace_id is required when target_workspace_id "
                    "is provided."
                ),
                code="AMBIGUOUS_WORKSPACE_SCOPE",
                metadata=self._base_metadata(request),
            )

        return self._safe_result(
            message="Action classification context validated.",
            data={
                "valid": True,
                "user_scope_present": bool(request.user_id),
                "workspace_scope_present": bool(request.workspace_id),
            },
            metadata=self._base_metadata(request),
        )

    def _requires_security_check(
        self,
        *,
        action_type: ActionType,
        resource_type: ResourceType,
        sensitivity: SensitivityLevel,
        permission_level: PermissionLevel,
        risk_score: float,
        cross_user_scope: bool,
        cross_workspace_scope: bool,
    ) -> bool:
        """Determine whether Security Agent review is mandatory."""

        if cross_workspace_scope or cross_user_scope:
            return True

        if sensitivity in {
            SensitivityLevel.CONFIDENTIAL,
            SensitivityLevel.RESTRICTED,
            SensitivityLevel.CRITICAL,
        }:
            return True

        if permission_level in {
            PermissionLevel.ADMIN,
            PermissionLevel.WORKSPACE_OWNER,
            PermissionLevel.SECURITY_ADMIN,
            PermissionLevel.SYSTEM_ADMIN,
            PermissionLevel.SUPER_ADMIN,
            PermissionLevel.EXPLICIT_APPROVAL,
            PermissionLevel.DENY,
        }:
            return True

        if action_type in (
            self.DESTRUCTIVE_ACTIONS
            | self.FINANCIAL_ACTIONS
            | self.PRIVILEGED_ACTIONS
        ):
            return True

        if resource_type in self.CRITICAL_RESOURCES:
            return True

        return risk_score >= 0.45

    def _request_security_approval(
        self,
        request: ActionClassificationInput,
        classification: ActionClassification,
    ) -> Dict[str, Any]:
        """
        Prepare or submit a Security Agent approval request.

        Without a callback, the request remains pending and no action is
        authorized.
        """

        payload = {
            "approval_request_id": self._new_id("secapproval"),
            "classification_id": classification.classification_id,
            "request_id": request.request_id,
            "requesting_component": self.agent_name,
            "requesting_component_id": self.agent_id,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "target_user_id": request.target_user_id,
            "target_workspace_id": request.target_workspace_id,
            "source_agent": classification.source_agent,
            "action_type": classification.action_type.value,
            "resource_type": classification.resource_type.value,
            "resource_id": request.resource_id,
            "sensitivity": classification.sensitivity.value,
            "permission_level": classification.permission_level.value,
            "risk_score": classification.risk_score,
            "approval_types": [
                item.value
                for item in classification.approval_types
            ],
            "destructive": classification.destructive,
            "financial": classification.financial,
            "external_side_effect": (
                classification.external_side_effect
            ),
            "cross_user_scope": classification.cross_user_scope,
            "cross_workspace_scope": (
                classification.cross_workspace_scope
            ),
            "created_at": self._utc_now(),
        }

        if self.security_approval_callback is None:
            return {
                "success": True,
                "status": "pending",
                "approved": False,
                "message": (
                    "Security approval is required. No approval callback "
                    "is connected, so execution remains unauthorized."
                ),
                "request": payload,
            }

        try:
            response = self.security_approval_callback(payload)

            if not isinstance(response, dict):
                return {
                    "success": False,
                    "status": "invalid_response",
                    "approved": False,
                    "message": (
                        "Security approval callback returned an invalid "
                        "response."
                    ),
                    "request": payload,
                }

            response.setdefault("approved", False)
            response.setdefault("request", payload)

            return response

        except Exception as exc:
            self.logger.exception(
                "Security approval callback failed."
            )
            return {
                "success": False,
                "status": "callback_error",
                "approved": False,
                "message": "Security approval callback failed.",
                "error": {
                    "type": exc.__class__.__name__,
                    "message": str(exc),
                },
                "request": payload,
            }

    def _prepare_verification_payload(
        self,
        *,
        request: ActionClassificationInput,
        classification: ActionClassification,
        security_request: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Prepare a Verification Agent payload."""

        return {
            "verification_id": self._new_id("verify"),
            "verification_type": "security_action_classification",
            "source_agent": self.agent_name,
            "source_agent_id": self.agent_id,
            "classification_id": classification.classification_id,
            "request_id": request.request_id,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "task_id": request.task_id,
            "conversation_id": request.conversation_id,
            "session_id": request.session_id,
            "checks": {
                "user_scope_present": bool(request.user_id),
                "workspace_scope_present": bool(request.workspace_id),
                "action_type_classified": (
                    classification.action_type
                    != ActionType.UNKNOWN
                ),
                "resource_type_classified": (
                    classification.resource_type
                    not in {
                        ResourceType.UNKNOWN,
                        ResourceType.NONE,
                    }
                ),
                "permission_level_assigned": bool(
                    classification.permission_level.value
                ),
                "sensitivity_assigned": bool(
                    classification.sensitivity.value
                ),
                "risk_score_valid": (
                    0.0 <= classification.risk_score <= 1.0
                ),
                "security_request_attached": (
                    security_request is not None
                ),
                "classification_only": True,
                "action_executed": False,
            },
            "classification": self._classification_to_dict(
                classification
            ),
            "security_request": security_request,
            "created_at": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        *,
        request: ActionClassificationInput,
        classification: ActionClassification,
    ) -> Dict[str, Any]:
        """
        Prepare useful, privacy-conscious context for Memory Agent.

        Raw secrets and action parameters are intentionally excluded.
        """

        return {
            "memory_event_id": self._new_id("securitymem"),
            "memory_type": "security_action_classification",
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "task_id": request.task_id,
            "conversation_id": request.conversation_id,
            "classification_id": classification.classification_id,
            "source_agent": classification.source_agent,
            "action_type": classification.action_type.value,
            "resource_type": classification.resource_type.value,
            "sensitivity": classification.sensitivity.value,
            "permission_level": (
                classification.permission_level.value
            ),
            "decision": classification.decision.value,
            "risk_score": classification.risk_score,
            "risk_indicators": classification.risk_indicators,
            "requires_security_check": (
                classification.requires_security_check
            ),
            "requires_explicit_approval": (
                classification.requires_explicit_approval
            ),
            "requires_verification": (
                classification.requires_verification
            ),
            "retention_recommendation": (
                "audit_retention"
                if classification.requires_audit_log
                else "short_term"
            ),
            "privacy_level": classification.sensitivity.value,
            "store_raw_parameters": False,
            "created_at": self._utc_now(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
    ) -> None:
        """Emit a sanitized event for Dashboard/API/Registry."""

        sanitized = self._sanitize_payload(payload)

        if self.event_callback is not None:
            try:
                self.event_callback(event_name, sanitized)
                return
            except Exception:
                self.logger.exception(
                    "ActionClassifier event callback failed."
                )

        try:
            parent_emit = getattr(super(), "emit_event", None)

            if callable(parent_emit):
                parent_emit(event_name, sanitized)
                return

        except Exception:
            self.logger.debug(
                "BaseAgent emit_event unavailable.",
                exc_info=True,
            )

        self.logger.debug(
            "Agent event: %s | %s",
            event_name,
            sanitized,
        )

    def _log_audit_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
    ) -> None:
        """Write a sanitized audit event through available adapters."""

        sanitized = self._sanitize_payload(payload)

        if self.audit_callback is not None:
            try:
                self.audit_callback(event_name, sanitized)
                return
            except Exception:
                self.logger.exception(
                    "ActionClassifier audit callback failed."
                )

        try:
            parent_audit = getattr(super(), "log_audit", None)

            if callable(parent_audit):
                parent_audit(event_name, sanitized)
                return

        except Exception:
            self.logger.debug(
                "BaseAgent log_audit unavailable.",
                exc_info=True,
            )

        self.logger.info(
            "Security audit: %s | %s",
            event_name,
            sanitized,
        )

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return the William standard success structure."""

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "version": self.VERSION,
                "created_at": self._utc_now(),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        code: str = "ACTION_CLASSIFIER_ERROR",
        details: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return the William standard error structure."""

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": {
                "code": code,
                "message": message,
                "details": details or {},
            },
            "metadata": metadata or {
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "version": self.VERSION,
                "created_at": self._utc_now(),
            },
        }

    # =========================================================================
    # Approval, verification, and decision helpers
    # =========================================================================

    def _determine_approval_types(
        self,
        *,
        action_type: ActionType,
        resource_type: ResourceType,
        sensitivity: SensitivityLevel,
        permission_level: PermissionLevel,
        risk_score: float,
        financial: bool,
        destructive: bool,
        cross_user_scope: bool,
        cross_workspace_scope: bool,
    ) -> List[ApprovalType]:
        """Determine all approval mechanisms needed."""

        approvals: List[ApprovalType] = []

        if permission_level == PermissionLevel.DENY:
            return [ApprovalType.DENIED]

        if cross_workspace_scope:
            approvals.extend(
                [
                    ApprovalType.SECURITY_ADMIN,
                    ApprovalType.SYSTEM_ADMIN,
                    ApprovalType.DUAL_APPROVAL,
                ]
            )

        elif cross_user_scope:
            approvals.append(ApprovalType.WORKSPACE_OWNER)

        if financial:
            approvals.extend(
                [
                    ApprovalType.USER_CONFIRMATION,
                    ApprovalType.FINANCE_APPROVAL,
                ]
            )

            if risk_score >= 0.70:
                approvals.append(ApprovalType.MULTI_FACTOR)

        if action_type in {
            ActionType.ACCESS_SECRET,
            ActionType.ROTATE_SECRET,
            ActionType.CHANGE_ROLE,
            ActionType.GRANT_PERMISSION,
            ActionType.REVOKE_PERMISSION,
        }:
            approvals.append(ApprovalType.SECURITY_ADMIN)

        if resource_type == ResourceType.BIOMETRIC_DATA:
            approvals.append(ApprovalType.BIOMETRIC)

        if sensitivity == SensitivityLevel.CRITICAL:
            approvals.extend(
                [
                    ApprovalType.SECURITY_AGENT,
                    ApprovalType.DUAL_APPROVAL,
                    ApprovalType.MULTI_FACTOR,
                ]
            )

        elif sensitivity == SensitivityLevel.RESTRICTED:
            approvals.append(ApprovalType.SECURITY_AGENT)

        if destructive:
            approvals.append(ApprovalType.USER_CONFIRMATION)

            if risk_score >= 0.65:
                approvals.append(ApprovalType.WORKSPACE_ADMIN)

        if permission_level == PermissionLevel.SYSTEM_ADMIN:
            approvals.append(ApprovalType.SYSTEM_ADMIN)

        elif permission_level == PermissionLevel.SECURITY_ADMIN:
            approvals.append(ApprovalType.SECURITY_ADMIN)

        elif permission_level == PermissionLevel.WORKSPACE_OWNER:
            approvals.append(ApprovalType.WORKSPACE_OWNER)

        elif permission_level == PermissionLevel.EXPLICIT_APPROVAL:
            approvals.append(ApprovalType.USER_CONFIRMATION)

        if risk_score >= 0.85:
            approvals.append(ApprovalType.MANUAL_REVIEW)

        unique: List[ApprovalType] = []

        for approval in approvals:
            if approval not in unique:
                unique.append(approval)

        return unique or [ApprovalType.NONE]

    def _requires_verification(
        self,
        *,
        action_type: ActionType,
        sensitivity: SensitivityLevel,
        destructive: bool,
        financial: bool,
        external_side_effect: bool,
        risk_score: float,
    ) -> bool:
        """Determine whether Verification Agent must inspect completion."""

        if destructive or financial or external_side_effect:
            return True

        if sensitivity in {
            SensitivityLevel.CONFIDENTIAL,
            SensitivityLevel.RESTRICTED,
            SensitivityLevel.CRITICAL,
        }:
            return True

        if action_type in {
            ActionType.CREATE,
            ActionType.UPDATE,
            ActionType.DELETE,
            ActionType.EXECUTE,
            ActionType.DEPLOY,
            ActionType.ROLLBACK,
            ActionType.CHANGE_SETTINGS,
            ActionType.GRANT_PERMISSION,
            ActionType.REVOKE_PERMISSION,
            ActionType.CHANGE_ROLE,
        }:
            return True

        return risk_score >= 0.40

    def _requires_audit_log(
        self,
        *,
        action_type: ActionType,
        sensitivity: SensitivityLevel,
        requires_security_check: bool,
        external_side_effect: bool,
    ) -> bool:
        """Determine whether the classification must be audited."""

        if requires_security_check or external_side_effect:
            return True

        if sensitivity not in {
            SensitivityLevel.PUBLIC,
            SensitivityLevel.LOW,
        }:
            return True

        return action_type not in {
            ActionType.READ,
            ActionType.SEARCH,
            ActionType.LIST,
            ActionType.BROWSER_NAVIGATION,
        }

    def _determine_decision(
        self,
        *,
        permission_level: PermissionLevel,
        sensitivity: SensitivityLevel,
        requires_security_check: bool,
        requires_explicit_approval: bool,
        requires_biometric: bool,
        risk_score: float,
        cross_workspace_scope: bool,
    ) -> ClassificationDecision:
        """Determine recommended security handling."""

        if permission_level == PermissionLevel.DENY:
            return ClassificationDecision.DENY

        if cross_workspace_scope and risk_score >= 0.95:
            return ClassificationDecision.DENY

        if requires_biometric:
            return ClassificationDecision.REQUIRE_BIOMETRIC

        if requires_explicit_approval:
            return ClassificationDecision.REQUIRE_APPROVAL

        if requires_security_check:
            return ClassificationDecision.REQUIRE_SECURITY_REVIEW

        if permission_level not in {
            PermissionLevel.NONE,
            PermissionLevel.PUBLIC,
        }:
            return ClassificationDecision.REQUIRE_PERMISSION_CHECK

        if sensitivity in {
            SensitivityLevel.RESTRICTED,
            SensitivityLevel.CRITICAL,
        }:
            return ClassificationDecision.REQUIRE_SECURITY_REVIEW

        return ClassificationDecision.ALLOW_CLASSIFICATION

    def _build_classification_reasons(
        self,
        *,
        action_type: ActionType,
        resource_type: ResourceType,
        source_agent: str,
        source_agent_trust: SourceAgentTrust,
        sensitivity: SensitivityLevel,
        permission_level: PermissionLevel,
        decision: ClassificationDecision,
        destructive: bool,
        financial: bool,
        external_side_effect: bool,
        cross_user_scope: bool,
        cross_workspace_scope: bool,
        risk_score: float,
    ) -> List[str]:
        """Build human-readable classification reasons."""

        reasons = [
            f"Action type classified as {action_type.value}.",
            f"Resource type classified as {resource_type.value}.",
            (
                f"Source agent '{source_agent}' has "
                f"{source_agent_trust.value} trust."
            ),
            f"Sensitivity classified as {sensitivity.value}.",
            (
                f"Minimum permission level is "
                f"{permission_level.value}."
            ),
            f"Security decision is {decision.value}.",
            f"Calculated risk score is {risk_score:.3f}.",
        ]

        if destructive:
            reasons.append("The action may remove, stop, or reverse data or services.")

        if financial:
            reasons.append("The action may create a financial consequence.")

        if external_side_effect:
            reasons.append("The action may affect an external person or system.")

        if cross_user_scope:
            reasons.append("The target user differs from the requesting user.")

        if cross_workspace_scope:
            reasons.append(
                "The target workspace differs from the requesting workspace."
            )

        return reasons

    # =========================================================================
    # Scope and security detection
    # =========================================================================

    def _is_cross_user_scope(
        self,
        request: ActionClassificationInput,
    ) -> bool:
        """Detect whether an action targets another user."""

        target_user_id = (
            request.target_user_id
            or request.metadata.get("target_user_id")
            or request.parameters.get("target_user_id")
            or request.parameters.get("owner_user_id")
        )

        return bool(
            request.user_id
            and target_user_id
            and str(request.user_id) != str(target_user_id)
        )

    def _is_cross_workspace_scope(
        self,
        request: ActionClassificationInput,
    ) -> bool:
        """Detect whether an action targets another workspace."""

        target_workspace_id = (
            request.target_workspace_id
            or request.metadata.get("target_workspace_id")
            or request.parameters.get("target_workspace_id")
            or request.parameters.get("owner_workspace_id")
        )

        return bool(
            request.workspace_id
            and target_workspace_id
            and str(request.workspace_id)
            != str(target_workspace_id)
        )

    def _contains_secret_pattern(self, text: str) -> bool:
        """Detect secret-related terms without extracting secret values."""

        normalized = self._normalize_text(text)

        return any(
            re.search(pattern, normalized, flags=re.IGNORECASE)
            for pattern in self.SECRET_PATTERNS
        )

    def _contains_system_command_pattern(self, text: str) -> bool:
        """Detect potentially privileged system commands."""

        normalized = self._normalize_text(text)

        return any(
            re.search(pattern, normalized, flags=re.IGNORECASE)
            for pattern in self.SYSTEM_COMMAND_PATTERNS
        )

    def _mapping_contains_sensitive_values(
        self,
        mapping: Mapping[str, Any],
    ) -> bool:
        """
        Detect sensitive parameter keys without exposing values.
        """

        sensitive_fragments = (
            "password",
            "passcode",
            "secret",
            "token",
            "api_key",
            "apikey",
            "private_key",
            "credential",
            "cvv",
            "card_number",
            "otp",
            "authorization",
        )

        for key, value in mapping.items():
            normalized_key = str(key).lower()

            if any(
                fragment in normalized_key
                for fragment in sensitive_fragments
            ):
                return True

            if isinstance(value, Mapping):
                if self._mapping_contains_sensitive_values(value):
                    return True

            elif isinstance(value, (list, tuple)):
                for item in value:
                    if isinstance(item, Mapping):
                        if self._mapping_contains_sensitive_values(item):
                            return True

        return False

    # =========================================================================
    # Conversion and normalization helpers
    # =========================================================================

    def _classification_to_dict(
        self,
        classification: ActionClassification,
    ) -> Dict[str, Any]:
        """Convert classification dataclass into JSON-safe form."""

        result = asdict(classification)

        result["action_type"] = classification.action_type.value
        result["resource_type"] = classification.resource_type.value
        result["source_agent_trust"] = (
            classification.source_agent_trust.value
        )
        result["sensitivity"] = classification.sensitivity.value
        result["permission_level"] = (
            classification.permission_level.value
        )
        result["decision"] = classification.decision.value
        result["approval_types"] = [
            item.value
            for item in classification.approval_types
        ]

        return result

    def _normalize_batch_item(
        self,
        item: Union[
            str,
            Mapping[str, Any],
            ActionClassificationInput,
        ],
        *,
        default_user_id: Optional[str],
        default_workspace_id: Optional[str],
        default_source_agent: Optional[str],
        default_metadata: Dict[str, Any],
        dry_run: bool,
    ) -> Dict[str, Any]:
        """Normalize a batch item into classify_action arguments."""

        if isinstance(item, str):
            return {
                "action": item,
                "user_id": default_user_id,
                "workspace_id": default_workspace_id,
                "source_agent": default_source_agent,
                "metadata": dict(default_metadata),
                "dry_run": dry_run,
            }

        if isinstance(item, ActionClassificationInput):
            payload = asdict(item)

        elif isinstance(item, Mapping):
            payload = dict(item)

        else:
            raise TypeError(
                "Each batch item must be a string, mapping, or "
                "ActionClassificationInput."
            )

        if "action" not in payload:
            raise ValueError("Batch action item must include 'action'.")

        payload.setdefault("user_id", default_user_id)
        payload.setdefault("workspace_id", default_workspace_id)
        payload.setdefault("source_agent", default_source_agent)
        payload.setdefault("dry_run", dry_run)

        payload["metadata"] = {
            **default_metadata,
            **dict(payload.get("metadata") or {}),
        }

        payload["parameters"] = dict(
            payload.get("parameters") or {}
        )

        return payload

    def _safe_enum(
        self,
        value: Union[str, Enum],
        enum_class: Type[EnumType],
        default: EnumType,
    ) -> EnumType:
        """Convert a string or enum into a target enum safely."""

        if isinstance(value, enum_class):
            return value

        normalized = str(value).strip().lower()

        for member in enum_class:
            if (
                normalized == str(member.value).lower()
                or normalized == member.name.lower()
            ):
                return member

        return default

    def _normalize_text(self, value: Any) -> str:
        """Normalize text while preserving semantic content."""

        if value is None:
            return ""

        text = str(value).replace("\x00", "")
        text = re.sub(r"\s+", " ", text).strip()

        return text

    def _normalize_identifier(self, value: str) -> str:
        """Normalize an agent or component identifier."""

        value = self._normalize_text(value).lower()
        value = re.sub(r"[^a-z0-9_.:\-]+", "_", value)
        value = re.sub(r"_+", "_", value).strip("_")

        return value

    def _is_safe_identifier(self, value: str) -> bool:
        """Validate common UUID, integer, slug, and external ID formats."""

        return bool(
            re.fullmatch(
                r"[A-Za-z0-9_.:@\-]{1,160}",
                value,
            )
        )

    def _looks_like_file_path(self, value: str) -> bool:
        """Detect common file path patterns."""

        patterns = (
            r"(?:[A-Za-z0-9_.\-]+/)+[A-Za-z0-9_.\-]+",
            r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*"
            r"[^\\/:*?\"<>|\r\n]*",
            r"\b[A-Za-z0-9_.\-]+\.(?:py|js|ts|php|html|css|json|"
            r"yaml|yml|txt|csv|pdf|docx|xlsx|pptx)\b",
        )

        return any(
            re.search(pattern, value, flags=re.IGNORECASE)
            for pattern in patterns
        )

    def _looks_like_url(self, value: str) -> bool:
        """Detect HTTP, HTTPS, or domain-like URLs."""

        return bool(
            re.search(
                r"\bhttps?://[^\s]+|"
                r"\b[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+"
                r"(?:/[^\s]*)?",
                value,
                flags=re.IGNORECASE,
            )
        )

    def _build_action_fingerprint(
        self,
        request: ActionClassificationInput,
    ) -> str:
        """
        Build a scope-aware fingerprint for deduplication.

        Raw parameters are not included to avoid hashing unnecessary secrets.
        """

        material = "|".join(
            [
                self._normalize_text(request.action),
                self._normalize_text(request.resource),
                str(request.resource_id or ""),
                str(request.user_id or ""),
                str(request.workspace_id or ""),
                str(request.target_user_id or ""),
                str(request.target_workspace_id or ""),
                self._normalize_identifier(
                    request.source_agent or "unknown_agent"
                ),
            ]
        )

        return hashlib.sha256(
            material.encode("utf-8")
        ).hexdigest()

    def _sanitize_payload(
        self,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Recursively sanitize sensitive values before logging or events."""

        sensitive_fragments = (
            "password",
            "passcode",
            "secret",
            "token",
            "api_key",
            "apikey",
            "private_key",
            "credential",
            "authorization",
            "cookie",
            "cvv",
            "card_number",
            "otp",
        )

        sanitized: Dict[str, Any] = {}

        for key, value in payload.items():
            normalized_key = str(key).lower()

            if any(
                fragment in normalized_key
                for fragment in sensitive_fragments
            ):
                sanitized[str(key)] = "[REDACTED]"
                continue

            if normalized_key in {
                "parameters",
                "request_body",
                "raw_body",
                "raw_content",
            }:
                sanitized[str(key)] = "[OMITTED]"
                continue

            if isinstance(value, Mapping):
                sanitized[str(key)] = self._sanitize_payload(value)

            elif isinstance(value, list):
                sanitized[str(key)] = [
                    self._sanitize_payload(item)
                    if isinstance(item, Mapping)
                    else item
                    for item in value
                ]

            elif isinstance(value, tuple):
                sanitized[str(key)] = [
                    self._sanitize_payload(item)
                    if isinstance(item, Mapping)
                    else item
                    for item in value
                ]

            else:
                sanitized[str(key)] = value

        return sanitized

    def _base_metadata(
        self,
        request: Optional[ActionClassificationInput] = None,
    ) -> Dict[str, Any]:
        """Build standard response metadata."""

        metadata: Dict[str, Any] = {
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "module": "agents.security_agent.action_classifier",
            "version": self.VERSION,
            "classification_only": True,
            "created_at": self._utc_now(),
        }

        if request is not None:
            metadata.update(
                {
                    "user_id": request.user_id,
                    "workspace_id": request.workspace_id,
                    "task_id": request.task_id,
                    "conversation_id": request.conversation_id,
                    "session_id": request.session_id,
                    "request_id": request.request_id,
                    "source_agent": request.source_agent,
                    "dry_run": request.dry_run,
                }
            )

        return metadata

    def _utc_now(self) -> str:
        """Return an ISO-8601 UTC timestamp."""

        return datetime.now(timezone.utc).isoformat()

    def _new_id(self, prefix: str) -> str:
        """Generate a prefixed unique identifier."""

        return f"{prefix}_{uuid.uuid4().hex}"

    # =========================================================================
    # Registry and dashboard compatibility
    # =========================================================================

    def get_agent_manifest(self) -> Dict[str, Any]:
        """Return an Agent Registry-compatible manifest."""

        return {
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "class_name": self.__class__.__name__,
            "module": "agents.security_agent.action_classifier",
            "version": self.VERSION,
            "agent_module": "security_agent",
            "component_type": "security_helper",
            "capabilities": [
                "action_type_classification",
                "resource_type_classification",
                "source_agent_classification",
                "source_agent_trust_classification",
                "sensitivity_classification",
                "permission_level_classification",
                "risk_scoring",
                "approval_requirement_classification",
                "cross_user_scope_detection",
                "cross_workspace_scope_detection",
                "verification_payload_preparation",
                "memory_payload_preparation",
                "audit_event_preparation",
            ],
            "supported_hooks": [
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
            "requires_user_id": self.strict_context_validation,
            "requires_workspace_id": self.workspace_required,
            "executes_actions": False,
            "modifies_resources": False,
            "safe_to_import": True,
            "created_at": self._utc_now(),
        }

    def health_check(self) -> Dict[str, Any]:
        """Return component health for Dashboard/API monitoring."""

        return self._safe_result(
            message="ActionClassifier is healthy.",
            data={
                "status": "healthy",
                "agent_name": self.agent_name,
                "agent_id": self.agent_id,
                "version": self.VERSION,
                "strict_context_validation": (
                    self.strict_context_validation
                ),
                "workspace_required": self.workspace_required,
                "security_callback_connected": (
                    self.security_approval_callback is not None
                ),
                "event_callback_connected": (
                    self.event_callback is not None
                ),
                "audit_callback_connected": (
                    self.audit_callback is not None
                ),
                "supported_action_types": len(ActionType),
                "supported_resource_types": len(ResourceType),
                "supported_sensitivity_levels": len(
                    SensitivityLevel
                ),
                "supported_permission_levels": len(
                    PermissionLevel
                ),
                "classification_only": True,
            },
            metadata=self._base_metadata(),
        )


# =============================================================================
# Standalone smoke test
# =============================================================================

def _smoke_test() -> Dict[str, Any]:
    """
    Run a harmless classification-only smoke test.

    No action is executed and no external resource is accessed.
    """

    classifier = ActionClassifier()

    return classifier.classify_action(
        "Deploy the application to production",
        user_id="user_demo",
        workspace_id="workspace_demo",
        source_agent="code_agent",
        resource="production deployment",
        resource_id="deployment_demo",
        description=(
            "Prepare a production deployment classification without "
            "executing the deployment."
        ),
        task_id="task_demo",
        request_id="request_demo",
        metadata={
            "production": True,
            "unattended": False,
        },
        dry_run=True,
    )


if __name__ == "__main__":
    import json

    logging.basicConfig(level=logging.INFO)

    print(
        json.dumps(
            _smoke_test(),
            indent=2,
            default=str,
        )
    )


# FILE COMPLETE