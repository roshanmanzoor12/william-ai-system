"""
agents/visual_agent/screen_context.py

ScreenContext for William / Jarvis Visual Agent.

Purpose:
    Detects the current screen/app/page/workflow context from OCR text, UI elements,
    browser metadata, app/window metadata, screenshot metadata, and prior workflow hints.

Architecture Fit:
    - Part of William / Jarvis Visual Agent.
    - Compatible with Master Agent routing, Agent Registry, Agent Loader, Dashboard/API,
      Memory Agent, Security Agent, and Verification Agent.
    - Import-safe even when future William modules are not created yet.
    - SaaS-safe: validates user_id and workspace_id for user-specific execution.
    - Does not perform real system/browser/call/message/destructive actions.
    - Produces structured JSON-style results:
        {
            "success": bool,
            "message": str,
            "data": dict,
            "error": dict | None,
            "metadata": dict
        }

Responsibilities:
    - Detect current app context: browser, code editor, terminal, dashboard, email,
      calendar, CRM, WordPress, Google Sheets, ad platform, payment page, etc.
    - Detect current page/screen type: login, signup, dashboard, form, checkout,
      payment, search results, error, success confirmation, file upload, chat, etc.
    - Detect workflow stage: authentication, search, form filling, file upload,
      content editing, code editing, configuration, checkout, payment, submission,
      error handling, success, communication, data review.
    - Produce confidence scores, evidence, safe memory payloads, verification payloads,
      audit events, and routing hints.
    - Keep all outputs sanitized and safe for multi-tenant SaaS use.

Important:
    This file does not run OCR itself, does not inspect the real screen directly,
    and does not control apps. It classifies context from data supplied by other agents.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as _dt
import json
import logging
import math
import re
import traceback
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union


# ======================================================================================
# Optional BaseAgent import with safe fallback
# ======================================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent used only when the real William/Jarvis BaseAgent is not
        available yet. Keeps this file import-safe during staged development.
        """

        agent_name: str = "base_agent_fallback"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_name, payload)

        def log_audit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.info("Fallback audit_event: %s %s", event_name, payload)


# ======================================================================================
# Enums and Constants
# ======================================================================================

class ScreenAppType(str, Enum):
    UNKNOWN = "unknown"
    BROWSER = "browser"
    WEB_APP = "web_app"
    DESKTOP_APP = "desktop_app"
    MOBILE_APP = "mobile_app"
    CODE_EDITOR = "code_editor"
    TERMINAL = "terminal"
    FILE_MANAGER = "file_manager"
    EMAIL = "email"
    CALENDAR = "calendar"
    CRM = "crm"
    DASHBOARD = "dashboard"
    WORDPRESS = "wordpress"
    GOOGLE_SHEETS = "google_sheets"
    GOOGLE_DOCS = "google_docs"
    GOOGLE_FORMS = "google_forms"
    SOCIAL_MEDIA = "social_media"
    AD_PLATFORM = "ad_platform"
    PAYMENT = "payment"
    COMMUNICATION = "communication"
    DESIGN_TOOL = "design_tool"
    SECURITY_PAGE = "security_page"
    SETTINGS = "settings"


class ScreenPageType(str, Enum):
    UNKNOWN = "unknown"
    LOGIN = "login"
    SIGNUP = "signup"
    FORGOT_PASSWORD = "forgot_password"
    RESET_PASSWORD = "reset_password"
    DASHBOARD = "dashboard"
    ADMIN = "admin"
    FORM = "form"
    SEARCH_RESULTS = "search_results"
    PRODUCT_PAGE = "product_page"
    CHECKOUT = "checkout"
    PAYMENT = "payment"
    SETTINGS = "settings"
    PROFILE = "profile"
    CONTENT_EDITOR = "content_editor"
    CODE_VIEW = "code_view"
    TERMINAL_VIEW = "terminal_view"
    ERROR = "error"
    SUCCESS_CONFIRMATION = "success_confirmation"
    LIST_TABLE = "list_table"
    DETAIL_VIEW = "detail_view"
    MAP_VIEW = "map_view"
    CHAT = "chat"
    CALL_SCREEN = "call_screen"
    FILE_UPLOAD = "file_upload"
    LANDING_PAGE = "landing_page"
    WORDPRESS_ADMIN = "wordpress_admin"
    ANALYTICS = "analytics"


class WorkflowStage(str, Enum):
    UNKNOWN = "unknown"
    START = "start"
    NAVIGATION = "navigation"
    AUTHENTICATION = "authentication"
    LOGIN = "login"
    SIGNUP = "signup"
    SEARCH = "search"
    REVIEW = "review"
    FORM_FILLING = "form_filling"
    FILE_UPLOAD = "file_upload"
    CONTENT_EDITING = "content_editing"
    CODE_EDITING = "code_editing"
    CONFIGURATION = "configuration"
    PAYMENT = "payment"
    CHECKOUT = "checkout"
    SUBMISSION = "submission"
    PROCESSING = "processing"
    ERROR_HANDLING = "error_handling"
    SUCCESS = "success"
    VERIFICATION = "verification"
    COMMUNICATION = "communication"
    CALLING = "calling"
    DATA_REVIEW = "data_review"


class ContextRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


SENSITIVE_KEYS: Tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "cookies",
    "session",
    "credential",
    "private_key",
    "access_key",
    "refresh_token",
)

DEFAULT_ERROR_PATTERNS: Tuple[str, ...] = (
    r"\b404\b",
    r"\b403\b",
    r"\b401\b",
    r"\b500\b",
    r"\b502\b",
    r"\b503\b",
    r"\b504\b",
    r"page not found",
    r"not found",
    r"access denied",
    r"forbidden",
    r"unauthorized",
    r"internal server error",
    r"bad gateway",
    r"service unavailable",
    r"gateway timeout",
    r"this site can.?t be reached",
    r"connection timed out",
    r"connection refused",
    r"dns_probe",
    r"err_name_not_resolved",
    r"err_connection",
    r"privacy error",
    r"certificate error",
    r"ssl error",
    r"aw,\s*snap",
    r"crashed",
    r"failed",
    r"something went wrong",
    r"invalid",
)


APP_RULES: Dict[str, Dict[str, Any]] = {
    ScreenAppType.BROWSER.value: {
        "keywords": [
            "address bar", "new tab", "chrome", "firefox", "edge", "safari",
            "browser", "http://", "https://", "back", "forward", "refresh",
        ],
        "url_domains": [],
        "weight": 1.0,
    },
    ScreenAppType.CODE_EDITOR.value: {
        "keywords": [
            "visual studio code", "vscode", "pycharm", "cursor", "sublime",
            "atom", "file explorer", "source control", "terminal", "problems",
            "debug console", ".py", ".js", ".ts", ".tsx", ".php", ".html",
            ".css", "def ", "class ", "function ", "import ",
        ],
        "url_domains": [],
        "weight": 1.25,
    },
    ScreenAppType.TERMINAL.value: {
        "keywords": [
            "powershell", "cmd.exe", "terminal", "bash", "zsh", "ubuntu",
            "wsl", "root@", "$ ", "> ", "npm ", "pip ", "python ",
            "git ", "docker ", "uvicorn",
        ],
        "url_domains": [],
        "weight": 1.2,
    },
    ScreenAppType.WORDPRESS.value: {
        "keywords": [
            "wordpress", "wp-admin", "dashboard", "plugins", "appearance",
            "elementor", "woocommerce", "pages", "posts", "media library",
        ],
        "url_domains": [],
        "weight": 1.35,
    },
    ScreenAppType.GOOGLE_SHEETS.value: {
        "keywords": [
            "google sheets", "spreadsheet", "sheet", "rows", "columns",
            "formula", "insert chart", "data validation",
        ],
        "url_domains": ["docs.google.com/spreadsheets"],
        "weight": 1.35,
    },
    ScreenAppType.GOOGLE_DOCS.value: {
        "keywords": [
            "google docs", "document", "editing", "suggesting", "word count", "docs",
        ],
        "url_domains": ["docs.google.com/document"],
        "weight": 1.25,
    },
    ScreenAppType.GOOGLE_FORMS.value: {
        "keywords": [
            "google forms", "questions", "responses", "form description",
            "required", "short answer", "multiple choice",
        ],
        "url_domains": ["docs.google.com/forms"],
        "weight": 1.35,
    },
    ScreenAppType.EMAIL.value: {
        "keywords": [
            "gmail", "inbox", "compose", "sent", "drafts", "subject",
            "from", "to", "reply", "forward",
        ],
        "url_domains": ["mail.google.com", "outlook.live.com", "outlook.office.com"],
        "weight": 1.25,
    },
    ScreenAppType.CALENDAR.value: {
        "keywords": [
            "calendar", "event", "meeting", "schedule", "today", "week",
            "month", "invite guests",
        ],
        "url_domains": ["calendar.google.com"],
        "weight": 1.2,
    },
    ScreenAppType.CRM.value: {
        "keywords": [
            "crm", "leads", "contacts", "pipeline", "deal", "opportunity",
            "customer", "sales", "hubspot", "salesforce", "zoho",
        ],
        "url_domains": ["hubspot.com", "salesforce.com", "zoho.com"],
        "weight": 1.2,
    },
    ScreenAppType.AD_PLATFORM.value: {
        "keywords": [
            "ads manager", "campaigns", "ad set", "budget", "cpc", "cpm",
            "ctr", "conversions", "meta ads", "google ads", "tiktok ads",
        ],
        "url_domains": ["adsmanager.facebook.com", "ads.google.com", "business.facebook.com"],
        "weight": 1.35,
    },
    ScreenAppType.PAYMENT.value: {
        "keywords": [
            "stripe", "paypal", "checkout", "invoice", "payment", "billing",
            "card number", "subscription",
        ],
        "url_domains": ["stripe.com", "paypal.com"],
        "weight": 1.3,
    },
    ScreenAppType.COMMUNICATION.value: {
        "keywords": [
            "slack", "discord", "teams", "whatsapp", "message", "chat",
            "channel", "thread",
        ],
        "url_domains": ["slack.com", "discord.com", "teams.microsoft.com", "web.whatsapp.com"],
        "weight": 1.2,
    },
    ScreenAppType.DESIGN_TOOL.value: {
        "keywords": [
            "figma", "canva", "photoshop", "illustrator", "layers", "frame",
            "design", "prototype", "assets",
        ],
        "url_domains": ["figma.com", "canva.com", "adobe.com"],
        "weight": 1.2,
    },
    ScreenAppType.SETTINGS.value: {
        "keywords": [
            "settings", "preferences", "configuration", "account settings",
            "permissions", "privacy", "security",
        ],
        "url_domains": [],
        "weight": 1.0,
    },
}


PAGE_RULES: Dict[str, Dict[str, Any]] = {
    ScreenPageType.LOGIN.value: {
        "keywords": ["login", "log in", "sign in", "email", "password", "remember me", "forgot password"],
        "required_any": ["password", "sign in", "login", "log in"],
        "weight": 1.35,
    },
    ScreenPageType.SIGNUP.value: {
        "keywords": ["signup", "sign up", "create account", "register", "get started", "confirm password"],
        "required_any": ["sign up", "create account", "register"],
        "weight": 1.3,
    },
    ScreenPageType.FORGOT_PASSWORD.value: {
        "keywords": ["forgot password", "reset password", "recover account", "send reset link"],
        "required_any": ["forgot password", "reset password"],
        "weight": 1.35,
    },
    ScreenPageType.DASHBOARD.value: {
        "keywords": ["dashboard", "overview", "analytics", "reports", "summary", "stats", "activity"],
        "required_any": ["dashboard", "overview", "analytics"],
        "weight": 1.2,
    },
    ScreenPageType.ADMIN.value: {
        "keywords": ["admin", "administrator", "manage", "users", "roles", "permissions", "settings"],
        "required_any": ["admin", "manage", "permissions"],
        "weight": 1.1,
    },
    ScreenPageType.FORM.value: {
        "keywords": ["form", "submit", "required", "first name", "last name", "email", "phone", "message"],
        "required_any": ["submit", "required", "email"],
        "weight": 1.15,
    },
    ScreenPageType.SEARCH_RESULTS.value: {
        "keywords": ["search", "results", "sponsored", "people also ask", "related searches", "more results"],
        "required_any": ["search", "results", "sponsored"],
        "weight": 1.25,
    },
    ScreenPageType.CHECKOUT.value: {
        "keywords": ["checkout", "cart", "shipping", "billing", "place order", "order summary", "total"],
        "required_any": ["checkout", "cart", "order summary", "place order"],
        "weight": 1.35,
    },
    ScreenPageType.PAYMENT.value: {
        "keywords": ["payment", "card number", "expiry", "cvv", "billing", "pay now", "invoice"],
        "required_any": ["payment", "card number", "pay now"],
        "weight": 1.35,
    },
    ScreenPageType.SETTINGS.value: {
        "keywords": ["settings", "preferences", "configuration", "profile", "notifications", "privacy"],
        "required_any": ["settings", "preferences", "configuration"],
        "weight": 1.15,
    },
    ScreenPageType.CONTENT_EDITOR.value: {
        "keywords": ["editor", "publish", "update", "draft", "preview", "blocks", "elementor", "content"],
        "required_any": ["publish", "update", "editor", "draft"],
        "weight": 1.2,
    },
    ScreenPageType.CODE_VIEW.value: {
        "keywords": ["def ", "class ", "function ", "import ", "const ", "return ", "try:", "except", "{", "}"],
        "required_any": ["def ", "class ", "function ", "import ", "return "],
        "weight": 1.25,
    },
    ScreenPageType.TERMINAL_VIEW.value: {
        "keywords": ["npm", "pip", "python", "git", "docker", "uvicorn", "error:", "warning:", "$", ">"],
        "required_any": ["npm", "pip", "python", "git", "docker", "$", ">"],
        "weight": 1.25,
    },
    ScreenPageType.ERROR.value: {
        "keywords": list(DEFAULT_ERROR_PATTERNS),
        "required_any": ["error", "failed", "not found", "forbidden", "unauthorized"],
        "weight": 1.5,
        "regex": True,
    },
    ScreenPageType.SUCCESS_CONFIRMATION.value: {
        "keywords": ["success", "completed", "thank you", "confirmed", "submitted", "verified", "done"],
        "required_any": ["success", "completed", "thank you", "confirmed", "submitted"],
        "weight": 1.35,
    },
    ScreenPageType.LIST_TABLE.value: {
        "keywords": ["table", "rows", "columns", "filter", "sort", "status", "date", "actions"],
        "required_any": ["filter", "sort", "status", "actions"],
        "weight": 1.1,
    },
    ScreenPageType.CHAT.value: {
        "keywords": ["chat", "message", "send", "reply", "thread", "conversation", "typing"],
        "required_any": ["message", "send", "reply", "chat"],
        "weight": 1.2,
    },
    ScreenPageType.CALL_SCREEN.value: {
        "keywords": ["call", "dial", "phone", "mute", "speaker", "hang up", "incoming", "outgoing"],
        "required_any": ["call", "dial", "phone", "hang up"],
        "weight": 1.35,
    },
    ScreenPageType.FILE_UPLOAD.value: {
        "keywords": ["upload", "choose file", "drag and drop", "browse files", "attachment", "drop file"],
        "required_any": ["upload", "choose file", "drag and drop", "browse files"],
        "weight": 1.3,
    },
    ScreenPageType.WORDPRESS_ADMIN.value: {
        "keywords": ["wp-admin", "wordpress", "plugins", "appearance", "pages", "posts", "media", "elementor"],
        "required_any": ["wordpress", "wp-admin", "plugins", "appearance", "elementor"],
        "weight": 1.35,
    },
    ScreenPageType.ANALYTICS.value: {
        "keywords": ["analytics", "sessions", "users", "traffic", "conversion", "cpc", "ctr", "impressions"],
        "required_any": ["analytics", "traffic", "conversion", "impressions"],
        "weight": 1.2,
    },
}


WORKFLOW_RULES: Dict[str, Dict[str, Any]] = {
    WorkflowStage.AUTHENTICATION.value: {
        "keywords": ["login", "log in", "sign in", "signup", "password", "verification code", "2fa"],
        "weight": 1.25,
    },
    WorkflowStage.LOGIN.value: {
        "keywords": ["login", "log in", "sign in", "password", "remember me"],
        "weight": 1.3,
    },
    WorkflowStage.SIGNUP.value: {
        "keywords": ["signup", "sign up", "register", "create account", "confirm password"],
        "weight": 1.3,
    },
    WorkflowStage.SEARCH.value: {
        "keywords": ["search", "results", "query", "sponsored", "filters", "more results"],
        "weight": 1.2,
    },
    WorkflowStage.FORM_FILLING.value: {
        "keywords": ["form", "first name", "last name", "email", "phone", "message", "submit", "required"],
        "weight": 1.2,
    },
    WorkflowStage.FILE_UPLOAD.value: {
        "keywords": ["upload", "choose file", "drag and drop", "browse files", "attachment"],
        "weight": 1.25,
    },
    WorkflowStage.CONTENT_EDITING.value: {
        "keywords": ["edit", "editor", "publish", "update", "draft", "preview", "content", "save changes"],
        "weight": 1.2,
    },
    WorkflowStage.CODE_EDITING.value: {
        "keywords": ["def ", "class ", "function ", "import ", "git", "terminal", "problems", "debug"],
        "weight": 1.25,
    },
    WorkflowStage.CONFIGURATION.value: {
        "keywords": ["settings", "configuration", "permissions", "preferences", "api", "integration"],
        "weight": 1.15,
    },
    WorkflowStage.PAYMENT.value: {
        "keywords": ["payment", "billing", "card number", "invoice", "pay now", "subscription"],
        "weight": 1.35,
    },
    WorkflowStage.CHECKOUT.value: {
        "keywords": ["checkout", "cart", "shipping", "order summary", "place order", "total"],
        "weight": 1.35,
    },
    WorkflowStage.SUBMISSION.value: {
        "keywords": ["submit", "send", "save", "continue", "next", "confirm", "apply"],
        "weight": 1.1,
    },
    WorkflowStage.PROCESSING.value: {
        "keywords": ["loading", "processing", "please wait", "saving", "uploading", "submitting"],
        "weight": 1.15,
    },
    WorkflowStage.ERROR_HANDLING.value: {
        "keywords": ["error", "failed", "invalid", "not found", "access denied", "try again"],
        "weight": 1.4,
    },
    WorkflowStage.SUCCESS.value: {
        "keywords": ["success", "completed", "confirmed", "submitted", "verified", "thank you"],
        "weight": 1.35,
    },
    WorkflowStage.COMMUNICATION.value: {
        "keywords": ["chat", "message", "reply", "email", "compose", "send", "conversation"],
        "weight": 1.15,
    },
    WorkflowStage.CALLING.value: {
        "keywords": ["call", "dial", "phone", "mute", "speaker", "hang up"],
        "weight": 1.3,
    },
    WorkflowStage.DATA_REVIEW.value: {
        "keywords": ["table", "report", "analytics", "status", "filter", "sort", "export", "download"],
        "weight": 1.15,
    },
}


# ======================================================================================
# Data Structures
# ======================================================================================

@dataclass(frozen=True)
class ScreenContextConfig:
    """
    Configuration for ScreenContext.

    strict_workspace_isolation:
        Requires user_id and workspace_id for user-specific tasks.

    max_text_chars:
        Maximum OCR/body text characters used for classification.

    max_evidence_items:
        Maximum evidence items stored in result.

    min_confidence_for_success:
        Minimum confidence for the context detection result to be considered successful.

    include_text_excerpt:
        Whether sanitized OCR text excerpt can be returned.

    event_enabled/audit_enabled:
        Enables local event/audit hooks.

    allow_sensitive_context_memory:
        If False, memory payload only stores safe summaries, not raw OCR text.

    risk_keywords:
        Text that indicates high-sensitivity screens, such as payment, password, API key.
    """

    strict_workspace_isolation: bool = True
    max_text_chars: int = 20000
    max_evidence_items: int = 30
    min_confidence_for_success: float = 0.35
    include_text_excerpt: bool = True
    text_excerpt_chars: int = 1200
    event_enabled: bool = True
    audit_enabled: bool = True
    allow_sensitive_context_memory: bool = False
    default_language: str = "en"
    risk_keywords: Tuple[str, ...] = (
        "password",
        "card number",
        "cvv",
        "secret",
        "api key",
        "token",
        "private key",
        "billing",
        "payment",
        "bank",
        "ssn",
        "social security",
        "passport",
        "authorization",
    )


@dataclass
class UIElementSignal:
    """
    Normalized UI element signal from UI Mapper / Element Detector.
    """

    element_type: Optional[str] = None
    text: Optional[str] = None
    role: Optional[str] = None
    aria_label: Optional[str] = None
    placeholder: Optional[str] = None
    bounds: Optional[Dict[str, Any]] = None
    confidence: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def searchable_text(self) -> str:
        parts = [
            self.element_type or "",
            self.text or "",
            self.role or "",
            self.aria_label or "",
            self.placeholder or "",
        ]
        return " ".join(part for part in parts if part).strip()


@dataclass
class ScreenContextSnapshot:
    """
    Normalized screen context input built from OCR, UI map, browser metadata,
    screenshot metadata, and workflow hints.
    """

    ocr_text: Optional[str] = None
    ui_elements: List[UIElementSignal] = field(default_factory=list)
    url: Optional[str] = None
    title: Optional[str] = None
    app_name: Optional[str] = None
    window_title: Optional[str] = None
    package_name: Optional[str] = None
    route_name: Optional[str] = None
    screenshot_id: Optional[str] = None
    screenshot_path: Optional[str] = None
    image_size: Optional[Dict[str, Any]] = None
    prior_context: Optional[Dict[str, Any]] = None
    workflow_hint: Optional[str] = None
    source: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def combined_text(self, *, max_chars: int = 20000) -> str:
        parts: List[str] = []

        for value in [
            self.app_name,
            self.window_title,
            self.title,
            self.url,
            self.package_name,
            self.route_name,
            self.workflow_hint,
            self.ocr_text,
        ]:
            if value:
                parts.append(str(value))

        for element in self.ui_elements:
            text = element.searchable_text()
            if text:
                parts.append(text)

        if self.prior_context:
            for key in ("app_type", "page_type", "workflow_stage", "summary", "last_action"):
                value = self.prior_context.get(key)
                if value:
                    parts.append(str(value))

        combined = "\n".join(parts)
        return combined[:max_chars]


@dataclass
class ContextCandidate:
    """
    Candidate classification output.
    """

    label: str
    score: float
    confidence: float
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "score": round(float(self.score), 4),
            "confidence": round(float(self.confidence), 4),
            "evidence": list(self.evidence),
        }


@dataclass
class ScreenContextDetection:
    """
    Final detected screen context.
    """

    app_type: str
    page_type: str
    workflow_stage: str
    confidence: float
    risk_level: str
    summary: str
    app_candidates: List[ContextCandidate] = field(default_factory=list)
    page_candidates: List[ContextCandidate] = field(default_factory=list)
    workflow_candidates: List[ContextCandidate] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "app_type": self.app_type,
            "page_type": self.page_type,
            "workflow_stage": self.workflow_stage,
            "confidence": round(float(self.confidence), 4),
            "risk_level": self.risk_level,
            "summary": self.summary,
            "app_candidates": [candidate.to_dict() for candidate in self.app_candidates],
            "page_candidates": [candidate.to_dict() for candidate in self.page_candidates],
            "workflow_candidates": [candidate.to_dict() for candidate in self.workflow_candidates],
            "evidence": list(self.evidence),
            "warnings": list(self.warnings),
        }


# ======================================================================================
# ScreenContext
# ======================================================================================

class ScreenContext(BaseAgent):
    """
    Detects current screen/app/page/workflow context for the Visual Agent.

    Master Agent:
        Master Agent can route screenshot/screen-understanding tasks here when it needs
        to know what screen is visible before deciding the next action.

    Security Agent:
        This class does not perform screen capture or app control. It classifies supplied
        data only. If future integrations request sensitive raw text memory, the security
        hook can block or require approval.

    Memory Agent:
        Safe summaries can be prepared for long-term memory. Raw sensitive OCR text is
        excluded by default.

    Verification Agent:
        A verification payload is prepared after each detection so other agents can
        confirm visible state before/after actions.

    Dashboard/API:
        Public methods return structured JSON-style results ready for FastAPI.
    """

    public_methods: Tuple[str, ...] = (
        "detect_context",
        "detect_from_screenshot",
        "detect_from_ocr",
        "detect_from_ui_map",
        "classify_app",
        "classify_page",
        "classify_workflow",
        "build_context_snapshot",
    )

    def __init__(
        self,
        config: Optional[ScreenContextConfig] = None,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], bool]] = None,
        event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        memory_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        verification_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name="ScreenContext", **kwargs)
        self.config = config or ScreenContextConfig()
        self.security_approval_callback = security_approval_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.memory_callback = memory_callback
        self.verification_callback = verification_callback
        self.logger = logger or logging.getLogger("william.visual.screen_context")

    # ----------------------------------------------------------------------------------
    # Public API
    # ----------------------------------------------------------------------------------

    def detect_context(
        self,
        task_context: Mapping[str, Any],
        *,
        snapshot: Optional[Union[ScreenContextSnapshot, Mapping[str, Any]]] = None,
        ocr_text: Optional[str] = None,
        ui_elements: Optional[Sequence[Union[UIElementSignal, Mapping[str, Any]]]] = None,
        screenshot_metadata: Optional[Mapping[str, Any]] = None,
        browser_metadata: Optional[Mapping[str, Any]] = None,
        app_metadata: Optional[Mapping[str, Any]] = None,
        workflow_hint: Optional[str] = None,
        prior_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Main method to detect current screen/app/page/workflow context.
        """
        started_at = self._utc_now()

        context_validation = self._validate_task_context(task_context)
        if not context_validation["success"]:
            return context_validation

        try:
            context_snapshot = self._coerce_snapshot(
                snapshot=snapshot,
                ocr_text=ocr_text,
                ui_elements=ui_elements,
                screenshot_metadata=screenshot_metadata,
                browser_metadata=browser_metadata,
                app_metadata=app_metadata,
                workflow_hint=workflow_hint,
                prior_context=prior_context,
            )

            security_payload = {
                "operation": "screen_context_detection",
                "read_only": True,
                "user_id": task_context.get("user_id"),
                "workspace_id": task_context.get("workspace_id"),
                "has_ocr_text": bool(context_snapshot.ocr_text),
                "risk_preview": self._detect_risk_level(context_snapshot.combined_text(max_chars=5000)),
            }

            if self._requires_security_check(security_payload):
                approved = self._request_security_approval(security_payload)
                if not approved:
                    return self._error_result(
                        message="Screen context detection blocked by security policy.",
                        error_code="SECURITY_APPROVAL_DENIED",
                        details={"operation": "screen_context_detection"},
                        metadata=self._base_metadata(task_context, started_at),
                    )

            self._emit_agent_event(
                "visual.screen_context.started",
                {
                    "user_id": task_context.get("user_id"),
                    "workspace_id": task_context.get("workspace_id"),
                    "source": context_snapshot.source,
                    "has_ocr_text": bool(context_snapshot.ocr_text),
                    "ui_element_count": len(context_snapshot.ui_elements),
                },
            )

            detection = self._detect(context_snapshot)
            success = detection.confidence >= self.config.min_confidence_for_success

            message = (
                "Screen context detected successfully."
                if success
                else "Screen context detection completed with low confidence."
            )

            data = {
                "context": detection.to_dict(),
                "snapshot": self._snapshot_to_safe_dict(context_snapshot),
                "routing_hints": self._build_routing_hints(detection),
                "verification_relevance": self._build_verification_relevance(detection),
                "memory_relevance": self._build_memory_relevance(detection),
            }

            result = self._safe_result(
                success=success,
                message=message,
                data=data,
                metadata=self._base_metadata(task_context, started_at),
            )

            verification_payload = self._prepare_verification_payload(
                task_context=task_context,
                result=result,
                checker_name="screen_context",
            )
            memory_payload = self._prepare_memory_payload(
                task_context=task_context,
                result=result,
                checker_name="screen_context",
            )

            self._dispatch_optional_payloads(verification_payload, memory_payload)

            self._log_audit_event(
                "visual.screen_context.completed",
                {
                    "user_id": task_context.get("user_id"),
                    "workspace_id": task_context.get("workspace_id"),
                    "success": success,
                    "app_type": detection.app_type,
                    "page_type": detection.page_type,
                    "workflow_stage": detection.workflow_stage,
                    "confidence": detection.confidence,
                    "risk_level": detection.risk_level,
                },
            )

            self._emit_agent_event(
                "visual.screen_context.completed",
                {
                    "user_id": task_context.get("user_id"),
                    "workspace_id": task_context.get("workspace_id"),
                    "success": success,
                    "summary": detection.summary,
                    "confidence": detection.confidence,
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("Screen context detection failed unexpectedly.")
            result = self._error_result(
                message="Screen context detection failed due to an unexpected error.",
                error_code="SCREEN_CONTEXT_DETECTION_FAILED",
                details={
                    "exception_type": exc.__class__.__name__,
                    "exception": str(exc),
                    "trace": traceback.format_exc(limit=5),
                },
                metadata=self._base_metadata(task_context, started_at),
            )
            self._log_audit_event(
                "visual.screen_context.failed",
                {
                    "user_id": task_context.get("user_id"),
                    "workspace_id": task_context.get("workspace_id"),
                    "error": str(exc),
                },
            )
            return result

    def detect_from_screenshot(
        self,
        task_context: Mapping[str, Any],
        *,
        screenshot_metadata: Optional[Mapping[str, Any]] = None,
        ocr_text: Optional[str] = None,
        ui_elements: Optional[Sequence[Union[UIElementSignal, Mapping[str, Any]]]] = None,
        browser_metadata: Optional[Mapping[str, Any]] = None,
        app_metadata: Optional[Mapping[str, Any]] = None,
        workflow_hint: Optional[str] = None,
        prior_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Convenience method for screenshot_reader/image_analyzer outputs.
        """
        return self.detect_context(
            task_context=task_context,
            ocr_text=ocr_text,
            ui_elements=ui_elements,
            screenshot_metadata=screenshot_metadata,
            browser_metadata=browser_metadata,
            app_metadata=app_metadata,
            workflow_hint=workflow_hint,
            prior_context=prior_context,
        )

    def detect_from_ocr(
        self,
        task_context: Mapping[str, Any],
        ocr_text: str,
        *,
        url: Optional[str] = None,
        title: Optional[str] = None,
        app_name: Optional[str] = None,
        workflow_hint: Optional[str] = None,
        prior_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Convenience method for plain OCR text.
        """
        browser_metadata = {"url": url, "title": title} if url or title else None
        app_metadata = {"app_name": app_name} if app_name else None

        return self.detect_context(
            task_context=task_context,
            ocr_text=ocr_text,
            browser_metadata=browser_metadata,
            app_metadata=app_metadata,
            workflow_hint=workflow_hint,
            prior_context=prior_context,
        )

    def detect_from_ui_map(
        self,
        task_context: Mapping[str, Any],
        ui_map: Mapping[str, Any],
        *,
        ocr_text: Optional[str] = None,
        browser_metadata: Optional[Mapping[str, Any]] = None,
        app_metadata: Optional[Mapping[str, Any]] = None,
        workflow_hint: Optional[str] = None,
        prior_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Convenience method for ui_mapper outputs.
        """
        elements = (
            ui_map.get("elements")
            or ui_map.get("ui_elements")
            or ui_map.get("nodes")
            or ui_map.get("controls")
            or []
        )

        screenshot_metadata = {
            "source": ui_map.get("source", "ui_map"),
            "image_size": ui_map.get("image_size"),
            "screenshot_id": ui_map.get("screenshot_id"),
            "screenshot_path": ui_map.get("screenshot_path"),
            "metadata": ui_map.get("metadata", {}),
        }

        return self.detect_context(
            task_context=task_context,
            ocr_text=ocr_text,
            ui_elements=elements,
            screenshot_metadata=screenshot_metadata,
            browser_metadata=browser_metadata,
            app_metadata=app_metadata,
            workflow_hint=workflow_hint,
            prior_context=prior_context,
        )

    def classify_app(
        self,
        text: str,
        *,
        url: Optional[str] = None,
        app_name: Optional[str] = None,
        window_title: Optional[str] = None,
        top_n: int = 5,
    ) -> Dict[str, Any]:
        """
        Classify only the app type from text/url/app metadata.
        """
        combined = "\n".join(part for part in [app_name, window_title, url, text] if part)
        candidates = self._score_rules(combined, APP_RULES, url=url, top_n=top_n)
        best = candidates[0] if candidates else ContextCandidate(ScreenAppType.UNKNOWN.value, 0.0, 0.0, [])
        return self._safe_result(
            success=best.label != ScreenAppType.UNKNOWN.value,
            message="App classification completed.",
            data={
                "app_type": best.label,
                "confidence": best.confidence,
                "candidates": [candidate.to_dict() for candidate in candidates],
            },
            metadata={
                "agent": "ScreenContext",
                "method": "classify_app",
                "timestamp": self._utc_now_iso(),
            },
        )

    def classify_page(
        self,
        text: str,
        *,
        url: Optional[str] = None,
        title: Optional[str] = None,
        top_n: int = 5,
    ) -> Dict[str, Any]:
        """
        Classify only the page/screen type.
        """
        combined = "\n".join(part for part in [title, url, text] if part)
        candidates = self._score_rules(combined, PAGE_RULES, url=url, top_n=top_n)
        best = candidates[0] if candidates else ContextCandidate(ScreenPageType.UNKNOWN.value, 0.0, 0.0, [])
        return self._safe_result(
            success=best.label != ScreenPageType.UNKNOWN.value,
            message="Page classification completed.",
            data={
                "page_type": best.label,
                "confidence": best.confidence,
                "candidates": [candidate.to_dict() for candidate in candidates],
            },
            metadata={
                "agent": "ScreenContext",
                "method": "classify_page",
                "timestamp": self._utc_now_iso(),
            },
        )

    def classify_workflow(
        self,
        text: str,
        *,
        workflow_hint: Optional[str] = None,
        prior_context: Optional[Mapping[str, Any]] = None,
        top_n: int = 5,
    ) -> Dict[str, Any]:
        """
        Classify only the likely workflow stage.
        """
        prior_text = ""
        if prior_context:
            prior_text = " ".join(str(value) for value in prior_context.values() if value is not None)

        combined = "\n".join(part for part in [workflow_hint, prior_text, text] if part)
        candidates = self._score_rules(combined, WORKFLOW_RULES, top_n=top_n)
        best = candidates[0] if candidates else ContextCandidate(WorkflowStage.UNKNOWN.value, 0.0, 0.0, [])
        return self._safe_result(
            success=best.label != WorkflowStage.UNKNOWN.value,
            message="Workflow classification completed.",
            data={
                "workflow_stage": best.label,
                "confidence": best.confidence,
                "candidates": [candidate.to_dict() for candidate in candidates],
            },
            metadata={
                "agent": "ScreenContext",
                "method": "classify_workflow",
                "timestamp": self._utc_now_iso(),
            },
        )

    def build_context_snapshot(
        self,
        *,
        ocr_text: Optional[str] = None,
        ui_elements: Optional[Sequence[Union[UIElementSignal, Mapping[str, Any]]]] = None,
        url: Optional[str] = None,
        title: Optional[str] = None,
        app_name: Optional[str] = None,
        window_title: Optional[str] = None,
        package_name: Optional[str] = None,
        route_name: Optional[str] = None,
        screenshot_id: Optional[str] = None,
        screenshot_path: Optional[str] = None,
        image_size: Optional[Mapping[str, Any]] = None,
        prior_context: Optional[Mapping[str, Any]] = None,
        workflow_hint: Optional[str] = None,
        source: str = "manual",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> ScreenContextSnapshot:
        """
        Public helper for other agents to build a normalized snapshot.
        """
        return ScreenContextSnapshot(
            ocr_text=self._trim_text(ocr_text),
            ui_elements=self._coerce_ui_elements(ui_elements or []),
            url=self._none_if_empty(url),
            title=self._none_if_empty(title),
            app_name=self._none_if_empty(app_name),
            window_title=self._none_if_empty(window_title),
            package_name=self._none_if_empty(package_name),
            route_name=self._none_if_empty(route_name),
            screenshot_id=self._none_if_empty(screenshot_id),
            screenshot_path=self._none_if_empty(screenshot_path),
            image_size=self._safe_mapping(image_size or {}),
            prior_context=self._safe_mapping(prior_context or {}) if prior_context else None,
            workflow_hint=self._none_if_empty(workflow_hint),
            source=source,
            metadata=self._safe_mapping(metadata or {}),
        )

    # ----------------------------------------------------------------------------------
    # Core Detection Logic
    # ----------------------------------------------------------------------------------

    def _detect(self, snapshot: ScreenContextSnapshot) -> ScreenContextDetection:
        combined_text = snapshot.combined_text(max_chars=self.config.max_text_chars)
        url = snapshot.url

        app_candidates = self._score_rules(combined_text, APP_RULES, url=url, top_n=5)
        page_candidates = self._score_rules(combined_text, PAGE_RULES, url=url, top_n=5)
        workflow_candidates = self._score_rules(combined_text, WORKFLOW_RULES, top_n=5)

        app_best = self._best_or_unknown(app_candidates, ScreenAppType.UNKNOWN.value)
        page_best = self._best_or_unknown(page_candidates, ScreenPageType.UNKNOWN.value)
        workflow_best = self._best_or_unknown(workflow_candidates, WorkflowStage.UNKNOWN.value)

        app_label = self._refine_app_type(app_best.label, snapshot, combined_text)
        page_label = self._refine_page_type(page_best.label, snapshot, combined_text, app_label)
        workflow_label = self._refine_workflow_stage(workflow_best.label, page_label, combined_text)

        confidence = self._combine_confidence(
            app_best.confidence,
            page_best.confidence,
            workflow_best.confidence,
            snapshot=snapshot,
        )

        risk_level = self._detect_risk_level(combined_text)
        evidence = self._collect_final_evidence(app_candidates, page_candidates, workflow_candidates)
        warnings = self._build_warnings(snapshot, app_label, page_label, workflow_label, confidence, risk_level)
        summary = self._build_summary(app_label, page_label, workflow_label, confidence, risk_level)

        return ScreenContextDetection(
            app_type=app_label,
            page_type=page_label,
            workflow_stage=workflow_label,
            confidence=confidence,
            risk_level=risk_level,
            summary=summary,
            app_candidates=app_candidates,
            page_candidates=page_candidates,
            workflow_candidates=workflow_candidates,
            evidence=evidence,
            warnings=warnings,
        )

    def _score_rules(
        self,
        text: str,
        rules: Mapping[str, Mapping[str, Any]],
        *,
        url: Optional[str] = None,
        top_n: int = 5,
    ) -> List[ContextCandidate]:
        normalized_text = self._normalize_text(text)
        normalized_url = self._normalize_text(url or "")
        candidates: List[ContextCandidate] = []

        for label, rule in rules.items():
            keywords = list(rule.get("keywords", []))
            required_any = list(rule.get("required_any", []))
            url_domains = list(rule.get("url_domains", []))
            weight = float(rule.get("weight", 1.0))
            use_regex = bool(rule.get("regex", False))

            score = 0.0
            evidence: List[str] = []

            for keyword in keywords:
                keyword_text = str(keyword)
                if not keyword_text:
                    continue

                if use_regex:
                    matched = self._regex_search(keyword_text, normalized_text)
                else:
                    matched = self._keyword_match(normalized_text, keyword_text)

                if matched:
                    keyword_score = self._keyword_score(keyword_text)
                    score += keyword_score
                    evidence.append(f"matched keyword: {self._safe_evidence(keyword_text)}")

            if required_any:
                required_hit = any(
                    self._keyword_match(normalized_text, str(required))
                    or self._keyword_match(normalized_url, str(required))
                    for required in required_any
                )
                if required_hit:
                    score += 2.5
                    evidence.append("matched required signal")
                elif score > 0:
                    score *= 0.65
                    evidence.append("missing stronger required signal")

            for domain in url_domains:
                domain_text = self._normalize_text(str(domain))
                if domain_text and domain_text in normalized_url:
                    score += 4.0
                    evidence.append(f"matched url/domain: {self._safe_evidence(domain_text)}")

            if score > 0:
                weighted_score = score * weight
                confidence = self._score_to_confidence(weighted_score)
                candidates.append(
                    ContextCandidate(
                        label=label,
                        score=weighted_score,
                        confidence=confidence,
                        evidence=evidence[: self.config.max_evidence_items],
                    )
                )

        candidates.sort(key=lambda candidate: (candidate.confidence, candidate.score), reverse=True)
        return candidates[:top_n]

    def _best_or_unknown(self, candidates: Sequence[ContextCandidate], unknown_label: str) -> ContextCandidate:
        if not candidates:
            return ContextCandidate(label=unknown_label, score=0.0, confidence=0.0, evidence=[])
        return candidates[0]

    def _refine_app_type(
        self,
        app_label: str,
        snapshot: ScreenContextSnapshot,
        combined_text: str,
    ) -> str:
        url = snapshot.url or ""
        app_name = self._normalize_text(snapshot.app_name or "")
        window_title = self._normalize_text(snapshot.window_title or "")
        package_name = self._normalize_text(snapshot.package_name or "")
        text = self._normalize_text(combined_text)

        if self._url_contains(url, "wp-admin") or "wordpress" in text or "elementor" in text:
            return ScreenAppType.WORDPRESS.value

        if self._url_contains(url, "docs.google.com/spreadsheets"):
            return ScreenAppType.GOOGLE_SHEETS.value

        if self._url_contains(url, "docs.google.com/document"):
            return ScreenAppType.GOOGLE_DOCS.value

        if self._url_contains(url, "docs.google.com/forms"):
            return ScreenAppType.GOOGLE_FORMS.value

        if self._url_contains(url, "mail.google.com") or "gmail" in text:
            return ScreenAppType.EMAIL.value

        if self._url_contains(url, "calendar.google.com"):
            return ScreenAppType.CALENDAR.value

        if "code" in app_name or "visual studio code" in window_title or "cursor" in app_name:
            return ScreenAppType.CODE_EDITOR.value

        if "terminal" in app_name or "powershell" in app_name or "cmd" in app_name:
            return ScreenAppType.TERMINAL.value

        if "com.android" in package_name or "android" in package_name:
            return ScreenAppType.MOBILE_APP.value

        if url.startswith(("http://", "https://")) and app_label == ScreenAppType.UNKNOWN.value:
            return ScreenAppType.BROWSER.value

        return app_label

    def _refine_page_type(
        self,
        page_label: str,
        snapshot: ScreenContextSnapshot,
        combined_text: str,
        app_label: str,
    ) -> str:
        text = self._normalize_text(combined_text)
        url = snapshot.url or ""

        if app_label == ScreenAppType.WORDPRESS.value:
            return ScreenPageType.WORDPRESS_ADMIN.value

        if any(self._regex_search(pattern, text) for pattern in DEFAULT_ERROR_PATTERNS):
            return ScreenPageType.ERROR.value

        if self._url_contains(url, "checkout") or "place order" in text or "order summary" in text:
            return ScreenPageType.CHECKOUT.value

        if self._url_contains(url, "wp-admin") or "wp-admin" in text:
            return ScreenPageType.WORDPRESS_ADMIN.value

        if "forgot password" in text or "reset password" in text:
            return ScreenPageType.FORGOT_PASSWORD.value

        if "password" in text and any(term in text for term in ("login", "log in", "sign in")):
            return ScreenPageType.LOGIN.value

        if any(term in text for term in ("create account", "sign up", "signup", "register")):
            return ScreenPageType.SIGNUP.value

        if "sponsored" in text and ("search" in text or "results" in text):
            return ScreenPageType.SEARCH_RESULTS.value

        if "card number" in text or "cvv" in text or "pay now" in text:
            return ScreenPageType.PAYMENT.value

        if self._has_form_shape(snapshot) and page_label == ScreenPageType.UNKNOWN.value:
            return ScreenPageType.FORM.value

        if self._has_table_shape(snapshot) and page_label == ScreenPageType.UNKNOWN.value:
            return ScreenPageType.LIST_TABLE.value

        return page_label

    def _refine_workflow_stage(
        self,
        workflow_label: str,
        page_label: str,
        combined_text: str,
    ) -> str:
        text = self._normalize_text(combined_text)

        page_to_workflow = {
            ScreenPageType.LOGIN.value: WorkflowStage.LOGIN.value,
            ScreenPageType.SIGNUP.value: WorkflowStage.SIGNUP.value,
            ScreenPageType.FORGOT_PASSWORD.value: WorkflowStage.AUTHENTICATION.value,
            ScreenPageType.SEARCH_RESULTS.value: WorkflowStage.SEARCH.value,
            ScreenPageType.FORM.value: WorkflowStage.FORM_FILLING.value,
            ScreenPageType.FILE_UPLOAD.value: WorkflowStage.FILE_UPLOAD.value,
            ScreenPageType.CONTENT_EDITOR.value: WorkflowStage.CONTENT_EDITING.value,
            ScreenPageType.CODE_VIEW.value: WorkflowStage.CODE_EDITING.value,
            ScreenPageType.TERMINAL_VIEW.value: WorkflowStage.CODE_EDITING.value,
            ScreenPageType.CHECKOUT.value: WorkflowStage.CHECKOUT.value,
            ScreenPageType.PAYMENT.value: WorkflowStage.PAYMENT.value,
            ScreenPageType.ERROR.value: WorkflowStage.ERROR_HANDLING.value,
            ScreenPageType.SUCCESS_CONFIRMATION.value: WorkflowStage.SUCCESS.value,
            ScreenPageType.CHAT.value: WorkflowStage.COMMUNICATION.value,
            ScreenPageType.CALL_SCREEN.value: WorkflowStage.CALLING.value,
            ScreenPageType.LIST_TABLE.value: WorkflowStage.DATA_REVIEW.value,
            ScreenPageType.ANALYTICS.value: WorkflowStage.DATA_REVIEW.value,
            ScreenPageType.SETTINGS.value: WorkflowStage.CONFIGURATION.value,
        }

        if page_label in page_to_workflow:
            return page_to_workflow[page_label]

        if "loading" in text or "processing" in text or "please wait" in text:
            return WorkflowStage.PROCESSING.value

        if workflow_label == WorkflowStage.UNKNOWN.value and any(
            term in text for term in ("submit", "save", "continue", "next", "confirm")
        ):
            return WorkflowStage.SUBMISSION.value

        return workflow_label

    def _combine_confidence(
        self,
        app_confidence: float,
        page_confidence: float,
        workflow_confidence: float,
        *,
        snapshot: ScreenContextSnapshot,
    ) -> float:
        weighted = (app_confidence * 0.35) + (page_confidence * 0.35) + (workflow_confidence * 0.30)

        signal_bonus = 0.0
        if snapshot.ocr_text:
            signal_bonus += 0.04
        if snapshot.ui_elements:
            signal_bonus += min(0.08, len(snapshot.ui_elements) * 0.005)
        if snapshot.url:
            signal_bonus += 0.04
        if snapshot.title:
            signal_bonus += 0.03
        if snapshot.app_name or snapshot.window_title:
            signal_bonus += 0.03
        if snapshot.prior_context:
            signal_bonus += 0.02

        confidence = min(1.0, weighted + signal_bonus)
        return round(max(0.0, confidence), 4)

    def _detect_risk_level(self, text: str) -> str:
        normalized = self._normalize_text(text)
        hits = [keyword for keyword in self.config.risk_keywords if keyword.lower() in normalized]

        high_terms = {"password", "secret", "api key", "token", "private key", "card number", "cvv"}
        if any(keyword in hits for keyword in high_terms):
            return ContextRiskLevel.HIGH.value

        if len(hits) >= 2:
            return ContextRiskLevel.HIGH.value

        if hits:
            return ContextRiskLevel.MEDIUM.value

        return ContextRiskLevel.LOW.value

    def _collect_final_evidence(
        self,
        app_candidates: Sequence[ContextCandidate],
        page_candidates: Sequence[ContextCandidate],
        workflow_candidates: Sequence[ContextCandidate],
    ) -> List[str]:
        evidence: List[str] = []

        for group_name, candidates in (
            ("app", app_candidates[:2]),
            ("page", page_candidates[:2]),
            ("workflow", workflow_candidates[:2]),
        ):
            for candidate in candidates:
                evidence.append(f"{group_name}:{candidate.label} confidence={round(candidate.confidence, 3)}")
                evidence.extend(candidate.evidence[:3])

        deduped: List[str] = []
        seen = set()

        for item in evidence:
            safe_item = self._safe_evidence(item)
            if safe_item not in seen:
                seen.add(safe_item)
                deduped.append(safe_item)

        return deduped[: self.config.max_evidence_items]

    def _build_warnings(
        self,
        snapshot: ScreenContextSnapshot,
        app_label: str,
        page_label: str,
        workflow_label: str,
        confidence: float,
        risk_level: str,
    ) -> List[str]:
        warnings: List[str] = []

        if confidence < self.config.min_confidence_for_success:
            warnings.append("Low confidence detection; more OCR/UI/browser metadata would improve accuracy.")

        if not snapshot.ocr_text and not snapshot.ui_elements:
            warnings.append("No OCR text or UI elements were provided.")

        if app_label == ScreenAppType.UNKNOWN.value:
            warnings.append("App type is unknown.")

        if page_label == ScreenPageType.UNKNOWN.value:
            warnings.append("Page type is unknown.")

        if workflow_label == WorkflowStage.UNKNOWN.value:
            warnings.append("Workflow stage is unknown.")

        if risk_level == ContextRiskLevel.HIGH.value:
            warnings.append("High-sensitivity screen detected; avoid storing raw visible text.")

        return warnings

    def _build_summary(
        self,
        app_label: str,
        page_label: str,
        workflow_label: str,
        confidence: float,
        risk_level: str,
    ) -> str:
        return (
            f"Detected {app_label} app context, {page_label} page/screen type, "
            f"and {workflow_label} workflow stage with {round(confidence * 100, 1)}% confidence. "
            f"Risk level: {risk_level}."
        )

    def _build_routing_hints(self, detection: ScreenContextDetection) -> Dict[str, Any]:
        """
        Hints for Master Agent / Agent Router.
        """
        recommended_agents: List[str] = ["VisualAgent"]

        if detection.page_type == ScreenPageType.ERROR.value:
            recommended_agents.append("VerificationAgent")

        if detection.app_type in {ScreenAppType.BROWSER.value, ScreenAppType.WEB_APP.value, ScreenAppType.WORDPRESS.value}:
            recommended_agents.append("BrowserAgent")

        if detection.app_type in {ScreenAppType.CODE_EDITOR.value, ScreenAppType.TERMINAL.value}:
            recommended_agents.append("CodeAgent")

        if detection.workflow_stage in {
            WorkflowStage.FORM_FILLING.value,
            WorkflowStage.FILE_UPLOAD.value,
            WorkflowStage.CHECKOUT.value,
            WorkflowStage.PAYMENT.value,
        }:
            recommended_agents.append("SecurityAgent")

        if detection.workflow_stage in {
            WorkflowStage.CONTENT_EDITING.value,
            WorkflowStage.CONFIGURATION.value,
            WorkflowStage.DATA_REVIEW.value,
        }:
            recommended_agents.append("WorkflowAgent")

        return {
            "recommended_agents": sorted(set(recommended_agents)),
            "requires_security_attention": detection.risk_level in {
                ContextRiskLevel.MEDIUM.value,
                ContextRiskLevel.HIGH.value,
            },
            "safe_for_auto_action": detection.risk_level == ContextRiskLevel.LOW.value and detection.confidence >= 0.65,
            "suggested_next_check": self._suggest_next_check(detection),
        }

    def _build_verification_relevance(self, detection: ScreenContextDetection) -> Dict[str, Any]:
        """
        Hints for Verification Agent payload consumers.
        """
        return {
            "should_verify_before_action": detection.risk_level != ContextRiskLevel.LOW.value,
            "should_collect_proof": detection.confidence >= self.config.min_confidence_for_success,
            "verification_targets": {
                "app_type": detection.app_type,
                "page_type": detection.page_type,
                "workflow_stage": detection.workflow_stage,
            },
            "confidence": detection.confidence,
        }

    def _build_memory_relevance(self, detection: ScreenContextDetection) -> Dict[str, Any]:
        """
        Hints for Memory Agent.
        """
        return {
            "safe_to_store_summary": True,
            "safe_to_store_raw_text": self.config.allow_sensitive_context_memory
            and detection.risk_level == ContextRiskLevel.LOW.value,
            "store_for_workflow_learning": detection.confidence >= 0.55,
            "context_key": f"{detection.app_type}:{detection.page_type}:{detection.workflow_stage}",
        }

    def _suggest_next_check(self, detection: ScreenContextDetection) -> str:
        if detection.page_type == ScreenPageType.ERROR.value:
            return "error_screen_detector"

        if detection.page_type in {
            ScreenPageType.FORM.value,
            ScreenPageType.LOGIN.value,
            ScreenPageType.SIGNUP.value,
        }:
            return "form_reader"

        if detection.workflow_stage in {
            WorkflowStage.FORM_FILLING.value,
            WorkflowStage.CHECKOUT.value,
        }:
            return "ui_element_checker"

        if detection.app_type in {
            ScreenAppType.BROWSER.value,
            ScreenAppType.WORDPRESS.value,
        }:
            return "browser_state_checker"

        if detection.app_type in {
            ScreenAppType.CODE_EDITOR.value,
            ScreenAppType.TERMINAL.value,
        }:
            return "code_state_checker"

        return "visual_validator"

    # ----------------------------------------------------------------------------------
    # Snapshot Coercion
    # ----------------------------------------------------------------------------------

    def _coerce_snapshot(
        self,
        *,
        snapshot: Optional[Union[ScreenContextSnapshot, Mapping[str, Any]]],
        ocr_text: Optional[str],
        ui_elements: Optional[Sequence[Union[UIElementSignal, Mapping[str, Any]]]],
        screenshot_metadata: Optional[Mapping[str, Any]],
        browser_metadata: Optional[Mapping[str, Any]],
        app_metadata: Optional[Mapping[str, Any]],
        workflow_hint: Optional[str],
        prior_context: Optional[Mapping[str, Any]],
    ) -> ScreenContextSnapshot:
        if isinstance(snapshot, ScreenContextSnapshot):
            return snapshot

        if isinstance(snapshot, Mapping):
            return self.build_context_snapshot(
                ocr_text=snapshot.get("ocr_text") or ocr_text,
                ui_elements=snapshot.get("ui_elements") or snapshot.get("elements") or ui_elements,
                url=snapshot.get("url") or self._mapping_get(browser_metadata, "url"),
                title=snapshot.get("title") or self._mapping_get(browser_metadata, "title"),
                app_name=snapshot.get("app_name") or self._mapping_get(app_metadata, "app_name"),
                window_title=snapshot.get("window_title") or self._mapping_get(app_metadata, "window_title"),
                package_name=snapshot.get("package_name") or self._mapping_get(app_metadata, "package_name"),
                route_name=snapshot.get("route_name") or self._mapping_get(app_metadata, "route_name"),
                screenshot_id=snapshot.get("screenshot_id") or self._mapping_get(screenshot_metadata, "screenshot_id"),
                screenshot_path=snapshot.get("screenshot_path") or self._mapping_get(screenshot_metadata, "screenshot_path"),
                image_size=snapshot.get("image_size") or self._mapping_get(screenshot_metadata, "image_size") or {},
                prior_context=snapshot.get("prior_context") or prior_context,
                workflow_hint=snapshot.get("workflow_hint") or workflow_hint,
                source=str(snapshot.get("source") or self._mapping_get(screenshot_metadata, "source") or "snapshot"),
                metadata=snapshot.get("metadata") or {},
            )

        screenshot_metadata = screenshot_metadata or {}
        browser_metadata = browser_metadata or {}
        app_metadata = app_metadata or {}

        return self.build_context_snapshot(
            ocr_text=ocr_text,
            ui_elements=ui_elements or [],
            url=self._mapping_get(browser_metadata, "url") or self._mapping_get(browser_metadata, "current_url"),
            title=self._mapping_get(browser_metadata, "title") or self._mapping_get(browser_metadata, "page_title"),
            app_name=self._mapping_get(app_metadata, "app_name") or self._mapping_get(app_metadata, "name"),
            window_title=self._mapping_get(app_metadata, "window_title") or self._mapping_get(browser_metadata, "window_title"),
            package_name=self._mapping_get(app_metadata, "package_name"),
            route_name=self._mapping_get(app_metadata, "route_name") or self._mapping_get(browser_metadata, "route_name"),
            screenshot_id=self._mapping_get(screenshot_metadata, "screenshot_id") or self._mapping_get(screenshot_metadata, "id"),
            screenshot_path=self._mapping_get(screenshot_metadata, "screenshot_path") or self._mapping_get(screenshot_metadata, "path"),
            image_size=self._mapping_get(screenshot_metadata, "image_size") or {},
            prior_context=prior_context,
            workflow_hint=workflow_hint,
            source=str(self._mapping_get(screenshot_metadata, "source") or "composed_inputs"),
            metadata={
                "screenshot_metadata": self._safe_mapping(screenshot_metadata),
                "browser_metadata": self._safe_mapping(browser_metadata),
                "app_metadata": self._safe_mapping(app_metadata),
            },
        )

    def _coerce_ui_elements(
        self,
        ui_elements: Sequence[Union[UIElementSignal, Mapping[str, Any]]],
    ) -> List[UIElementSignal]:
        normalized: List[UIElementSignal] = []

        for element in ui_elements:
            if isinstance(element, UIElementSignal):
                normalized.append(element)
                continue

            if not isinstance(element, Mapping):
                continue

            normalized.append(
                UIElementSignal(
                    element_type=self._none_if_empty(
                        element.get("element_type")
                        or element.get("type")
                        or element.get("tag")
                        or element.get("kind")
                    ),
                    text=self._none_if_empty(
                        element.get("text")
                        or element.get("label")
                        or element.get("value")
                        or element.get("name")
                    ),
                    role=self._none_if_empty(element.get("role")),
                    aria_label=self._none_if_empty(element.get("aria_label") or element.get("aria-label")),
                    placeholder=self._none_if_empty(element.get("placeholder")),
                    bounds=self._safe_mapping(element.get("bounds") or element.get("bbox") or {}),
                    confidence=self._to_optional_float(element.get("confidence")),
                    metadata=self._safe_mapping(element.get("metadata") or {}),
                )
            )

        return normalized

    def _snapshot_to_safe_dict(self, snapshot: ScreenContextSnapshot) -> Dict[str, Any]:
        text_excerpt: Optional[str] = None

        if self.config.include_text_excerpt and snapshot.ocr_text:
            text_excerpt = self._sanitize_for_output(snapshot.ocr_text[: self.config.text_excerpt_chars])

        return {
            "ocr_text_excerpt": text_excerpt,
            "ocr_text_length": len(snapshot.ocr_text or ""),
            "ui_element_count": len(snapshot.ui_elements),
            "url": snapshot.url,
            "title": snapshot.title,
            "app_name": snapshot.app_name,
            "window_title": snapshot.window_title,
            "package_name": snapshot.package_name,
            "route_name": snapshot.route_name,
            "screenshot_id": snapshot.screenshot_id,
            "screenshot_path": snapshot.screenshot_path,
            "image_size": snapshot.image_size,
            "workflow_hint": snapshot.workflow_hint,
            "source": snapshot.source,
            "metadata": snapshot.metadata,
        }

    # ----------------------------------------------------------------------------------
    # Shape Heuristics
    # ----------------------------------------------------------------------------------

    def _has_form_shape(self, snapshot: ScreenContextSnapshot) -> bool:
        input_like = 0
        button_like = 0

        for element in snapshot.ui_elements:
            searchable = self._normalize_text(element.searchable_text())
            element_type = self._normalize_text(element.element_type or "")
            role = self._normalize_text(element.role or "")

            if any(term in element_type for term in ("input", "textarea", "select", "checkbox", "radio")):
                input_like += 1

            if any(term in role for term in ("textbox", "combobox", "checkbox", "radio")):
                input_like += 1

            if any(term in searchable for term in ("email", "phone", "name", "message", "password", "required")):
                input_like += 1

            if any(term in searchable for term in ("submit", "send", "save", "continue", "next")):
                button_like += 1

        return input_like >= 2 and button_like >= 1

    def _has_table_shape(self, snapshot: ScreenContextSnapshot) -> bool:
        text = self._normalize_text(snapshot.combined_text(max_chars=8000))
        table_terms = ("filter", "sort", "rows", "columns", "status", "actions", "date", "export")
        hits = sum(1 for term in table_terms if term in text)

        grid_elements = 0
        for element in snapshot.ui_elements:
            searchable = self._normalize_text(element.searchable_text())
            if any(term in searchable for term in ("row", "column", "cell", "grid", "table")):
                grid_elements += 1

        return hits >= 3 or grid_elements >= 4

    # ----------------------------------------------------------------------------------
    # Required Compatibility Hooks
    # ----------------------------------------------------------------------------------

    def _validate_task_context(self, task_context: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.
        """
        if not isinstance(task_context, Mapping):
            return self._error_result(
                message="Invalid task context. Expected mapping/dict.",
                error_code="INVALID_TASK_CONTEXT",
                details={"received_type": type(task_context).__name__},
            )

        user_id = task_context.get("user_id")
        workspace_id = task_context.get("workspace_id")

        if self.config.strict_workspace_isolation:
            missing: List[str] = []
            if not user_id:
                missing.append("user_id")
            if not workspace_id:
                missing.append("workspace_id")

            if missing:
                return self._error_result(
                    message="Task context missing required SaaS isolation fields.",
                    error_code="MISSING_CONTEXT_FIELDS",
                    details={"missing": missing},
                )

        return self._safe_result(
            success=True,
            message="Task context validated.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def _requires_security_check(self, payload: Mapping[str, Any]) -> bool:
        """
        Read-only context detection is generally safe.

        Security check is required if:
            - A high-risk screen is detected and raw sensitive memory is enabled.
            - A future caller marks operation as not read-only.
        """
        if not payload.get("read_only", True):
            return True

        if (
            payload.get("risk_preview") == ContextRiskLevel.HIGH.value
            and self.config.allow_sensitive_context_memory
        ):
            return True

        return False

    def _request_security_approval(self, payload: Mapping[str, Any]) -> bool:
        """
        Ask Security Agent/callback for approval.
        """
        safe_payload = self._sanitize_for_output(dict(payload))

        if self.security_approval_callback:
            try:
                return bool(self.security_approval_callback(safe_payload))
            except Exception as exc:
                self.logger.warning("Security approval callback failed: %s", exc)
                return False

        if not safe_payload.get("read_only", True):
            return False

        if (
            safe_payload.get("risk_preview") == ContextRiskLevel.HIGH.value
            and self.config.allow_sensitive_context_memory
        ):
            return False

        return True

    def _prepare_verification_payload(
        self,
        task_context: Mapping[str, Any],
        result: Mapping[str, Any],
        checker_name: str,
    ) -> Dict[str, Any]:
        """
        Prepare structured payload for Verification Agent.
        """
        data = result.get("data") if isinstance(result.get("data"), Mapping) else {}
        context = data.get("context") if isinstance(data, Mapping) else {}

        return self._sanitize_for_output(
            {
                "type": "verification_payload",
                "source_agent": "VisualAgent",
                "checker": checker_name,
                "file": "screen_context.py",
                "user_id": task_context.get("user_id"),
                "workspace_id": task_context.get("workspace_id"),
                "success": result.get("success"),
                "message": result.get("message"),
                "context": context,
                "verification_relevance": data.get("verification_relevance") if isinstance(data, Mapping) else None,
                "created_at": self._utc_now_iso(),
            }
        )

    def _prepare_memory_payload(
        self,
        task_context: Mapping[str, Any],
        result: Mapping[str, Any],
        checker_name: str,
    ) -> Dict[str, Any]:
        """
        Prepare safe payload for Memory Agent.
        """
        data = result.get("data") if isinstance(result.get("data"), Mapping) else {}
        context = data.get("context") if isinstance(data, Mapping) else {}
        memory_relevance = data.get("memory_relevance") if isinstance(data, Mapping) else {}

        safe_to_store_raw = bool(
            isinstance(memory_relevance, Mapping)
            and memory_relevance.get("safe_to_store_raw_text")
        )

        payload = {
            "type": "visual_screen_context_memory",
            "source_agent": "VisualAgent",
            "checker": checker_name,
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "success": result.get("success"),
            "summary": context.get("summary") if isinstance(context, Mapping) else result.get("message"),
            "app_type": context.get("app_type") if isinstance(context, Mapping) else None,
            "page_type": context.get("page_type") if isinstance(context, Mapping) else None,
            "workflow_stage": context.get("workflow_stage") if isinstance(context, Mapping) else None,
            "confidence": context.get("confidence") if isinstance(context, Mapping) else None,
            "risk_level": context.get("risk_level") if isinstance(context, Mapping) else None,
            "context_key": memory_relevance.get("context_key") if isinstance(memory_relevance, Mapping) else None,
            "created_at": self._utc_now_iso(),
        }

        if safe_to_store_raw:
            snapshot = data.get("snapshot") if isinstance(data, Mapping) else {}
            if isinstance(snapshot, Mapping):
                payload["ocr_text_excerpt"] = snapshot.get("ocr_text_excerpt")

        return self._sanitize_for_output(payload)

    def _emit_agent_event(self, event_name: str, payload: Mapping[str, Any]) -> None:
        """
        Emit event for Master Agent, Agent Router, Registry, or Dashboard listeners.
        """
        if not self.config.event_enabled:
            return

        safe_payload = self._sanitize_for_output(dict(payload))

        if self.event_callback:
            with contextlib.suppress(Exception):
                self.event_callback(event_name, safe_payload)
                return

        if hasattr(super(), "emit_event"):
            with contextlib.suppress(Exception):
                super().emit_event(event_name, safe_payload)  # type: ignore[misc]
                return

        self.logger.debug("Agent event: %s %s", event_name, safe_payload)

    def _log_audit_event(self, event_name: str, payload: Mapping[str, Any]) -> None:
        """
        Log audit event for SaaS dashboard/audit trail.
        """
        if not self.config.audit_enabled:
            return

        safe_payload = self._sanitize_for_output(dict(payload))

        if self.audit_callback:
            with contextlib.suppress(Exception):
                self.audit_callback(event_name, safe_payload)
                return

        if hasattr(super(), "log_audit_event"):
            with contextlib.suppress(Exception):
                super().log_audit_event(event_name, safe_payload)  # type: ignore[misc]
                return

        self.logger.info("Audit event: %s %s", event_name, safe_payload)

    def _safe_result(
        self,
        *,
        success: bool,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured result envelope.
        """
        return {
            "success": bool(success),
            "message": str(message),
            "data": self._sanitize_for_output(data or {}),
            "error": self._sanitize_for_output(error) if error else None,
            "metadata": self._sanitize_for_output(metadata or {}),
        }

    def _error_result(
        self,
        *,
        message: str,
        error_code: str,
        details: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured error result envelope.
        """
        return {
            "success": False,
            "message": str(message),
            "data": {},
            "error": {
                "code": str(error_code),
                "details": self._sanitize_for_output(details or {}),
            },
            "metadata": self._sanitize_for_output(metadata or {}),
        }

    # ----------------------------------------------------------------------------------
    # Utility Helpers
    # ----------------------------------------------------------------------------------

    def _dispatch_optional_payloads(
        self,
        verification_payload: Dict[str, Any],
        memory_payload: Dict[str, Any],
    ) -> None:
        if self.verification_callback:
            with contextlib.suppress(Exception):
                self.verification_callback(verification_payload)

        if self.memory_callback:
            with contextlib.suppress(Exception):
                self.memory_callback(memory_payload)

    def _keyword_match(self, normalized_text: str, keyword: str) -> bool:
        normalized_keyword = self._normalize_text(keyword)
        if not normalized_keyword:
            return False

        if len(normalized_keyword) <= 2:
            return re.search(rf"(?<!\w){re.escape(normalized_keyword)}(?!\w)", normalized_text) is not None

        return normalized_keyword in normalized_text

    def _keyword_score(self, keyword: str) -> float:
        keyword = keyword.strip()
        if not keyword:
            return 0.0

        if len(keyword) >= 12:
            return 2.0

        if " " in keyword:
            return 1.75

        if len(keyword) >= 5:
            return 1.2

        return 0.8

    def _score_to_confidence(self, score: float) -> float:
        """
        Smooth score into 0..1 confidence.
        """
        confidence = 1.0 - math.exp(-max(0.0, score) / 7.0)
        return round(min(1.0, confidence), 4)

    def _normalize_text(self, text: Optional[Any]) -> str:
        if text is None:
            return ""

        value = str(text)
        value = value.replace("\u00a0", " ")
        value = re.sub(r"\s+", " ", value)

        return value.strip().lower()

    def _url_contains(self, url: str, fragment: str) -> bool:
        return self._normalize_text(fragment) in self._normalize_text(url)

    def _regex_search(self, pattern: str, text: str, flags: int = re.IGNORECASE | re.MULTILINE) -> bool:
        if not pattern or text is None:
            return False

        try:
            return re.search(pattern, text, flags=flags) is not None
        except re.error:
            return False

    def _trim_text(self, text: Optional[Any]) -> Optional[str]:
        if text is None:
            return None

        value = str(text)
        if len(value) > self.config.max_text_chars:
            return value[: self.config.max_text_chars]

        return value

    def _none_if_empty(self, value: Any) -> Optional[str]:
        if value is None:
            return None

        text = str(value).strip()
        return text if text else None

    def _mapping_get(self, mapping: Optional[Mapping[str, Any]], key: str) -> Any:
        if not isinstance(mapping, Mapping):
            return None

        return mapping.get(key)

    def _to_optional_float(self, value: Any) -> Optional[float]:
        if value is None:
            return None

        try:
            return float(value)
        except Exception:
            return None

    def _safe_mapping(self, value: Mapping[str, Any]) -> Dict[str, Any]:
        if not isinstance(value, Mapping):
            return {}

        return self._sanitize_for_output(dict(value))

    def _safe_evidence(self, text: Any) -> str:
        safe = self._sanitize_for_output(str(text))
        safe = re.sub(r"\s+", " ", str(safe)).strip()

        if len(safe) > 160:
            return safe[:157] + "..."

        return safe

    def _sanitize_for_output(self, value: Any) -> Any:
        """
        Redact secrets and convert values to JSON-safe structures.
        """
        if isinstance(value, Mapping):
            clean: Dict[str, Any] = {}
            for key, item in value.items():
                key_text = str(key)
                if any(secret_key in key_text.lower() for secret_key in SENSITIVE_KEYS):
                    clean[key_text] = "[REDACTED]"
                else:
                    clean[key_text] = self._sanitize_for_output(item)
            return clean

        if isinstance(value, (list, tuple, set)):
            return [self._sanitize_for_output(item) for item in value]

        if dataclasses.is_dataclass(value):
            return self._sanitize_for_output(dataclasses.asdict(value))

        if isinstance(value, (_dt.datetime, _dt.date)):
            return value.isoformat()

        if isinstance(value, str):
            return self._redact_sensitive_inline(value)

        if isinstance(value, (int, float, bool)) or value is None:
            return value

        try:
            json.dumps(value)
            return value
        except Exception:
            return repr(value)

    def _redact_sensitive_inline(self, text: str) -> str:
        redacted = text

        redaction_patterns = (
            r"(?i)(api[_-]?key\s*[:=]\s*)([^\s&]+)",
            r"(?i)(token\s*[:=]\s*)([^\s&]+)",
            r"(?i)(password\s*[:=]\s*)([^\s&]+)",
            r"(?i)(authorization\s*[:=]\s*)([^\s&]+)",
            r"(?i)(secret\s*[:=]\s*)([^\s&]+)",
            r"(?i)(private[_-]?key\s*[:=]\s*)([^\s&]+)",
            r"(?i)(card\s*number\s*[:=]?\s*)(\d[\d\s-]{10,}\d)",
            r"(?i)(cvv\s*[:=]?\s*)(\d{3,4})",
        )

        for pattern in redaction_patterns:
            redacted = re.sub(pattern, r"\1[REDACTED]", redacted)

        return redacted

    def _base_metadata(
        self,
        task_context: Mapping[str, Any],
        started_at: Optional[_dt.datetime] = None,
    ) -> Dict[str, Any]:
        now = self._utc_now()

        metadata = {
            "agent": "ScreenContext",
            "module": "visual_agent",
            "file": "screen_context.py",
            "user_id": task_context.get("user_id") if isinstance(task_context, Mapping) else None,
            "workspace_id": task_context.get("workspace_id") if isinstance(task_context, Mapping) else None,
            "timestamp": now.isoformat(),
        }

        if started_at:
            metadata["started_at"] = started_at.isoformat()
            metadata["duration_ms"] = round((now - started_at).total_seconds() * 1000, 2)

        return metadata

    def _utc_now(self) -> _dt.datetime:
        return _dt.datetime.now(tz=_dt.timezone.utc)

    def _utc_now_iso(self) -> str:
        return self._utc_now().isoformat()


# ======================================================================================
# Registry / Loader Compatibility Helpers
# ======================================================================================

def get_agent_class() -> type:
    """
    Agent Registry / Agent Loader compatibility helper.
    """
    return ScreenContext


def create_agent(**kwargs: Any) -> ScreenContext:
    """
    Dynamic factory for Agent Loader / Registry.
    """
    return ScreenContext(**kwargs)


def health_check() -> Dict[str, Any]:
    """
    Lightweight import and readiness check for dashboard/API.
    """
    checker = ScreenContext()
    return checker._safe_result(
        success=True,
        message="ScreenContext is importable and ready.",
        data={
            "agent": "ScreenContext",
            "module": "visual_agent",
            "public_methods": list(ScreenContext.public_methods),
            "supported_app_types": [item.value for item in ScreenAppType],
            "supported_page_types": [item.value for item in ScreenPageType],
            "supported_workflow_stages": [item.value for item in WorkflowStage],
        },
        metadata={
            "file": "screen_context.py",
            "timestamp": checker._utc_now_iso(),
        },
    )


__all__ = [
    "ScreenContext",
    "ScreenContextConfig",
    "ScreenContextSnapshot",
    "ScreenContextDetection",
    "ContextCandidate",
    "UIElementSignal",
    "ScreenAppType",
    "ScreenPageType",
    "WorkflowStage",
    "ContextRiskLevel",
    "get_agent_class",
    "create_agent",
    "health_check",
]