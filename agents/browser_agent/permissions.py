"""
agents/browser_agent/permissions.py

Browser-specific permission rules for William / Jarvis Browser Agent.

Purpose:
    - Control permission decisions for forms, logins, scraping, downloads,
      screenshots, navigation, and browser automation.
    - Enforce SaaS user/workspace isolation.
    - Route sensitive browser actions through Security Agent approval hooks.
    - Prepare structured payloads for Verification Agent, Memory Agent,
      Dashboard/API, audit logs, Agent Registry, Agent Router, and Master Agent.

This file is intentionally import-safe:
    - No external William modules are required at import time.
    - Optional integrations can be injected later.
    - No real browser/system/network/destructive actions are executed here.

Author:
    Digital Promotix / William-Jarvis Architecture
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union
from urllib.parse import urlparse


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# =============================================================================
# Safe fallback base class
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Import-safe fallback BaseAgent.

        Real William/Jarvis deployments should provide agents.base_agent.BaseAgent.
        This fallback prevents import crashes while the full project is being built.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        def emit_event(self, *args: Any, **kwargs: Any) -> None:
            return None


# =============================================================================
# Enums
# =============================================================================

class BrowserAction(str, Enum):
    """
    Browser action types controlled by BrowserPermissions.
    """

    NAVIGATE = "navigate"
    SEARCH = "search"
    SCRAPE = "scrape"
    EXTRACT_CONTENT = "extract_content"
    ANALYZE_PAGE = "analyze_page"
    SUBMIT_FORM = "submit_form"
    FILL_FORM = "fill_form"
    LOGIN = "login"
    LOGOUT = "logout"
    DOWNLOAD = "download"
    UPLOAD = "upload"
    SCREENSHOT = "screenshot"
    CLICK = "click"
    MULTI_TAB = "multi_tab"
    AUTOMATION = "automation"
    PRICE_MONITOR = "price_monitor"
    SEO_ANALYZE = "seo_analyze"
    COMPETITOR_ANALYZE = "competitor_analyze"
    SESSION_CREATE = "session_create"
    SESSION_CLOSE = "session_close"
    COOKIE_READ = "cookie_read"
    COOKIE_WRITE = "cookie_write"
    LOCAL_STORAGE_READ = "local_storage_read"
    LOCAL_STORAGE_WRITE = "local_storage_write"
    UNKNOWN = "unknown"


class PermissionDecision(str, Enum):
    """
    Final permission decision.
    """

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_SECURITY_APPROVAL = "require_security_approval"
    REQUIRE_USER_CONFIRMATION = "require_user_confirmation"
    REQUIRE_MORE_CONTEXT = "require_more_context"


class RiskLevel(str, Enum):
    """
    Browser action risk level.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ResourceType(str, Enum):
    """
    Browser resource types.
    """

    URL = "url"
    DOMAIN = "domain"
    FORM = "form"
    LOGIN = "login"
    DOWNLOAD = "download"
    FILE = "file"
    COOKIE = "cookie"
    STORAGE = "storage"
    PAGE = "page"
    TAB = "tab"
    SESSION = "session"
    UNKNOWN = "unknown"


# =============================================================================
# Data models
# =============================================================================

@dataclass
class PermissionRule:
    """
    A single browser permission rule.
    """

    name: str
    action: Union[str, BrowserAction]
    decision: Union[str, PermissionDecision]
    risk_level: Union[str, RiskLevel] = RiskLevel.LOW
    description: str = ""
    resource_type: Union[str, ResourceType] = ResourceType.UNKNOWN
    domains: List[str] = field(default_factory=list)
    url_patterns: List[str] = field(default_factory=list)
    workspace_ids: List[str] = field(default_factory=list)
    user_ids: List[str] = field(default_factory=list)
    requires_security: bool = False
    requires_user_confirmation: bool = False
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PermissionContext:
    """
    Normalized context used for permission decisions.
    """

    user_id: str
    workspace_id: str
    action: BrowserAction
    url: Optional[str] = None
    domain: Optional[str] = None
    resource_type: ResourceType = ResourceType.UNKNOWN
    task_id: Optional[str] = None
    session_id: Optional[str] = None
    agent_name: str = "BrowserPermissions"
    requested_by: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PermissionCheckResult:
    """
    Structured permission decision result.
    """

    success: bool
    decision: PermissionDecision
    message: str
    risk_level: RiskLevel
    action: BrowserAction
    user_id: Optional[str] = None
    workspace_id: Optional[str] = None
    security_required: bool = False
    user_confirmation_required: bool = False
    matched_rules: List[str] = field(default_factory=list)
    blocked_reasons: List[str] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# BrowserPermissions
# =============================================================================

class BrowserPermissions(BaseAgent):
    """
    Browser-specific permission engine.

    This class does not execute browser actions. It only decides whether an
    action is allowed, denied, or must go through Security Agent / user approval.

    Integration points:
        - Master Agent:
            Calls can_execute_browser_action() before routing browser actions.
        - Browser Agent:
            Uses validate_* methods before navigation, forms, scraping,
            downloads, screenshots, sessions, cookies, and automation.
        - Security Agent:
            Sensitive actions use _requires_security_check()
            and _request_security_approval().
        - Verification Agent:
            Every check can prepare _prepare_verification_payload().
        - Memory Agent:
            Useful safe context can be transformed through _prepare_memory_payload().
        - Dashboard/API:
            Structured result dicts are returned for API responses.
        - Registry/Loader/Router:
            Class is import-safe and exposes stable public methods.
    """

    DEFAULT_BLOCKED_DOMAINS: Set[str] = {
        "localhost.invalid",
        "example-malware.test",
        "phishing.test",
    }

    DEFAULT_SENSITIVE_FIELD_NAMES: Set[str] = {
        "password",
        "pass",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "credit_card",
        "card_number",
        "cvv",
        "ssn",
        "social_security",
        "otp",
        "2fa",
        "mfa",
        "pin",
        "bank_account",
        "routing_number",
    }

    DEFAULT_DANGEROUS_FILE_EXTENSIONS: Set[str] = {
        ".exe",
        ".bat",
        ".cmd",
        ".com",
        ".scr",
        ".msi",
        ".ps1",
        ".vbs",
        ".js",
        ".jar",
        ".dll",
        ".sh",
        ".app",
        ".deb",
        ".rpm",
    }

    DEFAULT_ALLOWED_DOWNLOAD_EXTENSIONS: Set[str] = {
        ".txt",
        ".csv",
        ".json",
        ".xml",
        ".pdf",
        ".png",
        ".jpg",
        ".jpeg",
        ".webp",
        ".gif",
        ".xlsx",
        ".xls",
        ".docx",
        ".doc",
        ".pptx",
        ".zip",
    }

    DEFAULT_PUBLIC_SCRAPE_ALLOWED_SCHEMES: Set[str] = {
        "http",
        "https",
    }

    DEFAULT_HIGH_RISK_ACTIONS: Set[BrowserAction] = {
        BrowserAction.LOGIN,
        BrowserAction.SUBMIT_FORM,
        BrowserAction.DOWNLOAD,
        BrowserAction.UPLOAD,
        BrowserAction.COOKIE_READ,
        BrowserAction.COOKIE_WRITE,
        BrowserAction.LOCAL_STORAGE_READ,
        BrowserAction.LOCAL_STORAGE_WRITE,
        BrowserAction.AUTOMATION,
    }

    DEFAULT_SECURITY_REQUIRED_ACTIONS: Set[BrowserAction] = {
        BrowserAction.LOGIN,
        BrowserAction.SUBMIT_FORM,
        BrowserAction.DOWNLOAD,
        BrowserAction.UPLOAD,
        BrowserAction.COOKIE_READ,
        BrowserAction.COOKIE_WRITE,
        BrowserAction.LOCAL_STORAGE_WRITE,
    }

    def __init__(
        self,
        *,
        agent_name: str = "BrowserPermissions",
        blocked_domains: Optional[Iterable[str]] = None,
        allowed_domains: Optional[Iterable[str]] = None,
        sensitive_field_names: Optional[Iterable[str]] = None,
        allowed_download_extensions: Optional[Iterable[str]] = None,
        dangerous_file_extensions: Optional[Iterable[str]] = None,
        rules: Optional[Sequence[PermissionRule]] = None,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        strict_mode: bool = True,
        allow_public_scraping_by_default: bool = True,
        allow_screenshots_by_default: bool = True,
        allow_navigation_by_default: bool = True,
        max_download_size_mb: int = 50,
        max_form_fields: int = 100,
        max_tabs_per_workspace: int = 20,
    ) -> None:
        super().__init__(agent_name=agent_name)

        self.agent_name = agent_name
        self.strict_mode = bool(strict_mode)
        self.allow_public_scraping_by_default = bool(allow_public_scraping_by_default)
        self.allow_screenshots_by_default = bool(allow_screenshots_by_default)
        self.allow_navigation_by_default = bool(allow_navigation_by_default)

        self.blocked_domains: Set[str] = self._normalize_domain_set(
            blocked_domains or self.DEFAULT_BLOCKED_DOMAINS
        )
        self.allowed_domains: Set[str] = self._normalize_domain_set(allowed_domains or [])

        self.sensitive_field_names: Set[str] = {
            str(x).strip().lower()
            for x in (sensitive_field_names or self.DEFAULT_SENSITIVE_FIELD_NAMES)
            if str(x).strip()
        }

        self.allowed_download_extensions: Set[str] = {
            self._normalize_extension(x)
            for x in (allowed_download_extensions or self.DEFAULT_ALLOWED_DOWNLOAD_EXTENSIONS)
            if str(x).strip()
        }

        self.dangerous_file_extensions: Set[str] = {
            self._normalize_extension(x)
            for x in (dangerous_file_extensions or self.DEFAULT_DANGEROUS_FILE_EXTENSIONS)
            if str(x).strip()
        }

        self.rules: List[PermissionRule] = list(rules or [])

        self.security_approval_callback = security_approval_callback
        self.audit_callback = audit_callback
        self.event_callback = event_callback

        self.max_download_size_mb = int(max_download_size_mb)
        self.max_form_fields = int(max_form_fields)
        self.max_tabs_per_workspace = int(max_tabs_per_workspace)

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def can_execute_browser_action(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        action: Union[str, BrowserAction],
        url: Optional[str] = None,
        resource_type: Union[str, ResourceType, None] = None,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        requested_by: Optional[str] = None,
        payload: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Main permission entry point for Browser Agent, Master Agent, Router,
        Dashboard, or future API endpoints.
        """

        try:
            context_result = self._build_context(
                user_id=user_id,
                workspace_id=workspace_id,
                action=action,
                url=url,
                resource_type=resource_type,
                task_id=task_id,
                session_id=session_id,
                requested_by=requested_by,
                payload=dict(payload or {}),
                metadata=dict(metadata or {}),
            )

            if not context_result["success"]:
                return context_result

            context: PermissionContext = context_result["data"]["context"]

            validation = self._validate_task_context(context)
            if not validation["success"]:
                return validation

            domain_check = self._check_domain_policy(context)
            if domain_check["decision"] == PermissionDecision.DENY:
                return domain_check

            rule_check = self._evaluate_rules(context)
            if rule_check["decision"] in {
                PermissionDecision.DENY,
                PermissionDecision.REQUIRE_SECURITY_APPROVAL,
                PermissionDecision.REQUIRE_USER_CONFIRMATION,
            }:
                return self._finalize_permission_result(context, rule_check)

            action_check = self._evaluate_action_policy(context)
            return self._finalize_permission_result(context, action_check)

        except Exception as exc:
            logger.exception("Browser permission check failed.")
            return self._error_result(
                message="Browser permission check failed.",
                error=str(exc),
                metadata={
                    "action": str(action),
                    "url": url,
                    "task_id": task_id,
                    "session_id": session_id,
                },
            )

    def validate_navigation(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        url: str,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate browser navigation permission.
        """

        return self.can_execute_browser_action(
            user_id=user_id,
            workspace_id=workspace_id,
            action=BrowserAction.NAVIGATE,
            url=url,
            resource_type=ResourceType.URL,
            task_id=task_id,
            session_id=session_id,
            metadata=metadata,
        )

    def validate_scraping(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        url: str,
        scrape_type: str = "public_content",
        respects_robots: bool = True,
        requires_login: bool = False,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate scraping permission.

        Important:
            This method does not bypass websites, login walls, paywalls,
            rate limits, robots rules, or legal restrictions.
        """

        payload = {
            "scrape_type": scrape_type,
            "respects_robots": bool(respects_robots),
            "requires_login": bool(requires_login),
        }

        result = self.can_execute_browser_action(
            user_id=user_id,
            workspace_id=workspace_id,
            action=BrowserAction.SCRAPE,
            url=url,
            resource_type=ResourceType.PAGE,
            task_id=task_id,
            session_id=session_id,
            payload=payload,
            metadata=metadata,
        )

        if not result.get("success"):
            return result

        if requires_login:
            return self._safe_result(
                decision=PermissionDecision.REQUIRE_SECURITY_APPROVAL,
                message="Scraping behind login requires Security Agent approval.",
                risk_level=RiskLevel.HIGH,
                action=BrowserAction.SCRAPE,
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                security_required=True,
                blocked_reasons=["requires_login"],
                data={"url": url, "scrape_type": scrape_type},
                metadata=self._merge_metadata(metadata, {"policy": "scraping_login_gate"}),
            )

        if not respects_robots:
            return self._safe_result(
                decision=PermissionDecision.REQUIRE_USER_CONFIRMATION,
                message="Scraping request does not confirm robots/rate-limit compliance.",
                risk_level=RiskLevel.MEDIUM,
                action=BrowserAction.SCRAPE,
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                user_confirmation_required=True,
                blocked_reasons=["robots_compliance_not_confirmed"],
                data={"url": url, "scrape_type": scrape_type},
                metadata=self._merge_metadata(metadata, {"policy": "scraping_robots_gate"}),
            )

        return result

    def validate_form_fill(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        url: str,
        form_fields: Mapping[str, Any],
        submit: bool = False,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate form filling or form submission.

        Filling a form is lower risk than submitting a form.
        Sensitive fields trigger Security Agent approval.
        """

        action = BrowserAction.SUBMIT_FORM if submit else BrowserAction.FILL_FORM
        field_analysis = self.analyze_form_fields(form_fields)

        payload = {
            "submit": bool(submit),
            "field_count": len(form_fields),
            "field_analysis": field_analysis,
        }

        base_result = self.can_execute_browser_action(
            user_id=user_id,
            workspace_id=workspace_id,
            action=action,
            url=url,
            resource_type=ResourceType.FORM,
            task_id=task_id,
            session_id=session_id,
            payload=payload,
            metadata=metadata,
        )

        if not base_result.get("success"):
            return base_result

        if len(form_fields) > self.max_form_fields:
            return self._safe_result(
                decision=PermissionDecision.DENY,
                message="Form contains too many fields for safe automated handling.",
                risk_level=RiskLevel.HIGH,
                action=action,
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                blocked_reasons=["max_form_fields_exceeded"],
                data=payload,
                metadata=self._merge_metadata(metadata, {"max_form_fields": self.max_form_fields}),
            )

        if field_analysis["has_sensitive_fields"]:
            return self._safe_result(
                decision=PermissionDecision.REQUIRE_SECURITY_APPROVAL,
                message="Sensitive form fields require Security Agent approval.",
                risk_level=RiskLevel.HIGH,
                action=action,
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                security_required=True,
                matched_rules=["sensitive_form_fields"],
                data=payload,
                metadata=self._merge_metadata(metadata, {"policy": "sensitive_form_gate"}),
            )

        if submit:
            return self._safe_result(
                decision=PermissionDecision.REQUIRE_USER_CONFIRMATION,
                message="Submitting a form requires user confirmation.",
                risk_level=RiskLevel.MEDIUM,
                action=action,
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                user_confirmation_required=True,
                data=payload,
                metadata=self._merge_metadata(metadata, {"policy": "form_submit_confirmation"}),
            )

        return base_result

    def validate_login(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        url: str,
        username_field_present: bool = True,
        password_field_present: bool = True,
        uses_2fa: bool = False,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate login action.

        Login is always sensitive and requires Security Agent approval.
        """

        payload = {
            "username_field_present": bool(username_field_present),
            "password_field_present": bool(password_field_present),
            "uses_2fa": bool(uses_2fa),
        }

        result = self.can_execute_browser_action(
            user_id=user_id,
            workspace_id=workspace_id,
            action=BrowserAction.LOGIN,
            url=url,
            resource_type=ResourceType.LOGIN,
            task_id=task_id,
            session_id=session_id,
            payload=payload,
            metadata=metadata,
        )

        if not result.get("success"):
            return result

        return self._safe_result(
            decision=PermissionDecision.REQUIRE_SECURITY_APPROVAL,
            message="Browser login requires Security Agent approval.",
            risk_level=RiskLevel.HIGH if not uses_2fa else RiskLevel.CRITICAL,
            action=BrowserAction.LOGIN,
            user_id=str(user_id),
            workspace_id=str(workspace_id),
            security_required=True,
            matched_rules=["login_security_gate"],
            data=payload,
            metadata=self._merge_metadata(metadata, {"policy": "login_security_gate"}),
        )

    def validate_download(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        url: str,
        filename: Optional[str] = None,
        content_type: Optional[str] = None,
        size_mb: Optional[Union[int, float]] = None,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate browser download permission.
        """

        extension = self._extract_extension(filename or url)
        payload = {
            "filename": filename,
            "content_type": content_type,
            "size_mb": size_mb,
            "extension": extension,
        }

        base_result = self.can_execute_browser_action(
            user_id=user_id,
            workspace_id=workspace_id,
            action=BrowserAction.DOWNLOAD,
            url=url,
            resource_type=ResourceType.DOWNLOAD,
            task_id=task_id,
            session_id=session_id,
            payload=payload,
            metadata=metadata,
        )

        if not base_result.get("success"):
            return base_result

        if size_mb is not None and float(size_mb) > self.max_download_size_mb:
            return self._safe_result(
                decision=PermissionDecision.REQUIRE_SECURITY_APPROVAL,
                message="Download size exceeds safe default limit and requires approval.",
                risk_level=RiskLevel.HIGH,
                action=BrowserAction.DOWNLOAD,
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                security_required=True,
                blocked_reasons=["download_size_limit_exceeded"],
                data=payload,
                metadata=self._merge_metadata(metadata, {"max_download_size_mb": self.max_download_size_mb}),
            )

        if extension in self.dangerous_file_extensions:
            return self._safe_result(
                decision=PermissionDecision.REQUIRE_SECURITY_APPROVAL,
                message="Potentially executable or dangerous download requires Security Agent approval.",
                risk_level=RiskLevel.CRITICAL,
                action=BrowserAction.DOWNLOAD,
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                security_required=True,
                blocked_reasons=["dangerous_file_extension"],
                data=payload,
                metadata=self._merge_metadata(metadata, {"policy": "dangerous_download_gate"}),
            )

        if extension and extension not in self.allowed_download_extensions:
            return self._safe_result(
                decision=PermissionDecision.REQUIRE_USER_CONFIRMATION,
                message="Unknown download file type requires user confirmation.",
                risk_level=RiskLevel.MEDIUM,
                action=BrowserAction.DOWNLOAD,
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                user_confirmation_required=True,
                blocked_reasons=["unknown_download_extension"],
                data=payload,
                metadata=self._merge_metadata(metadata, {"policy": "unknown_download_extension"}),
            )

        return self._safe_result(
            decision=PermissionDecision.REQUIRE_USER_CONFIRMATION,
            message="Download is allowed after user confirmation.",
            risk_level=RiskLevel.MEDIUM,
            action=BrowserAction.DOWNLOAD,
            user_id=str(user_id),
            workspace_id=str(workspace_id),
            user_confirmation_required=True,
            data=payload,
            metadata=self._merge_metadata(metadata, {"policy": "download_confirmation"}),
        )

    def validate_screenshot(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        url: Optional[str] = None,
        contains_sensitive_content: bool = False,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate screenshot permission.
        """

        payload = {"contains_sensitive_content": bool(contains_sensitive_content)}

        result = self.can_execute_browser_action(
            user_id=user_id,
            workspace_id=workspace_id,
            action=BrowserAction.SCREENSHOT,
            url=url,
            resource_type=ResourceType.PAGE,
            task_id=task_id,
            session_id=session_id,
            payload=payload,
            metadata=metadata,
        )

        if not result.get("success"):
            return result

        if contains_sensitive_content:
            return self._safe_result(
                decision=PermissionDecision.REQUIRE_SECURITY_APPROVAL,
                message="Screenshot may contain sensitive content and requires Security Agent approval.",
                risk_level=RiskLevel.HIGH,
                action=BrowserAction.SCREENSHOT,
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                security_required=True,
                data=payload,
                metadata=self._merge_metadata(metadata, {"policy": "sensitive_screenshot_gate"}),
            )

        if not self.allow_screenshots_by_default:
            return self._safe_result(
                decision=PermissionDecision.REQUIRE_USER_CONFIRMATION,
                message="Screenshot requires user confirmation by current policy.",
                risk_level=RiskLevel.MEDIUM,
                action=BrowserAction.SCREENSHOT,
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                user_confirmation_required=True,
                data=payload,
                metadata=self._merge_metadata(metadata, {"policy": "screenshot_confirmation"}),
            )

        return result

    def validate_cookie_access(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        url: str,
        write: bool = False,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate cookie read/write access.

        Cookie access is sensitive because it may expose sessions or auth state.
        """

        action = BrowserAction.COOKIE_WRITE if write else BrowserAction.COOKIE_READ

        return self._safe_result(
            decision=PermissionDecision.REQUIRE_SECURITY_APPROVAL,
            message="Cookie access requires Security Agent approval.",
            risk_level=RiskLevel.HIGH,
            action=action,
            user_id=str(user_id),
            workspace_id=str(workspace_id),
            security_required=True,
            data={"url": url, "write": bool(write)},
            metadata=self._merge_metadata(metadata, {"policy": "cookie_security_gate"}),
        )

    def validate_storage_access(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        url: str,
        write: bool = False,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate local/session storage read/write access.
        """

        action = BrowserAction.LOCAL_STORAGE_WRITE if write else BrowserAction.LOCAL_STORAGE_READ

        if write:
            return self._safe_result(
                decision=PermissionDecision.REQUIRE_SECURITY_APPROVAL,
                message="Browser storage write requires Security Agent approval.",
                risk_level=RiskLevel.HIGH,
                action=action,
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                security_required=True,
                data={"url": url, "write": bool(write)},
                metadata=self._merge_metadata(metadata, {"policy": "storage_write_security_gate"}),
            )

        return self.can_execute_browser_action(
            user_id=user_id,
            workspace_id=workspace_id,
            action=action,
            url=url,
            resource_type=ResourceType.STORAGE,
            task_id=task_id,
            session_id=session_id,
            metadata=metadata,
        )

    def validate_multi_tab_action(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        tab_count: int,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate multi-tab planning/action.
        """

        if int(tab_count) > self.max_tabs_per_workspace:
            return self._safe_result(
                decision=PermissionDecision.REQUIRE_USER_CONFIRMATION,
                message="Requested tab count exceeds safe workspace default.",
                risk_level=RiskLevel.MEDIUM,
                action=BrowserAction.MULTI_TAB,
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                user_confirmation_required=True,
                blocked_reasons=["max_tabs_per_workspace_exceeded"],
                data={
                    "tab_count": int(tab_count),
                    "max_tabs_per_workspace": self.max_tabs_per_workspace,
                },
                metadata=self._merge_metadata(metadata, {"policy": "multi_tab_limit"}),
            )

        return self.can_execute_browser_action(
            user_id=user_id,
            workspace_id=workspace_id,
            action=BrowserAction.MULTI_TAB,
            resource_type=ResourceType.TAB,
            task_id=task_id,
            session_id=session_id,
            payload={"tab_count": int(tab_count)},
            metadata=metadata,
        )

    def analyze_form_fields(self, form_fields: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Analyze form fields for sensitive values/names without exposing values.

        Values are not returned. Only field names and risk indicators are returned.
        """

        sensitive_fields: List[str] = []
        field_names: List[str] = []

        for raw_name in form_fields.keys():
            name = str(raw_name).strip()
            normalized = self._normalize_field_name(name)
            field_names.append(name)

            if self._is_sensitive_field_name(normalized):
                sensitive_fields.append(name)

        return {
            "field_count": len(form_fields),
            "field_names": field_names,
            "has_sensitive_fields": bool(sensitive_fields),
            "sensitive_fields": sensitive_fields,
        }

    def add_rule(self, rule: PermissionRule) -> Dict[str, Any]:
        """
        Add a permission rule at runtime.
        """

        if not isinstance(rule, PermissionRule):
            return self._error_result(
                message="Invalid permission rule.",
                error="rule must be PermissionRule",
            )

        self.rules.append(rule)

        return self._safe_result(
            decision=PermissionDecision.ALLOW,
            message="Permission rule added.",
            risk_level=RiskLevel.LOW,
            action=BrowserAction.UNKNOWN,
            data={"rule": asdict(rule)},
            metadata={"rule_count": len(self.rules)},
        )

    def remove_rule(self, rule_name: str) -> Dict[str, Any]:
        """
        Remove rules by name.
        """

        before = len(self.rules)
        self.rules = [rule for rule in self.rules if rule.name != rule_name]
        removed = before - len(self.rules)

        return self._safe_result(
            decision=PermissionDecision.ALLOW,
            message=f"Removed {removed} permission rule(s).",
            risk_level=RiskLevel.LOW,
            action=BrowserAction.UNKNOWN,
            data={"rule_name": rule_name, "removed": removed},
            metadata={"rule_count": len(self.rules)},
        )

    def list_rules(self) -> Dict[str, Any]:
        """
        List configured permission rules.
        """

        return self._safe_result(
            decision=PermissionDecision.ALLOW,
            message="Permission rules listed.",
            risk_level=RiskLevel.LOW,
            action=BrowserAction.UNKNOWN,
            data={"rules": [asdict(rule) for rule in self.rules]},
            metadata={"rule_count": len(self.rules)},
        )

    def get_policy_snapshot(self) -> Dict[str, Any]:
        """
        Return a safe snapshot of current BrowserPermissions policy.
        """

        return self._safe_result(
            decision=PermissionDecision.ALLOW,
            message="Browser permission policy snapshot prepared.",
            risk_level=RiskLevel.LOW,
            action=BrowserAction.UNKNOWN,
            data={
                "strict_mode": self.strict_mode,
                "allow_public_scraping_by_default": self.allow_public_scraping_by_default,
                "allow_screenshots_by_default": self.allow_screenshots_by_default,
                "allow_navigation_by_default": self.allow_navigation_by_default,
                "blocked_domains": sorted(self.blocked_domains),
                "allowed_domains": sorted(self.allowed_domains),
                "allowed_download_extensions": sorted(self.allowed_download_extensions),
                "dangerous_file_extensions": sorted(self.dangerous_file_extensions),
                "max_download_size_mb": self.max_download_size_mb,
                "max_form_fields": self.max_form_fields,
                "max_tabs_per_workspace": self.max_tabs_per_workspace,
                "rule_count": len(self.rules),
            },
        )

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(self, context: PermissionContext) -> Dict[str, Any]:
        """
        Validate SaaS context and prevent cross-user/workspace ambiguity.
        """

        blocked_reasons: List[str] = []

        if not context.user_id:
            blocked_reasons.append("missing_user_id")

        if not context.workspace_id:
            blocked_reasons.append("missing_workspace_id")

        if context.user_id in {"None", "null", "undefined", "0"}:
            blocked_reasons.append("invalid_user_id")

        if context.workspace_id in {"None", "null", "undefined", "0"}:
            blocked_reasons.append("invalid_workspace_id")

        if context.action == BrowserAction.UNKNOWN:
            blocked_reasons.append("unknown_action")

        if context.url:
            parsed = urlparse(context.url)
            if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
                blocked_reasons.append("unsupported_url_scheme")
            if not parsed.netloc and context.action in {
                BrowserAction.NAVIGATE,
                BrowserAction.SCRAPE,
                BrowserAction.DOWNLOAD,
                BrowserAction.LOGIN,
                BrowserAction.SUBMIT_FORM,
                BrowserAction.FILL_FORM,
            }:
                blocked_reasons.append("invalid_url")

        if blocked_reasons:
            return self._safe_result(
                decision=PermissionDecision.DENY,
                message="Browser task context failed validation.",
                risk_level=RiskLevel.HIGH,
                action=context.action,
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                blocked_reasons=blocked_reasons,
                data={"context": self._context_to_safe_dict(context)},
                metadata={"policy": "task_context_validation"},
            )

        return self._safe_result(
            decision=PermissionDecision.ALLOW,
            message="Browser task context validated.",
            risk_level=RiskLevel.LOW,
            action=context.action,
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            data={"context": self._context_to_safe_dict(context)},
            metadata={"policy": "task_context_validation"},
        )

    def _requires_security_check(
        self,
        context_or_action: Union[PermissionContext, BrowserAction, str],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Determine if action must pass through Security Agent.
        """

        if isinstance(context_or_action, PermissionContext):
            action = context_or_action.action
            action_payload = context_or_action.payload
        else:
            action = self._normalize_action(context_or_action)
            action_payload = dict(payload or {})

        if action in self.DEFAULT_SECURITY_REQUIRED_ACTIONS:
            return True

        if action_payload.get("contains_sensitive_content"):
            return True

        if action_payload.get("requires_login"):
            return True

        field_analysis = action_payload.get("field_analysis")
        if isinstance(field_analysis, Mapping) and field_analysis.get("has_sensitive_fields"):
            return True

        return False

    def _request_security_approval(
        self,
        context: PermissionContext,
        reason: str,
        risk_level: RiskLevel = RiskLevel.HIGH,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If a callback is injected, it is called safely. Otherwise, a structured
        approval-required response is returned.
        """

        approval_payload = {
            "approval_id": str(uuid.uuid4()),
            "agent_name": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "session_id": context.session_id,
            "action": context.action.value,
            "url": context.url,
            "domain": context.domain,
            "resource_type": context.resource_type.value,
            "reason": reason,
            "risk_level": risk_level.value,
            "created_at": time.time(),
            "metadata": dict(context.metadata or {}),
        }

        if self.security_approval_callback:
            try:
                response = self.security_approval_callback(approval_payload)
                if isinstance(response, Mapping):
                    return dict(response)
            except Exception as exc:
                logger.exception("Security approval callback failed.")
                return self._error_result(
                    message="Security approval request failed.",
                    error=str(exc),
                    metadata=approval_payload,
                )

        return self._safe_result(
            decision=PermissionDecision.REQUIRE_SECURITY_APPROVAL,
            message="Security Agent approval is required.",
            risk_level=risk_level,
            action=context.action,
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            security_required=True,
            data={"approval_payload": approval_payload},
            metadata={"policy": "security_agent_approval_required"},
        )

    def _prepare_verification_payload(
        self,
        context: PermissionContext,
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload after permission decision.
        """

        return {
            "verification_id": str(uuid.uuid4()),
            "source_agent": self.agent_name,
            "target_agent": "VerificationAgent",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "session_id": context.session_id,
            "action": context.action.value,
            "url": context.url,
            "domain": context.domain,
            "decision": result.get("decision"),
            "success": result.get("success"),
            "risk_level": result.get("risk_level"),
            "security_required": result.get("security_required", False),
            "user_confirmation_required": result.get("user_confirmation_required", False),
            "blocked_reasons": result.get("blocked_reasons", []),
            "created_at": time.time(),
            "metadata": {
                "permission_module": "agents/browser_agent/permissions.py",
                "resource_type": context.resource_type.value,
            },
        }

    def _prepare_memory_payload(
        self,
        context: PermissionContext,
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare safe Memory Agent payload.

        Sensitive form values, secrets, cookies, tokens, and passwords are never
        included here.
        """

        return {
            "memory_id": str(uuid.uuid4()),
            "source_agent": self.agent_name,
            "target_agent": "MemoryAgent",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "session_id": context.session_id,
            "memory_type": "browser_permission_decision",
            "summary": f"Browser action {context.action.value} received decision {result.get('decision')}.",
            "safe_context": {
                "action": context.action.value,
                "domain": context.domain,
                "resource_type": context.resource_type.value,
                "decision": result.get("decision"),
                "risk_level": result.get("risk_level"),
                "blocked_reasons": result.get("blocked_reasons", []),
            },
            "created_at": time.time(),
            "metadata": {
                "permission_module": "agents/browser_agent/permissions.py",
                "contains_sensitive_values": False,
            },
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Mapping[str, Any],
    ) -> None:
        """
        Emit event for dashboard/API/agent-event stream.
        """

        event = {
            "event_id": str(uuid.uuid4()),
            "event_name": event_name,
            "agent_name": self.agent_name,
            "created_at": time.time(),
            "payload": dict(payload),
        }

        if self.event_callback:
            try:
                self.event_callback(event)
                return
            except Exception:
                logger.exception("Browser permission event callback failed.")

        try:
            if hasattr(super(), "emit_event"):
                super().emit_event(event_name, event)  # type: ignore[misc]
        except Exception:
            logger.debug("BaseAgent event emission unavailable.", exc_info=True)

    def _log_audit_event(
        self,
        event_type: str,
        context: PermissionContext,
        result: Mapping[str, Any],
    ) -> None:
        """
        Log audit event with SaaS isolation context.
        """

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent_name": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "session_id": context.session_id,
            "action": context.action.value,
            "url": context.url,
            "domain": context.domain,
            "resource_type": context.resource_type.value,
            "decision": result.get("decision"),
            "success": result.get("success"),
            "risk_level": result.get("risk_level"),
            "security_required": result.get("security_required", False),
            "user_confirmation_required": result.get("user_confirmation_required", False),
            "blocked_reasons": result.get("blocked_reasons", []),
            "created_at": time.time(),
            "metadata": dict(context.metadata or {}),
        }

        if self.audit_callback:
            try:
                self.audit_callback(audit_event)
                return
            except Exception:
                logger.exception("Browser permission audit callback failed.")

        logger.info("Browser permission audit event: %s", audit_event)

    def _safe_result(
        self,
        *,
        decision: Union[PermissionDecision, str],
        message: str,
        risk_level: Union[RiskLevel, str],
        action: Union[BrowserAction, str],
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        security_required: bool = False,
        user_confirmation_required: bool = False,
        matched_rules: Optional[List[str]] = None,
        blocked_reasons: Optional[List[str]] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success result format.
        """

        normalized_decision = self._normalize_decision(decision)
        normalized_risk = self._normalize_risk_level(risk_level)
        normalized_action = self._normalize_action(action)

        success = normalized_decision in {
            PermissionDecision.ALLOW,
            PermissionDecision.REQUIRE_SECURITY_APPROVAL,
            PermissionDecision.REQUIRE_USER_CONFIRMATION,
            PermissionDecision.REQUIRE_MORE_CONTEXT,
        }

        return {
            "success": success,
            "message": message,
            "data": dict(data or {}),
            "error": None,
            "metadata": {
                "agent_name": self.agent_name,
                "module": "agents/browser_agent/permissions.py",
                "timestamp": time.time(),
                **dict(metadata or {}),
            },
            "decision": normalized_decision.value,
            "risk_level": normalized_risk.value,
            "action": normalized_action.value,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "security_required": bool(security_required),
            "user_confirmation_required": bool(user_confirmation_required),
            "matched_rules": list(matched_rules or []),
            "blocked_reasons": list(blocked_reasons or []),
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result format.
        """

        return {
            "success": False,
            "message": message,
            "data": dict(data or {}),
            "error": error or message,
            "metadata": {
                "agent_name": self.agent_name,
                "module": "agents/browser_agent/permissions.py",
                "timestamp": time.time(),
                **dict(metadata or {}),
            },
            "decision": PermissionDecision.DENY.value,
            "risk_level": RiskLevel.HIGH.value,
            "action": BrowserAction.UNKNOWN.value,
            "user_id": None,
            "workspace_id": None,
            "security_required": False,
            "user_confirmation_required": False,
            "matched_rules": [],
            "blocked_reasons": ["internal_error"],
        }

    # -------------------------------------------------------------------------
    # Internal policy engine
    # -------------------------------------------------------------------------

    def _build_context(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        action: Union[str, BrowserAction],
        url: Optional[str],
        resource_type: Union[str, ResourceType, None],
        task_id: Optional[str],
        session_id: Optional[str],
        requested_by: Optional[str],
        payload: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Build normalized PermissionContext.
        """

        normalized_action = self._normalize_action(action)
        normalized_resource = self._normalize_resource_type(resource_type)
        domain = self._extract_domain(url) if url else None

        context = PermissionContext(
            user_id=str(user_id).strip(),
            workspace_id=str(workspace_id).strip(),
            action=normalized_action,
            url=url,
            domain=domain,
            resource_type=normalized_resource,
            task_id=task_id,
            session_id=session_id,
            agent_name=self.agent_name,
            requested_by=requested_by,
            payload=dict(payload or {}),
            metadata=dict(metadata or {}),
        )

        return self._safe_result(
            decision=PermissionDecision.ALLOW,
            message="Permission context built.",
            risk_level=RiskLevel.LOW,
            action=normalized_action,
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            data={"context": context},
            metadata={"policy": "context_builder"},
        )

    def _check_domain_policy(self, context: PermissionContext) -> Dict[str, Any]:
        """
        Check blocked/allowed domain policy.
        """

        if not context.domain:
            return self._safe_result(
                decision=PermissionDecision.ALLOW,
                message="No domain policy needed.",
                risk_level=RiskLevel.LOW,
                action=context.action,
                user_id=context.user_id,
                workspace_id=context.workspace_id,
            )

        domain = self._normalize_domain(context.domain)

        if self._domain_matches(domain, self.blocked_domains):
            return self._safe_result(
                decision=PermissionDecision.DENY,
                message="Domain is blocked by Browser Agent permission policy.",
                risk_level=RiskLevel.HIGH,
                action=context.action,
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                blocked_reasons=["blocked_domain"],
                data={"domain": domain},
                metadata={"policy": "blocked_domain"},
            )

        if self.allowed_domains and not self._domain_matches(domain, self.allowed_domains):
            return self._safe_result(
                decision=PermissionDecision.REQUIRE_USER_CONFIRMATION,
                message="Domain is not in allowlist and requires confirmation.",
                risk_level=RiskLevel.MEDIUM,
                action=context.action,
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                user_confirmation_required=True,
                blocked_reasons=["domain_not_allowlisted"],
                data={"domain": domain},
                metadata={"policy": "domain_allowlist"},
            )

        return self._safe_result(
            decision=PermissionDecision.ALLOW,
            message="Domain policy passed.",
            risk_level=RiskLevel.LOW,
            action=context.action,
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            data={"domain": domain},
            metadata={"policy": "domain_policy"},
        )

    def _evaluate_rules(self, context: PermissionContext) -> Dict[str, Any]:
        """
        Evaluate explicit permission rules.
        """

        matched: List[PermissionRule] = []

        for rule in self.rules:
            if not rule.enabled:
                continue

            if not self._rule_matches_context(rule, context):
                continue

            matched.append(rule)

        if not matched:
            return self._safe_result(
                decision=PermissionDecision.ALLOW,
                message="No explicit permission rule matched.",
                risk_level=RiskLevel.LOW,
                action=context.action,
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                metadata={"policy": "rule_evaluation"},
            )

        highest = self._select_highest_priority_rule(matched)

        decision = self._normalize_decision(highest.decision)
        risk = self._normalize_risk_level(highest.risk_level)

        return self._safe_result(
            decision=decision,
            message=highest.description or f"Permission rule matched: {highest.name}",
            risk_level=risk,
            action=context.action,
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            security_required=highest.requires_security or decision == PermissionDecision.REQUIRE_SECURITY_APPROVAL,
            user_confirmation_required=(
                highest.requires_user_confirmation
                or decision == PermissionDecision.REQUIRE_USER_CONFIRMATION
            ),
            matched_rules=[rule.name for rule in matched],
            data={
                "selected_rule": asdict(highest),
                "matched_rule_count": len(matched),
            },
            metadata={"policy": "explicit_permission_rule"},
        )

    def _evaluate_action_policy(self, context: PermissionContext) -> Dict[str, Any]:
        """
        Evaluate default action policy.
        """

        if self._requires_security_check(context):
            return self._safe_result(
                decision=PermissionDecision.REQUIRE_SECURITY_APPROVAL,
                message="Browser action requires Security Agent approval.",
                risk_level=self._risk_for_action(context.action),
                action=context.action,
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                security_required=True,
                matched_rules=["default_security_required_action"],
                data={"context": self._context_to_safe_dict(context)},
                metadata={"policy": "default_security_required_action"},
            )

        if context.action == BrowserAction.NAVIGATE:
            if self.allow_navigation_by_default:
                return self._allow_result(context, "Navigation is allowed by default browser policy.")
            return self._confirmation_result(context, "Navigation requires user confirmation by policy.")

        if context.action in {
            BrowserAction.SEARCH,
            BrowserAction.EXTRACT_CONTENT,
            BrowserAction.ANALYZE_PAGE,
            BrowserAction.SEO_ANALYZE,
            BrowserAction.COMPETITOR_ANALYZE,
            BrowserAction.PRICE_MONITOR,
        }:
            return self._allow_result(context, "Browser analysis action is allowed by default policy.")

        if context.action == BrowserAction.SCRAPE:
            if self.allow_public_scraping_by_default:
                return self._allow_result(context, "Public scraping is allowed by default policy.")
            return self._confirmation_result(context, "Scraping requires user confirmation by policy.")

        if context.action == BrowserAction.SCREENSHOT:
            if self.allow_screenshots_by_default:
                return self._allow_result(context, "Screenshot is allowed by default policy.")
            return self._confirmation_result(context, "Screenshot requires user confirmation by policy.")

        if context.action in {
            BrowserAction.CLICK,
            BrowserAction.MULTI_TAB,
            BrowserAction.SESSION_CREATE,
            BrowserAction.SESSION_CLOSE,
            BrowserAction.LOGOUT,
        }:
            return self._allow_result(context, "Low-risk browser action is allowed by default policy.")

        if context.action in self.DEFAULT_HIGH_RISK_ACTIONS:
            return self._security_required_result(context, "High-risk browser action requires Security Agent approval.")

        if self.strict_mode:
            return self._confirmation_result(context, "Unknown browser action requires user confirmation in strict mode.")

        return self._allow_result(context, "Browser action is allowed because strict mode is disabled.")

    def _finalize_permission_result(
        self,
        context: PermissionContext,
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Attach verification/memory payloads, emit event, and log audit.
        """

        final_result = dict(result)

        verification_payload = self._prepare_verification_payload(context, final_result)
        memory_payload = self._prepare_memory_payload(context, final_result)

        final_result.setdefault("data", {})
        if isinstance(final_result["data"], dict):
            final_result["data"]["verification_payload"] = verification_payload
            final_result["data"]["memory_payload"] = memory_payload

        self._emit_agent_event(
            "browser_permission_decision",
            {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "task_id": context.task_id,
                "session_id": context.session_id,
                "action": context.action.value,
                "decision": final_result.get("decision"),
                "risk_level": final_result.get("risk_level"),
            },
        )

        self._log_audit_event(
            event_type="browser_permission_decision",
            context=context,
            result=final_result,
        )

        return final_result

    # -------------------------------------------------------------------------
    # Rule matching helpers
    # -------------------------------------------------------------------------

    def _rule_matches_context(self, rule: PermissionRule, context: PermissionContext) -> bool:
        """
        Check if a permission rule matches current context.
        """

        rule_action = self._normalize_action(rule.action)
        if rule_action != BrowserAction.UNKNOWN and rule_action != context.action:
            return False

        if rule.user_ids and context.user_id not in {str(x) for x in rule.user_ids}:
            return False

        if rule.workspace_ids and context.workspace_id not in {str(x) for x in rule.workspace_ids}:
            return False

        rule_resource = self._normalize_resource_type(rule.resource_type)
        if rule_resource != ResourceType.UNKNOWN and rule_resource != context.resource_type:
            return False

        if rule.domains:
            if not context.domain:
                return False
            if not self._domain_matches(context.domain, self._normalize_domain_set(rule.domains)):
                return False

        if rule.url_patterns:
            if not context.url:
                return False
            if not any(self._safe_regex_match(pattern, context.url) for pattern in rule.url_patterns):
                return False

        return True

    def _select_highest_priority_rule(self, rules: Sequence[PermissionRule]) -> PermissionRule:
        """
        Select highest priority rule.

        Priority:
            DENY > SECURITY > USER_CONFIRMATION > MORE_CONTEXT > ALLOW
            Then CRITICAL > HIGH > MEDIUM > LOW
        """

        decision_priority = {
            PermissionDecision.DENY: 100,
            PermissionDecision.REQUIRE_SECURITY_APPROVAL: 80,
            PermissionDecision.REQUIRE_USER_CONFIRMATION: 60,
            PermissionDecision.REQUIRE_MORE_CONTEXT: 40,
            PermissionDecision.ALLOW: 10,
        }

        risk_priority = {
            RiskLevel.CRITICAL: 40,
            RiskLevel.HIGH: 30,
            RiskLevel.MEDIUM: 20,
            RiskLevel.LOW: 10,
        }

        def score(rule: PermissionRule) -> Tuple[int, int]:
            return (
                decision_priority[self._normalize_decision(rule.decision)],
                risk_priority[self._normalize_risk_level(rule.risk_level)],
            )

        return sorted(rules, key=score, reverse=True)[0]

    # -------------------------------------------------------------------------
    # Result helpers
    # -------------------------------------------------------------------------

    def _allow_result(self, context: PermissionContext, message: str) -> Dict[str, Any]:
        return self._safe_result(
            decision=PermissionDecision.ALLOW,
            message=message,
            risk_level=self._risk_for_action(context.action),
            action=context.action,
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            data={"context": self._context_to_safe_dict(context)},
            metadata={"policy": "default_allow"},
        )

    def _confirmation_result(self, context: PermissionContext, message: str) -> Dict[str, Any]:
        return self._safe_result(
            decision=PermissionDecision.REQUIRE_USER_CONFIRMATION,
            message=message,
            risk_level=self._risk_for_action(context.action),
            action=context.action,
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            user_confirmation_required=True,
            data={"context": self._context_to_safe_dict(context)},
            metadata={"policy": "user_confirmation_required"},
        )

    def _security_required_result(self, context: PermissionContext, message: str) -> Dict[str, Any]:
        return self._safe_result(
            decision=PermissionDecision.REQUIRE_SECURITY_APPROVAL,
            message=message,
            risk_level=self._risk_for_action(context.action),
            action=context.action,
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            security_required=True,
            data={"context": self._context_to_safe_dict(context)},
            metadata={"policy": "security_required"},
        )

    # -------------------------------------------------------------------------
    # Normalization helpers
    # -------------------------------------------------------------------------

    def _normalize_action(self, action: Union[str, BrowserAction]) -> BrowserAction:
        if isinstance(action, BrowserAction):
            return action

        raw = str(action or "").strip().lower()

        if not raw:
            return BrowserAction.UNKNOWN

        aliases = {
            "form_submit": BrowserAction.SUBMIT_FORM,
            "submit": BrowserAction.SUBMIT_FORM,
            "form_fill": BrowserAction.FILL_FORM,
            "fill": BrowserAction.FILL_FORM,
            "signin": BrowserAction.LOGIN,
            "sign_in": BrowserAction.LOGIN,
            "signout": BrowserAction.LOGOUT,
            "sign_out": BrowserAction.LOGOUT,
            "capture": BrowserAction.SCREENSHOT,
            "screen_capture": BrowserAction.SCREENSHOT,
            "extract": BrowserAction.EXTRACT_CONTENT,
            "content_extract": BrowserAction.EXTRACT_CONTENT,
            "page_analysis": BrowserAction.ANALYZE_PAGE,
            "tabs": BrowserAction.MULTI_TAB,
            "browser_automation": BrowserAction.AUTOMATION,
        }

        if raw in aliases:
            return aliases[raw]

        try:
            return BrowserAction(raw)
        except ValueError:
            return BrowserAction.UNKNOWN

    def _normalize_decision(self, decision: Union[str, PermissionDecision]) -> PermissionDecision:
        if isinstance(decision, PermissionDecision):
            return decision

        raw = str(decision or "").strip().lower()

        aliases = {
            "approved": PermissionDecision.ALLOW,
            "allowed": PermissionDecision.ALLOW,
            "block": PermissionDecision.DENY,
            "blocked": PermissionDecision.DENY,
            "reject": PermissionDecision.DENY,
            "rejected": PermissionDecision.DENY,
            "security": PermissionDecision.REQUIRE_SECURITY_APPROVAL,
            "security_approval": PermissionDecision.REQUIRE_SECURITY_APPROVAL,
            "confirm": PermissionDecision.REQUIRE_USER_CONFIRMATION,
            "confirmation": PermissionDecision.REQUIRE_USER_CONFIRMATION,
            "more_context": PermissionDecision.REQUIRE_MORE_CONTEXT,
            "context": PermissionDecision.REQUIRE_MORE_CONTEXT,
        }

        if raw in aliases:
            return aliases[raw]

        try:
            return PermissionDecision(raw)
        except ValueError:
            return PermissionDecision.DENY

    def _normalize_risk_level(self, risk_level: Union[str, RiskLevel]) -> RiskLevel:
        if isinstance(risk_level, RiskLevel):
            return risk_level

        raw = str(risk_level or "").strip().lower()

        try:
            return RiskLevel(raw)
        except ValueError:
            return RiskLevel.MEDIUM

    def _normalize_resource_type(
        self,
        resource_type: Union[str, ResourceType, None],
    ) -> ResourceType:
        if isinstance(resource_type, ResourceType):
            return resource_type

        raw = str(resource_type or "").strip().lower()

        if not raw:
            return ResourceType.UNKNOWN

        aliases = {
            "webpage": ResourceType.PAGE,
            "website": ResourceType.URL,
            "link": ResourceType.URL,
            "file_download": ResourceType.DOWNLOAD,
            "browser_session": ResourceType.SESSION,
        }

        if raw in aliases:
            return aliases[raw]

        try:
            return ResourceType(raw)
        except ValueError:
            return ResourceType.UNKNOWN

    def _risk_for_action(self, action: BrowserAction) -> RiskLevel:
        if action in {
            BrowserAction.LOGIN,
            BrowserAction.COOKIE_READ,
            BrowserAction.COOKIE_WRITE,
            BrowserAction.LOCAL_STORAGE_WRITE,
        }:
            return RiskLevel.HIGH

        if action in {
            BrowserAction.SUBMIT_FORM,
            BrowserAction.DOWNLOAD,
            BrowserAction.UPLOAD,
            BrowserAction.AUTOMATION,
        }:
            return RiskLevel.MEDIUM

        if action in {
            BrowserAction.SCRAPE,
            BrowserAction.SCREENSHOT,
            BrowserAction.MULTI_TAB,
            BrowserAction.PRICE_MONITOR,
        }:
            return RiskLevel.MEDIUM

        return RiskLevel.LOW

    # -------------------------------------------------------------------------
    # URL/domain/file helpers
    # -------------------------------------------------------------------------

    def _extract_domain(self, url: Optional[str]) -> Optional[str]:
        if not url:
            return None

        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split("/")[0]
            domain = domain.split("@")[-1]
            domain = domain.split(":")[0]
            return self._normalize_domain(domain)
        except Exception:
            return None

    def _normalize_domain(self, domain: str) -> str:
        clean = str(domain or "").strip().lower()
        clean = clean.replace("http://", "").replace("https://", "")
        clean = clean.split("/")[0].split(":")[0].strip()
        clean = clean[4:] if clean.startswith("www.") else clean
        return clean

    def _normalize_domain_set(self, domains: Iterable[str]) -> Set[str]:
        return {
            self._normalize_domain(domain)
            for domain in domains
            if str(domain or "").strip()
        }

    def _domain_matches(self, domain: str, domain_set: Iterable[str]) -> bool:
        clean = self._normalize_domain(domain)
        for rule_domain in domain_set:
            rule_clean = self._normalize_domain(rule_domain)
            if clean == rule_clean:
                return True
            if clean.endswith("." + rule_clean):
                return True
        return False

    def _extract_extension(self, filename_or_url: str) -> str:
        raw = str(filename_or_url or "").strip().lower()
        if not raw:
            return ""

        path = urlparse(raw).path or raw
        if "." not in path:
            return ""

        ext = "." + path.rsplit(".", 1)[-1].split("?")[0].split("#")[0].strip(".")
        return self._normalize_extension(ext)

    def _normalize_extension(self, ext: str) -> str:
        clean = str(ext or "").strip().lower()
        if not clean:
            return ""
        return clean if clean.startswith(".") else f".{clean}"

    # -------------------------------------------------------------------------
    # Sensitive field helpers
    # -------------------------------------------------------------------------

    def _normalize_field_name(self, field_name: str) -> str:
        return re.sub(r"[^a-z0-9_]+", "_", str(field_name or "").strip().lower())

    def _is_sensitive_field_name(self, normalized_field_name: str) -> bool:
        if normalized_field_name in self.sensitive_field_names:
            return True

        for sensitive in self.sensitive_field_names:
            if sensitive and sensitive in normalized_field_name:
                return True

        return False

    # -------------------------------------------------------------------------
    # Misc helpers
    # -------------------------------------------------------------------------

    def _safe_regex_match(self, pattern: str, value: str) -> bool:
        try:
            return re.search(pattern, value, flags=re.IGNORECASE) is not None
        except re.error:
            logger.warning("Invalid permission rule regex pattern: %s", pattern)
            return False

    def _context_to_safe_dict(self, context: PermissionContext) -> Dict[str, Any]:
        """
        Convert context to safe dict without exposing sensitive form values.
        """

        safe_payload: Dict[str, Any] = {}

        for key, value in context.payload.items():
            normalized_key = self._normalize_field_name(str(key))
            if self._is_sensitive_field_name(normalized_key):
                safe_payload[key] = "[REDACTED]"
            elif key == "form_fields":
                safe_payload[key] = "[REDACTED_FORM_VALUES]"
            else:
                safe_payload[key] = value

        return {
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "action": context.action.value,
            "url": context.url,
            "domain": context.domain,
            "resource_type": context.resource_type.value,
            "task_id": context.task_id,
            "session_id": context.session_id,
            "agent_name": context.agent_name,
            "requested_by": context.requested_by,
            "payload": safe_payload,
            "metadata": dict(context.metadata or {}),
        }

    def _merge_metadata(
        self,
        original: Optional[Mapping[str, Any]],
        extra: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        merged = dict(original or {})
        merged.update(dict(extra or {}))
        return merged


# =============================================================================
# Convenience factory
# =============================================================================

def create_browser_permissions(
    **kwargs: Any,
) -> BrowserPermissions:
    """
    Factory helper for Agent Loader / Registry.

    Example:
        permissions = create_browser_permissions(strict_mode=True)
    """

    return BrowserPermissions(**kwargs)


# =============================================================================
# Module exports
# =============================================================================

__all__ = [
    "BrowserAction",
    "PermissionDecision",
    "RiskLevel",
    "ResourceType",
    "PermissionRule",
    "PermissionContext",
    "PermissionCheckResult",
    "BrowserPermissions",
    "create_browser_permissions",
]