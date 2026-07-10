"""
agents/browser_agent/config.py

Browser Agent configuration for William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    - Centralize Browser Agent settings.
    - Manage max tabs, supported search engines, rate limits, screenshot settings,
      safe browsing defaults, timeouts, user/workspace isolation, audit-ready metadata,
      and dashboard/API-safe export.
    - Keep the file import-safe even before the full William system is generated.

Architecture Compatibility:
    - Master Agent:
        Reads BrowserConfig to understand allowed browser capabilities.
    - Security Agent:
        Uses safe mode, restricted domains, sensitive action flags, and permission hooks.
    - Memory Agent:
        Can store safe configuration preferences per user/workspace.
    - Verification Agent:
        Receives verification payloads after configuration validation/update.
    - Dashboard/API:
        Can safely expose sanitized configuration via to_public_dict().
    - Registry/Loader/Router:
        Can import this file without hard dependency crashes.

Important:
    This file contains configuration and validation logic only.
    It does NOT perform real browsing, scraping, downloading, clicking, login,
    financial, messaging, or destructive actions.
"""

from __future__ import annotations

import copy
import logging
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union


LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Optional William/Jarvis Imports With Safe Fallbacks
# ---------------------------------------------------------------------------

try:
    from core.config import settings as william_settings  # type: ignore
except Exception:  # pragma: no cover
    william_settings = None


try:
    from core.context import AgentContext  # type: ignore
except Exception:  # pragma: no cover

    @dataclass
    class AgentContext:
        """
        Fallback AgentContext.

        Used only when the real core.context.AgentContext is not available yet.
        This keeps the file import-safe during staged project generation.
        """

        user_id: Optional[Union[str, int]] = None
        workspace_id: Optional[Union[str, int]] = None
        role: Optional[str] = None
        permissions: List[str] = field(default_factory=list)
        metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_BROWSER_AGENT_NAME = "browser_agent"
DEFAULT_BROWSER_CONFIG_VERSION = "1.0.0"

DEFAULT_MAX_TABS = 5
DEFAULT_MAX_TABS_HARD_LIMIT = 25
DEFAULT_REQUESTS_PER_MINUTE = 30
DEFAULT_REQUESTS_PER_HOUR = 500
DEFAULT_DAILY_REQUEST_LIMIT = 5000
DEFAULT_SCREENSHOT_MAX_PER_TASK = 10

DEFAULT_PAGE_TIMEOUT_SECONDS = 30
DEFAULT_NAVIGATION_TIMEOUT_SECONDS = 45
DEFAULT_DOWNLOAD_TIMEOUT_SECONDS = 120
DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60

DEFAULT_USER_AGENT = (
    "WilliamBrowserAgent/1.0 "
    "(SaaS-safe; permission-aware; +https://digitalpromotix.dev)"
)

DEFAULT_ALLOWED_SEARCH_ENGINES = [
    "google",
    "bing",
    "duckduckgo",
    "brave",
]

DEFAULT_SEARCH_ENGINE_URLS = {
    "google": "https://www.google.com/search?q={query}",
    "bing": "https://www.bing.com/search?q={query}",
    "duckduckgo": "https://duckduckgo.com/?q={query}",
    "brave": "https://search.brave.com/search?q={query}",
}

DEFAULT_BLOCKED_SCHEMES = [
    "file:",
    "ftp:",
    "javascript:",
    "data:",
    "chrome:",
    "chrome-extension:",
    "about:",
]

DEFAULT_RESTRICTED_DOMAINS = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
]

DEFAULT_SENSITIVE_ACTIONS = [
    "login",
    "submit_form",
    "download_file",
    "upload_file",
    "purchase",
    "payment",
    "send_message",
    "delete",
    "modify_account",
    "change_password",
    "access_private_data",
]

DEFAULT_BROWSER_PERMISSIONS = [
    "browser.search",
    "browser.open_page",
    "browser.read_public_page",
    "browser.take_screenshot",
    "browser.extract_content",
]


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class BrowserSafetyMode(str, Enum):
    """
    Browser safety mode.

    STRICT:
        Maximum protection. Blocks restricted domains, sensitive actions,
        unsafe schemes, and requires security approval for anything risky.

    BALANCED:
        Production default. Allows normal public-page reads/searches while
        still protecting sensitive actions.

    RESEARCH:
        More permissive for public research but still blocks destructive actions.

    OFF:
        Not recommended. Kept only for internal supervised environments.
    """

    STRICT = "strict"
    BALANCED = "balanced"
    RESEARCH = "research"
    OFF = "off"


class ScreenshotFormat(str, Enum):
    """Supported screenshot formats."""

    PNG = "png"
    JPEG = "jpeg"
    WEBP = "webp"


class SearchEngineMode(str, Enum):
    """Search engine selection behavior."""

    FIXED = "fixed"
    ROTATE = "rotate"
    FAILOVER = "failover"


class BrowserExecutionMode(str, Enum):
    """
    Browser execution mode.

    CONFIG_ONLY:
        Default for this config file. No browser actions.

    HEADLESS:
        Intended for future browser runtime.

    VISIBLE:
        Intended for supervised dashboard/browser runtime.
    """

    CONFIG_ONLY = "config_only"
    HEADLESS = "headless"
    VISIBLE = "visible"


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class RateLimitConfig:
    """
    Rate limit configuration for Browser Agent tasks.

    This does not execute rate limiting directly across distributed systems.
    It provides safe limits to workers, dashboard, router, and future middleware.
    """

    requests_per_minute: int = DEFAULT_REQUESTS_PER_MINUTE
    requests_per_hour: int = DEFAULT_REQUESTS_PER_HOUR
    daily_request_limit: int = DEFAULT_DAILY_REQUEST_LIMIT
    burst_limit: int = 5
    cooldown_seconds: int = 3
    window_seconds: int = DEFAULT_RATE_LIMIT_WINDOW_SECONDS

    def validate(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if self.requests_per_minute < 1:
            errors.append("requests_per_minute must be at least 1.")
        if self.requests_per_hour < self.requests_per_minute:
            errors.append("requests_per_hour must be greater than or equal to requests_per_minute.")
        if self.daily_request_limit < self.requests_per_hour:
            errors.append("daily_request_limit must be greater than or equal to requests_per_hour.")
        if self.burst_limit < 1:
            errors.append("burst_limit must be at least 1.")
        if self.cooldown_seconds < 0:
            errors.append("cooldown_seconds cannot be negative.")
        if self.window_seconds < 1:
            errors.append("window_seconds must be at least 1.")

        return len(errors) == 0, errors

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScreenshotConfig:
    """
    Screenshot settings.

    Screenshots can contain sensitive data, so capture must be controlled by:
        - safe mode
        - permission checks
        - per-task limits
        - audit metadata
    """

    enabled: bool = True
    format: ScreenshotFormat = ScreenshotFormat.PNG
    quality: int = 85
    full_page: bool = False
    max_per_task: int = DEFAULT_SCREENSHOT_MAX_PER_TASK
    redact_sensitive_fields: bool = True
    store_locally: bool = False
    storage_path: str = "storage/browser/screenshots"
    attach_to_verification_payload: bool = True

    def validate(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if isinstance(self.format, str):
            try:
                self.format = ScreenshotFormat(self.format)
            except ValueError:
                errors.append(f"Unsupported screenshot format: {self.format}")

        if not 1 <= self.quality <= 100:
            errors.append("screenshot quality must be between 1 and 100.")

        if self.max_per_task < 0:
            errors.append("max_per_task cannot be negative.")

        if self.store_locally and not self.storage_path:
            errors.append("storage_path is required when store_locally is enabled.")

        return len(errors) == 0, errors

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["format"] = self.format.value if isinstance(self.format, ScreenshotFormat) else self.format
        return data


@dataclass
class SearchEngineConfig:
    """
    Search engine configuration.

    This provides configuration only. Actual querying must be implemented in
    Browser Agent search tools and routed through Security Agent permissions.
    """

    default_engine: str = "google"
    allowed_engines: List[str] = field(default_factory=lambda: copy.deepcopy(DEFAULT_ALLOWED_SEARCH_ENGINES))
    engine_urls: Dict[str, str] = field(default_factory=lambda: copy.deepcopy(DEFAULT_SEARCH_ENGINE_URLS))
    mode: SearchEngineMode = SearchEngineMode.FAILOVER
    safe_search: bool = True
    region: str = "us"
    language: str = "en"
    max_results_per_query: int = 10

    def validate(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if isinstance(self.mode, str):
            try:
                self.mode = SearchEngineMode(self.mode)
            except ValueError:
                errors.append(f"Unsupported search engine mode: {self.mode}")

        if not self.allowed_engines:
            errors.append("At least one search engine must be allowed.")

        if self.default_engine not in self.allowed_engines:
            errors.append("default_engine must exist in allowed_engines.")

        missing_urls = [engine for engine in self.allowed_engines if engine not in self.engine_urls]
        if missing_urls:
            errors.append(f"Missing engine URLs for: {missing_urls}")

        for engine, url in self.engine_urls.items():
            if "{query}" not in url:
                errors.append(f"Search engine URL for '{engine}' must contain '{{query}}'.")

        if self.max_results_per_query < 1:
            errors.append("max_results_per_query must be at least 1.")

        if self.max_results_per_query > 100:
            errors.append("max_results_per_query cannot exceed 100.")

        return len(errors) == 0, errors

    def get_engine_url(self, engine: Optional[str] = None) -> Optional[str]:
        selected = engine or self.default_engine
        return self.engine_urls.get(selected)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["mode"] = self.mode.value if isinstance(self.mode, SearchEngineMode) else self.mode
        return data


@dataclass
class BrowserSecurityConfig:
    """
    Browser safety and permission configuration.

    This configuration is consumed by:
        - Browser Agent runtime
        - Security Agent
        - Master Agent policy checks
        - Dashboard/API permission views
    """

    safety_mode: BrowserSafetyMode = BrowserSafetyMode.BALANCED
    require_security_for_sensitive_actions: bool = True
    require_security_for_downloads: bool = True
    require_security_for_uploads: bool = True
    require_security_for_login: bool = True
    block_restricted_domains: bool = True
    block_unsafe_schemes: bool = True
    allow_private_network_access: bool = False
    allow_file_scheme: bool = False
    allowed_domains: List[str] = field(default_factory=list)
    restricted_domains: List[str] = field(default_factory=lambda: copy.deepcopy(DEFAULT_RESTRICTED_DOMAINS))
    blocked_schemes: List[str] = field(default_factory=lambda: copy.deepcopy(DEFAULT_BLOCKED_SCHEMES))
    sensitive_actions: List[str] = field(default_factory=lambda: copy.deepcopy(DEFAULT_SENSITIVE_ACTIONS))

    def validate(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if isinstance(self.safety_mode, str):
            try:
                self.safety_mode = BrowserSafetyMode(self.safety_mode)
            except ValueError:
                errors.append(f"Unsupported safety mode: {self.safety_mode}")

        if self.allow_file_scheme and "file:" in self.blocked_schemes:
            self.blocked_schemes = [scheme for scheme in self.blocked_schemes if scheme != "file:"]

        if not self.allow_private_network_access and not self.restricted_domains:
            self.restricted_domains = copy.deepcopy(DEFAULT_RESTRICTED_DOMAINS)

        return len(errors) == 0, errors

    def is_sensitive_action(self, action: str) -> bool:
        normalized = (action or "").strip().lower()
        return normalized in {item.strip().lower() for item in self.sensitive_actions}

    def is_scheme_blocked(self, url: str) -> bool:
        normalized = (url or "").strip().lower()
        if not self.block_unsafe_schemes:
            return False

        for scheme in self.blocked_schemes:
            if normalized.startswith(scheme.lower()):
                return True

        return False

    def is_domain_restricted(self, domain_or_url: str) -> bool:
        value = (domain_or_url or "").strip().lower()

        if not self.block_restricted_domains:
            return False

        if self.allowed_domains:
            for allowed in self.allowed_domains:
                if allowed.lower() in value:
                    return False

        for restricted in self.restricted_domains:
            if restricted.lower() in value:
                return True

        return False

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["safety_mode"] = (
            self.safety_mode.value
            if isinstance(self.safety_mode, BrowserSafetyMode)
            else self.safety_mode
        )
        return data


@dataclass
class BrowserTimeoutConfig:
    """Browser timeout settings."""

    page_timeout_seconds: int = DEFAULT_PAGE_TIMEOUT_SECONDS
    navigation_timeout_seconds: int = DEFAULT_NAVIGATION_TIMEOUT_SECONDS
    download_timeout_seconds: int = DEFAULT_DOWNLOAD_TIMEOUT_SECONDS
    idle_timeout_seconds: int = 300
    task_timeout_seconds: int = 900

    def validate(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if self.page_timeout_seconds < 1:
            errors.append("page_timeout_seconds must be at least 1.")
        if self.navigation_timeout_seconds < 1:
            errors.append("navigation_timeout_seconds must be at least 1.")
        if self.download_timeout_seconds < 1:
            errors.append("download_timeout_seconds must be at least 1.")
        if self.idle_timeout_seconds < 1:
            errors.append("idle_timeout_seconds must be at least 1.")
        if self.task_timeout_seconds < self.page_timeout_seconds:
            errors.append("task_timeout_seconds must be greater than or equal to page_timeout_seconds.")

        return len(errors) == 0, errors

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Main BrowserConfig Class
# ---------------------------------------------------------------------------

@dataclass
class BrowserConfig:
    """
    Production-level Browser Agent configuration.

    This class is safe to import and use before the rest of the project exists.
    It exposes structured methods so Master Agent, Agent Router, Dashboard/API,
    Security Agent, Verification Agent, and Memory Agent can interact with it.

    Public Responsibilities:
        - Store Browser Agent settings.
        - Validate settings.
        - Export safe public config.
        - Export internal config.
        - Apply controlled updates.
        - Prepare audit, memory, and verification payloads.
        - Enforce SaaS user/workspace context validation.
    """

    agent_name: str = DEFAULT_BROWSER_AGENT_NAME
    config_version: str = DEFAULT_BROWSER_CONFIG_VERSION
    enabled: bool = True
    execution_mode: BrowserExecutionMode = BrowserExecutionMode.CONFIG_ONLY

    max_tabs: int = DEFAULT_MAX_TABS
    max_tabs_hard_limit: int = DEFAULT_MAX_TABS_HARD_LIMIT
    allow_multi_tab: bool = True
    close_tabs_after_task: bool = True

    user_agent: str = DEFAULT_USER_AGENT
    respect_robots_txt: bool = True
    enable_cookies: bool = False
    enable_cache: bool = False
    enable_javascript: bool = True
    enable_downloads: bool = False
    enable_form_autofill: bool = False

    rate_limits: RateLimitConfig = field(default_factory=RateLimitConfig)
    screenshots: ScreenshotConfig = field(default_factory=ScreenshotConfig)
    search: SearchEngineConfig = field(default_factory=SearchEngineConfig)
    security: BrowserSecurityConfig = field(default_factory=BrowserSecurityConfig)
    timeouts: BrowserTimeoutConfig = field(default_factory=BrowserTimeoutConfig)

    default_permissions: List[str] = field(default_factory=lambda: copy.deepcopy(DEFAULT_BROWSER_PERMISSIONS))

    user_id: Optional[Union[str, int]] = None
    workspace_id: Optional[Union[str, int]] = None

    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        self._normalize_enums()
        self._load_env_overrides()
        self.validate_config()

    # -----------------------------------------------------------------------
    # Normalization / Factory Methods
    # -----------------------------------------------------------------------

    def _normalize_enums(self) -> None:
        if isinstance(self.execution_mode, str):
            try:
                self.execution_mode = BrowserExecutionMode(self.execution_mode)
            except ValueError:
                self.execution_mode = BrowserExecutionMode.CONFIG_ONLY

        if isinstance(self.rate_limits, dict):
            self.rate_limits = RateLimitConfig(**self.rate_limits)

        if isinstance(self.screenshots, dict):
            self.screenshots = ScreenshotConfig(**self.screenshots)

        if isinstance(self.search, dict):
            self.search = SearchEngineConfig(**self.search)

        if isinstance(self.security, dict):
            self.security = BrowserSecurityConfig(**self.security)

        if isinstance(self.timeouts, dict):
            self.timeouts = BrowserTimeoutConfig(**self.timeouts)

    def _load_env_overrides(self) -> None:
        """
        Load safe environment overrides.

        Secrets are never loaded here.
        This only reads non-sensitive operational defaults.
        """

        env_enabled = os.getenv("WILLIAM_BROWSER_ENABLED")
        env_max_tabs = os.getenv("WILLIAM_BROWSER_MAX_TABS")
        env_safe_mode = os.getenv("WILLIAM_BROWSER_SAFETY_MODE")
        env_default_engine = os.getenv("WILLIAM_BROWSER_DEFAULT_SEARCH_ENGINE")
        env_screenshots = os.getenv("WILLIAM_BROWSER_SCREENSHOTS_ENABLED")

        if env_enabled is not None:
            self.enabled = env_enabled.strip().lower() in {"1", "true", "yes", "on"}

        if env_max_tabs:
            try:
                self.max_tabs = int(env_max_tabs)
            except ValueError:
                LOGGER.warning("Invalid WILLIAM_BROWSER_MAX_TABS value ignored.")

        if env_safe_mode:
            try:
                self.security.safety_mode = BrowserSafetyMode(env_safe_mode.strip().lower())
            except ValueError:
                LOGGER.warning("Invalid WILLIAM_BROWSER_SAFETY_MODE value ignored.")

        if env_default_engine:
            normalized_engine = env_default_engine.strip().lower()
            if normalized_engine in self.search.allowed_engines:
                self.search.default_engine = normalized_engine

        if env_screenshots is not None:
            self.screenshots.enabled = env_screenshots.strip().lower() in {"1", "true", "yes", "on"}

    @classmethod
    def default(
        cls,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> "BrowserConfig":
        """
        Create a default BrowserConfig instance.

        Args:
            user_id: SaaS user identifier.
            workspace_id: SaaS workspace identifier.

        Returns:
            BrowserConfig
        """

        return cls(user_id=user_id, workspace_id=workspace_id)

    @classmethod
    def strict(
        cls,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> "BrowserConfig":
        """
        Create a strict BrowserConfig instance.
        Recommended for production SaaS defaults.
        """

        return cls(
            user_id=user_id,
            workspace_id=workspace_id,
            max_tabs=3,
            enable_cookies=False,
            enable_cache=False,
            enable_downloads=False,
            enable_form_autofill=False,
            security=BrowserSecurityConfig(
                safety_mode=BrowserSafetyMode.STRICT,
                require_security_for_sensitive_actions=True,
                require_security_for_downloads=True,
                require_security_for_uploads=True,
                require_security_for_login=True,
                block_restricted_domains=True,
                block_unsafe_schemes=True,
                allow_private_network_access=False,
                allow_file_scheme=False,
            ),
            screenshots=ScreenshotConfig(
                enabled=True,
                redact_sensitive_fields=True,
                max_per_task=5,
                store_locally=False,
            ),
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BrowserConfig":
        """
        Build BrowserConfig from dict.

        This is useful for loading dashboard/API configuration or database rows.
        """

        safe_data = copy.deepcopy(data or {})

        if "rate_limits" in safe_data and isinstance(safe_data["rate_limits"], dict):
            safe_data["rate_limits"] = RateLimitConfig(**safe_data["rate_limits"])

        if "screenshots" in safe_data and isinstance(safe_data["screenshots"], dict):
            safe_data["screenshots"] = ScreenshotConfig(**safe_data["screenshots"])

        if "search" in safe_data and isinstance(safe_data["search"], dict):
            safe_data["search"] = SearchEngineConfig(**safe_data["search"])

        if "security" in safe_data and isinstance(safe_data["security"], dict):
            safe_data["security"] = BrowserSecurityConfig(**safe_data["security"])

        if "timeouts" in safe_data and isinstance(safe_data["timeouts"], dict):
            safe_data["timeouts"] = BrowserTimeoutConfig(**safe_data["timeouts"])

        return cls(**safe_data)

    # -----------------------------------------------------------------------
    # Validation
    # -----------------------------------------------------------------------

    def validate_config(self) -> Dict[str, Any]:
        """
        Validate the full BrowserConfig.

        Returns:
            Structured dict with success, message, data, error, metadata.
        """

        errors: List[str] = []
        warnings: List[str] = []

        self._normalize_enums()

        if not self.agent_name:
            errors.append("agent_name is required.")

        if isinstance(self.execution_mode, str):
            try:
                self.execution_mode = BrowserExecutionMode(self.execution_mode)
            except ValueError:
                errors.append(f"Unsupported execution mode: {self.execution_mode}")

        if self.max_tabs < 1:
            errors.append("max_tabs must be at least 1.")

        if self.max_tabs_hard_limit < 1:
            errors.append("max_tabs_hard_limit must be at least 1.")

        if self.max_tabs > self.max_tabs_hard_limit:
            errors.append("max_tabs cannot exceed max_tabs_hard_limit.")

        if self.max_tabs_hard_limit > 100:
            warnings.append("max_tabs_hard_limit is very high for SaaS browser workloads.")

        if not self.user_agent:
            errors.append("user_agent is required.")

        rate_ok, rate_errors = self.rate_limits.validate()
        if not rate_ok:
            errors.extend(rate_errors)

        screenshot_ok, screenshot_errors = self.screenshots.validate()
        if not screenshot_ok:
            errors.extend(screenshot_errors)

        search_ok, search_errors = self.search.validate()
        if not search_ok:
            errors.extend(search_errors)

        security_ok, security_errors = self.security.validate()
        if not security_ok:
            errors.extend(security_errors)

        timeout_ok, timeout_errors = self.timeouts.validate()
        if not timeout_ok:
            errors.extend(timeout_errors)

        if self.security.safety_mode == BrowserSafetyMode.OFF:
            warnings.append("Browser safety mode is OFF. This is not recommended for production.")

        if self.enable_downloads and self.security.require_security_for_downloads is False:
            warnings.append("Downloads are enabled without mandatory security approval.")

        if self.enable_form_autofill and self.security.require_security_for_sensitive_actions is False:
            warnings.append("Form autofill is enabled without mandatory sensitive action approval.")

        result = {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
        }

        if errors:
            return self._error_result(
                message="Browser configuration validation failed.",
                error={"errors": errors, "warnings": warnings},
                metadata={"agent_name": self.agent_name, "config_version": self.config_version},
            )

        return self._safe_result(
            message="Browser configuration validated successfully.",
            data=result,
            metadata={"agent_name": self.agent_name, "config_version": self.config_version},
        )

    def _validate_task_context(
        self,
        context: Optional[Union[AgentContext, Dict[str, Any]]] = None,
        require_user_workspace: bool = True,
    ) -> Dict[str, Any]:
        """
        Validate user/workspace context for SaaS isolation.

        Args:
            context: AgentContext or dict with user_id/workspace_id.
            require_user_workspace: If true, both user_id and workspace_id are required.

        Returns:
            Structured result.
        """

        context_user_id = self.user_id
        context_workspace_id = self.workspace_id

        if context is not None:
            if isinstance(context, dict):
                context_user_id = context.get("user_id", context_user_id)
                context_workspace_id = context.get("workspace_id", context_workspace_id)
            else:
                context_user_id = getattr(context, "user_id", context_user_id)
                context_workspace_id = getattr(context, "workspace_id", context_workspace_id)

        if require_user_workspace:
            if context_user_id in (None, ""):
                return self._error_result(
                    message="Missing user_id for Browser Agent task context.",
                    error="user_id_required",
                    metadata={"agent_name": self.agent_name},
                )

            if context_workspace_id in (None, ""):
                return self._error_result(
                    message="Missing workspace_id for Browser Agent task context.",
                    error="workspace_id_required",
                    metadata={"agent_name": self.agent_name},
                )

        return self._safe_result(
            message="Browser Agent task context validated.",
            data={
                "user_id": context_user_id,
                "workspace_id": context_workspace_id,
            },
            metadata={"agent_name": self.agent_name},
        )

    # -----------------------------------------------------------------------
    # Permission / Security Compatibility Hooks
    # -----------------------------------------------------------------------

    def _requires_security_check(
        self,
        action: str,
        url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Decide whether an action requires Security Agent approval.

        Args:
            action: Browser action name.
            url: Optional target URL.
            metadata: Optional extra task metadata.

        Returns:
            bool
        """

        normalized_action = (action or "").strip().lower()
        metadata = metadata or {}

        if self.security.safety_mode == BrowserSafetyMode.STRICT:
            if normalized_action not in {"search", "read_public_page", "extract_content"}:
                return True

        if self.security.require_security_for_sensitive_actions:
            if self.security.is_sensitive_action(normalized_action):
                return True

        if normalized_action == "download_file" and self.security.require_security_for_downloads:
            return True

        if normalized_action == "upload_file" and self.security.require_security_for_uploads:
            return True

        if normalized_action == "login" and self.security.require_security_for_login:
            return True

        if url:
            if self.security.is_scheme_blocked(url):
                return True
            if self.security.is_domain_restricted(url):
                return True

        if metadata.get("sensitive") is True:
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        context: Optional[Union[AgentContext, Dict[str, Any]]] = None,
        url: Optional[str] = None,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Security Agent approval request payload.

        This method does NOT approve or execute anything.
        It only creates a structured payload that Master Agent/Security Agent
        can process.
        """

        context_result = self._validate_task_context(context=context, require_user_workspace=False)
        context_data = context_result.get("data") or {}

        request_id = str(uuid.uuid4())
        payload = {
            "request_id": request_id,
            "agent_name": self.agent_name,
            "config_version": self.config_version,
            "action": action,
            "url": url,
            "reason": reason or "Browser action requires security approval.",
            "requires_security_check": self._requires_security_check(
                action=action,
                url=url,
                metadata=metadata,
            ),
            "user_id": context_data.get("user_id", self.user_id),
            "workspace_id": context_data.get("workspace_id", self.workspace_id),
            "safety_mode": self.security.safety_mode.value,
            "metadata": metadata or {},
            "created_at": time.time(),
        }

        return self._safe_result(
            message="Security approval payload prepared.",
            data=payload,
            metadata={"request_id": request_id, "agent_name": self.agent_name},
        )

    def is_action_allowed_without_security(
        self,
        action: str,
        url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Convenience method for router/runtime checks.

        Returns True only if security approval is not required.
        """

        return not self._requires_security_check(action=action, url=url, metadata=metadata)

    # -----------------------------------------------------------------------
    # Config Update Methods
    # -----------------------------------------------------------------------

    def update_config(
        self,
        updates: Dict[str, Any],
        context: Optional[Union[AgentContext, Dict[str, Any]]] = None,
        require_security: bool = True,
    ) -> Dict[str, Any]:
        """
        Safely update configuration values.

        Sensitive changes should be approved by Security Agent first.
        This method prepares approval metadata if required, but does not call
        an external Security Agent directly.

        Args:
            updates: Dict of config updates.
            context: SaaS user/workspace context.
            require_security: Whether sensitive config updates require approval.

        Returns:
            Structured result.
        """

        if not isinstance(updates, dict):
            return self._error_result(
                message="Config updates must be a dictionary.",
                error="invalid_updates_type",
            )

        context_result = self._validate_task_context(context=context, require_user_workspace=False)
        if not context_result.get("success"):
            return context_result

        sensitive_fields = {
            "enable_downloads",
            "enable_form_autofill",
            "enable_cookies",
            "security",
            "max_tabs_hard_limit",
            "execution_mode",
        }

        touched_sensitive = any(key in sensitive_fields for key in updates.keys())

        if require_security and touched_sensitive:
            approval = self._request_security_approval(
                action="update_browser_config",
                context=context,
                reason="Sensitive Browser Agent configuration update requested.",
                metadata={"updates_requested": list(updates.keys())},
            )

            return self._safe_result(
                message="Security approval required before applying sensitive BrowserConfig update.",
                data={
                    "applied": False,
                    "security_approval": approval.get("data"),
                    "updates_requested": list(updates.keys()),
                },
                metadata={"agent_name": self.agent_name},
            )

        before = self.to_internal_dict()

        try:
            for key, value in updates.items():
                self._apply_single_update(key, value)

            self.updated_at = time.time()
            validation = self.validate_config()

            if not validation.get("success"):
                self._restore_from_dict(before)
                return self._error_result(
                    message="Config update failed validation. Previous config restored.",
                    error=validation.get("error"),
                    metadata={"updates_requested": list(updates.keys())},
                )

            audit_payload = self._log_audit_event(
                event_type="browser_config_updated",
                context=context,
                data={
                    "updated_fields": list(updates.keys()),
                    "before_summary": self._summarize_config(before),
                    "after_summary": self._summarize_config(self.to_internal_dict()),
                },
            )

            verification_payload = self._prepare_verification_payload(
                action="update_browser_config",
                success=True,
                data={"updated_fields": list(updates.keys())},
            )

            memory_payload = self._prepare_memory_payload(
                context=context,
                preference_type="browser_config",
                data=self.to_public_dict(),
            )

            return self._safe_result(
                message="Browser configuration updated successfully.",
                data={
                    "config": self.to_public_dict(),
                    "audit_payload": audit_payload.get("data"),
                    "verification_payload": verification_payload.get("data"),
                    "memory_payload": memory_payload.get("data"),
                },
                metadata={"agent_name": self.agent_name, "updated_at": self.updated_at},
            )

        except Exception as exc:
            self._restore_from_dict(before)
            LOGGER.exception("BrowserConfig update failed.")
            return self._error_result(
                message="Browser configuration update failed. Previous config restored.",
                error=str(exc),
                metadata={"updates_requested": list(updates.keys())},
            )

    def _apply_single_update(self, key: str, value: Any) -> None:
        """
        Apply a single config update.

        Nested updates can be passed as dicts for:
            - rate_limits
            - screenshots
            - search
            - security
            - timeouts
        """

        if key == "rate_limits" and isinstance(value, dict):
            current = self.rate_limits.to_dict()
            current.update(value)
            self.rate_limits = RateLimitConfig(**current)
            return

        if key == "screenshots" and isinstance(value, dict):
            current = self.screenshots.to_dict()
            current.update(value)
            self.screenshots = ScreenshotConfig(**current)
            return

        if key == "search" and isinstance(value, dict):
            current = self.search.to_dict()
            current.update(value)
            self.search = SearchEngineConfig(**current)
            return

        if key == "security" and isinstance(value, dict):
            current = self.security.to_dict()
            current.update(value)
            self.security = BrowserSecurityConfig(**current)
            return

        if key == "timeouts" and isinstance(value, dict):
            current = self.timeouts.to_dict()
            current.update(value)
            self.timeouts = BrowserTimeoutConfig(**current)
            return

        if not hasattr(self, key):
            raise AttributeError(f"Unknown BrowserConfig field: {key}")

        setattr(self, key, value)

    def _restore_from_dict(self, data: Dict[str, Any]) -> None:
        restored = BrowserConfig.from_dict(data)
        self.__dict__.update(restored.__dict__)

    # -----------------------------------------------------------------------
    # Browser Setting Helpers
    # -----------------------------------------------------------------------

    def can_open_new_tab(self, current_tab_count: int) -> bool:
        """Return whether a new tab can be opened under current limits."""

        if not self.enabled:
            return False

        if not self.allow_multi_tab and current_tab_count >= 1:
            return False

        return current_tab_count < self.max_tabs

    def get_available_tab_slots(self, current_tab_count: int) -> int:
        """Return remaining tab slots."""

        remaining = self.max_tabs - max(0, current_tab_count)
        return max(0, remaining)

    def get_search_url(self, query: str, engine: Optional[str] = None) -> Dict[str, Any]:
        """
        Build a configured search URL.

        This only formats the search URL. It does not perform a search.
        """

        if not query or not str(query).strip():
            return self._error_result(
                message="Search query is required.",
                error="empty_query",
            )

        selected_engine = (engine or self.search.default_engine).strip().lower()

        if selected_engine not in self.search.allowed_engines:
            return self._error_result(
                message=f"Search engine '{selected_engine}' is not allowed.",
                error="search_engine_not_allowed",
                metadata={"allowed_engines": self.search.allowed_engines},
            )

        template = self.search.get_engine_url(selected_engine)
        if not template:
            return self._error_result(
                message=f"No URL template configured for search engine '{selected_engine}'.",
                error="missing_search_engine_url",
            )

        from urllib.parse import quote_plus

        url = template.format(query=quote_plus(str(query).strip()))

        return self._safe_result(
            message="Search URL prepared.",
            data={
                "engine": selected_engine,
                "query": query,
                "url": url,
                "safe_search": self.search.safe_search,
                "region": self.search.region,
                "language": self.search.language,
            },
            metadata={"agent_name": self.agent_name},
        )

    def should_take_screenshot(self, screenshots_taken: int, action: Optional[str] = None) -> bool:
        """Return whether screenshot capture is allowed for the current task."""

        if not self.screenshots.enabled:
            return False

        if screenshots_taken >= self.screenshots.max_per_task:
            return False

        if action and self.security.is_sensitive_action(action):
            return self.screenshots.redact_sensitive_fields

        return True

    def is_url_allowed(self, url: str) -> Dict[str, Any]:
        """
        Validate whether a URL is allowed by config.

        This does not fetch the URL.
        """

        if not url or not str(url).strip():
            return self._error_result(
                message="URL is required.",
                error="empty_url",
            )

        if self.security.is_scheme_blocked(url):
            return self._error_result(
                message="URL scheme is blocked by BrowserConfig security policy.",
                error="blocked_scheme",
                metadata={"url": url},
            )

        if self.security.is_domain_restricted(url):
            return self._error_result(
                message="Domain is restricted by BrowserConfig security policy.",
                error="restricted_domain",
                metadata={"url": url},
            )

        return self._safe_result(
            message="URL is allowed by BrowserConfig.",
            data={"url": url, "allowed": True},
            metadata={"agent_name": self.agent_name},
        )

    # -----------------------------------------------------------------------
    # Payload Hooks
    # -----------------------------------------------------------------------

    def _prepare_verification_payload(
        self,
        action: str,
        success: bool,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can use this to confirm config updates, validation,
        and security decision outcomes.
        """

        payload = {
            "verification_id": str(uuid.uuid4()),
            "agent_name": self.agent_name,
            "action": action,
            "success": success,
            "data": data or {},
            "error": error,
            "config_version": self.config_version,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "timestamp": time.time(),
        }

        return self._safe_result(
            message="Verification payload prepared.",
            data=payload,
            metadata={"agent_name": self.agent_name},
        )

    def _prepare_memory_payload(
        self,
        context: Optional[Union[AgentContext, Dict[str, Any]]] = None,
        preference_type: str = "browser_config",
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        This should store only safe preferences/settings, not secrets or private
        browsing content.
        """

        context_result = self._validate_task_context(context=context, require_user_workspace=False)
        context_data = context_result.get("data") or {}

        payload = {
            "memory_id": str(uuid.uuid4()),
            "agent_name": self.agent_name,
            "type": preference_type,
            "user_id": context_data.get("user_id", self.user_id),
            "workspace_id": context_data.get("workspace_id", self.workspace_id),
            "data": data or self.to_public_dict(),
            "safe_to_store": True,
            "contains_secret": False,
            "timestamp": time.time(),
        }

        return self._safe_result(
            message="Memory payload prepared.",
            data=payload,
            metadata={"agent_name": self.agent_name},
        )

    def _emit_agent_event(
        self,
        event_type: str,
        data: Optional[Dict[str, Any]] = None,
        context: Optional[Union[AgentContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare an event payload for dashboard/task history/event bus.

        This method does not require an external event bus to exist.
        """

        context_result = self._validate_task_context(context=context, require_user_workspace=False)
        context_data = context_result.get("data") or {}

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent_name": self.agent_name,
            "user_id": context_data.get("user_id", self.user_id),
            "workspace_id": context_data.get("workspace_id", self.workspace_id),
            "data": data or {},
            "timestamp": time.time(),
        }

        LOGGER.info("Browser Agent event prepared: %s", event_type)

        return self._safe_result(
            message="Agent event payload prepared.",
            data=event,
            metadata={"agent_name": self.agent_name},
        )

    def _log_audit_event(
        self,
        event_type: str,
        data: Optional[Dict[str, Any]] = None,
        context: Optional[Union[AgentContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare audit log payload.

        Audit data must preserve user/workspace boundaries.
        """

        context_result = self._validate_task_context(context=context, require_user_workspace=False)
        context_data = context_result.get("data") or {}

        audit = {
            "audit_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent_name": self.agent_name,
            "user_id": context_data.get("user_id", self.user_id),
            "workspace_id": context_data.get("workspace_id", self.workspace_id),
            "data": data or {},
            "timestamp": time.time(),
            "source": "agents.browser_agent.config",
        }

        LOGGER.info("Browser Agent audit payload prepared: %s", event_type)

        return self._safe_result(
            message="Audit event payload prepared.",
            data=audit,
            metadata={"agent_name": self.agent_name},
        )

    # -----------------------------------------------------------------------
    # Export Methods
    # -----------------------------------------------------------------------

    def to_internal_dict(self) -> Dict[str, Any]:
        """
        Export complete internal config.

        This should be used only inside trusted backend/server-side logic.
        """

        return {
            "agent_name": self.agent_name,
            "config_version": self.config_version,
            "enabled": self.enabled,
            "execution_mode": self.execution_mode.value
            if isinstance(self.execution_mode, BrowserExecutionMode)
            else self.execution_mode,
            "max_tabs": self.max_tabs,
            "max_tabs_hard_limit": self.max_tabs_hard_limit,
            "allow_multi_tab": self.allow_multi_tab,
            "close_tabs_after_task": self.close_tabs_after_task,
            "user_agent": self.user_agent,
            "respect_robots_txt": self.respect_robots_txt,
            "enable_cookies": self.enable_cookies,
            "enable_cache": self.enable_cache,
            "enable_javascript": self.enable_javascript,
            "enable_downloads": self.enable_downloads,
            "enable_form_autofill": self.enable_form_autofill,
            "rate_limits": self.rate_limits.to_dict(),
            "screenshots": self.screenshots.to_dict(),
            "search": self.search.to_dict(),
            "security": self.security.to_dict(),
            "timeouts": self.timeouts.to_dict(),
            "default_permissions": copy.deepcopy(self.default_permissions),
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "metadata": copy.deepcopy(self.metadata),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def to_public_dict(self) -> Dict[str, Any]:
        """
        Export dashboard/API-safe config.

        Does not expose secrets because this file does not store secrets.
        Still avoids overly internal metadata.
        """

        return {
            "agent_name": self.agent_name,
            "config_version": self.config_version,
            "enabled": self.enabled,
            "execution_mode": self.execution_mode.value
            if isinstance(self.execution_mode, BrowserExecutionMode)
            else self.execution_mode,
            "max_tabs": self.max_tabs,
            "allow_multi_tab": self.allow_multi_tab,
            "close_tabs_after_task": self.close_tabs_after_task,
            "respect_robots_txt": self.respect_robots_txt,
            "enable_cookies": self.enable_cookies,
            "enable_cache": self.enable_cache,
            "enable_javascript": self.enable_javascript,
            "enable_downloads": self.enable_downloads,
            "enable_form_autofill": self.enable_form_autofill,
            "rate_limits": self.rate_limits.to_dict(),
            "screenshots": self.screenshots.to_dict(),
            "search": self.search.to_dict(),
            "security": {
                "safety_mode": self.security.safety_mode.value
                if isinstance(self.security.safety_mode, BrowserSafetyMode)
                else self.security.safety_mode,
                "require_security_for_sensitive_actions": self.security.require_security_for_sensitive_actions,
                "require_security_for_downloads": self.security.require_security_for_downloads,
                "require_security_for_uploads": self.security.require_security_for_uploads,
                "require_security_for_login": self.security.require_security_for_login,
                "block_restricted_domains": self.security.block_restricted_domains,
                "block_unsafe_schemes": self.security.block_unsafe_schemes,
                "allow_private_network_access": self.security.allow_private_network_access,
                "allow_file_scheme": self.security.allow_file_scheme,
                "allowed_domains": copy.deepcopy(self.security.allowed_domains),
            },
            "timeouts": self.timeouts.to_dict(),
            "default_permissions": copy.deepcopy(self.default_permissions),
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "updated_at": self.updated_at,
        }

    def _summarize_config(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create compact audit-safe config summary."""

        return {
            "enabled": data.get("enabled"),
            "execution_mode": data.get("execution_mode"),
            "max_tabs": data.get("max_tabs"),
            "safety_mode": (data.get("security") or {}).get("safety_mode"),
            "default_engine": (data.get("search") or {}).get("default_engine"),
            "screenshots_enabled": (data.get("screenshots") or {}).get("enabled"),
            "downloads_enabled": data.get("enable_downloads"),
        }

    # -----------------------------------------------------------------------
    # Structured Result Helpers
    # -----------------------------------------------------------------------

    def _safe_result(
        self,
        message: str,
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success result format.
        Compatible with William/Jarvis agent result expectations.
        """

        return {
            "success": True,
            "message": message,
            "data": data,
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Any] = None,
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result format.
        Compatible with William/Jarvis agent result expectations.
        """

        return {
            "success": False,
            "message": message,
            "data": data,
            "error": error,
            "metadata": metadata or {},
        }


# ---------------------------------------------------------------------------
# Module-Level Defaults / Helpers
# ---------------------------------------------------------------------------

DEFAULT_BROWSER_CONFIG = BrowserConfig.default()


def get_default_browser_config(
    user_id: Optional[Union[str, int]] = None,
    workspace_id: Optional[Union[str, int]] = None,
) -> BrowserConfig:
    """
    Return a fresh default BrowserConfig instance.

    Do not mutate DEFAULT_BROWSER_CONFIG directly for user/workspace config.
    """

    return BrowserConfig.default(user_id=user_id, workspace_id=workspace_id)


def get_strict_browser_config(
    user_id: Optional[Union[str, int]] = None,
    workspace_id: Optional[Union[str, int]] = None,
) -> BrowserConfig:
    """
    Return a fresh strict BrowserConfig instance.
    """

    return BrowserConfig.strict(user_id=user_id, workspace_id=workspace_id)


def load_browser_config_from_dict(data: Dict[str, Any]) -> BrowserConfig:
    """
    Load BrowserConfig from a dictionary.

    Useful for database, API, dashboard, or workspace-specific settings.
    """

    return BrowserConfig.from_dict(data)


__all__ = [
    "BrowserConfig",
    "RateLimitConfig",
    "ScreenshotConfig",
    "SearchEngineConfig",
    "BrowserSecurityConfig",
    "BrowserTimeoutConfig",
    "BrowserSafetyMode",
    "ScreenshotFormat",
    "SearchEngineMode",
    "BrowserExecutionMode",
    "DEFAULT_BROWSER_CONFIG",
    "get_default_browser_config",
    "get_strict_browser_config",
    "load_browser_config_from_dict",
]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    config = BrowserConfig.strict(user_id="demo_user", workspace_id="demo_workspace")
    validation_result = config.validate_config()

    print("BrowserConfig validation:")
    print(validation_result)

    print("\nPublic config:")
    print(config.to_public_dict())

    print("\nSearch URL test:")
    print(config.get_search_url("William Jarvis AI SaaS system"))

    print("\nSecurity check test:")
    print(
        config._request_security_approval(
            action="download_file",
            url="https://example.com/report.pdf",
            reason="Download action requires approval in strict mode.",
        )
    )

    print("\nFILE COMPLETE")