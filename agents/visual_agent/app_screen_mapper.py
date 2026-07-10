"""
agents/visual_agent/app_screen_mapper.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Known app-specific screen maps for Chrome, VS Code, WordPress, Google Ads,
    Google Sheets, Gmail, YouTube Studio, and other common dashboard/web apps.

Architecture Role:
    - Visual Agent helper/component.
    - Converts raw visual context, OCR text, window titles, URLs, UI element labels,
      and detected layout hints into known app/screen classifications.
    - Helps Master Agent, Browser Agent, Workflow Agent, Verification Agent,
      and Dashboard/API understand where the user currently is.
    - Produces SaaS-safe structured outputs with user_id/workspace_id isolation.
    - Does not perform clicks, browser actions, filesystem writes, messaging,
      calls, finance actions, or destructive actions.
    - Sensitive actions are routed through Security Agent compatibility hooks.

Import Safety:
    This file is safe to import even if the rest of the William/Jarvis system is
    not created yet. Optional project imports use fallback stubs.

Result Format:
    All public methods return dict/JSON style:
        {
            "success": bool,
            "message": str,
            "data": dict,
            "error": dict | None,
            "metadata": dict
        }
"""

from __future__ import annotations

import json
import logging
import re
import time
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# =============================================================================
# Optional William/Jarvis imports with safe fallbacks
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early file generation

    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        The real William/Jarvis BaseAgent will be used automatically when present.
        This fallback keeps the file import-safe during incremental module builds.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early file generation

    class SecurityAgent:  # type: ignore
        """
        Minimal fallback SecurityAgent.

        This file does not execute sensitive actions by itself. The fallback only
        exists so compatibility hooks do not crash before the real Security Agent
        is available.
        """

        def approve_action(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
            return {
                "success": True,
                "approved": True,
                "message": "Fallback approval granted for non-destructive screen mapping.",
                "data": {"source": "fallback_security_agent"},
                "error": None,
                "metadata": {},
            }


# =============================================================================
# Logging
# =============================================================================

LOGGER = logging.getLogger("william.visual.app_screen_mapper")
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


# =============================================================================
# Types and constants
# =============================================================================

JsonDict = Dict[str, Any]
EventEmitterCallable = Callable[[str, Mapping[str, Any]], None]
AuditLoggerCallable = Callable[[Mapping[str, Any]], None]


class AppCategory(str, Enum):
    """Known app categories used by Visual Agent and Master Agent routing."""

    BROWSER = "browser"
    CODE_EDITOR = "code_editor"
    CMS = "cms"
    ADS_PLATFORM = "ads_platform"
    ANALYTICS = "analytics"
    PRODUCTIVITY = "productivity"
    EMAIL = "email"
    SOCIAL_CREATOR = "social_creator"
    DESIGN = "design"
    DEVTOOLS = "devtools"
    FILE_MANAGER = "file_manager"
    TERMINAL = "terminal"
    UNKNOWN = "unknown"


class ScreenConfidence(str, Enum):
    """Human-readable confidence buckets."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class TaskContext:
    """
    SaaS-safe request context.

    Every user/workspace-specific mapping request must include user_id and
    workspace_id. This prevents screen context, workflow learning, memory summaries,
    and verification artifacts from mixing across tenants.
    """

    user_id: str
    workspace_id: str
    task_id: Optional[str] = None
    run_id: Optional[str] = None
    agent_id: Optional[str] = None
    source_agent: Optional[str] = None
    requested_by: Optional[str] = None
    role: Optional[str] = None
    permissions: Sequence[str] = field(default_factory=tuple)
    metadata: JsonDict = field(default_factory=dict)

    def to_dict(self) -> JsonDict:
        return asdict(self)


@dataclass
class ElementZone:
    """
    Common UI zone definition.

    Coordinates are normalized ratios from 0.0 to 1.0:
        left, top, right, bottom
    This keeps the map useful across screen resolutions.
    """

    name: str
    description: str
    bounds_ratio: Tuple[float, float, float, float]
    expected_labels: Sequence[str] = field(default_factory=tuple)
    role: str = "region"
    priority: int = 50
    safe_to_click: bool = False
    requires_security: bool = False

    def to_dict(self) -> JsonDict:
        return {
            "name": self.name,
            "description": self.description,
            "bounds_ratio": list(self.bounds_ratio),
            "expected_labels": list(self.expected_labels),
            "role": self.role,
            "priority": self.priority,
            "safe_to_click": self.safe_to_click,
            "requires_security": self.requires_security,
        }


@dataclass
class ScreenMap:
    """
    Known screen signature and UI map.

    A ScreenMap is a non-executing visual/navigation description. It gives the
    Visual Agent known regions, labels, and route hints, but it does not perform
    any real action.
    """

    app_id: str
    app_name: str
    category: AppCategory
    screen_id: str
    screen_name: str
    description: str
    title_keywords: Sequence[str] = field(default_factory=tuple)
    url_keywords: Sequence[str] = field(default_factory=tuple)
    ocr_keywords: Sequence[str] = field(default_factory=tuple)
    negative_keywords: Sequence[str] = field(default_factory=tuple)
    element_labels: Sequence[str] = field(default_factory=tuple)
    zones: Sequence[ElementZone] = field(default_factory=tuple)
    primary_actions: Sequence[str] = field(default_factory=tuple)
    route_hints: Sequence[str] = field(default_factory=tuple)
    verification_hints: Sequence[str] = field(default_factory=tuple)
    memory_tags: Sequence[str] = field(default_factory=tuple)
    risk_notes: Sequence[str] = field(default_factory=tuple)
    version: str = "1.0"

    def to_dict(self) -> JsonDict:
        data = asdict(self)
        data["category"] = self.category.value
        data["zones"] = [zone.to_dict() for zone in self.zones]
        return data


@dataclass
class ScreenMatch:
    """Screen matching result."""

    screen_map: ScreenMap
    score: float
    confidence: ScreenConfidence
    evidence: JsonDict = field(default_factory=dict)

    def to_dict(self) -> JsonDict:
        return {
            "app_id": self.screen_map.app_id,
            "app_name": self.screen_map.app_name,
            "category": self.screen_map.category.value,
            "screen_id": self.screen_map.screen_id,
            "screen_name": self.screen_map.screen_name,
            "score": round(self.score, 4),
            "confidence": self.confidence.value,
            "evidence": self.evidence,
            "screen_map": self.screen_map.to_dict(),
        }


@dataclass
class AppScreenMapperConfig:
    """Configuration for AppScreenMapper."""

    min_score_for_match: float = 0.22
    min_score_for_high_confidence: float = 0.62
    min_score_for_medium_confidence: float = 0.38
    max_matches: int = 5
    redact_sensitive_text: bool = True
    max_ocr_chars_kept: int = 5000
    max_title_chars_kept: int = 500
    max_url_chars_kept: int = 1000
    enable_custom_maps: bool = True
    require_security_for_custom_map_registration: bool = False
    sensitive_fragments: Sequence[str] = field(
        default_factory=lambda: (
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "cookie",
            "set-cookie",
            "bearer",
            "private_key",
            "client_secret",
            "refresh_token",
            "access_token",
            "card_number",
            "cvv",
            "ssn",
        )
    )


# =============================================================================
# Utility helpers
# =============================================================================

def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_str(value: Any, max_length: int = 2000) -> str:
    try:
        text = str(value)
    except Exception:
        text = repr(value)
    if len(text) > max_length:
        return text[: max_length - 18] + "...[truncated]"
    return text


def _normalize_text(value: Any) -> str:
    text = _safe_str(value, max_length=100000)
    text = text.replace("\x00", " ")
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text


def _unique_preserve_order(items: Iterable[str]) -> List[str]:
    seen = set()
    output: List[str] = []
    for item in items:
        clean = str(item).strip()
        if not clean:
            continue
        key = clean.lower()
        if key not in seen:
            seen.add(key)
            output.append(clean)
    return output


def _hash_text(value: Any) -> str:
    return sha256(_safe_str(value, max_length=100000).encode("utf-8", errors="replace")).hexdigest()


def _redact_text(text: str, sensitive_fragments: Sequence[str]) -> str:
    """
    Lightweight redaction for OCR/title/url snippets.

    This keeps Memory Agent and dashboard output safer while preserving enough
    screen evidence for troubleshooting.
    """
    if not text:
        return text

    redacted = text

    # Redact common key=value and key: value patterns.
    for fragment in sensitive_fragments:
        frag = re.escape(fragment)
        redacted = re.sub(
            rf"(?i)\b({frag})\s*[:=]\s*([^\s,;&]+)",
            r"\1=[REDACTED]",
            redacted,
        )

    # Redact bearer-like token sequences.
    redacted = re.sub(r"(?i)\bbearer\s+[a-z0-9._\-+/=]{12,}", "Bearer [REDACTED]", redacted)

    # Redact long token-looking values.
    redacted = re.sub(r"\b[A-Za-z0-9_\-]{32,}\b", "[REDACTED_LONG_VALUE]", redacted)

    return redacted


def _redact_mapping(value: Any, sensitive_fragments: Sequence[str]) -> Any:
    if isinstance(value, Mapping):
        clean: JsonDict = {}
        for key, item in value.items():
            key_text = str(key).lower()
            if any(fragment.lower() in key_text for fragment in sensitive_fragments):
                clean[str(key)] = "[REDACTED]"
            else:
                clean[str(key)] = _redact_mapping(item, sensitive_fragments)
        return clean

    if isinstance(value, list):
        return [_redact_mapping(item, sensitive_fragments) for item in value]

    if isinstance(value, tuple):
        return tuple(_redact_mapping(item, sensitive_fragments) for item in value)

    if isinstance(value, str):
        return _redact_text(value, sensitive_fragments)

    return value


def _keyword_hits(text: str, keywords: Sequence[str]) -> List[str]:
    hits: List[str] = []
    haystack = text.lower()
    for keyword in keywords:
        needle = str(keyword).strip().lower()
        if needle and needle in haystack:
            hits.append(str(keyword))
    return _unique_preserve_order(hits)


def _tokenize_labels(elements: Sequence[Mapping[str, Any]]) -> str:
    labels: List[str] = []
    for element in elements:
        for key in ("text", "label", "aria_label", "name", "title", "role"):
            value = element.get(key)
            if value:
                labels.append(str(value))
    return _normalize_text(" ".join(labels))


def _confidence_from_score(score: float, config: AppScreenMapperConfig) -> ScreenConfidence:
    if score >= config.min_score_for_high_confidence:
        return ScreenConfidence.HIGH
    if score >= config.min_score_for_medium_confidence:
        return ScreenConfidence.MEDIUM
    if score >= config.min_score_for_match:
        return ScreenConfidence.LOW
    return ScreenConfidence.UNKNOWN


# =============================================================================
# Default screen map library
# =============================================================================

def _zone(
    name: str,
    description: str,
    bounds: Tuple[float, float, float, float],
    labels: Sequence[str] = (),
    role: str = "region",
    priority: int = 50,
    safe_to_click: bool = False,
    requires_security: bool = False,
) -> ElementZone:
    return ElementZone(
        name=name,
        description=description,
        bounds_ratio=bounds,
        expected_labels=labels,
        role=role,
        priority=priority,
        safe_to_click=safe_to_click,
        requires_security=requires_security,
    )


def build_default_screen_maps() -> List[ScreenMap]:
    """
    Build the known app-specific screen map library.

    These maps are intentionally descriptive, not executable. They support
    screen recognition and workflow hints only.
    """
    maps: List[ScreenMap] = []

    # -------------------------------------------------------------------------
    # Chrome / Chromium
    # -------------------------------------------------------------------------
    maps.append(
        ScreenMap(
            app_id="chrome",
            app_name="Google Chrome",
            category=AppCategory.BROWSER,
            screen_id="chrome_new_tab",
            screen_name="Chrome New Tab / Search",
            description="Chrome browser new tab or address/search page.",
            title_keywords=("new tab", "google chrome", "chrome"),
            url_keywords=("chrome://newtab", "about:newtab"),
            ocr_keywords=("search google or type a url", "google", "new tab", "customize chrome"),
            element_labels=("address and search bar", "search", "google apps", "profile"),
            zones=(
                _zone("tab_bar", "Top tab strip.", (0.00, 0.00, 1.00, 0.07), ("new tab",), "navigation", 80),
                _zone("address_bar", "Chrome omnibox/address bar.", (0.12, 0.05, 0.86, 0.12), ("search google or type a url",), "input", 95, True),
                _zone("page_search_box", "New tab page search field.", (0.22, 0.34, 0.78, 0.46), ("search", "google"), "input", 90, True),
                _zone("profile_menu", "Chrome profile/avatar menu.", (0.91, 0.04, 0.98, 0.12), ("profile",), "menu", 35, True),
            ),
            primary_actions=("search_web", "open_url", "switch_tab"),
            route_hints=("BrowserAgent.open_url", "BrowserAgent.search", "VisualAgent.read_page"),
            verification_hints=("Confirm URL in address bar.", "Confirm page title or visible loaded content."),
            memory_tags=("browser", "chrome", "new_tab"),
        )
    )

    maps.append(
        ScreenMap(
            app_id="chrome",
            app_name="Google Chrome",
            category=AppCategory.BROWSER,
            screen_id="chrome_serp",
            screen_name="Google Search Results",
            description="Google search results page inside Chrome.",
            title_keywords=("google search", "google chrome"),
            url_keywords=("google.com/search", "q="),
            ocr_keywords=("all", "images", "videos", "news", "people also ask", "search results", "sponsored"),
            negative_keywords=("google ads", "ads overview"),
            element_labels=("search", "tools", "images", "videos", "news"),
            zones=(
                _zone("address_bar", "Chrome omnibox/address bar.", (0.12, 0.05, 0.86, 0.12), ("google.com/search",), "input", 90),
                _zone("search_tabs", "Google search category tabs.", (0.05, 0.14, 0.95, 0.22), ("all", "images", "videos", "news"), "navigation", 80),
                _zone("results_column", "Organic and sponsored search results list.", (0.05, 0.22, 0.72, 0.95), ("sponsored", "people also ask"), "content", 95),
                _zone("right_panel", "Knowledge panel / side information.", (0.72, 0.22, 0.98, 0.95), (), "content", 40),
            ),
            primary_actions=("read_results", "extract_sponsored_results", "open_result"),
            route_hints=("BrowserAgent.search_results", "VisualAgent.element_detector", "VerificationAgent.result_validator"),
            verification_hints=("Check visible query text.", "Separate sponsored results from organic results."),
            memory_tags=("browser", "google_search", "serp"),
        )
    )

    maps.append(
        ScreenMap(
            app_id="chrome",
            app_name="Google Chrome",
            category=AppCategory.BROWSER,
            screen_id="chrome_devtools",
            screen_name="Chrome DevTools",
            description="Chrome Developer Tools panel.",
            title_keywords=("devtools", "developer tools"),
            url_keywords=("devtools://",),
            ocr_keywords=("elements", "console", "sources", "network", "performance", "application", "lighthouse"),
            element_labels=("elements", "console", "network", "sources"),
            zones=(
                _zone("devtools_tabs", "DevTools top tool tabs.", (0.00, 0.00, 1.00, 0.08), ("elements", "console", "network"), "navigation", 85),
                _zone("main_panel", "DevTools active panel.", (0.00, 0.08, 1.00, 0.92), (), "content", 90),
                _zone("console_drawer", "Console drawer or bottom pane.", (0.00, 0.68, 1.00, 1.00), ("console",), "content", 60),
            ),
            primary_actions=("inspect_dom", "read_console", "monitor_network"),
            route_hints=("CodeAgent.debug_context", "BrowserAgent.devtools_context"),
            verification_hints=("Confirm active DevTools tab.", "Read console/network error lines if present."),
            memory_tags=("browser", "chrome_devtools", "debugging"),
        )
    )

    # -------------------------------------------------------------------------
    # VS Code
    # -------------------------------------------------------------------------
    maps.append(
        ScreenMap(
            app_id="vscode",
            app_name="Visual Studio Code",
            category=AppCategory.CODE_EDITOR,
            screen_id="vscode_editor",
            screen_name="VS Code Editor",
            description="Main Visual Studio Code editor screen.",
            title_keywords=("visual studio code", "vscode", ".py", ".js", ".ts", ".html", ".css"),
            ocr_keywords=("explorer", "search", "source control", "run and debug", "extensions", "terminal", "problems", "output"),
            element_labels=("explorer", "terminal", "source control", "extensions"),
            zones=(
                _zone("activity_bar", "Left icon activity bar.", (0.00, 0.00, 0.05, 1.00), ("explorer", "search", "source control"), "navigation", 85),
                _zone("side_bar", "Explorer/search/source control side panel.", (0.05, 0.06, 0.25, 0.95), ("explorer",), "navigation", 80),
                _zone("editor_tabs", "Open file tabs.", (0.25, 0.04, 1.00, 0.10), (), "navigation", 70),
                _zone("code_editor", "Main code editor area.", (0.25, 0.10, 1.00, 0.75), (), "content", 95),
                _zone("terminal_panel", "Integrated terminal/problems/output panel.", (0.25, 0.75, 1.00, 0.97), ("terminal", "problems", "output"), "content", 75),
                _zone("status_bar", "Bottom status bar.", (0.00, 0.97, 1.00, 1.00), (), "status", 50),
            ),
            primary_actions=("read_code", "find_file", "read_terminal", "detect_errors"),
            route_hints=("CodeAgent.inspect_file", "SystemAgent.process_status", "VerificationAgent.code_state_checker"),
            verification_hints=("Check active file tab.", "Check terminal output and Problems panel."),
            memory_tags=("code_editor", "vscode", "development"),
        )
    )

    maps.append(
        ScreenMap(
            app_id="vscode",
            app_name="Visual Studio Code",
            category=AppCategory.CODE_EDITOR,
            screen_id="vscode_terminal_focus",
            screen_name="VS Code Integrated Terminal",
            description="VS Code with terminal panel active or focused.",
            title_keywords=("visual studio code", "vscode"),
            ocr_keywords=("terminal", "powershell", "cmd", "bash", "zsh", "npm", "python", "traceback", "error", "warning"),
            element_labels=("terminal", "problems", "output", "debug console"),
            zones=(
                _zone("code_editor", "Main code editor area.", (0.25, 0.08, 1.00, 0.55), (), "content", 70),
                _zone("terminal_panel", "Terminal panel with command output.", (0.20, 0.55, 1.00, 0.97), ("terminal", "powershell", "bash"), "content", 98),
                _zone("terminal_tabs", "Terminal tab list and controls.", (0.20, 0.52, 1.00, 0.60), ("terminal",), "navigation", 80),
            ),
            primary_actions=("read_terminal", "detect_command_status", "extract_errors"),
            route_hints=("CodeAgent.terminal_reader", "VerificationAgent.error_detector"),
            verification_hints=("Identify last command output.", "Check exit/error messages."),
            memory_tags=("vscode", "terminal", "debugging"),
        )
    )

    # -------------------------------------------------------------------------
    # WordPress
    # -------------------------------------------------------------------------
    maps.append(
        ScreenMap(
            app_id="wordpress",
            app_name="WordPress",
            category=AppCategory.CMS,
            screen_id="wordpress_dashboard",
            screen_name="WordPress Admin Dashboard",
            description="WordPress wp-admin dashboard/home.",
            title_keywords=("dashboard", "wordpress"),
            url_keywords=("/wp-admin", "wp-admin/index.php"),
            ocr_keywords=("dashboard", "posts", "media", "pages", "comments", "appearance", "plugins", "users", "settings"),
            element_labels=("dashboard", "posts", "media", "pages", "plugins", "settings"),
            zones=(
                _zone("admin_bar", "Top WordPress admin bar.", (0.00, 0.00, 1.00, 0.06), ("wordpress", "new", "view site"), "navigation", 80),
                _zone("left_menu", "WordPress admin menu.", (0.00, 0.06, 0.18, 1.00), ("posts", "pages", "plugins", "settings"), "navigation", 95),
                _zone("dashboard_content", "Dashboard widgets/content area.", (0.18, 0.06, 1.00, 1.00), ("dashboard", "site health"), "content", 80),
            ),
            primary_actions=("navigate_wp_admin", "read_dashboard", "open_pages", "open_plugins"),
            route_hints=("BrowserAgent.wordpress_admin", "VisualAgent.ui_mapper", "WorkflowAgent.cms_workflow"),
            verification_hints=("Confirm wp-admin URL.", "Confirm left admin menu visibility."),
            memory_tags=("wordpress", "cms", "dashboard"),
        )
    )

    maps.append(
        ScreenMap(
            app_id="wordpress",
            app_name="WordPress",
            category=AppCategory.CMS,
            screen_id="wordpress_page_editor",
            screen_name="WordPress Page/Post Editor",
            description="WordPress block editor, classic editor, Elementor, or page editing screen.",
            title_keywords=("edit page", "edit post", "wordpress"),
            url_keywords=("/wp-admin/post.php", "/wp-admin/post-new.php", "action=edit"),
            ocr_keywords=("add title", "publish", "update", "preview", "save draft", "block", "elementor", "edit with elementor"),
            element_labels=("publish", "update", "preview", "save draft", "add block"),
            zones=(
                _zone("top_editor_bar", "Editor toolbar with preview/update/publish buttons.", (0.00, 0.00, 1.00, 0.10), ("publish", "update", "preview"), "toolbar", 95),
                _zone("editor_canvas", "Main page/post editor canvas.", (0.12, 0.10, 0.78, 1.00), ("add title", "block"), "content", 90),
                _zone("settings_sidebar", "Post/page/block settings sidebar.", (0.78, 0.10, 1.00, 1.00), ("settings", "block", "page"), "panel", 75),
                _zone("left_admin_menu", "Collapsed or visible WordPress admin menu.", (0.00, 0.06, 0.14, 1.00), ("pages", "posts"), "navigation", 50),
            ),
            primary_actions=("read_page_content", "detect_publish_status", "map_editor_controls"),
            route_hints=("CreatorAgent.content_editor", "VerificationAgent.ui_element_checker"),
            verification_hints=("Check Update/Publish button state.", "Check page title and editor canvas."),
            memory_tags=("wordpress", "editor", "cms"),
            risk_notes=("Publishing/updating pages is sensitive and must require explicit security approval outside this mapper.",),
        )
    )

    maps.append(
        ScreenMap(
            app_id="wordpress",
            app_name="WordPress",
            category=AppCategory.CMS,
            screen_id="wordpress_elementor_editor",
            screen_name="Elementor Editor",
            description="Elementor visual page builder inside WordPress.",
            title_keywords=("elementor", "wordpress"),
            url_keywords=("elementor", "action=elementor"),
            ocr_keywords=("elementor", "widgets", "update", "navigator", "responsive mode", "history", "publish"),
            element_labels=("update", "widgets", "navigator", "responsive mode"),
            zones=(
                _zone("elementor_panel", "Left Elementor widgets/settings panel.", (0.00, 0.00, 0.27, 1.00), ("widgets", "elementor", "update"), "panel", 95),
                _zone("page_canvas", "Live page design canvas.", (0.27, 0.00, 1.00, 0.95), (), "content", 90),
                _zone("bottom_tools", "Elementor bottom toolbar.", (0.00, 0.92, 0.27, 1.00), ("responsive", "history", "navigator"), "toolbar", 75),
            ),
            primary_actions=("map_design_canvas", "read_widget_panel", "detect_update_button"),
            route_hints=("CreatorAgent.page_builder", "VisualAgent.annotation_tool"),
            verification_hints=("Confirm Elementor panel visible.", "Confirm Update button state."),
            memory_tags=("wordpress", "elementor", "page_builder"),
            risk_notes=("Updating/publishing Elementor pages is sensitive and must be approved outside this mapper.",),
        )
    )

    # -------------------------------------------------------------------------
    # Google Ads
    # -------------------------------------------------------------------------
    maps.append(
        ScreenMap(
            app_id="google_ads",
            app_name="Google Ads",
            category=AppCategory.ADS_PLATFORM,
            screen_id="google_ads_overview",
            screen_name="Google Ads Overview",
            description="Google Ads account overview/campaign dashboard.",
            title_keywords=("google ads", "overview"),
            url_keywords=("ads.google.com", "/aw/overview", "/aw/campaigns"),
            ocr_keywords=("overview", "campaigns", "recommendations", "insights", "conversions", "cost", "clicks", "impressions"),
            element_labels=("overview", "campaigns", "recommendations", "insights", "tools"),
            zones=(
                _zone("top_bar", "Google Ads top navigation/search/account bar.", (0.00, 0.00, 1.00, 0.09), ("search", "help", "tools"), "navigation", 75),
                _zone("left_nav", "Google Ads left navigation.", (0.00, 0.09, 0.18, 1.00), ("overview", "campaigns", "goals"), "navigation", 90),
                _zone("metrics_area", "Overview cards and performance metrics.", (0.18, 0.09, 1.00, 0.45), ("clicks", "impressions", "cost"), "content", 95),
                _zone("chart_area", "Performance chart.", (0.18, 0.45, 1.00, 0.78), (), "chart", 75),
                _zone("table_area", "Campaign/ad group data table.", (0.18, 0.78, 1.00, 1.00), ("campaign", "status"), "table", 70),
            ),
            primary_actions=("read_ads_metrics", "detect_campaign_status", "map_campaign_table"),
            route_hints=("BusinessAgent.ads_dashboard", "FinanceAgent.ad_spend_summary", "VerificationAgent.result_validator"),
            verification_hints=("Check selected date range.", "Check visible account/campaign scope."),
            memory_tags=("google_ads", "ads", "dashboard"),
            risk_notes=("Budget, campaign enable/disable, and bidding changes require Security Agent approval outside this mapper.",),
        )
    )

    maps.append(
        ScreenMap(
            app_id="google_ads",
            app_name="Google Ads",
            category=AppCategory.ADS_PLATFORM,
            screen_id="google_ads_campaigns",
            screen_name="Google Ads Campaigns Table",
            description="Google Ads campaign management table.",
            title_keywords=("google ads", "campaigns"),
            url_keywords=("ads.google.com", "/aw/campaigns"),
            ocr_keywords=("campaigns", "budget", "status", "optimization score", "clicks", "cost", "conversions", "bid strategy"),
            element_labels=("campaigns", "budget", "status", "columns", "segment"),
            zones=(
                _zone("campaign_toolbar", "Campaign actions/filter/date toolbar.", (0.18, 0.10, 1.00, 0.25), ("filter", "columns", "segment"), "toolbar", 80),
                _zone("campaign_table", "Campaign table rows and metrics.", (0.18, 0.25, 1.00, 0.95), ("campaign", "budget", "status"), "table", 98),
                _zone("left_nav", "Google Ads left navigation.", (0.00, 0.09, 0.18, 1.00), ("campaigns", "ad groups", "ads"), "navigation", 75),
            ),
            primary_actions=("read_campaign_rows", "detect_status", "extract_budget_and_cost"),
            route_hints=("BusinessAgent.campaign_audit", "VerificationAgent.table_reader"),
            verification_hints=("Check filters and date range.", "Check campaign status column."),
            memory_tags=("google_ads", "campaigns", "ads_table"),
            risk_notes=("Changing campaign status or budget requires Security Agent approval outside this mapper.",),
        )
    )

    # -------------------------------------------------------------------------
    # Google Sheets
    # -------------------------------------------------------------------------
    maps.append(
        ScreenMap(
            app_id="google_sheets",
            app_name="Google Sheets",
            category=AppCategory.PRODUCTIVITY,
            screen_id="google_sheets_grid",
            screen_name="Google Sheets Spreadsheet",
            description="Google Sheets spreadsheet grid.",
            title_keywords=("google sheets", "sheets"),
            url_keywords=("docs.google.com/spreadsheets"),
            ocr_keywords=("file", "edit", "view", "insert", "format", "data", "tools", "extensions", "share"),
            element_labels=("file", "edit", "view", "insert", "data", "share"),
            zones=(
                _zone("menu_bar", "Sheets menu bar.", (0.00, 0.00, 1.00, 0.12), ("file", "edit", "view", "insert", "format"), "navigation", 80),
                _zone("toolbar", "Formatting toolbar.", (0.00, 0.12, 1.00, 0.20), (), "toolbar", 70),
                _zone("formula_bar", "Name box/formula bar.", (0.00, 0.20, 1.00, 0.27), (), "input", 60),
                _zone("sheet_grid", "Spreadsheet cells grid.", (0.00, 0.27, 1.00, 0.93), (), "table", 98),
                _zone("sheet_tabs", "Sheet tabs at bottom.", (0.00, 0.93, 1.00, 1.00), (), "navigation", 65),
            ),
            primary_actions=("read_sheet_grid", "detect_selected_cell", "map_columns"),
            route_hints=("WorkflowAgent.sheet_workflow", "BusinessAgent.data_analysis", "VerificationAgent.file_state_checker"),
            verification_hints=("Confirm spreadsheet URL/title.", "Check selected cell and visible grid region."),
            memory_tags=("google_sheets", "spreadsheet", "productivity"),
            risk_notes=("Editing, sharing, or deleting sheet data requires explicit approval outside this mapper.",),
        )
    )

    # -------------------------------------------------------------------------
    # Gmail
    # -------------------------------------------------------------------------
    maps.append(
        ScreenMap(
            app_id="gmail",
            app_name="Gmail",
            category=AppCategory.EMAIL,
            screen_id="gmail_inbox",
            screen_name="Gmail Inbox",
            description="Gmail inbox/message list screen.",
            title_keywords=("gmail", "inbox"),
            url_keywords=("mail.google.com", "#inbox"),
            ocr_keywords=("inbox", "starred", "snoozed", "sent", "drafts", "compose", "primary", "promotions"),
            element_labels=("compose", "inbox", "starred", "sent", "drafts"),
            zones=(
                _zone("top_search", "Gmail search bar and top actions.", (0.15, 0.00, 0.85, 0.11), ("search mail",), "input", 85),
                _zone("left_mail_nav", "Mailbox navigation and Compose button.", (0.00, 0.08, 0.22, 1.00), ("compose", "inbox", "sent"), "navigation", 90),
                _zone("category_tabs", "Primary/social/promotions tabs.", (0.22, 0.10, 1.00, 0.20), ("primary", "promotions"), "navigation", 70),
                _zone("message_list", "Email message list.", (0.22, 0.20, 1.00, 0.95), (), "list", 98),
            ),
            primary_actions=("read_inbox_overview", "find_email", "detect_unread_messages"),
            route_hints=("BusinessAgent.email_summary", "WorkflowAgent.email_workflow"),
            verification_hints=("Confirm mailbox folder.", "Check sender/subject rows."),
            memory_tags=("gmail", "email", "inbox"),
            risk_notes=("Sending, forwarding, deleting, or archiving email requires explicit user action outside this mapper.",),
        )
    )

    maps.append(
        ScreenMap(
            app_id="gmail",
            app_name="Gmail",
            category=AppCategory.EMAIL,
            screen_id="gmail_compose",
            screen_name="Gmail Compose Window",
            description="Gmail email compose modal/window.",
            title_keywords=("gmail",),
            url_keywords=("mail.google.com",),
            ocr_keywords=("new message", "recipients", "subject", "send", "cc", "bcc", "discard draft"),
            element_labels=("send", "to", "subject", "cc", "bcc"),
            zones=(
                _zone("compose_window", "Compose modal/window.", (0.45, 0.35, 0.98, 0.98), ("new message", "send"), "dialog", 98),
                _zone("recipient_field", "To/recipient field.", (0.47, 0.40, 0.96, 0.48), ("recipients", "to"), "input", 90),
                _zone("subject_field", "Subject field.", (0.47, 0.48, 0.96, 0.55), ("subject",), "input", 85),
                _zone("body_field", "Email body editor.", (0.47, 0.55, 0.96, 0.90), (), "input", 85),
                _zone("send_button", "Send button.", (0.47, 0.90, 0.58, 0.98), ("send",), "button", 95, False, True),
            ),
            primary_actions=("detect_compose_fields", "read_draft_state"),
            route_hints=("BusinessAgent.email_draft", "VerificationAgent.form_reader"),
            verification_hints=("Check recipient and subject fields.", "Do not send without explicit approval."),
            memory_tags=("gmail", "compose", "email"),
            risk_notes=("Sending email is sensitive and must require explicit user confirmation outside this mapper.",),
        )
    )

    # -------------------------------------------------------------------------
    # Google Analytics
    # -------------------------------------------------------------------------
    maps.append(
        ScreenMap(
            app_id="google_analytics",
            app_name="Google Analytics",
            category=AppCategory.ANALYTICS,
            screen_id="ga4_reports",
            screen_name="Google Analytics Reports",
            description="GA4 reports dashboard.",
            title_keywords=("google analytics", "analytics"),
            url_keywords=("analytics.google.com", "/reports"),
            ocr_keywords=("reports", "realtime", "acquisition", "engagement", "monetization", "users", "events"),
            element_labels=("reports", "explore", "advertising", "admin"),
            zones=(
                _zone("left_nav", "GA4 navigation.", (0.00, 0.08, 0.18, 1.00), ("reports", "explore", "admin"), "navigation", 90),
                _zone("report_header", "Report title/date controls.", (0.18, 0.08, 1.00, 0.22), ("date", "share"), "toolbar", 75),
                _zone("metrics_cards", "Report metrics cards.", (0.18, 0.22, 1.00, 0.45), ("users", "events"), "content", 85),
                _zone("charts_tables", "Report charts and data tables.", (0.18, 0.45, 1.00, 1.00), (), "content", 85),
            ),
            primary_actions=("read_analytics_report", "extract_metrics", "detect_date_range"),
            route_hints=("BusinessAgent.analytics_summary", "VerificationAgent.result_validator"),
            verification_hints=("Check selected property and date range.", "Confirm report name."),
            memory_tags=("analytics", "ga4", "reports"),
        )
    )

    # -------------------------------------------------------------------------
    # YouTube Studio
    # -------------------------------------------------------------------------
    maps.append(
        ScreenMap(
            app_id="youtube_studio",
            app_name="YouTube Studio",
            category=AppCategory.SOCIAL_CREATOR,
            screen_id="youtube_studio_content",
            screen_name="YouTube Studio Content",
            description="YouTube Studio channel content/videos table.",
            title_keywords=("youtube studio", "channel content"),
            url_keywords=("studio.youtube.com", "/channel/", "/videos"),
            ocr_keywords=("channel content", "videos", "visibility", "restrictions", "date", "views", "comments", "likes"),
            element_labels=("content", "analytics", "comments", "subtitles"),
            zones=(
                _zone("left_nav", "YouTube Studio navigation.", (0.00, 0.08, 0.18, 1.00), ("dashboard", "content", "analytics"), "navigation", 90),
                _zone("content_table", "Video/content table.", (0.18, 0.18, 1.00, 0.95), ("visibility", "views", "comments"), "table", 95),
                _zone("top_bar", "Search/create/account top bar.", (0.00, 0.00, 1.00, 0.08), ("create", "search"), "navigation", 70),
            ),
            primary_actions=("read_video_table", "detect_video_status", "extract_performance_metrics"),
            route_hints=("CreatorAgent.youtube_content", "BusinessAgent.content_analytics"),
            verification_hints=("Confirm channel/content page.", "Check video visibility/status."),
            memory_tags=("youtube_studio", "creator", "content"),
            risk_notes=("Publishing, deleting, or changing visibility requires explicit approval outside this mapper.",),
        )
    )

    # -------------------------------------------------------------------------
    # Canva / design tools
    # -------------------------------------------------------------------------
    maps.append(
        ScreenMap(
            app_id="canva",
            app_name="Canva",
            category=AppCategory.DESIGN,
            screen_id="canva_editor",
            screen_name="Canva Design Editor",
            description="Canva visual design editor.",
            title_keywords=("canva", "design"),
            url_keywords=("canva.com/design",),
            ocr_keywords=("design", "elements", "text", "uploads", "share", "download", "templates", "resize"),
            element_labels=("elements", "text", "uploads", "share", "download"),
            zones=(
                _zone("left_tools", "Canva tool/sidebar.", (0.00, 0.08, 0.24, 1.00), ("templates", "elements", "text", "uploads"), "navigation", 90),
                _zone("top_toolbar", "Canva top toolbar.", (0.00, 0.00, 1.00, 0.08), ("share", "download", "resize"), "toolbar", 80),
                _zone("design_canvas", "Design canvas.", (0.24, 0.08, 0.88, 0.92), (), "content", 95),
                _zone("page_panel", "Page thumbnails or notes area.", (0.88, 0.08, 1.00, 0.92), (), "panel", 45),
            ),
            primary_actions=("map_design_canvas", "read_design_controls", "detect_export_controls"),
            route_hints=("CreatorAgent.design_context", "VisualAgent.image_analyzer"),
            verification_hints=("Confirm design canvas and active page.", "Check export/share controls."),
            memory_tags=("canva", "design", "creator"),
            risk_notes=("Publishing, sharing, or downloading assets may require approval outside this mapper depending on workspace policy.",),
        )
    )

    # -------------------------------------------------------------------------
    # Generic web dashboard
    # -------------------------------------------------------------------------
    maps.append(
        ScreenMap(
            app_id="generic_web_dashboard",
            app_name="Generic Web Dashboard",
            category=AppCategory.PRODUCTIVITY,
            screen_id="dashboard_common",
            screen_name="Common Web Dashboard",
            description="Generic dashboard with sidebar, metrics, charts, and table.",
            title_keywords=("dashboard", "admin", "panel", "overview"),
            ocr_keywords=("dashboard", "overview", "analytics", "settings", "users", "reports", "export"),
            element_labels=("dashboard", "settings", "users", "reports"),
            zones=(
                _zone("top_nav", "Top navigation/header.", (0.00, 0.00, 1.00, 0.10), ("search", "profile"), "navigation", 70),
                _zone("side_nav", "Sidebar navigation.", (0.00, 0.10, 0.22, 1.00), ("dashboard", "settings"), "navigation", 80),
                _zone("metric_cards", "KPI/stat cards.", (0.22, 0.10, 1.00, 0.35), (), "content", 65),
                _zone("main_content", "Charts, tables, cards, and reports.", (0.22, 0.35, 1.00, 1.00), (), "content", 75),
            ),
            primary_actions=("read_dashboard", "map_sidebar", "extract_metrics"),
            route_hints=("BusinessAgent.dashboard_summary", "VisualAgent.ui_mapper"),
            verification_hints=("Identify active section.", "Check visible metric labels."),
            memory_tags=("dashboard", "generic_web_app"),
        )
    )

    # -------------------------------------------------------------------------
    # Terminal
    # -------------------------------------------------------------------------
    maps.append(
        ScreenMap(
            app_id="terminal",
            app_name="Terminal / Command Prompt",
            category=AppCategory.TERMINAL,
            screen_id="terminal_shell",
            screen_name="Terminal Shell",
            description="Terminal, command prompt, PowerShell, bash, or shell output.",
            title_keywords=("terminal", "command prompt", "powershell", "cmd", "bash", "zsh"),
            ocr_keywords=("$", ">", "powershell", "cmd", "bash", "npm", "python", "pip", "git", "error", "traceback"),
            element_labels=("terminal", "shell"),
            zones=(
                _zone("terminal_output", "Terminal output area.", (0.00, 0.00, 1.00, 0.95), (), "content", 95),
                _zone("command_prompt", "Likely current command prompt input area.", (0.00, 0.85, 1.00, 1.00), (), "input", 75),
            ),
            primary_actions=("read_terminal_output", "detect_last_command", "detect_errors"),
            route_hints=("CodeAgent.terminal_context", "SystemAgent.command_status"),
            verification_hints=("Check final output lines.", "Look for error/traceback/success text."),
            memory_tags=("terminal", "cli", "debugging"),
            risk_notes=("Executing commands is sensitive and must be approved outside this mapper.",),
        )
    )

    return maps


# =============================================================================
# AppScreenMapper
# =============================================================================

class AppScreenMapper(BaseAgent):
    """
    Visual Agent helper for app-specific screen recognition.

    It uses known app maps to classify visual context and expose likely regions
    and safe route hints. This is a non-executing helper: it does not click, type,
    submit forms, send messages, change ads, publish content, or modify files.

    Public methods:
        - map_screen()
        - identify_app_screen()
        - list_known_apps()
        - get_screen_map()
        - register_custom_screen_map()
        - suggest_zones()
        - prepare_visual_context_summary()
    """

    def __init__(
        self,
        config: Optional[Union[AppScreenMapperConfig, Mapping[str, Any]]] = None,
        screen_maps: Optional[Sequence[ScreenMap]] = None,
        security_agent: Optional[Any] = None,
        event_emitter: Optional[EventEmitterCallable] = None,
        audit_logger: Optional[AuditLoggerCallable] = None,
        logger: Optional[logging.Logger] = None,
        agent_name: str = "AppScreenMapper",
        agent_id: str = "visual.app_screen_mapper",
    ) -> None:
        super().__init__(agent_name=agent_name, agent_id=agent_id)
        self.agent_name = agent_name
        self.agent_id = agent_id
        self.config = self._coerce_config(config)
        self.security_agent = security_agent or SecurityAgent()
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.logger = logger or LOGGER
        self._screen_maps: List[ScreenMap] = list(screen_maps or build_default_screen_maps())
        self._custom_screen_maps: List[ScreenMap] = []

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def map_screen(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        *,
        ocr_text: Optional[str] = None,
        window_title: Optional[str] = None,
        url: Optional[str] = None,
        detected_elements: Optional[Sequence[Mapping[str, Any]]] = None,
        app_hint: Optional[str] = None,
        screen_size: Optional[Tuple[int, int]] = None,
        include_all_candidates: bool = True,
    ) -> JsonDict:
        """
        Main screen mapping method.

        Args:
            context:
                SaaS task context containing user_id and workspace_id.
            ocr_text:
                Text extracted from screenshot or video frame.
            window_title:
                Active window title if available.
            url:
                Browser URL if available.
            detected_elements:
                Optional UI elements from element_detector/ui_mapper.
            app_hint:
                Optional app hint from screen_context.py or user request.
            screen_size:
                Optional screen size in pixels, e.g. (1920, 1080).
            include_all_candidates:
                Include top candidate matches, not only best match.

        Returns:
            Structured result with best match, zones, route hints, verification
            payload, memory payload, and safe visual context summary.
        """
        started = time.monotonic()

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: TaskContext = ctx_result["data"]["context"]

        visual_context = self._build_visual_context(
            ocr_text=ocr_text,
            window_title=window_title,
            url=url,
            detected_elements=detected_elements,
            app_hint=app_hint,
            screen_size=screen_size,
        )

        matches = self._score_all_maps(visual_context)
        best_match = matches[0] if matches else None

        if best_match and best_match.score >= self.config.min_score_for_match:
            message = "App screen mapped successfully."
            mapped = True
        else:
            message = "No strong app-specific screen match found."
            mapped = False

        zones = []
        if best_match:
            zones = self._zones_with_pixel_bounds(
                best_match.screen_map.zones,
                screen_size=screen_size,
            )

        candidate_data = [match.to_dict() for match in matches[: self.config.max_matches]]
        best_data = best_match.to_dict() if best_match else None

        map_payload = {
            "mapped": mapped,
            "best_match": best_data,
            "candidates": candidate_data if include_all_candidates else [],
            "zones": zones,
            "route_hints": list(best_match.screen_map.route_hints) if best_match else [],
            "primary_actions": list(best_match.screen_map.primary_actions) if best_match else [],
            "verification_hints": list(best_match.screen_map.verification_hints) if best_match else [],
            "risk_notes": list(best_match.screen_map.risk_notes) if best_match else [],
            "visual_context_summary": self._safe_visual_context_summary(visual_context),
        }

        verification_payload = self._prepare_verification_payload(ctx, map_payload)
        memory_payload = self._prepare_memory_payload(ctx, map_payload)

        duration_ms = round((time.monotonic() - started) * 1000, 3)

        self._emit_agent_event(
            "app_screen_mapped",
            {
                "context": self._safe_context_public(ctx),
                "mapped": mapped,
                "best_app": best_match.screen_map.app_id if best_match else None,
                "best_screen": best_match.screen_map.screen_id if best_match else None,
                "score": round(best_match.score, 4) if best_match else None,
                "duration_ms": duration_ms,
            },
        )

        self._log_audit_event(
            {
                "event_type": "visual.app_screen_mapper.map_screen",
                "context": self._safe_context_public(ctx),
                "mapped": mapped,
                "best_app": best_match.screen_map.app_id if best_match else None,
                "best_screen": best_match.screen_map.screen_id if best_match else None,
                "confidence": best_match.confidence.value if best_match else ScreenConfidence.UNKNOWN.value,
                "duration_ms": duration_ms,
            }
        )

        return self._safe_result(
            message=message,
            data={
                "screen_mapping": map_payload,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent_id": self.agent_id,
                "agent_name": self.agent_name,
                "duration_ms": duration_ms,
                "known_map_count": len(self._screen_maps) + len(self._custom_screen_maps),
            },
        )

    def identify_app_screen(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        *,
        ocr_text: Optional[str] = None,
        window_title: Optional[str] = None,
        url: Optional[str] = None,
        detected_elements: Optional[Sequence[Mapping[str, Any]]] = None,
        app_hint: Optional[str] = None,
    ) -> JsonDict:
        """
        Lightweight wrapper around map_screen() returning only identification data.
        """
        result = self.map_screen(
            context,
            ocr_text=ocr_text,
            window_title=window_title,
            url=url,
            detected_elements=detected_elements,
            app_hint=app_hint,
            include_all_candidates=True,
        )
        if not result["success"]:
            return result

        mapping = result["data"]["screen_mapping"]
        return self._safe_result(
            message=result["message"],
            data={
                "mapped": mapping["mapped"],
                "best_match": mapping["best_match"],
                "candidates": mapping["candidates"],
            },
            metadata=result.get("metadata", {}),
        )

    def suggest_zones(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        *,
        app_id: Optional[str] = None,
        screen_id: Optional[str] = None,
        screen_size: Optional[Tuple[int, int]] = None,
        ocr_text: Optional[str] = None,
        window_title: Optional[str] = None,
        url: Optional[str] = None,
        detected_elements: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> JsonDict:
        """
        Suggest known UI zones for an app/screen.

        If app_id and screen_id are not provided, it first attempts screen mapping.
        """
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]["context"]

        screen_map: Optional[ScreenMap] = None

        if app_id and screen_id:
            screen_map = self._find_screen_map(app_id=app_id, screen_id=screen_id)
        else:
            mapping = self.map_screen(
                ctx,
                ocr_text=ocr_text,
                window_title=window_title,
                url=url,
                detected_elements=detected_elements,
                screen_size=screen_size,
                include_all_candidates=False,
            )
            if mapping["success"]:
                best = mapping["data"]["screen_mapping"].get("best_match")
                if best:
                    screen_map = self._find_screen_map(
                        app_id=best.get("app_id"),
                        screen_id=best.get("screen_id"),
                    )

        if not screen_map:
            return self._error_result(
                message="No screen map found for zone suggestions.",
                error={
                    "code": "SCREEN_MAP_NOT_FOUND",
                    "app_id": app_id,
                    "screen_id": screen_id,
                },
                metadata={"agent_id": self.agent_id},
            )

        zones = self._zones_with_pixel_bounds(screen_map.zones, screen_size=screen_size)

        return self._safe_result(
            message="Screen zones suggested.",
            data={
                "app_id": screen_map.app_id,
                "app_name": screen_map.app_name,
                "screen_id": screen_map.screen_id,
                "screen_name": screen_map.screen_name,
                "zones": zones,
                "risk_notes": list(screen_map.risk_notes),
            },
            metadata={"agent_id": self.agent_id},
        )

    def list_known_apps(
        self,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        *,
        include_screens: bool = True,
    ) -> JsonDict:
        """
        List known apps and screen maps.

        Context is optional because this only returns static app map metadata.
        If context is supplied, it is validated and audit-safe.
        """
        ctx: Optional[TaskContext] = None
        if context is not None:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

        grouped: Dict[str, JsonDict] = {}
        for screen_map in self._all_maps():
            app = grouped.setdefault(
                screen_map.app_id,
                {
                    "app_id": screen_map.app_id,
                    "app_name": screen_map.app_name,
                    "category": screen_map.category.value,
                    "screen_count": 0,
                    "screens": [],
                },
            )
            app["screen_count"] += 1
            if include_screens:
                app["screens"].append(
                    {
                        "screen_id": screen_map.screen_id,
                        "screen_name": screen_map.screen_name,
                        "description": screen_map.description,
                        "primary_actions": list(screen_map.primary_actions),
                        "route_hints": list(screen_map.route_hints),
                    }
                )

        if ctx:
            self._log_audit_event(
                {
                    "event_type": "visual.app_screen_mapper.list_known_apps",
                    "context": self._safe_context_public(ctx),
                    "app_count": len(grouped),
                }
            )

        return self._safe_result(
            message="Known apps listed.",
            data={
                "apps": list(grouped.values()),
                "app_count": len(grouped),
                "screen_map_count": len(self._all_maps()),
            },
            metadata={"agent_id": self.agent_id},
        )

    def get_screen_map(
        self,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        *,
        app_id: str,
        screen_id: str,
    ) -> JsonDict:
        """
        Return one known screen map by app_id and screen_id.
        """
        ctx: Optional[TaskContext] = None
        if context is not None:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

        screen_map = self._find_screen_map(app_id=app_id, screen_id=screen_id)
        if not screen_map:
            return self._error_result(
                message="Screen map not found.",
                error={
                    "code": "SCREEN_MAP_NOT_FOUND",
                    "app_id": app_id,
                    "screen_id": screen_id,
                },
                metadata={"agent_id": self.agent_id},
            )

        if ctx:
            self._log_audit_event(
                {
                    "event_type": "visual.app_screen_mapper.get_screen_map",
                    "context": self._safe_context_public(ctx),
                    "app_id": app_id,
                    "screen_id": screen_id,
                }
            )

        return self._safe_result(
            message="Screen map found.",
            data={"screen_map": screen_map.to_dict()},
            metadata={"agent_id": self.agent_id},
        )

    def register_custom_screen_map(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        *,
        screen_map_data: Mapping[str, Any],
    ) -> JsonDict:
        """
        Register a workspace/runtime custom screen map.

        This supports future SaaS dashboard extensions without editing code.
        The custom map is stored in memory only by this helper. Persisting it to DB
        should be handled by Visual Memory / Dashboard API outside this file.
        """
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]["context"]

        if not self.config.enable_custom_maps:
            return self._error_result(
                message="Custom screen maps are disabled by configuration.",
                error={"code": "CUSTOM_MAPS_DISABLED"},
                metadata={"agent_id": self.agent_id},
            )

        approval = self._request_if_required(
            ctx,
            action="register_custom_screen_map",
            risk_level="low",
            required=self.config.require_security_for_custom_map_registration,
            details={"screen_map_data_keys": sorted(list(screen_map_data.keys()))},
        )
        if not approval["success"]:
            return approval

        try:
            screen_map = self._screen_map_from_mapping(screen_map_data)
        except Exception as exc:
            return self._error_result(
                message="Custom screen map validation failed.",
                error=self._exception_error(exc),
                metadata={"agent_id": self.agent_id},
            )

        existing = self._find_screen_map(screen_map.app_id, screen_map.screen_id)
        if existing:
            return self._error_result(
                message="Screen map already exists.",
                error={
                    "code": "SCREEN_MAP_ALREADY_EXISTS",
                    "app_id": screen_map.app_id,
                    "screen_id": screen_map.screen_id,
                },
                metadata={"agent_id": self.agent_id},
            )

        self._custom_screen_maps.append(screen_map)

        self._emit_agent_event(
            "custom_screen_map_registered",
            {
                "context": self._safe_context_public(ctx),
                "app_id": screen_map.app_id,
                "screen_id": screen_map.screen_id,
            },
        )

        self._log_audit_event(
            {
                "event_type": "visual.app_screen_mapper.custom_map_registered",
                "context": self._safe_context_public(ctx),
                "app_id": screen_map.app_id,
                "screen_id": screen_map.screen_id,
            }
        )

        return self._safe_result(
            message="Custom screen map registered.",
            data={"screen_map": screen_map.to_dict()},
            metadata={"agent_id": self.agent_id},
        )

    def prepare_visual_context_summary(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        *,
        ocr_text: Optional[str] = None,
        window_title: Optional[str] = None,
        url: Optional[str] = None,
        detected_elements: Optional[Sequence[Mapping[str, Any]]] = None,
        app_hint: Optional[str] = None,
        screen_size: Optional[Tuple[int, int]] = None,
    ) -> JsonDict:
        """
        Prepare a redacted visual context summary for dashboard/API or Memory Agent.
        """
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]["context"]

        visual_context = self._build_visual_context(
            ocr_text=ocr_text,
            window_title=window_title,
            url=url,
            detected_elements=detected_elements,
            app_hint=app_hint,
            screen_size=screen_size,
        )

        summary = self._safe_visual_context_summary(visual_context)

        return self._safe_result(
            message="Visual context summary prepared.",
            data={
                "visual_context_summary": summary,
                "memory_payload": self._prepare_memory_payload(
                    ctx,
                    {"visual_context_summary": summary, "mapped": False},
                ),
            },
            metadata={"agent_id": self.agent_id},
        )

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[TaskContext, Mapping[str, Any], None],
    ) -> JsonDict:
        """
        Validate SaaS user/workspace context.

        Required by William/Jarvis global compatibility rules.
        """
        if context is None:
            return self._error_result(
                message="Task context is required.",
                error={
                    "code": "MISSING_CONTEXT",
                    "details": "user_id and workspace_id are required.",
                },
            )

        if isinstance(context, TaskContext):
            ctx = context
        elif isinstance(context, Mapping):
            ctx = TaskContext(
                user_id=str(context.get("user_id") or "").strip(),
                workspace_id=str(context.get("workspace_id") or "").strip(),
                task_id=self._optional_str(context.get("task_id")),
                run_id=self._optional_str(context.get("run_id")),
                agent_id=self._optional_str(context.get("agent_id")),
                source_agent=self._optional_str(context.get("source_agent")),
                requested_by=self._optional_str(context.get("requested_by")),
                role=self._optional_str(context.get("role")),
                permissions=tuple(str(x) for x in context.get("permissions", []) or []),
                metadata=dict(context.get("metadata") or {}),
            )
        else:
            return self._error_result(
                message="Invalid task context type.",
                error={
                    "code": "INVALID_CONTEXT_TYPE",
                    "expected": "TaskContext or Mapping",
                    "actual": type(context).__name__,
                },
            )

        missing = []
        if not ctx.user_id:
            missing.append("user_id")
        if not ctx.workspace_id:
            missing.append("workspace_id")

        if missing:
            return self._error_result(
                message="Task context validation failed.",
                error={
                    "code": "INVALID_CONTEXT",
                    "missing_fields": missing,
                    "details": "SaaS isolation requires user_id and workspace_id.",
                },
            )

        return self._safe_result(
            message="Task context validated.",
            data={"context": ctx},
            metadata={"agent_id": self.agent_id},
        )

    def _requires_security_check(
        self,
        action: str,
        risk_level: str = "low",
        details: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Determine whether an action requires Security Agent approval.

        Mapping a screen is non-destructive. Registering custom maps can be
        security-gated by config because maps may influence future routing.
        """
        action_clean = (action or "").strip().lower()
        if action_clean == "register_custom_screen_map":
            return self.config.require_security_for_custom_map_registration
        return risk_level.lower() in {"medium", "high", "critical"}

    def _request_security_approval(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        action: str,
        risk_level: str = "low",
        details: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """
        Request approval from Security Agent.

        Required by William/Jarvis compatibility rules.
        """
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]["context"]

        payload = {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "action": action,
            "risk_level": risk_level,
            "context": self._safe_context_public(ctx),
            "details": self._redact_if_needed(dict(details or {})),
            "requested_at": _utc_iso(),
        }

        try:
            if hasattr(self.security_agent, "approve_action"):
                approval = self.security_agent.approve_action(payload)
            elif hasattr(self.security_agent, "request_approval"):
                approval = self.security_agent.request_approval(payload)
            else:
                approval = {
                    "success": True,
                    "approved": True,
                    "message": "Security agent has no approval method; fallback allowed.",
                    "data": {"source": "local_fallback"},
                    "error": None,
                    "metadata": {},
                }

            if not isinstance(approval, Mapping):
                return self._error_result(
                    message="Security approval returned invalid response.",
                    error={"code": "INVALID_SECURITY_RESPONSE", "response": _safe_str(approval)},
                    metadata={"agent_id": self.agent_id},
                )

            approved = bool(approval.get("approved", approval.get("success", False)))
            success = bool(approval.get("success", approved))

            if success and approved:
                return self._safe_result(
                    message="Security approval granted.",
                    data={"approval": dict(approval)},
                    metadata={"agent_id": self.agent_id},
                )

            return self._error_result(
                message="Security approval denied.",
                error={
                    "code": "SECURITY_APPROVAL_DENIED",
                    "approval": dict(approval),
                },
                metadata={"agent_id": self.agent_id},
            )

        except Exception as exc:
            return self._error_result(
                message="Security approval request failed.",
                error=self._exception_error(exc),
                metadata={"agent_id": self.agent_id},
            )

    def _prepare_verification_payload(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        result_data: Mapping[str, Any],
    ) -> JsonDict:
        """
        Prepare Verification Agent payload.

        This supports verification reports, state checker correlation, and
        dashboard task completion evidence.
        """
        ctx = context if isinstance(context, TaskContext) else self._validate_task_context(context)["data"]["context"]

        best_match = result_data.get("best_match") or {}
        if not isinstance(best_match, Mapping):
            best_match = {}

        return {
            "payload_type": "visual_app_screen_mapping",
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "user_id": ctx.user_id,
            "workspace_id": ctx.workspace_id,
            "task_id": ctx.task_id,
            "run_id": ctx.run_id,
            "mapped": bool(result_data.get("mapped")),
            "app_id": best_match.get("app_id"),
            "app_name": best_match.get("app_name"),
            "screen_id": best_match.get("screen_id"),
            "screen_name": best_match.get("screen_name"),
            "confidence": best_match.get("confidence"),
            "score": best_match.get("score"),
            "verification_hints": list(result_data.get("verification_hints") or []),
            "risk_notes": list(result_data.get("risk_notes") or []),
            "created_at": _utc_iso(),
        }

    def _prepare_memory_payload(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        result_data: Mapping[str, Any],
    ) -> JsonDict:
        """
        Prepare Memory Agent compatible summary.

        Raw OCR text and sensitive data are not stored. The payload focuses on
        app/screen identity, confidence, and safe workflow hints.
        """
        ctx = context if isinstance(context, TaskContext) else self._validate_task_context(context)["data"]["context"]

        best_match = result_data.get("best_match") or {}
        if not isinstance(best_match, Mapping):
            best_match = {}

        visual_summary = result_data.get("visual_context_summary") or {}
        if not isinstance(visual_summary, Mapping):
            visual_summary = {}

        return {
            "payload_type": "visual_app_screen_memory_summary",
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "user_id": ctx.user_id,
            "workspace_id": ctx.workspace_id,
            "task_id": ctx.task_id,
            "run_id": ctx.run_id,
            "mapped": bool(result_data.get("mapped")),
            "app_id": best_match.get("app_id"),
            "app_name": best_match.get("app_name"),
            "category": best_match.get("category"),
            "screen_id": best_match.get("screen_id"),
            "screen_name": best_match.get("screen_name"),
            "confidence": best_match.get("confidence"),
            "primary_actions": list(result_data.get("primary_actions") or []),
            "route_hints": list(result_data.get("route_hints") or []),
            "visual_context_hash": visual_summary.get("context_hash"),
            "created_at": _utc_iso(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Mapping[str, Any],
    ) -> None:
        """
        Emit event for Master Agent, dashboard, router, registry, or observability.
        """
        try:
            safe_payload = self._redact_if_needed(dict(payload))
            if self.event_emitter:
                self.event_emitter(event_name, safe_payload)
            else:
                self.logger.debug("Agent event: %s %s", event_name, safe_payload)
        except Exception:
            self.logger.debug("Failed to emit agent event: %s", event_name, exc_info=True)

    def _log_audit_event(
        self,
        event: Mapping[str, Any],
    ) -> None:
        """
        Log audit event without mixing tenants.
        """
        try:
            safe_event = self._redact_if_needed(dict(event))
            safe_event.setdefault("agent_id", self.agent_id)
            safe_event.setdefault("agent_name", self.agent_name)
            safe_event.setdefault("timestamp", _utc_iso())

            if self.audit_logger:
                self.audit_logger(safe_event)
            else:
                self.logger.info("Audit event: %s", json.dumps(safe_event, default=str))
        except Exception:
            self.logger.debug("Failed to log audit event.", exc_info=True)

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """
        Standard success result format.
        """
        clean_data = dict(data or {})
        clean_metadata = dict(metadata or {})
        if self.config.redact_sensitive_text:
            clean_data = self._redact_if_needed(clean_data)
            clean_metadata = self._redact_if_needed(clean_metadata)

        return {
            "success": True,
            "message": message,
            "data": clean_data,
            "error": None,
            "metadata": clean_metadata,
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """
        Standard error result format.
        """
        clean_error = dict(error or {"code": "UNKNOWN_ERROR"})
        clean_data = dict(data or {})
        clean_metadata = dict(metadata or {})
        if self.config.redact_sensitive_text:
            clean_error = self._redact_if_needed(clean_error)
            clean_data = self._redact_if_needed(clean_data)
            clean_metadata = self._redact_if_needed(clean_metadata)

        return {
            "success": False,
            "message": message,
            "data": clean_data,
            "error": clean_error,
            "metadata": clean_metadata,
        }

    # -------------------------------------------------------------------------
    # Internal scoring and mapping logic
    # -------------------------------------------------------------------------

    def _score_all_maps(self, visual_context: Mapping[str, Any]) -> List[ScreenMatch]:
        matches: List[ScreenMatch] = []

        for screen_map in self._all_maps():
            score, evidence = self._score_screen_map(screen_map, visual_context)
            confidence = _confidence_from_score(score, self.config)

            if score >= self.config.min_score_for_match:
                matches.append(
                    ScreenMatch(
                        screen_map=screen_map,
                        score=score,
                        confidence=confidence,
                        evidence=evidence,
                    )
                )

        matches.sort(key=lambda item: item.score, reverse=True)
        return matches

    def _score_screen_map(
        self,
        screen_map: ScreenMap,
        visual_context: Mapping[str, Any],
    ) -> Tuple[float, JsonDict]:
        title_text = str(visual_context.get("window_title_normalized") or "")
        url_text = str(visual_context.get("url_normalized") or "")
        ocr_text = str(visual_context.get("ocr_text_normalized") or "")
        element_text = str(visual_context.get("element_text_normalized") or "")
        app_hint = str(visual_context.get("app_hint_normalized") or "")

        title_hits = _keyword_hits(title_text, screen_map.title_keywords)
        url_hits = _keyword_hits(url_text, screen_map.url_keywords)
        ocr_hits = _keyword_hits(ocr_text, screen_map.ocr_keywords)
        element_hits = _keyword_hits(element_text, screen_map.element_labels)
        negative_hits = _keyword_hits(" ".join([title_text, url_text, ocr_text, element_text]), screen_map.negative_keywords)

        app_hint_score = 0.0
        if app_hint:
            app_name = screen_map.app_name.lower()
            app_id = screen_map.app_id.lower()
            if app_hint in app_id or app_id in app_hint or app_hint in app_name or app_name in app_hint:
                app_hint_score = 0.22

        title_score = min(0.22, len(title_hits) * 0.075)
        url_score = min(0.26, len(url_hits) * 0.11)
        ocr_score = min(0.30, len(ocr_hits) * 0.04)
        element_score = min(0.18, len(element_hits) * 0.05)
        negative_penalty = min(0.30, len(negative_hits) * 0.10)

        # Bonus when multiple independent signals agree.
        signal_count = sum(
            1
            for value in (
                bool(title_hits),
                bool(url_hits),
                bool(ocr_hits),
                bool(element_hits),
                bool(app_hint_score),
            )
            if value
        )
        multi_signal_bonus = 0.06 if signal_count >= 2 else 0.0
        if signal_count >= 3:
            multi_signal_bonus += 0.06

        score = max(
            0.0,
            min(
                1.0,
                title_score
                + url_score
                + ocr_score
                + element_score
                + app_hint_score
                + multi_signal_bonus
                - negative_penalty,
            ),
        )

        evidence = {
            "title_hits": title_hits,
            "url_hits": url_hits,
            "ocr_hits": ocr_hits,
            "element_hits": element_hits,
            "negative_hits": negative_hits,
            "signal_count": signal_count,
            "score_parts": {
                "title_score": round(title_score, 4),
                "url_score": round(url_score, 4),
                "ocr_score": round(ocr_score, 4),
                "element_score": round(element_score, 4),
                "app_hint_score": round(app_hint_score, 4),
                "multi_signal_bonus": round(multi_signal_bonus, 4),
                "negative_penalty": round(negative_penalty, 4),
            },
        }

        return score, evidence

    def _build_visual_context(
        self,
        *,
        ocr_text: Optional[str],
        window_title: Optional[str],
        url: Optional[str],
        detected_elements: Optional[Sequence[Mapping[str, Any]]],
        app_hint: Optional[str],
        screen_size: Optional[Tuple[int, int]],
    ) -> JsonDict:
        elements = list(detected_elements or [])

        ocr_raw = _safe_str(ocr_text or "", self.config.max_ocr_chars_kept)
        title_raw = _safe_str(window_title or "", self.config.max_title_chars_kept)
        url_raw = _safe_str(url or "", self.config.max_url_chars_kept)

        if self.config.redact_sensitive_text:
            ocr_safe = _redact_text(ocr_raw, self.config.sensitive_fragments)
            title_safe = _redact_text(title_raw, self.config.sensitive_fragments)
            url_safe = _redact_text(url_raw, self.config.sensitive_fragments)
            elements_safe = self._redact_if_needed(elements)
        else:
            ocr_safe = ocr_raw
            title_safe = title_raw
            url_safe = url_raw
            elements_safe = elements

        return {
            "ocr_text": ocr_safe,
            "window_title": title_safe,
            "url": url_safe,
            "detected_elements": elements_safe,
            "app_hint": _safe_str(app_hint or "", 200),
            "screen_size": list(screen_size) if screen_size else None,
            "ocr_text_normalized": _normalize_text(ocr_safe),
            "window_title_normalized": _normalize_text(title_safe),
            "url_normalized": _normalize_text(url_safe),
            "element_text_normalized": _tokenize_labels(elements_safe if isinstance(elements_safe, list) else []),
            "app_hint_normalized": _normalize_text(app_hint or ""),
            "context_hash": _hash_text(
                json.dumps(
                    {
                        "ocr": ocr_safe,
                        "title": title_safe,
                        "url": url_safe,
                        "elements": elements_safe,
                        "app_hint": app_hint,
                        "screen_size": screen_size,
                    },
                    sort_keys=True,
                    default=str,
                )
            ),
        }

    def _safe_visual_context_summary(self, visual_context: Mapping[str, Any]) -> JsonDict:
        ocr_text = str(visual_context.get("ocr_text") or "")
        window_title = str(visual_context.get("window_title") or "")
        url = str(visual_context.get("url") or "")
        elements = visual_context.get("detected_elements") or []

        if not isinstance(elements, list):
            elements = []

        labels: List[str] = []
        for element in elements[:50]:
            if not isinstance(element, Mapping):
                continue
            for key in ("text", "label", "aria_label", "name", "title", "role"):
                value = element.get(key)
                if value:
                    labels.append(_safe_str(value, 120))

        return {
            "context_hash": visual_context.get("context_hash"),
            "window_title": _safe_str(window_title, 300),
            "url": _safe_str(url, 600),
            "ocr_char_count": len(ocr_text),
            "ocr_excerpt": _safe_str(ocr_text, 700),
            "detected_element_count": len(elements),
            "detected_labels_excerpt": _unique_preserve_order(labels)[:30],
            "app_hint": visual_context.get("app_hint"),
            "screen_size": visual_context.get("screen_size"),
            "redacted": self.config.redact_sensitive_text,
        }

    def _zones_with_pixel_bounds(
        self,
        zones: Sequence[ElementZone],
        *,
        screen_size: Optional[Tuple[int, int]],
    ) -> List[JsonDict]:
        output: List[JsonDict] = []

        width = None
        height = None
        if screen_size and len(screen_size) == 2:
            try:
                width = int(screen_size[0])
                height = int(screen_size[1])
            except Exception:
                width = None
                height = None

        for zone in zones:
            data = zone.to_dict()
            if width and height:
                left, top, right, bottom = zone.bounds_ratio
                data["bounds_px"] = {
                    "left": int(round(left * width)),
                    "top": int(round(top * height)),
                    "right": int(round(right * width)),
                    "bottom": int(round(bottom * height)),
                    "center_x": int(round(((left + right) / 2) * width)),
                    "center_y": int(round(((top + bottom) / 2) * height)),
                }
            else:
                data["bounds_px"] = None
            output.append(data)

        output.sort(key=lambda item: int(item.get("priority", 50)), reverse=True)
        return output

    def _all_maps(self) -> List[ScreenMap]:
        return list(self._screen_maps) + list(self._custom_screen_maps)

    def _find_screen_map(self, app_id: Optional[str], screen_id: Optional[str]) -> Optional[ScreenMap]:
        if not app_id or not screen_id:
            return None

        app_clean = str(app_id).strip().lower()
        screen_clean = str(screen_id).strip().lower()

        for screen_map in self._all_maps():
            if screen_map.app_id.lower() == app_clean and screen_map.screen_id.lower() == screen_clean:
                return screen_map

        return None

    def _screen_map_from_mapping(self, data: Mapping[str, Any]) -> ScreenMap:
        required = ("app_id", "app_name", "category", "screen_id", "screen_name", "description")
        missing = [key for key in required if not str(data.get(key) or "").strip()]
        if missing:
            raise ValueError(f"Missing required screen map fields: {missing}")

        category_raw = str(data.get("category")).strip()
        try:
            category = AppCategory(category_raw)
        except Exception:
            category = AppCategory.UNKNOWN

        zones_raw = data.get("zones") or []
        zones: List[ElementZone] = []
        if not isinstance(zones_raw, Sequence) or isinstance(zones_raw, (str, bytes)):
            raise ValueError("zones must be a list of zone objects.")

        for zone_data in zones_raw:
            if not isinstance(zone_data, Mapping):
                continue
            bounds = zone_data.get("bounds_ratio") or zone_data.get("bounds") or (0.0, 0.0, 1.0, 1.0)
            if not isinstance(bounds, Sequence) or len(bounds) != 4:
                raise ValueError("Each zone bounds_ratio must contain 4 values.")

            bounds_tuple = tuple(float(x) for x in bounds)
            if any(x < 0 or x > 1 for x in bounds_tuple):
                raise ValueError("Zone bounds_ratio values must be between 0.0 and 1.0.")

            zones.append(
                ElementZone(
                    name=str(zone_data.get("name") or "custom_zone"),
                    description=str(zone_data.get("description") or ""),
                    bounds_ratio=bounds_tuple,  # type: ignore[arg-type]
                    expected_labels=tuple(str(x) for x in zone_data.get("expected_labels", []) or []),
                    role=str(zone_data.get("role") or "region"),
                    priority=int(zone_data.get("priority") or 50),
                    safe_to_click=bool(zone_data.get("safe_to_click", False)),
                    requires_security=bool(zone_data.get("requires_security", False)),
                )
            )

        return ScreenMap(
            app_id=str(data.get("app_id")).strip(),
            app_name=str(data.get("app_name")).strip(),
            category=category,
            screen_id=str(data.get("screen_id")).strip(),
            screen_name=str(data.get("screen_name")).strip(),
            description=str(data.get("description")).strip(),
            title_keywords=tuple(str(x) for x in data.get("title_keywords", []) or []),
            url_keywords=tuple(str(x) for x in data.get("url_keywords", []) or []),
            ocr_keywords=tuple(str(x) for x in data.get("ocr_keywords", []) or []),
            negative_keywords=tuple(str(x) for x in data.get("negative_keywords", []) or []),
            element_labels=tuple(str(x) for x in data.get("element_labels", []) or []),
            zones=tuple(zones),
            primary_actions=tuple(str(x) for x in data.get("primary_actions", []) or []),
            route_hints=tuple(str(x) for x in data.get("route_hints", []) or []),
            verification_hints=tuple(str(x) for x in data.get("verification_hints", []) or []),
            memory_tags=tuple(str(x) for x in data.get("memory_tags", []) or []),
            risk_notes=tuple(str(x) for x in data.get("risk_notes", []) or []),
            version=str(data.get("version") or "1.0"),
        )

    def _coerce_config(
        self,
        config: Optional[Union[AppScreenMapperConfig, Mapping[str, Any]]],
    ) -> AppScreenMapperConfig:
        if config is None:
            return AppScreenMapperConfig()
        if isinstance(config, AppScreenMapperConfig):
            return config
        if isinstance(config, Mapping):
            base = AppScreenMapperConfig()
            for key, value in config.items():
                if hasattr(base, str(key)):
                    setattr(base, str(key), value)
            return base
        return AppScreenMapperConfig()

    def _request_if_required(
        self,
        context: TaskContext,
        *,
        action: str,
        risk_level: str,
        required: bool,
        details: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        if not required and not self._requires_security_check(action, risk_level, details):
            return self._safe_result(
                message="Security approval not required.",
                data={"approval": {"approved": True, "source": "policy_not_required"}},
                metadata={"agent_id": self.agent_id},
            )
        return self._request_security_approval(
            context=context,
            action=action,
            risk_level=risk_level,
            details=details,
        )

    def _safe_context_public(self, context: TaskContext) -> JsonDict:
        return {
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "run_id": context.run_id,
            "agent_id": context.agent_id,
            "source_agent": context.source_agent,
            "requested_by": context.requested_by,
            "role": context.role,
        }

    def _redact_if_needed(self, value: Any) -> Any:
        if not self.config.redact_sensitive_text:
            return value
        return _redact_mapping(value, self.config.sensitive_fragments)

    def _optional_str(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def _exception_error(self, exc: BaseException) -> JsonDict:
        return {
            "code": exc.__class__.__name__.upper(),
            "message": _safe_str(exc, 1000),
            "traceback": traceback.format_exc(limit=5),
        }


# =============================================================================
# Factory and module metadata
# =============================================================================

def create_app_screen_mapper(
    config: Optional[Union[AppScreenMapperConfig, Mapping[str, Any]]] = None,
    security_agent: Optional[Any] = None,
    event_emitter: Optional[EventEmitterCallable] = None,
    audit_logger: Optional[AuditLoggerCallable] = None,
) -> AppScreenMapper:
    """
    Factory helper for Agent Loader / Agent Registry.

    Keeps construction consistent for FastAPI/dashboard integration.
    """
    return AppScreenMapper(
        config=config,
        security_agent=security_agent,
        event_emitter=event_emitter,
        audit_logger=audit_logger,
    )


AGENT_MODULE_METADATA: JsonDict = {
    "module": "agents.visual_agent.app_screen_mapper",
    "file_name": "app_screen_mapper.py",
    "class_name": "AppScreenMapper",
    "agent_module": "Visual Agent",
    "purpose": "Known app-specific screen maps for Chrome, VS Code, WordPress, Google Ads, etc.",
    "version": "1.0.0",
    "safe_to_import": True,
    "requires_user_workspace_context": True,
    "public_methods": [
        "map_screen",
        "identify_app_screen",
        "list_known_apps",
        "get_screen_map",
        "register_custom_screen_map",
        "suggest_zones",
        "prepare_visual_context_summary",
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
    "known_apps": [
        "chrome",
        "vscode",
        "wordpress",
        "google_ads",
        "google_sheets",
        "gmail",
        "google_analytics",
        "youtube_studio",
        "canva",
        "generic_web_dashboard",
        "terminal",
    ],
}


__all__ = [
    "AppScreenMapper",
    "AppScreenMapperConfig",
    "AppCategory",
    "ScreenConfidence",
    "TaskContext",
    "ElementZone",
    "ScreenMap",
    "ScreenMatch",
    "build_default_screen_maps",
    "create_app_screen_mapper",
    "AGENT_MODULE_METADATA",
]


if __name__ == "__main__":
    # Lightweight smoke test. No browser, file, OS, or destructive action is executed.
    mapper = AppScreenMapper()
    demo_context = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "task_id": "demo_task",
        "run_id": "demo_run",
    }

    demo_result = mapper.map_screen(
        demo_context,
        window_title="Dashboard ‹ My Website — WordPress",
        url="https://example.com/wp-admin/index.php",
        ocr_text="Dashboard Posts Media Pages Comments Appearance Plugins Users Settings",
        detected_elements=[
            {"text": "Dashboard", "role": "menuitem"},
            {"text": "Posts", "role": "menuitem"},
            {"text": "Pages", "role": "menuitem"},
            {"text": "Plugins", "role": "menuitem"},
        ],
        screen_size=(1920, 1080),
    )

    print(json.dumps(demo_result, indent=2, default=str))