"""
agents/browser_agent/browser_session.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

BrowserSession is a production-safe Browser Agent helper responsible for:
- Tracking browser tabs and active tab state
- Tracking visited URLs per user/workspace/task
- Tracking cookie/session metadata without storing sensitive cookie values
- Tracking browser task state for dashboard, Master Agent, Memory Agent, and Verification Agent
- Enforcing SaaS user/workspace isolation
- Preparing structured audit, memory, verification, and dashboard payloads

Important:
This file does NOT execute real browser actions.
It only manages safe browser session state and metadata.
Real browser automation must be handled by protected Browser Agent tools and Security Agent approval.
"""

from __future__ import annotations

import copy
import hashlib
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports
# ---------------------------------------------------------------------------
# This file must be safe to import even when the full William project has not
# been generated yet. These imports are optional and never required for basic
# operation.

try:
    from agents.registry import AgentRegistry  # type: ignore
except Exception:  # pragma: no cover
    AgentRegistry = None  # type: ignore


try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover

    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent stub.

        This keeps BrowserSession import-safe before the real BaseAgent exists.
        BrowserSession does not depend on BaseAgent behavior directly.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", "browser_session")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SESSION_SCHEMA_VERSION = "1.0.0"
DEFAULT_MAX_VISITED_URLS = 500
DEFAULT_MAX_EVENTS = 300
DEFAULT_MAX_TABS = 100

SENSITIVE_COOKIE_KEYWORDS = {
    "token",
    "session",
    "auth",
    "secret",
    "password",
    "csrf",
    "jwt",
    "credential",
    "key",
}

SAFE_DEFAULT_PERMISSIONS = {
    "can_track_tabs": True,
    "can_track_urls": True,
    "can_track_cookie_metadata": True,
    "can_store_memory_payload": True,
    "can_prepare_verification_payload": True,
    "can_emit_dashboard_events": True,
    "can_clear_session": False,
}


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class BrowserTabStatus(str, Enum):
    CREATED = "created"
    ACTIVE = "active"
    INACTIVE = "inactive"
    CLOSED = "closed"
    ERROR = "error"


class BrowserTaskStatus(str, Enum):
    IDLE = "idle"
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    WAITING_SECURITY_APPROVAL = "waiting_security_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class BrowserEventType(str, Enum):
    SESSION_CREATED = "session_created"
    SESSION_RESTORED = "session_restored"
    SESSION_CLEARED = "session_cleared"
    TAB_CREATED = "tab_created"
    TAB_SWITCHED = "tab_switched"
    TAB_UPDATED = "tab_updated"
    TAB_CLOSED = "tab_closed"
    URL_VISITED = "url_visited"
    COOKIE_METADATA_UPDATED = "cookie_metadata_updated"
    TASK_STATE_UPDATED = "task_state_updated"
    SECURITY_APPROVAL_REQUESTED = "security_approval_requested"
    VERIFICATION_PAYLOAD_PREPARED = "verification_payload_prepared"
    MEMORY_PAYLOAD_PREPARED = "memory_payload_prepared"
    AUDIT_EVENT = "audit_event"
    ERROR = "error"


class SecurityRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class BrowserUrlVisit:
    """
    Safe record of a visited URL.

    Stores metadata needed by Browser Agent, Master Agent, dashboard analytics,
    Memory Agent, and Verification Agent.
    """

    visit_id: str
    url: str
    normalized_url: str
    domain: str
    tab_id: Optional[str]
    title: Optional[str]
    user_id: str
    workspace_id: str
    task_id: Optional[str]
    timestamp: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BrowserTab:
    """
    Represents a tracked browser tab.

    This is state only. It does not control a real browser tab directly.
    """

    tab_id: str
    user_id: str
    workspace_id: str
    task_id: Optional[str]
    status: str = BrowserTabStatus.CREATED.value
    current_url: Optional[str] = None
    current_domain: Optional[str] = None
    title: Optional[str] = None
    opener_tab_id: Optional[str] = None
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())
    closed_at: Optional[str] = None
    visit_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BrowserCookieMetadata:
    """
    Cookie/session metadata record.

    Real cookie values must NOT be stored here.
    This object stores safe metadata only.
    """

    cookie_id: str
    user_id: str
    workspace_id: str
    domain: str
    name_hash: str
    name_hint: str
    secure: Optional[bool] = None
    http_only: Optional[bool] = None
    same_site: Optional[str] = None
    expires_at: Optional[str] = None
    path: Optional[str] = None
    is_sensitive_name: bool = False
    source_tab_id: Optional[str] = None
    task_id: Optional[str] = None
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BrowserTaskState:
    """
    Browser task state used by Master Agent, Browser Agent, dashboard,
    Verification Agent, and audit logging.
    """

    task_id: str
    user_id: str
    workspace_id: str
    status: str = BrowserTaskStatus.CREATED.value
    objective: Optional[str] = None
    active_tab_id: Optional[str] = None
    started_at: Optional[str] = None
    updated_at: str = field(default_factory=lambda: utc_now_iso())
    completed_at: Optional[str] = None
    failed_at: Optional[str] = None
    progress_percent: float = 0.0
    last_error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BrowserSessionEvent:
    """
    Internal session event.

    These events can be consumed later by:
    - Dashboard/API
    - Audit logs
    - Master Agent
    - Verification Agent
    - Memory Agent
    """

    event_id: str
    event_type: str
    user_id: str
    workspace_id: str
    task_id: Optional[str]
    timestamp: str
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    risk_level: str = SecurityRiskLevel.LOW.value


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def generate_id(prefix: str) -> str:
    """Generate a stable readable identifier."""
    return f"{prefix}_{uuid.uuid4().hex}"


def safe_hash(value: str) -> str:
    """Hash sensitive-ish values without exposing raw content."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_url(url: str) -> str:
    """
    Normalize URL for tracking/deduplication.

    This does not fetch the URL.
    """
    if not isinstance(url, str):
        raise ValueError("url must be a string")

    cleaned = url.strip()

    if not cleaned:
        raise ValueError("url cannot be empty")

    parsed = urlparse(cleaned)

    if not parsed.scheme:
        cleaned = f"https://{cleaned}"
        parsed = urlparse(cleaned)

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"

    if path != "/":
        path = path.rstrip("/")

    query = f"?{parsed.query}" if parsed.query else ""

    return f"{scheme}://{netloc}{path}{query}"


def extract_domain(url: str) -> str:
    """Extract normalized domain from URL."""
    parsed = urlparse(normalize_url(url))
    domain = parsed.netloc.lower()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def redact_cookie_name(cookie_name: str) -> Tuple[str, str, bool]:
    """
    Return safe cookie name metadata:
    - name_hash
    - name_hint
    - is_sensitive_name

    The full cookie name is not exposed in result payloads.
    """
    raw = str(cookie_name or "").strip()
    lower = raw.lower()
    is_sensitive = any(keyword in lower for keyword in SENSITIVE_COOKIE_KEYWORDS)

    if not raw:
        hint = "empty"
    elif len(raw) <= 3:
        hint = f"{raw[:1]}***"
    else:
        hint = f"{raw[:2]}***{raw[-1:]}"

    return safe_hash(raw), hint, is_sensitive


def safe_copy(data: Any) -> Any:
    """Deep-copy JSON-like data safely."""
    try:
        return copy.deepcopy(data)
    except Exception:
        return data


# ---------------------------------------------------------------------------
# BrowserSession
# ---------------------------------------------------------------------------

class BrowserSession:
    """
    Browser session state manager for William/Jarvis Browser Agent.

    Responsibilities:
    - Keep isolated tab state per user_id/workspace_id
    - Track visited URLs safely
    - Store cookie/session metadata without secrets
    - Track browser task state
    - Prepare payloads for Security, Verification, Memory, Audit, Dashboard/API
    - Stay import-safe before all future William files exist

    This class does not perform real browser actions.
    It only records and manages state.
    """

    module_name = "browser_agent"
    component_name = "browser_session"
    schema_version = SESSION_SCHEMA_VERSION

    def __init__(
        self,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        permissions: Optional[Dict[str, bool]] = None,
        max_tabs: int = DEFAULT_MAX_TABS,
        max_visited_urls: int = DEFAULT_MAX_VISITED_URLS,
        max_events: int = DEFAULT_MAX_EVENTS,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        security_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize a browser session.

        Args:
            user_id: SaaS user identifier.
            workspace_id: SaaS workspace identifier.
            task_id: Optional current task identifier.
            session_id: Optional session identifier.
            permissions: Optional permission map.
            max_tabs: Maximum tabs tracked in memory.
            max_visited_urls: Maximum URL visits retained in memory.
            max_events: Maximum session events retained in memory.
            event_callback: Optional event emitter for dashboard/API.
            audit_callback: Optional audit sink.
            security_callback: Optional Security Agent approval bridge.
            metadata: Optional safe metadata.
        """
        self.user_id = str(user_id or "").strip()
        self.workspace_id = str(workspace_id or "").strip()
        self.task_id = str(task_id).strip() if task_id else None
        self.session_id = session_id or generate_id("browser_session")

        self.permissions = dict(SAFE_DEFAULT_PERMISSIONS)
        if permissions:
            self.permissions.update({str(k): bool(v) for k, v in permissions.items()})

        self.max_tabs = max(1, int(max_tabs))
        self.max_visited_urls = max(1, int(max_visited_urls))
        self.max_events = max(1, int(max_events))

        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.security_callback = security_callback

        self.metadata: Dict[str, Any] = metadata.copy() if isinstance(metadata, dict) else {}

        self.tabs: Dict[str, BrowserTab] = {}
        self.active_tab_id: Optional[str] = None
        self.visited_urls: List[BrowserUrlVisit] = []
        self.cookie_metadata: Dict[str, BrowserCookieMetadata] = {}
        self.task_state: Optional[BrowserTaskState] = None
        self.events: List[BrowserSessionEvent] = []

        validation = self._validate_task_context()
        if not validation["success"]:
            raise ValueError(validation["error"])

        if self.task_id:
            self.task_state = BrowserTaskState(
                task_id=self.task_id,
                user_id=self.user_id,
                workspace_id=self.workspace_id,
                status=BrowserTaskStatus.CREATED.value,
            )

        self.created_at = utc_now_iso()
        self.updated_at = self.created_at

        self._emit_agent_event(
            BrowserEventType.SESSION_CREATED.value,
            "Browser session created.",
            data={
                "session_id": self.session_id,
                "task_id": self.task_id,
                "schema_version": self.schema_version,
            },
        )

    # -----------------------------------------------------------------------
    # Core public methods: tab state
    # -----------------------------------------------------------------------

    def create_tab(
        self,
        url: Optional[str] = None,
        title: Optional[str] = None,
        opener_tab_id: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        make_active: bool = True,
    ) -> Dict[str, Any]:
        """
        Create a tracked tab state.

        This does not open a real browser tab.
        """
        try:
            validation = self._validate_task_context(task_id=task_id)
            if not validation["success"]:
                return validation

            permission = self._check_permission("can_track_tabs")
            if not permission["success"]:
                return permission

            if len(self.tabs) >= self.max_tabs:
                return self._error_result(
                    "Maximum tracked tabs limit reached.",
                    error_code="MAX_TABS_REACHED",
                    metadata={"max_tabs": self.max_tabs},
                )

            tab_id = generate_id("tab")
            normalized = normalize_url(url) if url else None
            domain = extract_domain(normalized) if normalized else None

            tab = BrowserTab(
                tab_id=tab_id,
                user_id=self.user_id,
                workspace_id=self.workspace_id,
                task_id=task_id or self.task_id,
                status=BrowserTabStatus.ACTIVE.value if make_active else BrowserTabStatus.CREATED.value,
                current_url=normalized,
                current_domain=domain,
                title=title.strip() if isinstance(title, str) else None,
                opener_tab_id=opener_tab_id,
                metadata=metadata.copy() if isinstance(metadata, dict) else {},
            )

            self.tabs[tab_id] = tab

            if make_active:
                self._mark_tab_active(tab_id)

            if normalized:
                self.record_url_visit(
                    url=normalized,
                    tab_id=tab_id,
                    title=title,
                    task_id=task_id or self.task_id,
                    metadata={"source": "create_tab"},
                )

            self.updated_at = utc_now_iso()

            self._emit_agent_event(
                BrowserEventType.TAB_CREATED.value,
                "Browser tab state created.",
                task_id=task_id or self.task_id,
                data={"tab": self._tab_to_safe_dict(tab)},
            )

            self._log_audit_event(
                action="create_tab",
                status="success",
                details={"tab_id": tab_id, "domain": domain},
                task_id=task_id or self.task_id,
            )

            return self._safe_result(
                "Tab created successfully.",
                data={"tab": self._tab_to_safe_dict(tab), "active_tab_id": self.active_tab_id},
            )

        except Exception as exc:
            return self._handle_exception("Failed to create tab.", exc)

    def update_tab(
        self,
        tab_id: str,
        url: Optional[str] = None,
        title: Optional[str] = None,
        status: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Update tracked tab metadata.

        This does not control a real browser tab.
        """
        try:
            validation = self._validate_task_context(task_id=task_id)
            if not validation["success"]:
                return validation

            tab = self.tabs.get(tab_id)
            if not tab:
                return self._error_result(
                    "Tab not found.",
                    error_code="TAB_NOT_FOUND",
                    metadata={"tab_id": tab_id},
                )

            ownership = self._validate_record_scope(tab.user_id, tab.workspace_id)
            if not ownership["success"]:
                return ownership

            if url is not None:
                normalized = normalize_url(url)
                tab.current_url = normalized
                tab.current_domain = extract_domain(normalized)
                tab.visit_count += 1

                self.record_url_visit(
                    url=normalized,
                    tab_id=tab_id,
                    title=title or tab.title,
                    task_id=task_id or tab.task_id or self.task_id,
                    metadata={"source": "update_tab"},
                )

            if title is not None:
                tab.title = title.strip()

            if status is not None:
                tab.status = self._validate_tab_status(status)

            if isinstance(metadata, dict):
                tab.metadata.update(safe_copy(metadata))

            tab.updated_at = utc_now_iso()
            self.updated_at = tab.updated_at

            self._emit_agent_event(
                BrowserEventType.TAB_UPDATED.value,
                "Browser tab state updated.",
                task_id=task_id or tab.task_id or self.task_id,
                data={"tab": self._tab_to_safe_dict(tab)},
            )

            self._log_audit_event(
                action="update_tab",
                status="success",
                details={"tab_id": tab_id, "domain": tab.current_domain},
                task_id=task_id or tab.task_id or self.task_id,
            )

            return self._safe_result(
                "Tab updated successfully.",
                data={"tab": self._tab_to_safe_dict(tab)},
            )

        except Exception as exc:
            return self._handle_exception("Failed to update tab.", exc)

    def switch_tab(self, tab_id: str, task_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Mark a tracked tab as active.

        This does not switch a real browser tab.
        """
        try:
            validation = self._validate_task_context(task_id=task_id)
            if not validation["success"]:
                return validation

            if tab_id not in self.tabs:
                return self._error_result(
                    "Tab not found.",
                    error_code="TAB_NOT_FOUND",
                    metadata={"tab_id": tab_id},
                )

            tab = self.tabs[tab_id]
            ownership = self._validate_record_scope(tab.user_id, tab.workspace_id)
            if not ownership["success"]:
                return ownership

            if tab.status == BrowserTabStatus.CLOSED.value:
                return self._error_result(
                    "Cannot switch to a closed tab.",
                    error_code="TAB_CLOSED",
                    metadata={"tab_id": tab_id},
                )

            self._mark_tab_active(tab_id)
            self.updated_at = utc_now_iso()

            if self.task_state:
                self.task_state.active_tab_id = tab_id
                self.task_state.updated_at = self.updated_at

            self._emit_agent_event(
                BrowserEventType.TAB_SWITCHED.value,
                "Active browser tab updated.",
                task_id=task_id or tab.task_id or self.task_id,
                data={"active_tab_id": tab_id},
            )

            return self._safe_result(
                "Active tab switched successfully.",
                data={"active_tab_id": self.active_tab_id, "tab": self._tab_to_safe_dict(tab)},
            )

        except Exception as exc:
            return self._handle_exception("Failed to switch tab.", exc)

    def close_tab(self, tab_id: str, task_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Mark a tracked tab as closed.

        This does not close a real browser tab.
        """
        try:
            validation = self._validate_task_context(task_id=task_id)
            if not validation["success"]:
                return validation

            tab = self.tabs.get(tab_id)
            if not tab:
                return self._error_result(
                    "Tab not found.",
                    error_code="TAB_NOT_FOUND",
                    metadata={"tab_id": tab_id},
                )

            ownership = self._validate_record_scope(tab.user_id, tab.workspace_id)
            if not ownership["success"]:
                return ownership

            tab.status = BrowserTabStatus.CLOSED.value
            tab.closed_at = utc_now_iso()
            tab.updated_at = tab.closed_at

            if self.active_tab_id == tab_id:
                self.active_tab_id = self._find_next_open_tab_id()
                if self.active_tab_id:
                    self._mark_tab_active(self.active_tab_id)

            self.updated_at = utc_now_iso()

            self._emit_agent_event(
                BrowserEventType.TAB_CLOSED.value,
                "Browser tab state closed.",
                task_id=task_id or tab.task_id or self.task_id,
                data={"tab_id": tab_id, "new_active_tab_id": self.active_tab_id},
            )

            self._log_audit_event(
                action="close_tab",
                status="success",
                details={"tab_id": tab_id},
                task_id=task_id or tab.task_id or self.task_id,
            )

            return self._safe_result(
                "Tab closed successfully.",
                data={"tab": self._tab_to_safe_dict(tab), "active_tab_id": self.active_tab_id},
            )

        except Exception as exc:
            return self._handle_exception("Failed to close tab.", exc)

    def get_tab(self, tab_id: str) -> Dict[str, Any]:
        """Return one tab by ID."""
        tab = self.tabs.get(tab_id)
        if not tab:
            return self._error_result(
                "Tab not found.",
                error_code="TAB_NOT_FOUND",
                metadata={"tab_id": tab_id},
            )

        ownership = self._validate_record_scope(tab.user_id, tab.workspace_id)
        if not ownership["success"]:
            return ownership

        return self._safe_result(
            "Tab returned successfully.",
            data={"tab": self._tab_to_safe_dict(tab)},
        )

    def list_tabs(
        self,
        include_closed: bool = True,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List tracked tabs for this session."""
        try:
            tabs = []

            for tab in self.tabs.values():
                if not include_closed and tab.status == BrowserTabStatus.CLOSED.value:
                    continue

                if status and tab.status != status:
                    continue

                tabs.append(self._tab_to_safe_dict(tab))

            tabs.sort(key=lambda item: item.get("created_at") or "")

            return self._safe_result(
                "Tabs returned successfully.",
                data={
                    "tabs": tabs,
                    "count": len(tabs),
                    "active_tab_id": self.active_tab_id,
                },
            )

        except Exception as exc:
            return self._handle_exception("Failed to list tabs.", exc)

    # -----------------------------------------------------------------------
    # Core public methods: URL visits
    # -----------------------------------------------------------------------

    def record_url_visit(
        self,
        url: str,
        tab_id: Optional[str] = None,
        title: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Record a URL visit.

        This is safe tracking only. It does not fetch the URL.
        """
        try:
            validation = self._validate_task_context(task_id=task_id)
            if not validation["success"]:
                return validation

            permission = self._check_permission("can_track_urls")
            if not permission["success"]:
                return permission

            normalized = normalize_url(url)
            domain = extract_domain(normalized)

            if tab_id is not None and tab_id not in self.tabs:
                return self._error_result(
                    "Cannot record visit for unknown tab.",
                    error_code="TAB_NOT_FOUND",
                    metadata={"tab_id": tab_id},
                )

            if tab_id is not None:
                tab = self.tabs[tab_id]
                ownership = self._validate_record_scope(tab.user_id, tab.workspace_id)
                if not ownership["success"]:
                    return ownership

            visit = BrowserUrlVisit(
                visit_id=generate_id("visit"),
                url=normalized,
                normalized_url=normalized,
                domain=domain,
                tab_id=tab_id,
                title=title.strip() if isinstance(title, str) else None,
                user_id=self.user_id,
                workspace_id=self.workspace_id,
                task_id=task_id or self.task_id,
                timestamp=utc_now_iso(),
                metadata=metadata.copy() if isinstance(metadata, dict) else {},
            )

            self.visited_urls.append(visit)
            self._trim_visited_urls()

            if tab_id and tab_id in self.tabs:
                tab_obj = self.tabs[tab_id]
                tab_obj.current_url = normalized
                tab_obj.current_domain = domain
                if title:
                    tab_obj.title = title.strip()
                tab_obj.updated_at = utc_now_iso()

            self.updated_at = utc_now_iso()

            self._emit_agent_event(
                BrowserEventType.URL_VISITED.value,
                "URL visit recorded.",
                task_id=task_id or self.task_id,
                data={"visit": self._visit_to_safe_dict(visit)},
            )

            return self._safe_result(
                "URL visit recorded successfully.",
                data={"visit": self._visit_to_safe_dict(visit)},
            )

        except Exception as exc:
            return self._handle_exception("Failed to record URL visit.", exc)

    def list_visited_urls(
        self,
        domain: Optional[str] = None,
        tab_id: Optional[str] = None,
        limit: Optional[int] = None,
        newest_first: bool = True,
    ) -> Dict[str, Any]:
        """List safe visited URL records."""
        try:
            records = self.visited_urls

            if domain:
                wanted_domain = domain.lower().replace("www.", "").strip()
                records = [item for item in records if item.domain == wanted_domain]

            if tab_id:
                records = [item for item in records if item.tab_id == tab_id]

            sorted_records = sorted(
                records,
                key=lambda item: item.timestamp,
                reverse=newest_first,
            )

            if limit is not None:
                safe_limit = max(0, int(limit))
                sorted_records = sorted_records[:safe_limit]

            return self._safe_result(
                "Visited URLs returned successfully.",
                data={
                    "visited_urls": [self._visit_to_safe_dict(item) for item in sorted_records],
                    "count": len(sorted_records),
                },
            )

        except Exception as exc:
            return self._handle_exception("Failed to list visited URLs.", exc)

    def get_recent_domains(self, limit: int = 25) -> Dict[str, Any]:
        """Return recently visited unique domains."""
        try:
            safe_limit = max(1, int(limit))
            seen = set()
            domains = []

            for visit in reversed(self.visited_urls):
                if visit.domain not in seen:
                    seen.add(visit.domain)
                    domains.append(
                        {
                            "domain": visit.domain,
                            "last_url": visit.normalized_url,
                            "last_seen_at": visit.timestamp,
                            "tab_id": visit.tab_id,
                        }
                    )

                if len(domains) >= safe_limit:
                    break

            return self._safe_result(
                "Recent domains returned successfully.",
                data={"domains": domains, "count": len(domains)},
            )

        except Exception as exc:
            return self._handle_exception("Failed to get recent domains.", exc)

    # -----------------------------------------------------------------------
    # Core public methods: cookie/session metadata
    # -----------------------------------------------------------------------

    def update_cookie_metadata(
        self,
        domain: str,
        cookie_name: str,
        secure: Optional[bool] = None,
        http_only: Optional[bool] = None,
        same_site: Optional[str] = None,
        expires_at: Optional[str] = None,
        path: Optional[str] = None,
        source_tab_id: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Store safe cookie metadata.

        Never pass or store raw cookie values here.
        """
        try:
            validation = self._validate_task_context(task_id=task_id)
            if not validation["success"]:
                return validation

            permission = self._check_permission("can_track_cookie_metadata")
            if not permission["success"]:
                return permission

            clean_domain = str(domain or "").strip().lower().replace("www.", "")
            if not clean_domain:
                return self._error_result(
                    "Cookie domain is required.",
                    error_code="INVALID_COOKIE_DOMAIN",
                )

            if source_tab_id and source_tab_id not in self.tabs:
                return self._error_result(
                    "Source tab not found.",
                    error_code="TAB_NOT_FOUND",
                    metadata={"source_tab_id": source_tab_id},
                )

            name_hash, name_hint, is_sensitive_name = redact_cookie_name(cookie_name)
            cookie_key = f"{clean_domain}:{name_hash}"

            risk_level = (
                SecurityRiskLevel.MEDIUM.value
                if is_sensitive_name
                else SecurityRiskLevel.LOW.value
            )

            cookie_record = self.cookie_metadata.get(cookie_key)

            if cookie_record:
                cookie_record.secure = secure
                cookie_record.http_only = http_only
                cookie_record.same_site = same_site
                cookie_record.expires_at = expires_at
                cookie_record.path = path
                cookie_record.source_tab_id = source_tab_id
                cookie_record.task_id = task_id or self.task_id
                cookie_record.updated_at = utc_now_iso()
                if isinstance(metadata, dict):
                    cookie_record.metadata.update(safe_copy(metadata))
            else:
                cookie_record = BrowserCookieMetadata(
                    cookie_id=generate_id("cookie_meta"),
                    user_id=self.user_id,
                    workspace_id=self.workspace_id,
                    domain=clean_domain,
                    name_hash=name_hash,
                    name_hint=name_hint,
                    secure=secure,
                    http_only=http_only,
                    same_site=same_site,
                    expires_at=expires_at,
                    path=path,
                    is_sensitive_name=is_sensitive_name,
                    source_tab_id=source_tab_id,
                    task_id=task_id or self.task_id,
                    metadata=metadata.copy() if isinstance(metadata, dict) else {},
                )
                self.cookie_metadata[cookie_key] = cookie_record

            self.updated_at = utc_now_iso()

            self._emit_agent_event(
                BrowserEventType.COOKIE_METADATA_UPDATED.value,
                "Cookie metadata updated without storing cookie value.",
                task_id=task_id or self.task_id,
                data={"cookie_metadata": self._cookie_to_safe_dict(cookie_record)},
                risk_level=risk_level,
            )

            self._log_audit_event(
                action="update_cookie_metadata",
                status="success",
                details={
                    "domain": clean_domain,
                    "cookie_id": cookie_record.cookie_id,
                    "is_sensitive_name": is_sensitive_name,
                },
                task_id=task_id or self.task_id,
                risk_level=risk_level,
            )

            return self._safe_result(
                "Cookie metadata updated successfully.",
                data={"cookie_metadata": self._cookie_to_safe_dict(cookie_record)},
                metadata={"risk_level": risk_level},
            )

        except Exception as exc:
            return self._handle_exception("Failed to update cookie metadata.", exc)

    def list_cookie_metadata(
        self,
        domain: Optional[str] = None,
        include_sensitive_named: bool = True,
    ) -> Dict[str, Any]:
        """List safe cookie metadata records."""
        try:
            records = list(self.cookie_metadata.values())

            if domain:
                wanted_domain = domain.lower().replace("www.", "").strip()
                records = [item for item in records if item.domain == wanted_domain]

            if not include_sensitive_named:
                records = [item for item in records if not item.is_sensitive_name]

            records.sort(key=lambda item: item.updated_at, reverse=True)

            return self._safe_result(
                "Cookie metadata returned successfully.",
                data={
                    "cookie_metadata": [self._cookie_to_safe_dict(item) for item in records],
                    "count": len(records),
                },
            )

        except Exception as exc:
            return self._handle_exception("Failed to list cookie metadata.", exc)

    # -----------------------------------------------------------------------
    # Core public methods: task state
    # -----------------------------------------------------------------------

    def create_or_update_task_state(
        self,
        task_id: Optional[str] = None,
        status: Optional[str] = None,
        objective: Optional[str] = None,
        progress_percent: Optional[float] = None,
        active_tab_id: Optional[str] = None,
        last_error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create or update current browser task state.

        This state can be read by Master Agent, dashboard, audit layer,
        Verification Agent, and Workflow Agent.
        """
        try:
            actual_task_id = task_id or self.task_id or generate_id("browser_task")

            validation = self._validate_task_context(task_id=actual_task_id)
            if not validation["success"]:
                return validation

            if status:
                clean_status = self._validate_task_status(status)
            else:
                clean_status = (
                    self.task_state.status
                    if self.task_state
                    else BrowserTaskStatus.CREATED.value
                )

            if active_tab_id and active_tab_id not in self.tabs:
                return self._error_result(
                    "Active tab not found for task state.",
                    error_code="TAB_NOT_FOUND",
                    metadata={"active_tab_id": active_tab_id},
                )

            now = utc_now_iso()

            if not self.task_state or self.task_state.task_id != actual_task_id:
                self.task_id = actual_task_id
                self.task_state = BrowserTaskState(
                    task_id=actual_task_id,
                    user_id=self.user_id,
                    workspace_id=self.workspace_id,
                    status=clean_status,
                    objective=objective,
                    active_tab_id=active_tab_id or self.active_tab_id,
                    started_at=now if clean_status == BrowserTaskStatus.RUNNING.value else None,
                    progress_percent=self._safe_progress(progress_percent),
                    last_error=last_error,
                    metadata=metadata.copy() if isinstance(metadata, dict) else {},
                )
            else:
                self.task_state.status = clean_status

                if objective is not None:
                    self.task_state.objective = objective

                if progress_percent is not None:
                    self.task_state.progress_percent = self._safe_progress(progress_percent)

                if active_tab_id is not None:
                    self.task_state.active_tab_id = active_tab_id

                if last_error is not None:
                    self.task_state.last_error = last_error

                if isinstance(metadata, dict):
                    self.task_state.metadata.update(safe_copy(metadata))

                if clean_status == BrowserTaskStatus.RUNNING.value and not self.task_state.started_at:
                    self.task_state.started_at = now

                if clean_status == BrowserTaskStatus.COMPLETED.value:
                    self.task_state.completed_at = now
                    self.task_state.progress_percent = 100.0

                if clean_status == BrowserTaskStatus.FAILED.value:
                    self.task_state.failed_at = now

                self.task_state.updated_at = now

            self.updated_at = now

            self._emit_agent_event(
                BrowserEventType.TASK_STATE_UPDATED.value,
                "Browser task state updated.",
                task_id=actual_task_id,
                data={"task_state": self._task_to_safe_dict(self.task_state)},
            )

            self._log_audit_event(
                action="create_or_update_task_state",
                status="success",
                details={
                    "task_id": actual_task_id,
                    "task_status": clean_status,
                    "progress_percent": self.task_state.progress_percent,
                },
                task_id=actual_task_id,
            )

            return self._safe_result(
                "Task state updated successfully.",
                data={"task_state": self._task_to_safe_dict(self.task_state)},
            )

        except Exception as exc:
            return self._handle_exception("Failed to update task state.", exc)

    def get_task_state(self) -> Dict[str, Any]:
        """Return current task state."""
        if not self.task_state:
            return self._safe_result(
                "No active task state exists.",
                data={"task_state": None},
            )

        return self._safe_result(
            "Task state returned successfully.",
            data={"task_state": self._task_to_safe_dict(self.task_state)},
        )

    # -----------------------------------------------------------------------
    # Session snapshot / restore / clear
    # -----------------------------------------------------------------------

    def snapshot(self, include_events: bool = True) -> Dict[str, Any]:
        """
        Export a full safe session snapshot.

        This is useful for dashboard state sync, persistence, task history,
        audit inspection, and future session resume.
        """
        try:
            data = {
                "schema_version": self.schema_version,
                "session_id": self.session_id,
                "module_name": self.module_name,
                "component_name": self.component_name,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "task_id": self.task_id,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
                "active_tab_id": self.active_tab_id,
                "permissions": self.permissions.copy(),
                "metadata": safe_copy(self.metadata),
                "tabs": [self._tab_to_safe_dict(tab) for tab in self.tabs.values()],
                "visited_urls": [self._visit_to_safe_dict(visit) for visit in self.visited_urls],
                "cookie_metadata": [
                    self._cookie_to_safe_dict(cookie)
                    for cookie in self.cookie_metadata.values()
                ],
                "task_state": (
                    self._task_to_safe_dict(self.task_state)
                    if self.task_state
                    else None
                ),
            }

            if include_events:
                data["events"] = [self._event_to_safe_dict(event) for event in self.events]

            return self._safe_result(
                "Browser session snapshot prepared successfully.",
                data=data,
            )

        except Exception as exc:
            return self._handle_exception("Failed to prepare session snapshot.", exc)

    @classmethod
    def restore_from_snapshot(
        cls,
        snapshot_data: Dict[str, Any],
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        security_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> "BrowserSession":
        """
        Restore BrowserSession from a safe snapshot dictionary.

        Raises:
            ValueError if snapshot is invalid.
        """
        if not isinstance(snapshot_data, dict):
            raise ValueError("snapshot_data must be a dictionary")

        user_id = str(snapshot_data.get("user_id") or "").strip()
        workspace_id = str(snapshot_data.get("workspace_id") or "").strip()

        if not user_id or not workspace_id:
            raise ValueError("snapshot_data requires user_id and workspace_id")

        session = cls(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=snapshot_data.get("task_id"),
            session_id=snapshot_data.get("session_id"),
            permissions=snapshot_data.get("permissions"),
            event_callback=event_callback,
            audit_callback=audit_callback,
            security_callback=security_callback,
            metadata=snapshot_data.get("metadata") or {},
        )

        session.created_at = snapshot_data.get("created_at") or utc_now_iso()
        session.updated_at = snapshot_data.get("updated_at") or utc_now_iso()
        session.active_tab_id = snapshot_data.get("active_tab_id")

        session.tabs = {}
        for raw_tab in snapshot_data.get("tabs", []) or []:
            tab = BrowserTab(
                tab_id=raw_tab["tab_id"],
                user_id=raw_tab["user_id"],
                workspace_id=raw_tab["workspace_id"],
                task_id=raw_tab.get("task_id"),
                status=raw_tab.get("status", BrowserTabStatus.CREATED.value),
                current_url=raw_tab.get("current_url"),
                current_domain=raw_tab.get("current_domain"),
                title=raw_tab.get("title"),
                opener_tab_id=raw_tab.get("opener_tab_id"),
                created_at=raw_tab.get("created_at") or utc_now_iso(),
                updated_at=raw_tab.get("updated_at") or utc_now_iso(),
                closed_at=raw_tab.get("closed_at"),
                visit_count=int(raw_tab.get("visit_count") or 0),
                metadata=raw_tab.get("metadata") or {},
            )
            session.tabs[tab.tab_id] = tab

        session.visited_urls = []
        for raw_visit in snapshot_data.get("visited_urls", []) or []:
            session.visited_urls.append(
                BrowserUrlVisit(
                    visit_id=raw_visit["visit_id"],
                    url=raw_visit["url"],
                    normalized_url=raw_visit["normalized_url"],
                    domain=raw_visit["domain"],
                    tab_id=raw_visit.get("tab_id"),
                    title=raw_visit.get("title"),
                    user_id=raw_visit["user_id"],
                    workspace_id=raw_visit["workspace_id"],
                    task_id=raw_visit.get("task_id"),
                    timestamp=raw_visit.get("timestamp") or utc_now_iso(),
                    metadata=raw_visit.get("metadata") or {},
                )
            )

        session.cookie_metadata = {}
        for raw_cookie in snapshot_data.get("cookie_metadata", []) or []:
            cookie = BrowserCookieMetadata(
                cookie_id=raw_cookie["cookie_id"],
                user_id=raw_cookie["user_id"],
                workspace_id=raw_cookie["workspace_id"],
                domain=raw_cookie["domain"],
                name_hash=raw_cookie["name_hash"],
                name_hint=raw_cookie.get("name_hint", "***"),
                secure=raw_cookie.get("secure"),
                http_only=raw_cookie.get("http_only"),
                same_site=raw_cookie.get("same_site"),
                expires_at=raw_cookie.get("expires_at"),
                path=raw_cookie.get("path"),
                is_sensitive_name=bool(raw_cookie.get("is_sensitive_name")),
                source_tab_id=raw_cookie.get("source_tab_id"),
                task_id=raw_cookie.get("task_id"),
                created_at=raw_cookie.get("created_at") or utc_now_iso(),
                updated_at=raw_cookie.get("updated_at") or utc_now_iso(),
                metadata=raw_cookie.get("metadata") or {},
            )
            session.cookie_metadata[f"{cookie.domain}:{cookie.name_hash}"] = cookie

        raw_task = snapshot_data.get("task_state")
        if isinstance(raw_task, dict):
            session.task_state = BrowserTaskState(
                task_id=raw_task["task_id"],
                user_id=raw_task["user_id"],
                workspace_id=raw_task["workspace_id"],
                status=raw_task.get("status", BrowserTaskStatus.CREATED.value),
                objective=raw_task.get("objective"),
                active_tab_id=raw_task.get("active_tab_id"),
                started_at=raw_task.get("started_at"),
                updated_at=raw_task.get("updated_at") or utc_now_iso(),
                completed_at=raw_task.get("completed_at"),
                failed_at=raw_task.get("failed_at"),
                progress_percent=float(raw_task.get("progress_percent") or 0.0),
                last_error=raw_task.get("last_error"),
                metadata=raw_task.get("metadata") or {},
            )

        session.events = []
        for raw_event in snapshot_data.get("events", []) or []:
            session.events.append(
                BrowserSessionEvent(
                    event_id=raw_event.get("event_id") or generate_id("event"),
                    event_type=raw_event.get("event_type") or BrowserEventType.AUDIT_EVENT.value,
                    user_id=raw_event.get("user_id") or user_id,
                    workspace_id=raw_event.get("workspace_id") or workspace_id,
                    task_id=raw_event.get("task_id"),
                    timestamp=raw_event.get("timestamp") or utc_now_iso(),
                    message=raw_event.get("message") or "",
                    data=raw_event.get("data") or {},
                    risk_level=raw_event.get("risk_level") or SecurityRiskLevel.LOW.value,
                )
            )

        session._emit_agent_event(
            BrowserEventType.SESSION_RESTORED.value,
            "Browser session restored from snapshot.",
            data={"session_id": session.session_id},
        )

        return session

    def clear_session(
        self,
        reason: str = "manual_clear",
        task_id: Optional[str] = None,
        require_security: bool = True,
    ) -> Dict[str, Any]:
        """
        Clear tracked browser session state.

        Because this may remove audit-relevant session data, it can require
        Security Agent approval depending on permissions.
        """
        try:
            validation = self._validate_task_context(task_id=task_id)
            if not validation["success"]:
                return validation

            if require_security or self._requires_security_check("clear_session"):
                approval = self._request_security_approval(
                    action="clear_session",
                    risk_level=SecurityRiskLevel.MEDIUM.value,
                    reason=reason,
                    task_id=task_id or self.task_id,
                    payload={
                        "session_id": self.session_id,
                        "tabs_count": len(self.tabs),
                        "visited_urls_count": len(self.visited_urls),
                        "cookie_metadata_count": len(self.cookie_metadata),
                    },
                )
                if not approval["success"]:
                    return approval

            self.tabs.clear()
            self.active_tab_id = None
            self.visited_urls.clear()
            self.cookie_metadata.clear()

            if self.task_state:
                self.task_state.status = BrowserTaskStatus.CANCELLED.value
                self.task_state.updated_at = utc_now_iso()
                self.task_state.metadata["clear_reason"] = reason

            self.updated_at = utc_now_iso()

            self._emit_agent_event(
                BrowserEventType.SESSION_CLEARED.value,
                "Browser session state cleared.",
                task_id=task_id or self.task_id,
                data={"reason": reason},
                risk_level=SecurityRiskLevel.MEDIUM.value,
            )

            self._log_audit_event(
                action="clear_session",
                status="success",
                details={"reason": reason},
                task_id=task_id or self.task_id,
                risk_level=SecurityRiskLevel.MEDIUM.value,
            )

            return self._safe_result(
                "Browser session cleared successfully.",
                data={"session_id": self.session_id, "reason": reason},
            )

        except Exception as exc:
            return self._handle_exception("Failed to clear browser session.", exc)

    # -----------------------------------------------------------------------
    # Compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Required by William/Jarvis global rules.
        """
        actual_user_id = str(user_id or self.user_id or "").strip()
        actual_workspace_id = str(workspace_id or self.workspace_id or "").strip()

        if not actual_user_id:
            return self._error_result(
                "user_id is required for BrowserSession.",
                error_code="MISSING_USER_ID",
            )

        if not actual_workspace_id:
            return self._error_result(
                "workspace_id is required for BrowserSession.",
                error_code="MISSING_WORKSPACE_ID",
            )

        if actual_user_id != self.user_id:
            return self._error_result(
                "Cross-user BrowserSession access denied.",
                error_code="CROSS_USER_ACCESS_DENIED",
                metadata={"requested_user_id": actual_user_id},
            )

        if actual_workspace_id != self.workspace_id:
            return self._error_result(
                "Cross-workspace BrowserSession access denied.",
                error_code="CROSS_WORKSPACE_ACCESS_DENIED",
                metadata={"requested_workspace_id": actual_workspace_id},
            )

        if task_id is not None and not str(task_id).strip():
            return self._error_result(
                "task_id cannot be blank when provided.",
                error_code="INVALID_TASK_ID",
            )

        return self._safe_result(
            "Task context validated.",
            data={
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "task_id": task_id or self.task_id,
            },
        )

    def _requires_security_check(self, action: str) -> bool:
        """
        Decide whether an action needs Security Agent approval.

        BrowserSession itself is safe state tracking, but destructive state
        changes or sensitive cookie metadata operations should be protected.
        """
        protected_actions = {
            "clear_session",
            "export_cookie_metadata",
            "restore_session",
            "delete_session",
        }

        if action in protected_actions:
            return True

        if action == "update_cookie_metadata":
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        risk_level: str = SecurityRiskLevel.MEDIUM.value,
        reason: Optional[str] = None,
        task_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If no security_callback is attached, this method allows only actions
        explicitly permitted by local permissions.
        """
        request_payload = {
            "action": action,
            "risk_level": risk_level,
            "reason": reason,
            "module_name": self.module_name,
            "component_name": self.component_name,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "task_id": task_id or self.task_id,
            "payload": payload or {},
            "timestamp": utc_now_iso(),
        }

        self._emit_agent_event(
            BrowserEventType.SECURITY_APPROVAL_REQUESTED.value,
            "Security approval requested.",
            task_id=task_id or self.task_id,
            data=request_payload,
            risk_level=risk_level,
        )

        if self.security_callback:
            try:
                approval = self.security_callback(request_payload)
                if isinstance(approval, dict) and approval.get("success") is True:
                    return self._safe_result(
                        "Security approval granted.",
                        data={"approval": approval},
                    )

                return self._error_result(
                    "Security approval denied.",
                    error_code="SECURITY_APPROVAL_DENIED",
                    metadata={"approval": approval},
                )
            except Exception as exc:
                return self._handle_exception("Security approval callback failed.", exc)

        permission_key = f"can_{action}"
        if self.permissions.get(permission_key) is True:
            return self._safe_result(
                "Security approval granted by local permission.",
                data={"permission_key": permission_key},
            )

        return self._error_result(
            "Security approval required but no Security Agent callback approved this action.",
            error_code="SECURITY_APPROVAL_REQUIRED",
            metadata={
                "action": action,
                "permission_key": permission_key,
                "risk_level": risk_level,
            },
        )

    def _prepare_verification_payload(
        self,
        action: str,
        result: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can use this to confirm Browser Agent state changes.
        """
        payload = {
            "verification_type": "browser_session_state",
            "action": action,
            "module_name": self.module_name,
            "component_name": self.component_name,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "task_id": task_id or self.task_id,
            "active_tab_id": self.active_tab_id,
            "tabs_count": len(self.tabs),
            "visited_urls_count": len(self.visited_urls),
            "cookie_metadata_count": len(self.cookie_metadata),
            "task_state": (
                self._task_to_safe_dict(self.task_state)
                if self.task_state
                else None
            ),
            "result": safe_copy(result) if result else None,
            "timestamp": utc_now_iso(),
        }

        self._emit_agent_event(
            BrowserEventType.VERIFICATION_PAYLOAD_PREPARED.value,
            "Verification payload prepared.",
            task_id=task_id or self.task_id,
            data={"action": action},
        )

        return payload

    def _prepare_memory_payload(
        self,
        memory_type: str = "browser_session_summary",
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Prepare safe Memory Agent payload.

        This never includes raw cookies or secrets.
        """
        recent_urls = [
            self._visit_to_safe_dict(visit)
            for visit in self.visited_urls[-20:]
        ]

        payload = {
            "memory_type": memory_type,
            "module_name": self.module_name,
            "component_name": self.component_name,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "task_id": task_id or self.task_id,
            "summary": {
                "active_tab_id": self.active_tab_id,
                "tabs_count": len(self.tabs),
                "visited_urls_count": len(self.visited_urls),
                "cookie_metadata_count": len(self.cookie_metadata),
                "recent_urls": recent_urls,
                "recent_domains": self.get_recent_domains(limit=10).get("data", {}).get("domains", []),
                "task_state": (
                    self._task_to_safe_dict(self.task_state)
                    if self.task_state
                    else None
                ),
            },
            "timestamp": utc_now_iso(),
        }

        self._emit_agent_event(
            BrowserEventType.MEMORY_PAYLOAD_PREPARED.value,
            "Memory payload prepared.",
            task_id=task_id or self.task_id,
            data={"memory_type": memory_type},
        )

        return payload

    def _emit_agent_event(
        self,
        event_type: str,
        message: str,
        task_id: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        risk_level: str = SecurityRiskLevel.LOW.value,
    ) -> Dict[str, Any]:
        """
        Emit an internal Browser Agent event.

        Dashboard/API, Master Agent, and Registry can attach an event_callback
        to consume these events.
        """
        event = BrowserSessionEvent(
            event_id=generate_id("event"),
            event_type=event_type,
            user_id=self.user_id,
            workspace_id=self.workspace_id,
            task_id=task_id or self.task_id,
            timestamp=utc_now_iso(),
            message=message,
            data=data.copy() if isinstance(data, dict) else {},
            risk_level=risk_level,
        )

        self.events.append(event)
        self._trim_events()

        payload = self._event_to_safe_dict(event)

        if self.event_callback:
            try:
                self.event_callback(payload)
            except Exception:
                logger.exception("BrowserSession event_callback failed.")

        return self._safe_result(
            "Agent event emitted.",
            data={"event": payload},
        )

    def _log_audit_event(
        self,
        action: str,
        status: str,
        details: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
        risk_level: str = SecurityRiskLevel.LOW.value,
    ) -> Dict[str, Any]:
        """
        Write a safe audit event.

        If no audit_callback exists, event is retained in BrowserSession.events.
        """
        audit_payload = {
            "audit_id": generate_id("audit"),
            "module_name": self.module_name,
            "component_name": self.component_name,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "task_id": task_id or self.task_id,
            "action": action,
            "status": status,
            "risk_level": risk_level,
            "details": safe_copy(details) if details else {},
            "timestamp": utc_now_iso(),
        }

        self._emit_agent_event(
            BrowserEventType.AUDIT_EVENT.value,
            f"Audit event recorded for action: {action}",
            task_id=task_id or self.task_id,
            data=audit_payload,
            risk_level=risk_level,
        )

        if self.audit_callback:
            try:
                self.audit_callback(audit_payload)
            except Exception:
                logger.exception("BrowserSession audit_callback failed.")

        return self._safe_result(
            "Audit event logged.",
            data={"audit": audit_payload},
        )

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis success result."""
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "module_name": self.module_name,
                "component_name": self.component_name,
                "session_id": getattr(self, "session_id", None),
                "schema_version": self.schema_version,
                "timestamp": utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error_code: str = "BROWSER_SESSION_ERROR",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis error result."""
        return {
            "success": False,
            "message": message,
            "data": {},
            "error": {
                "code": error_code,
                "message": message,
            },
            "metadata": {
                "module_name": self.module_name,
                "component_name": self.component_name,
                "session_id": getattr(self, "session_id", None),
                "schema_version": self.schema_version,
                "timestamp": utc_now_iso(),
                **(metadata or {}),
            },
        }

    # -----------------------------------------------------------------------
    # Dashboard/API helpers
    # -----------------------------------------------------------------------

    def prepare_dashboard_payload(self) -> Dict[str, Any]:
        """
        Prepare compact dashboard state payload.

        Useful for FastAPI/WebSocket dashboard sync later.
        """
        open_tabs = [
            tab for tab in self.tabs.values()
            if tab.status != BrowserTabStatus.CLOSED.value
        ]

        payload = {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "task_id": self.task_id,
            "active_tab_id": self.active_tab_id,
            "open_tabs_count": len(open_tabs),
            "closed_tabs_count": len(self.tabs) - len(open_tabs),
            "visited_urls_count": len(self.visited_urls),
            "cookie_metadata_count": len(self.cookie_metadata),
            "recent_domains": self.get_recent_domains(limit=10).get("data", {}).get("domains", []),
            "task_state": (
                self._task_to_safe_dict(self.task_state)
                if self.task_state
                else None
            ),
            "updated_at": self.updated_at,
        }

        return self._safe_result(
            "Dashboard payload prepared successfully.",
            data={"dashboard": payload},
        )

    def export_for_memory_agent(self) -> Dict[str, Any]:
        """Public wrapper for Memory Agent payload."""
        permission = self._check_permission("can_store_memory_payload")
        if not permission["success"]:
            return permission

        payload = self._prepare_memory_payload()
        return self._safe_result(
            "Memory Agent payload prepared successfully.",
            data={"memory_payload": payload},
        )

    def export_for_verification_agent(
        self,
        action: str = "browser_session_snapshot",
        result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Public wrapper for Verification Agent payload."""
        permission = self._check_permission("can_prepare_verification_payload")
        if not permission["success"]:
            return permission

        payload = self._prepare_verification_payload(action=action, result=result)
        return self._safe_result(
            "Verification Agent payload prepared successfully.",
            data={"verification_payload": payload},
        )

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _check_permission(self, permission_key: str) -> Dict[str, Any]:
        """Check local session permission."""
        if self.permissions.get(permission_key) is True:
            return self._safe_result(
                "Permission granted.",
                data={"permission": permission_key},
            )

        return self._error_result(
            f"Permission denied: {permission_key}",
            error_code="PERMISSION_DENIED",
            metadata={"permission": permission_key},
        )

    def _validate_record_scope(self, user_id: str, workspace_id: str) -> Dict[str, Any]:
        """Validate a stored record belongs to this user/workspace."""
        if user_id != self.user_id:
            return self._error_result(
                "Stored record user scope mismatch.",
                error_code="RECORD_USER_SCOPE_MISMATCH",
            )

        if workspace_id != self.workspace_id:
            return self._error_result(
                "Stored record workspace scope mismatch.",
                error_code="RECORD_WORKSPACE_SCOPE_MISMATCH",
            )

        return self._safe_result("Record scope validated.")

    def _mark_tab_active(self, tab_id: str) -> None:
        """Set active tab and mark other open tabs inactive."""
        for current_tab_id, tab in self.tabs.items():
            if tab.status == BrowserTabStatus.CLOSED.value:
                continue

            if current_tab_id == tab_id:
                tab.status = BrowserTabStatus.ACTIVE.value
                tab.updated_at = utc_now_iso()
            elif tab.status == BrowserTabStatus.ACTIVE.value:
                tab.status = BrowserTabStatus.INACTIVE.value
                tab.updated_at = utc_now_iso()

        self.active_tab_id = tab_id

    def _find_next_open_tab_id(self) -> Optional[str]:
        """Find the newest open tab after active tab closes."""
        open_tabs = [
            tab
            for tab in self.tabs.values()
            if tab.status != BrowserTabStatus.CLOSED.value
        ]

        if not open_tabs:
            return None

        open_tabs.sort(key=lambda item: item.updated_at, reverse=True)
        return open_tabs[0].tab_id

    def _validate_tab_status(self, status: str) -> str:
        """Validate tab status enum."""
        clean = str(status).strip().lower()
        allowed = {item.value for item in BrowserTabStatus}

        if clean not in allowed:
            raise ValueError(f"Invalid tab status: {status}")

        return clean

    def _validate_task_status(self, status: str) -> str:
        """Validate task status enum."""
        clean = str(status).strip().lower()
        allowed = {item.value for item in BrowserTaskStatus}

        if clean not in allowed:
            raise ValueError(f"Invalid task status: {status}")

        return clean

    def _safe_progress(self, progress_percent: Optional[float]) -> float:
        """Clamp progress to 0..100."""
        if progress_percent is None:
            return 0.0

        try:
            value = float(progress_percent)
        except Exception:
            value = 0.0

        return max(0.0, min(100.0, value))

    def _trim_visited_urls(self) -> None:
        """Trim old URL visits."""
        if len(self.visited_urls) > self.max_visited_urls:
            self.visited_urls = self.visited_urls[-self.max_visited_urls:]

    def _trim_events(self) -> None:
        """Trim old events."""
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events:]

    def _handle_exception(self, message: str, exc: Exception) -> Dict[str, Any]:
        """Handle exceptions consistently."""
        logger.exception(message)

        try:
            self._emit_agent_event(
                BrowserEventType.ERROR.value,
                message,
                data={"exception_type": type(exc).__name__, "error": str(exc)},
                risk_level=SecurityRiskLevel.MEDIUM.value,
            )
        except Exception:
            pass

        return self._error_result(
            message,
            error_code=type(exc).__name__,
            metadata={"exception": str(exc)},
        )

    def _tab_to_safe_dict(self, tab: BrowserTab) -> Dict[str, Any]:
        """Convert tab to safe dictionary."""
        return asdict(tab)

    def _visit_to_safe_dict(self, visit: BrowserUrlVisit) -> Dict[str, Any]:
        """Convert visit to safe dictionary."""
        return asdict(visit)

    def _cookie_to_safe_dict(self, cookie: BrowserCookieMetadata) -> Dict[str, Any]:
        """
        Convert cookie metadata to safe dictionary.

        No raw cookie names or values are included.
        """
        return asdict(cookie)

    def _task_to_safe_dict(self, task: BrowserTaskState) -> Dict[str, Any]:
        """Convert task state to safe dictionary."""
        return asdict(task)

    def _event_to_safe_dict(self, event: BrowserSessionEvent) -> Dict[str, Any]:
        """Convert event to safe dictionary."""
        return asdict(event)


# ---------------------------------------------------------------------------
# Optional self-test helper
# ---------------------------------------------------------------------------

def _self_test() -> Dict[str, Any]:
    """
    Lightweight import-safe self-test.

    Run manually:
        python agents/browser_agent/browser_session.py
    """
    session = BrowserSession(
        user_id="test_user",
        workspace_id="test_workspace",
        task_id="test_task",
        permissions={"can_clear_session": True},
    )

    created = session.create_tab(
        url="example.com",
        title="Example",
        metadata={"source": "self_test"},
    )

    if not created["success"]:
        return created

    tab_id = created["data"]["tab"]["tab_id"]

    session.update_tab(
        tab_id=tab_id,
        url="https://example.com/about",
        title="About Example",
    )

    session.update_cookie_metadata(
        domain="example.com",
        cookie_name="session_token",
        secure=True,
        http_only=True,
        same_site="Lax",
        source_tab_id=tab_id,
    )

    session.create_or_update_task_state(
        status=BrowserTaskStatus.RUNNING.value,
        objective="Self-test browser session tracking",
        progress_percent=50,
        active_tab_id=tab_id,
    )

    session.create_or_update_task_state(
        status=BrowserTaskStatus.COMPLETED.value,
        progress_percent=100,
    )

    return session.snapshot()


if __name__ == "__main__":
    import json

    print(json.dumps(_self_test(), indent=2))