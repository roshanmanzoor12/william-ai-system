"""
agents/browser_agent/tab_manager.py

Tab Manager for William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Purpose:
    Open, close, switch, label, and organize browser tabs safely.

This file is designed to be:
    - Production-level
    - Import-safe
    - SaaS-aware with user_id and workspace_id isolation
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router,
      Master Agent routing, Security Agent, Memory Agent, Verification Agent,
      Dashboard/API, BrowserSession, and future Playwright/Selenium integrations.

Important:
    This file does not directly launch a destructive browser action.
    This file safely manages tab state records and optionally delegates real browser
    tab operations to an injected browser_session object when available.
    Every sensitive action can be routed through Security Agent.
    Every result returns structured dict/JSON style responses.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import logging
import re
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


# ======================================================================================
# Optional William/Jarvis internal imports with safe fallbacks
# ======================================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover

    class BaseAgent:
        """
        Safe fallback BaseAgent.

        This keeps TabManager import-safe when the full William/Jarvis project
        is not generated yet.
        """

        agent_name: str = "base_agent"
        agent_type: str = "base"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.logger = logging.getLogger(self.__class__.__name__)

        async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent does not implement run().",
                "data": {},
                "error": None,
                "metadata": {},
            }

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            logging.getLogger(self.__class__.__name__).debug(
                "Fallback emit_event: %s | %s",
                event_name,
                payload,
            )


try:
    from core.context import AgentContext  # type: ignore
except Exception:  # pragma: no cover

    @dataclass
    class AgentContext:
        """
        Safe fallback AgentContext.

        The real system can replace this with core.context.AgentContext later.
        """

        user_id: Optional[Union[str, int]] = None
        workspace_id: Optional[Union[str, int]] = None
        role: Optional[str] = None
        permissions: List[str] = field(default_factory=list)
        metadata: Dict[str, Any] = field(default_factory=dict)


# ======================================================================================
# Logging
# ======================================================================================

LOGGER = logging.getLogger("william.browser_agent.tab_manager")
if not LOGGER.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ======================================================================================
# Helper functions
# ======================================================================================

def utc_now_iso() -> str:
    """Return current UTC datetime in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def stable_hash(value: str) -> str:
    """Return stable SHA256 hash for fingerprints/cache keys."""
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def compact_whitespace(value: str) -> str:
    """Normalize whitespace."""
    return re.sub(r"\s+", " ", value or "").strip()


def normalize_url(url: str) -> str:
    """
    Normalize URL.

    Adds https:// if scheme is missing.
    """
    url = compact_whitespace(url)
    if not url:
        return ""
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
    return url


def is_valid_url(url: str) -> bool:
    """Check if URL is valid HTTP/HTTPS."""
    if not url or not isinstance(url, str):
        return False
    parsed = urllib.parse.urlparse(normalize_url(url))
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def domain_from_url(url: str) -> str:
    """Extract lowercase domain from URL."""
    try:
        parsed = urllib.parse.urlparse(normalize_url(url))
        return parsed.netloc.lower().replace("www.", "")
    except Exception:
        return ""


def safe_string(value: Any, max_length: int = 500) -> str:
    """Convert value to safe compact string."""
    text = compact_whitespace(str(value or ""))
    if len(text) > max_length:
        return text[: max_length - 15] + "...[truncated]"
    return text


# ======================================================================================
# Enums and data structures
# ======================================================================================

class TabAction(str, Enum):
    """
    Supported TabManager actions.

    MasterAgent / AgentRouter can route these actions through run()/execute().
    """

    HEALTH_CHECK = "health_check"
    OPEN_TAB = "open_tab"
    CLOSE_TAB = "close_tab"
    CLOSE_TABS = "close_tabs"
    SWITCH_TAB = "switch_tab"
    LABEL_TAB = "label_tab"
    RENAME_TAB = "rename_tab"
    PIN_TAB = "pin_tab"
    UNPIN_TAB = "unpin_tab"
    FAVORITE_TAB = "favorite_tab"
    UNFAVORITE_TAB = "unfavorite_tab"
    GROUP_TAB = "group_tab"
    UNGROUP_TAB = "ungroup_tab"
    MOVE_TAB = "move_tab"
    LIST_TABS = "list_tabs"
    GET_ACTIVE_TAB = "get_active_tab"
    GET_TAB = "get_tab"
    FIND_TABS = "find_tabs"
    ORGANIZE_TABS = "organize_tabs"
    CLOSE_INACTIVE_TABS = "close_inactive_tabs"
    RESTORE_TAB = "restore_tab"
    CLEAR_CLOSED_TABS = "clear_closed_tabs"
    EXPORT_STATE = "export_state"
    IMPORT_STATE = "import_state"


class TabStatus(str, Enum):
    """Tab lifecycle status."""

    OPEN = "open"
    ACTIVE = "active"
    CLOSED = "closed"
    SUSPENDED = "suspended"
    ERROR = "error"


class TabRiskLevel(str, Enum):
    """Risk levels for Security Agent approval."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TabSortMode(str, Enum):
    """Supported tab organization sort modes."""

    CREATED_ASC = "created_asc"
    CREATED_DESC = "created_desc"
    LAST_ACTIVE_ASC = "last_active_asc"
    LAST_ACTIVE_DESC = "last_active_desc"
    DOMAIN_ASC = "domain_asc"
    TITLE_ASC = "title_asc"
    GROUP_ASC = "group_asc"
    PINNED_FIRST = "pinned_first"


@dataclass
class TabManagerConfig:
    """
    Runtime configuration for TabManager.
    """

    manager_name: str = "tab_manager"
    manager_display_name: str = "Tab Manager"
    version: str = "1.0.0"

    max_tabs_per_workspace: int = 50
    max_closed_tabs_history: int = 100
    max_label_length: int = 80
    max_group_length: int = 80
    max_title_length: int = 180
    max_notes_length: int = 1000

    allow_http: bool = True
    allow_https: bool = True
    allow_localhost: bool = False
    allow_private_ips: bool = False

    blocked_domains: List[str] = field(default_factory=list)
    allowed_domains: List[str] = field(default_factory=list)

    require_security_for_open: bool = True
    require_security_for_close: bool = True
    require_security_for_switch: bool = False
    require_security_for_organize: bool = False
    require_security_for_import: bool = True

    audit_enabled: bool = True
    memory_enabled: bool = True
    verification_enabled: bool = True

    delegate_to_browser_session: bool = True
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TabTaskContext:
    """
    SaaS execution context for user/workspace isolation.
    """

    user_id: Union[str, int]
    workspace_id: Union[str, int]
    task_id: Optional[str] = None
    role: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    request_id: Optional[str] = None
    source: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def scope_key(self) -> str:
        """Return unique memory scope key for this user/workspace."""
        return f"{self.user_id}::{self.workspace_id}"

    def to_metadata(self) -> Dict[str, Any]:
        """Return serializable context metadata."""
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "task_id": self.task_id,
            "role": self.role,
            "request_id": self.request_id,
            "source": self.source,
            "metadata": self.metadata,
        }


@dataclass
class BrowserTab:
    """
    Browser tab record.

    This is a safe tab state object. A real browser integration may also store
    an external_page_id/session_page_id in metadata.
    """

    tab_id: str
    user_id: Union[str, int]
    workspace_id: Union[str, int]
    url: str
    title: str = ""
    label: str = ""
    group: str = ""
    status: str = TabStatus.OPEN.value
    is_active: bool = False
    is_pinned: bool = False
    is_favorite: bool = False
    position: int = 0
    domain: str = ""
    notes: str = ""
    opener_task_id: Optional[str] = None
    external_page_id: Optional[str] = None
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    last_active_at: Optional[str] = None
    closed_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def mark_updated(self) -> None:
        """Update modified timestamp."""
        self.updated_at = utc_now_iso()

    def to_dict(self) -> Dict[str, Any]:
        """Return serializable tab payload."""
        return dataclasses.asdict(self)


# ======================================================================================
# TabManager
# ======================================================================================

class TabManager(BaseAgent):
    """
    TabManager safely manages Browser Agent tab state.

    Responsibilities:
        - Open tab records safely
        - Close tab records safely
        - Switch active tab safely
        - Label and rename tabs
        - Pin/favorite tabs
        - Group and organize tabs
        - Find tabs
        - Export/import tab state
        - Optionally delegate real browser operations to browser_session

    Connections:
        - MasterAgent:
            Routes tab actions here through execute()/run().
        - BrowserAgent:
            Can call this manager to track pages during browsing workflows.
        - BrowserSession:
            Can be injected for real browser operations later.
        - SecurityAgent:
            Sensitive tab actions can call _request_security_approval().
        - MemoryAgent:
            Useful tab context is returned by _prepare_memory_payload().
        - VerificationAgent:
            Completed actions include _prepare_verification_payload().
        - Dashboard/API:
            Structured dict outputs are ready for FastAPI/dashboard display.
        - Registry/Loader/Router:
            Class name TabManager and public methods stay stable.
    """

    agent_name = "tab_manager"
    agent_type = "browser_helper"
    public_name = "Tab Manager"

    def __init__(
        self,
        config: Optional[TabManagerConfig] = None,
        browser_session: Optional[Any] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.config = config or TabManagerConfig()
        self.browser_session = browser_session
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.logger = logging.getLogger("william.browser_agent.TabManager")

        self._tabs_by_scope: Dict[str, Dict[str, BrowserTab]] = {}
        self._closed_tabs_by_scope: Dict[str, List[BrowserTab]] = {}
        self._active_tab_by_scope: Dict[str, Optional[str]] = {}

        self._action_map: Dict[str, Callable[..., Any]] = {
            TabAction.HEALTH_CHECK.value: self.health_check,
            TabAction.OPEN_TAB.value: self.open_tab,
            TabAction.CLOSE_TAB.value: self.close_tab,
            TabAction.CLOSE_TABS.value: self.close_tabs,
            TabAction.SWITCH_TAB.value: self.switch_tab,
            TabAction.LABEL_TAB.value: self.label_tab,
            TabAction.RENAME_TAB.value: self.rename_tab,
            TabAction.PIN_TAB.value: self.pin_tab,
            TabAction.UNPIN_TAB.value: self.unpin_tab,
            TabAction.FAVORITE_TAB.value: self.favorite_tab,
            TabAction.UNFAVORITE_TAB.value: self.unfavorite_tab,
            TabAction.GROUP_TAB.value: self.group_tab,
            TabAction.UNGROUP_TAB.value: self.ungroup_tab,
            TabAction.MOVE_TAB.value: self.move_tab,
            TabAction.LIST_TABS.value: self.list_tabs,
            TabAction.GET_ACTIVE_TAB.value: self.get_active_tab,
            TabAction.GET_TAB.value: self.get_tab,
            TabAction.FIND_TABS.value: self.find_tabs,
            TabAction.ORGANIZE_TABS.value: self.organize_tabs,
            TabAction.CLOSE_INACTIVE_TABS.value: self.close_inactive_tabs,
            TabAction.RESTORE_TAB.value: self.restore_tab,
            TabAction.CLEAR_CLOSED_TABS.value: self.clear_closed_tabs,
            TabAction.EXPORT_STATE.value: self.export_state,
            TabAction.IMPORT_STATE.value: self.import_state,
        }

    # ==================================================================================
    # BaseAgent / Router entrypoints
    # ==================================================================================

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible async entrypoint.

        MasterAgent, AgentRouter, or WorkflowAgent may call this method.
        """
        return await self.execute(task)

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a TabManager task.

        Expected task shape:
            {
                "action": "open_tab",
                "user_id": "1",
                "workspace_id": "main",
                "payload": {
                    "url": "https://example.com",
                    "label": "Research"
                },
                "task_id": "optional",
                "request_id": "optional"
            }
        """
        started_at = time.time()

        if not isinstance(task, dict):
            return self._error_result(
                message="Task must be a dictionary.",
                error="INVALID_TASK_TYPE",
                metadata={"received_type": type(task).__name__},
            )

        action = str(task.get("action") or "").strip()
        payload = task.get("payload") or {}

        if not isinstance(payload, dict):
            return self._error_result(
                message="Task payload must be a dictionary.",
                error="INVALID_PAYLOAD_TYPE",
                metadata={"action": action},
            )

        context_result = self._validate_task_context(task)
        if not context_result["success"]:
            return context_result

        context: TabTaskContext = context_result["data"]["context"]

        if not action:
            return self._error_result(
                message="Missing tab action.",
                error="MISSING_ACTION",
                metadata=context.to_metadata(),
            )

        handler = self._action_map.get(action)
        if not handler:
            return self._error_result(
                message=f"Unsupported tab action: {action}",
                error="UNSUPPORTED_ACTION",
                data={"supported_actions": sorted(self._action_map.keys())},
                metadata=context.to_metadata(),
            )

        try:
            self._emit_agent_event(
                "tab_task_started",
                {
                    "action": action,
                    "context": context.to_metadata(),
                    "payload_keys": sorted(payload.keys()),
                },
            )

            result = handler(context=context, **payload)

            if asyncio.iscoroutine(result):
                result = await result

            elapsed_ms = int((time.time() - started_at) * 1000)

            if isinstance(result, dict):
                result.setdefault("metadata", {})
                result["metadata"].update(
                    {
                        "action": action,
                        "elapsed_ms": elapsed_ms,
                        "agent": self.agent_name,
                        "agent_version": self.config.version,
                        "context": context.to_metadata(),
                    }
                )

                if self.config.verification_enabled and result.get("success"):
                    result["verification_payload"] = self._prepare_verification_payload(
                        action=action,
                        context=context,
                        result=result,
                    )

                if self.config.memory_enabled and result.get("success"):
                    result["memory_payload"] = self._prepare_memory_payload(
                        action=action,
                        context=context,
                        result=result,
                    )

                self._log_audit_event(
                    context=context,
                    action=action,
                    status="success" if result.get("success") else "failed",
                    details={
                        "message": result.get("message"),
                        "error": result.get("error"),
                        "elapsed_ms": elapsed_ms,
                    },
                )

                self._emit_agent_event(
                    "tab_task_completed",
                    {
                        "action": action,
                        "success": result.get("success"),
                        "elapsed_ms": elapsed_ms,
                        "context": context.to_metadata(),
                    },
                )

                return result

            return self._safe_result(
                message="Tab action completed.",
                data={"result": result},
                metadata={
                    "action": action,
                    "elapsed_ms": elapsed_ms,
                    "context": context.to_metadata(),
                },
            )

        except Exception as exc:
            elapsed_ms = int((time.time() - started_at) * 1000)
            self.logger.exception("TabManager execution failed.")

            self._log_audit_event(
                context=context,
                action=action,
                status="error",
                details={
                    "error": str(exc),
                    "elapsed_ms": elapsed_ms,
                },
            )

            return self._error_result(
                message="Tab action failed.",
                error=str(exc),
                metadata={
                    "action": action,
                    "elapsed_ms": elapsed_ms,
                    "context": context.to_metadata(),
                },
            )

    # ==================================================================================
    # Public methods
    # ==================================================================================

    def health_check(self, context: TabTaskContext, **kwargs: Any) -> Dict[str, Any]:
        """Return TabManager health/status information."""
        tabs = self._get_tabs(context)
        closed = self._get_closed_tabs(context)

        return self._safe_result(
            message="TabManager is healthy.",
            data={
                "manager": self.agent_name,
                "type": self.agent_type,
                "version": self.config.version,
                "open_tabs": len(tabs),
                "closed_tabs_history": len(closed),
                "active_tab_id": self._active_tab_by_scope.get(context.scope_key()),
                "browser_session_connected": self.browser_session is not None,
                "supported_actions": sorted(self._action_map.keys()),
            },
            metadata=context.to_metadata(),
        )

    def open_tab(
        self,
        context: TabTaskContext,
        url: str,
        title: Optional[str] = None,
        label: Optional[str] = None,
        group: Optional[str] = None,
        make_active: bool = True,
        pinned: bool = False,
        favorite: bool = False,
        notes: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Open a new tab safely.

        This creates an in-memory tab record and optionally delegates to browser_session.
        """
        normalized_url = normalize_url(url)

        if not self._is_url_allowed(normalized_url):
            return self._error_result(
                message="URL is not allowed by TabManager policy.",
                error="URL_NOT_ALLOWED",
                data={"url": normalized_url},
                metadata=context.to_metadata(),
            )

        tabs = self._get_tabs(context)
        if len(tabs) >= self.config.max_tabs_per_workspace:
            return self._error_result(
                message="Maximum tab limit reached for this workspace.",
                error="MAX_TABS_REACHED",
                data={
                    "max_tabs_per_workspace": self.config.max_tabs_per_workspace,
                    "current_tabs": len(tabs),
                },
                metadata=context.to_metadata(),
            )

        approval = self._maybe_request_security(
            context=context,
            action=TabAction.OPEN_TAB.value,
            risk_level=TabRiskLevel.MEDIUM,
            target=normalized_url,
            details={
                "title": title,
                "label": label,
                "group": group,
                "make_active": make_active,
                "pinned": pinned,
                "favorite": favorite,
            },
        )
        if not approval["success"]:
            return approval

        external_page_id = None
        session_result: Optional[Dict[str, Any]] = None

        if self.config.delegate_to_browser_session and self.browser_session is not None:
            session_result = self._delegate_browser_session(
                method_names=["open_tab", "new_tab", "open_page"],
                payload={
                    "url": normalized_url,
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "make_active": make_active,
                },
            )
            if session_result.get("success"):
                external_page_id = (
                    session_result.get("data", {}).get("page_id")
                    or session_result.get("data", {}).get("tab_id")
                    or session_result.get("data", {}).get("external_page_id")
                )

        tab_id = self._generate_tab_id(context=context, url=normalized_url)
        now = utc_now_iso()

        tab = BrowserTab(
            tab_id=tab_id,
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            url=normalized_url,
            title=safe_string(title or domain_from_url(normalized_url), self.config.max_title_length),
            label=safe_string(label or "", self.config.max_label_length),
            group=safe_string(group or "", self.config.max_group_length),
            status=TabStatus.ACTIVE.value if make_active else TabStatus.OPEN.value,
            is_active=bool(make_active),
            is_pinned=bool(pinned),
            is_favorite=bool(favorite),
            position=self._next_position(context),
            domain=domain_from_url(normalized_url),
            notes=safe_string(notes or "", self.config.max_notes_length),
            opener_task_id=context.task_id,
            external_page_id=external_page_id,
            created_at=now,
            updated_at=now,
            last_active_at=now if make_active else None,
            metadata=metadata or {},
        )

        tabs[tab.tab_id] = tab

        if make_active:
            self._set_active_tab(context, tab.tab_id)

        self._reindex_positions(context)

        return self._safe_result(
            message="Tab opened successfully.",
            data={
                "tab": tab.to_dict(),
                "session_result": session_result,
            },
            metadata=context.to_metadata(),
        )

    def close_tab(
        self,
        context: TabTaskContext,
        tab_id: str,
        reason: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Close one tab safely."""
        tabs = self._get_tabs(context)
        tab = tabs.get(tab_id)

        if not tab:
            return self._error_result(
                message="Tab not found.",
                error="TAB_NOT_FOUND",
                data={"tab_id": tab_id},
                metadata=context.to_metadata(),
            )

        approval = self._maybe_request_security(
            context=context,
            action=TabAction.CLOSE_TAB.value,
            risk_level=TabRiskLevel.MEDIUM,
            target=tab.url,
            details={"tab_id": tab_id, "reason": reason},
        )
        if not approval["success"]:
            return approval

        session_result: Optional[Dict[str, Any]] = None
        if self.config.delegate_to_browser_session and self.browser_session is not None:
            session_result = self._delegate_browser_session(
                method_names=["close_tab", "close_page"],
                payload={
                    "tab_id": tab_id,
                    "external_page_id": tab.external_page_id,
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                },
            )

        removed = tabs.pop(tab_id)
        removed.status = TabStatus.CLOSED.value
        removed.is_active = False
        removed.closed_at = utc_now_iso()
        removed.mark_updated()
        removed.metadata["close_reason"] = reason or "manual"

        self._push_closed_tab(context, removed)

        active_tab_id = self._active_tab_by_scope.get(context.scope_key())
        if active_tab_id == tab_id:
            next_tab_id = self._choose_next_active_tab(context)
            if next_tab_id:
                self._set_active_tab(context, next_tab_id)
            else:
                self._active_tab_by_scope[context.scope_key()] = None

        self._reindex_positions(context)

        return self._safe_result(
            message="Tab closed successfully.",
            data={
                "closed_tab": removed.to_dict(),
                "active_tab_id": self._active_tab_by_scope.get(context.scope_key()),
                "session_result": session_result,
            },
            metadata=context.to_metadata(),
        )

    def close_tabs(
        self,
        context: TabTaskContext,
        tab_ids: List[str],
        reason: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Close multiple tabs safely."""
        if not isinstance(tab_ids, list) or not tab_ids:
            return self._error_result(
                message="tab_ids list is required.",
                error="MISSING_TAB_IDS",
                metadata=context.to_metadata(),
            )

        closed: List[Dict[str, Any]] = []
        failed: List[Dict[str, Any]] = []

        for tab_id in tab_ids:
            result = self.close_tab(context=context, tab_id=str(tab_id), reason=reason)
            if result.get("success"):
                closed.append(result.get("data", {}).get("closed_tab", {}))
            else:
                failed.append(
                    {
                        "tab_id": tab_id,
                        "message": result.get("message"),
                        "error": result.get("error"),
                    }
                )

        return self._safe_result(
            message="Close tabs operation completed.",
            data={
                "closed_count": len(closed),
                "failed_count": len(failed),
                "closed": closed,
                "failed": failed,
                "active_tab_id": self._active_tab_by_scope.get(context.scope_key()),
            },
            metadata=context.to_metadata(),
        )

    def switch_tab(
        self,
        context: TabTaskContext,
        tab_id: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Switch active tab safely."""
        tabs = self._get_tabs(context)
        tab = tabs.get(tab_id)

        if not tab:
            return self._error_result(
                message="Tab not found.",
                error="TAB_NOT_FOUND",
                data={"tab_id": tab_id},
                metadata=context.to_metadata(),
            )

        approval = self._maybe_request_security(
            context=context,
            action=TabAction.SWITCH_TAB.value,
            risk_level=TabRiskLevel.LOW,
            target=tab.url,
            details={"tab_id": tab_id},
        )
        if not approval["success"]:
            return approval

        session_result: Optional[Dict[str, Any]] = None
        if self.config.delegate_to_browser_session and self.browser_session is not None:
            session_result = self._delegate_browser_session(
                method_names=["switch_tab", "activate_tab", "focus_page"],
                payload={
                    "tab_id": tab_id,
                    "external_page_id": tab.external_page_id,
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                },
            )

        self._set_active_tab(context, tab_id)

        return self._safe_result(
            message="Tab switched successfully.",
            data={
                "active_tab": tabs[tab_id].to_dict(),
                "session_result": session_result,
            },
            metadata=context.to_metadata(),
        )

    def label_tab(
        self,
        context: TabTaskContext,
        tab_id: str,
        label: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Set tab label."""
        tab_result = self._get_existing_tab_result(context, tab_id)
        if not tab_result["success"]:
            return tab_result

        tab: BrowserTab = tab_result["data"]["tab"]
        tab.label = safe_string(label, self.config.max_label_length)
        tab.mark_updated()

        return self._safe_result(
            message="Tab label updated successfully.",
            data={"tab": tab.to_dict()},
            metadata=context.to_metadata(),
        )

    def rename_tab(
        self,
        context: TabTaskContext,
        tab_id: str,
        title: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Rename tab title."""
        tab_result = self._get_existing_tab_result(context, tab_id)
        if not tab_result["success"]:
            return tab_result

        tab: BrowserTab = tab_result["data"]["tab"]
        tab.title = safe_string(title, self.config.max_title_length)
        tab.mark_updated()

        return self._safe_result(
            message="Tab renamed successfully.",
            data={"tab": tab.to_dict()},
            metadata=context.to_metadata(),
        )

    def pin_tab(
        self,
        context: TabTaskContext,
        tab_id: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Pin tab."""
        return self._set_tab_boolean(
            context=context,
            tab_id=tab_id,
            field_name="is_pinned",
            value=True,
            message="Tab pinned successfully.",
        )

    def unpin_tab(
        self,
        context: TabTaskContext,
        tab_id: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Unpin tab."""
        return self._set_tab_boolean(
            context=context,
            tab_id=tab_id,
            field_name="is_pinned",
            value=False,
            message="Tab unpinned successfully.",
        )

    def favorite_tab(
        self,
        context: TabTaskContext,
        tab_id: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Mark tab as favorite."""
        return self._set_tab_boolean(
            context=context,
            tab_id=tab_id,
            field_name="is_favorite",
            value=True,
            message="Tab marked as favorite successfully.",
        )

    def unfavorite_tab(
        self,
        context: TabTaskContext,
        tab_id: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Remove favorite mark from tab."""
        return self._set_tab_boolean(
            context=context,
            tab_id=tab_id,
            field_name="is_favorite",
            value=False,
            message="Tab removed from favorites successfully.",
        )

    def group_tab(
        self,
        context: TabTaskContext,
        tab_id: str,
        group: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Assign tab to group."""
        tab_result = self._get_existing_tab_result(context, tab_id)
        if not tab_result["success"]:
            return tab_result

        tab: BrowserTab = tab_result["data"]["tab"]
        tab.group = safe_string(group, self.config.max_group_length)
        tab.mark_updated()

        return self._safe_result(
            message="Tab grouped successfully.",
            data={"tab": tab.to_dict()},
            metadata=context.to_metadata(),
        )

    def ungroup_tab(
        self,
        context: TabTaskContext,
        tab_id: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Remove tab from group."""
        tab_result = self._get_existing_tab_result(context, tab_id)
        if not tab_result["success"]:
            return tab_result

        tab: BrowserTab = tab_result["data"]["tab"]
        tab.group = ""
        tab.mark_updated()

        return self._safe_result(
            message="Tab ungrouped successfully.",
            data={"tab": tab.to_dict()},
            metadata=context.to_metadata(),
        )

    def move_tab(
        self,
        context: TabTaskContext,
        tab_id: str,
        position: int,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Move tab to a new position."""
        tabs = self._get_tabs(context)
        tab = tabs.get(tab_id)

        if not tab:
            return self._error_result(
                message="Tab not found.",
                error="TAB_NOT_FOUND",
                data={"tab_id": tab_id},
                metadata=context.to_metadata(),
            )

        try:
            new_position = int(position)
        except Exception:
            return self._error_result(
                message="Position must be an integer.",
                error="INVALID_POSITION",
                data={"position": position},
                metadata=context.to_metadata(),
            )

        ordered = self._ordered_tabs(context)
        ordered = [item for item in ordered if item.tab_id != tab_id]

        new_position = max(0, min(new_position, len(ordered)))
        ordered.insert(new_position, tab)

        for index, item in enumerate(ordered):
            item.position = index
            item.mark_updated()

        return self._safe_result(
            message="Tab moved successfully.",
            data={
                "tab": tab.to_dict(),
                "tabs": [item.to_dict() for item in ordered],
            },
            metadata=context.to_metadata(),
        )

    def list_tabs(
        self,
        context: TabTaskContext,
        group: Optional[str] = None,
        domain: Optional[str] = None,
        pinned: Optional[bool] = None,
        favorite: Optional[bool] = None,
        active_only: bool = False,
        include_closed: bool = False,
        sort_by: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """List tabs in this user/workspace scope."""
        tabs = self._ordered_tabs(context)

        if group is not None:
            group_value = safe_string(group, self.config.max_group_length).lower()
            tabs = [tab for tab in tabs if tab.group.lower() == group_value]

        if domain is not None:
            domain_value = domain_from_url(domain) if is_valid_url(domain) else str(domain).lower()
            tabs = [tab for tab in tabs if tab.domain.lower() == domain_value]

        if pinned is not None:
            tabs = [tab for tab in tabs if tab.is_pinned == bool(pinned)]

        if favorite is not None:
            tabs = [tab for tab in tabs if tab.is_favorite == bool(favorite)]

        if active_only:
            tabs = [tab for tab in tabs if tab.is_active]

        if sort_by:
            tabs = self._sort_tabs(tabs, sort_by)

        data: Dict[str, Any] = {
            "count": len(tabs),
            "active_tab_id": self._active_tab_by_scope.get(context.scope_key()),
            "tabs": [tab.to_dict() for tab in tabs],
        }

        if include_closed:
            closed = self._get_closed_tabs(context)
            data["closed_count"] = len(closed)
            data["closed_tabs"] = [tab.to_dict() for tab in closed]

        return self._safe_result(
            message="Tabs listed successfully.",
            data=data,
            metadata=context.to_metadata(),
        )

    def get_active_tab(
        self,
        context: TabTaskContext,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Return the active tab for this user/workspace."""
        active_tab_id = self._active_tab_by_scope.get(context.scope_key())
        if not active_tab_id:
            return self._safe_result(
                message="No active tab found.",
                data={"active_tab": None, "active_tab_id": None},
                metadata=context.to_metadata(),
            )

        tab = self._get_tabs(context).get(active_tab_id)
        if not tab:
            self._active_tab_by_scope[context.scope_key()] = None
            return self._safe_result(
                message="No active tab found.",
                data={"active_tab": None, "active_tab_id": None},
                metadata=context.to_metadata(),
            )

        return self._safe_result(
            message="Active tab returned successfully.",
            data={"active_tab": tab.to_dict(), "active_tab_id": active_tab_id},
            metadata=context.to_metadata(),
        )

    def get_tab(
        self,
        context: TabTaskContext,
        tab_id: str,
        include_closed: bool = False,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Return one tab by ID."""
        tab = self._get_tabs(context).get(tab_id)

        if not tab and include_closed:
            for closed_tab in self._get_closed_tabs(context):
                if closed_tab.tab_id == tab_id:
                    tab = closed_tab
                    break

        if not tab:
            return self._error_result(
                message="Tab not found.",
                error="TAB_NOT_FOUND",
                data={"tab_id": tab_id},
                metadata=context.to_metadata(),
            )

        return self._safe_result(
            message="Tab returned successfully.",
            data={"tab": tab.to_dict()},
            metadata=context.to_metadata(),
        )

    def find_tabs(
        self,
        context: TabTaskContext,
        query: str,
        search_url: bool = True,
        search_title: bool = True,
        search_label: bool = True,
        search_group: bool = True,
        search_notes: bool = True,
        include_closed: bool = False,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Find tabs by query."""
        query_norm = compact_whitespace(query).lower()

        if not query_norm:
            return self._error_result(
                message="Search query is required.",
                error="MISSING_QUERY",
                metadata=context.to_metadata(),
            )

        candidates = self._ordered_tabs(context)
        if include_closed:
            candidates += self._get_closed_tabs(context)

        matched: List[BrowserTab] = []

        for tab in candidates:
            fields: List[str] = []

            if search_url:
                fields.append(tab.url)
                fields.append(tab.domain)
            if search_title:
                fields.append(tab.title)
            if search_label:
                fields.append(tab.label)
            if search_group:
                fields.append(tab.group)
            if search_notes:
                fields.append(tab.notes)

            haystack = " ".join(fields).lower()
            if query_norm in haystack:
                matched.append(tab)

        return self._safe_result(
            message="Tab search completed.",
            data={
                "query": query,
                "count": len(matched),
                "tabs": [tab.to_dict() for tab in matched],
            },
            metadata=context.to_metadata(),
        )

    def organize_tabs(
        self,
        context: TabTaskContext,
        sort_by: str = TabSortMode.PINNED_FIRST.value,
        group_by_domain: bool = False,
        auto_label_empty: bool = True,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Organize tabs safely."""
        approval = self._maybe_request_security(
            context=context,
            action=TabAction.ORGANIZE_TABS.value,
            risk_level=TabRiskLevel.LOW,
            target="workspace_tabs",
            details={
                "sort_by": sort_by,
                "group_by_domain": group_by_domain,
                "auto_label_empty": auto_label_empty,
            },
        )
        if not approval["success"]:
            return approval

        tabs = self._ordered_tabs(context)

        if group_by_domain:
            for tab in tabs:
                if not tab.group:
                    tab.group = tab.domain or "ungrouped"
                    tab.mark_updated()

        if auto_label_empty:
            for tab in tabs:
                if not tab.label:
                    tab.label = tab.title or tab.domain or "Untitled"
                    tab.label = safe_string(tab.label, self.config.max_label_length)
                    tab.mark_updated()

        sorted_tabs = self._sort_tabs(tabs, sort_by)

        for index, tab in enumerate(sorted_tabs):
            tab.position = index
            tab.mark_updated()

        return self._safe_result(
            message="Tabs organized successfully.",
            data={
                "sort_by": sort_by,
                "group_by_domain": group_by_domain,
                "auto_label_empty": auto_label_empty,
                "tabs": [tab.to_dict() for tab in sorted_tabs],
            },
            metadata=context.to_metadata(),
        )

    def close_inactive_tabs(
        self,
        context: TabTaskContext,
        keep_pinned: bool = True,
        keep_favorites: bool = True,
        keep_active: bool = True,
        group: Optional[str] = None,
        domain: Optional[str] = None,
        reason: str = "close_inactive_tabs",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Close inactive tabs with optional safety filters."""
        tabs = self._ordered_tabs(context)
        candidates: List[BrowserTab] = []

        for tab in tabs:
            if keep_active and tab.is_active:
                continue
            if keep_pinned and tab.is_pinned:
                continue
            if keep_favorites and tab.is_favorite:
                continue
            if group is not None and tab.group != group:
                continue
            if domain is not None and tab.domain != domain_from_url(domain):
                continue
            candidates.append(tab)

        if not candidates:
            return self._safe_result(
                message="No inactive tabs matched close criteria.",
                data={"closed_count": 0, "closed": []},
                metadata=context.to_metadata(),
            )

        return self.close_tabs(
            context=context,
            tab_ids=[tab.tab_id for tab in candidates],
            reason=reason,
        )

    def restore_tab(
        self,
        context: TabTaskContext,
        tab_id: Optional[str] = None,
        make_active: bool = True,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Restore a closed tab by ID or the most recent closed tab."""
        closed = self._get_closed_tabs(context)

        if not closed:
            return self._error_result(
                message="No closed tabs available to restore.",
                error="NO_CLOSED_TABS",
                metadata=context.to_metadata(),
            )

        restore_index = -1
        tab_to_restore: Optional[BrowserTab] = None

        if tab_id:
            for index, tab in enumerate(closed):
                if tab.tab_id == tab_id:
                    restore_index = index
                    tab_to_restore = tab
                    break
        else:
            restore_index = len(closed) - 1
            tab_to_restore = closed[-1]

        if not tab_to_restore:
            return self._error_result(
                message="Closed tab not found.",
                error="CLOSED_TAB_NOT_FOUND",
                data={"tab_id": tab_id},
                metadata=context.to_metadata(),
            )

        tabs = self._get_tabs(context)
        if len(tabs) >= self.config.max_tabs_per_workspace:
            return self._error_result(
                message="Maximum tab limit reached. Cannot restore tab.",
                error="MAX_TABS_REACHED",
                data={"max_tabs_per_workspace": self.config.max_tabs_per_workspace},
                metadata=context.to_metadata(),
            )

        restored = closed.pop(restore_index)
        restored.status = TabStatus.ACTIVE.value if make_active else TabStatus.OPEN.value
        restored.is_active = bool(make_active)
        restored.closed_at = None
        restored.updated_at = utc_now_iso()
        restored.last_active_at = utc_now_iso() if make_active else restored.last_active_at
        restored.position = self._next_position(context)
        restored.metadata["restored_at"] = utc_now_iso()

        tabs[restored.tab_id] = restored

        if make_active:
            self._set_active_tab(context, restored.tab_id)

        self._reindex_positions(context)

        return self._safe_result(
            message="Tab restored successfully.",
            data={"tab": restored.to_dict()},
            metadata=context.to_metadata(),
        )

    def clear_closed_tabs(
        self,
        context: TabTaskContext,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Clear closed tabs history for this user/workspace."""
        closed = self._get_closed_tabs(context)
        count = len(closed)
        self._closed_tabs_by_scope[context.scope_key()] = []

        return self._safe_result(
            message="Closed tabs history cleared successfully.",
            data={"cleared_count": count},
            metadata=context.to_metadata(),
        )

    def export_state(
        self,
        context: TabTaskContext,
        include_closed: bool = True,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Export tab state for this user/workspace."""
        tabs = self._ordered_tabs(context)
        closed = self._get_closed_tabs(context) if include_closed else []

        state = {
            "schema": "william.browser_agent.tab_manager.state.v1",
            "exported_at": utc_now_iso(),
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "active_tab_id": self._active_tab_by_scope.get(context.scope_key()),
            "tabs": [tab.to_dict() for tab in tabs],
            "closed_tabs": [tab.to_dict() for tab in closed],
        }

        return self._safe_result(
            message="Tab state exported successfully.",
            data={"state": state},
            metadata=context.to_metadata(),
        )

    def import_state(
        self,
        context: TabTaskContext,
        state: Dict[str, Any],
        merge: bool = False,
        restore_active: bool = True,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Import tab state safely for this user/workspace."""
        if not isinstance(state, dict):
            return self._error_result(
                message="State must be a dictionary.",
                error="INVALID_STATE",
                metadata=context.to_metadata(),
            )

        approval = self._maybe_request_security(
            context=context,
            action=TabAction.IMPORT_STATE.value,
            risk_level=TabRiskLevel.MEDIUM,
            target="tab_state_import",
            details={"merge": merge, "restore_active": restore_active},
        )
        if not approval["success"]:
            return approval

        incoming_tabs = state.get("tabs") or []
        incoming_closed = state.get("closed_tabs") or []

        if not isinstance(incoming_tabs, list):
            return self._error_result(
                message="State tabs must be a list.",
                error="INVALID_STATE_TABS",
                metadata=context.to_metadata(),
            )

        if len(incoming_tabs) > self.config.max_tabs_per_workspace:
            return self._error_result(
                message="Imported state exceeds max tabs per workspace.",
                error="MAX_TABS_REACHED",
                data={
                    "incoming_tabs": len(incoming_tabs),
                    "max_tabs_per_workspace": self.config.max_tabs_per_workspace,
                },
                metadata=context.to_metadata(),
            )

        if not merge:
            self._tabs_by_scope[context.scope_key()] = {}
            self._closed_tabs_by_scope[context.scope_key()] = []
            self._active_tab_by_scope[context.scope_key()] = None

        imported_tabs: List[BrowserTab] = []

        for raw_tab in incoming_tabs:
            if not isinstance(raw_tab, dict):
                continue

            tab = self._tab_from_dict(context, raw_tab)
            if not tab:
                continue

            self._get_tabs(context)[tab.tab_id] = tab
            imported_tabs.append(tab)

        imported_closed: List[BrowserTab] = []
        for raw_tab in incoming_closed:
            if not isinstance(raw_tab, dict):
                continue

            tab = self._tab_from_dict(context, raw_tab)
            if not tab:
                continue

            tab.status = TabStatus.CLOSED.value
            tab.is_active = False
            imported_closed.append(tab)

        self._closed_tabs_by_scope[context.scope_key()] = (
            self._get_closed_tabs(context) + imported_closed
        )[-self.config.max_closed_tabs_history:]

        active_tab_id = state.get("active_tab_id") if restore_active else None
        if active_tab_id and active_tab_id in self._get_tabs(context):
            self._set_active_tab(context, str(active_tab_id))
        else:
            self._reindex_positions(context)

        return self._safe_result(
            message="Tab state imported successfully.",
            data={
                "imported_tabs": len(imported_tabs),
                "imported_closed_tabs": len(imported_closed),
                "active_tab_id": self._active_tab_by_scope.get(context.scope_key()),
                "tabs": [tab.to_dict() for tab in self._ordered_tabs(context)],
            },
            metadata=context.to_metadata(),
        )

    # ==================================================================================
    # Context, security, verification, memory, audit, result hooks
    # ==================================================================================

    def _validate_task_context(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS context.

        Required:
            - user_id
            - workspace_id

        This prevents tab state, memory, logs, analytics, and audit data from mixing
        between users/workspaces.
        """
        user_id = task.get("user_id")
        workspace_id = task.get("workspace_id")

        payload = task.get("payload") or {}
        if isinstance(payload, dict):
            user_id = user_id or payload.get("user_id")
            workspace_id = workspace_id or payload.get("workspace_id")

        if user_id in (None, ""):
            return self._error_result(
                message="user_id is required for TabManager tasks.",
                error="MISSING_USER_ID",
                metadata={"task_keys": sorted(task.keys())},
            )

        if workspace_id in (None, ""):
            return self._error_result(
                message="workspace_id is required for TabManager tasks.",
                error="MISSING_WORKSPACE_ID",
                metadata={"task_keys": sorted(task.keys())},
            )

        permissions = task.get("permissions") or []
        if not isinstance(permissions, list):
            permissions = []

        context = TabTaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task.get("task_id"),
            role=task.get("role"),
            permissions=permissions,
            request_id=task.get("request_id"),
            source=task.get("source"),
            metadata=task.get("metadata") or {},
        )

        return self._safe_result(
            message="Task context validated.",
            data={"context": context},
            metadata=context.to_metadata(),
        )

    def _requires_security_check(
        self,
        action: str,
        risk_level: Union[str, TabRiskLevel] = TabRiskLevel.MEDIUM,
    ) -> bool:
        """Decide if an action requires SecurityAgent approval."""
        risk = TabRiskLevel(str(risk_level))

        if action == TabAction.OPEN_TAB.value:
            return bool(self.config.require_security_for_open)

        if action in {TabAction.CLOSE_TAB.value, TabAction.CLOSE_TABS.value}:
            return bool(self.config.require_security_for_close)

        if action == TabAction.SWITCH_TAB.value:
            return bool(self.config.require_security_for_switch)

        if action in {
            TabAction.ORGANIZE_TABS.value,
            TabAction.CLOSE_INACTIVE_TABS.value,
        }:
            return bool(self.config.require_security_for_organize)

        if action == TabAction.IMPORT_STATE.value:
            return bool(self.config.require_security_for_import)

        return risk == TabRiskLevel.HIGH

    def _request_security_approval(
        self,
        context: TabTaskContext,
        action: str,
        risk_level: Union[str, TabRiskLevel],
        target: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from SecurityAgent if available.

        Fallback behavior:
            If no security_client is attached, allow safe tab state management
            but return approval metadata. This keeps the file import-safe and usable
            before the full Security Agent exists.
        """
        payload = {
            "agent": self.agent_name,
            "action": action,
            "risk_level": str(risk_level),
            "target": target,
            "details": details or {},
            "context": context.to_metadata(),
            "timestamp": utc_now_iso(),
        }

        if self.security_client is None:
            return self._safe_result(
                message="Security approval fallback granted for safe tab action.",
                data={
                    "approved": True,
                    "approval_source": "fallback",
                    "payload": payload,
                },
                metadata=context.to_metadata(),
            )

        try:
            if hasattr(self.security_client, "approve_action"):
                approval = self.security_client.approve_action(payload)
            elif hasattr(self.security_client, "request_approval"):
                approval = self.security_client.request_approval(payload)
            else:
                approval = {
                    "success": False,
                    "approved": False,
                    "error": "SECURITY_CLIENT_MISSING_APPROVAL_METHOD",
                }

            if asyncio.iscoroutine(approval):
                raise RuntimeError(
                    "Async security client approval must be awaited by caller integration."
                )

            approved = bool(
                approval.get("approved")
                if isinstance(approval, dict)
                else False
            )

            if not approved:
                return self._error_result(
                    message="Security Agent denied this tab action.",
                    error="SECURITY_APPROVAL_DENIED",
                    data={"approval": approval, "payload": payload},
                    metadata=context.to_metadata(),
                )

            return self._safe_result(
                message="Security Agent approved tab action.",
                data={"approved": True, "approval": approval, "payload": payload},
                metadata=context.to_metadata(),
            )

        except Exception as exc:
            return self._error_result(
                message="Security approval failed.",
                error=str(exc),
                data={"payload": payload},
                metadata=context.to_metadata(),
            )

    def _maybe_request_security(
        self,
        context: TabTaskContext,
        action: str,
        risk_level: TabRiskLevel,
        target: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Run security approval only when required."""
        if not self._requires_security_check(action=action, risk_level=risk_level):
            return self._safe_result(
                message="Security check not required.",
                data={"approved": True, "approval_source": "not_required"},
                metadata=context.to_metadata(),
            )

        return self._request_security_approval(
            context=context,
            action=action,
            risk_level=risk_level,
            target=target,
            details=details,
        )

    def _prepare_verification_payload(
        self,
        action: str,
        context: TabTaskContext,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare payload for VerificationAgent.

        VerificationAgent can confirm that tab state changes are scoped,
        structured, and safe.
        """
        data = result.get("data", {})
        return {
            "agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "success": result.get("success"),
            "message": result.get("message"),
            "data_fingerprint": stable_hash(
                json.dumps(data, default=str, sort_keys=True)[:50_000]
            ),
            "checks": {
                "has_structured_result": isinstance(result, dict),
                "has_context": bool(context.user_id and context.workspace_id),
                "has_message": bool(result.get("message")),
                "has_error_field": "error" in result,
                "scope_key": context.scope_key(),
            },
            "created_at": utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: TabTaskContext,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare payload for MemoryAgent.

        This does not write memory directly unless memory_client integration is attached.
        """
        data = result.get("data", {})
        memory_items: List[Dict[str, Any]] = []

        if "tab" in data and isinstance(data["tab"], dict):
            tab = data["tab"]
            memory_items.append(
                {
                    "type": "browser_tab",
                    "action": action,
                    "tab_id": tab.get("tab_id"),
                    "url": tab.get("url"),
                    "title": tab.get("title"),
                    "label": tab.get("label"),
                    "group": tab.get("group"),
                    "domain": tab.get("domain"),
                }
            )

        if "active_tab" in data and isinstance(data["active_tab"], dict):
            tab = data["active_tab"]
            memory_items.append(
                {
                    "type": "browser_active_tab",
                    "action": action,
                    "tab_id": tab.get("tab_id"),
                    "url": tab.get("url"),
                    "title": tab.get("title"),
                    "domain": tab.get("domain"),
                }
            )

        if action in {TabAction.LIST_TABS.value, TabAction.ORGANIZE_TABS.value}:
            memory_items.append(
                {
                    "type": "browser_tab_collection",
                    "action": action,
                    "count": data.get("count") or len(data.get("tabs", [])),
                    "active_tab_id": data.get("active_tab_id"),
                }
            )

        payload = {
            "agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "items": memory_items,
            "created_at": utc_now_iso(),
        }

        if self.memory_client is not None:
            try:
                if hasattr(self.memory_client, "prepare"):
                    self.memory_client.prepare(payload)
                elif hasattr(self.memory_client, "store"):
                    self.memory_client.store(payload)
            except Exception as exc:
                self.logger.warning("Memory client write failed: %s", exc)

        return payload

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Emit agent event for Dashboard/API/Workflow logs.

        This intentionally does not crash the main task.
        """
        event_payload = {
            "event": event_name,
            "agent": self.agent_name,
            "timestamp": utc_now_iso(),
            "payload": payload,
        }

        try:
            if self.event_callback:
                self.event_callback(event_name, event_payload)
            elif hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_name, event_payload)  # type: ignore
                except Exception:
                    pass

            self.logger.debug("Agent event emitted: %s", event_payload)

        except Exception as exc:
            self.logger.warning("Failed to emit agent event: %s", exc)

    def _log_audit_event(
        self,
        context: TabTaskContext,
        action: str,
        status: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event.

        All audit payloads include user_id/workspace_id for SaaS isolation.
        """
        if not self.config.audit_enabled:
            return

        event = {
            "agent": self.agent_name,
            "action": action,
            "status": status,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "request_id": context.request_id,
            "details": details or {},
            "created_at": utc_now_iso(),
        }

        try:
            if self.audit_callback:
                self.audit_callback(event)
            else:
                self.logger.info("AUDIT | %s", json.dumps(event, default=str))
        except Exception as exc:
            self.logger.warning("Audit logging failed: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success result."""
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Any] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error result."""
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    # ==================================================================================
    # Internal tab store helpers
    # ==================================================================================

    def _get_tabs(self, context: TabTaskContext) -> Dict[str, BrowserTab]:
        """Get open tabs for user/workspace scope."""
        scope = context.scope_key()
        if scope not in self._tabs_by_scope:
            self._tabs_by_scope[scope] = {}
        return self._tabs_by_scope[scope]

    def _get_closed_tabs(self, context: TabTaskContext) -> List[BrowserTab]:
        """Get closed tabs history for user/workspace scope."""
        scope = context.scope_key()
        if scope not in self._closed_tabs_by_scope:
            self._closed_tabs_by_scope[scope] = []
        return self._closed_tabs_by_scope[scope]

    def _push_closed_tab(self, context: TabTaskContext, tab: BrowserTab) -> None:
        """Push tab into closed history with max limit."""
        closed = self._get_closed_tabs(context)
        closed.append(tab)

        if len(closed) > self.config.max_closed_tabs_history:
            del closed[0 : len(closed) - self.config.max_closed_tabs_history]

    def _ordered_tabs(self, context: TabTaskContext) -> List[BrowserTab]:
        """Return tabs ordered by position."""
        return sorted(
            self._get_tabs(context).values(),
            key=lambda tab: (tab.position, tab.created_at, tab.tab_id),
        )

    def _next_position(self, context: TabTaskContext) -> int:
        """Return next tab position."""
        tabs = self._get_tabs(context)
        if not tabs:
            return 0
        return max(tab.position for tab in tabs.values()) + 1

    def _reindex_positions(self, context: TabTaskContext) -> None:
        """Reindex tab positions."""
        for index, tab in enumerate(self._ordered_tabs(context)):
            tab.position = index
            tab.mark_updated()

    def _choose_next_active_tab(self, context: TabTaskContext) -> Optional[str]:
        """Choose next active tab after closing current active tab."""
        ordered = self._ordered_tabs(context)
        if not ordered:
            return None

        pinned = [tab for tab in ordered if tab.is_pinned]
        favorites = [tab for tab in ordered if tab.is_favorite]

        if pinned:
            return pinned[0].tab_id
        if favorites:
            return favorites[0].tab_id
        return ordered[0].tab_id

    def _set_active_tab(self, context: TabTaskContext, tab_id: str) -> None:
        """Set one tab active and mark all others inactive."""
        tabs = self._get_tabs(context)
        now = utc_now_iso()

        for existing in tabs.values():
            existing.is_active = False
            if existing.status == TabStatus.ACTIVE.value:
                existing.status = TabStatus.OPEN.value
            existing.mark_updated()

        tab = tabs.get(tab_id)
        if tab:
            tab.is_active = True
            tab.status = TabStatus.ACTIVE.value
            tab.last_active_at = now
            tab.mark_updated()
            self._active_tab_by_scope[context.scope_key()] = tab_id

    def _get_existing_tab_result(
        self,
        context: TabTaskContext,
        tab_id: str,
    ) -> Dict[str, Any]:
        """Return existing tab or structured error."""
        tab = self._get_tabs(context).get(tab_id)
        if not tab:
            return self._error_result(
                message="Tab not found.",
                error="TAB_NOT_FOUND",
                data={"tab_id": tab_id},
                metadata=context.to_metadata(),
            )

        return self._safe_result(
            message="Tab found.",
            data={"tab": tab},
            metadata=context.to_metadata(),
        )

    def _set_tab_boolean(
        self,
        context: TabTaskContext,
        tab_id: str,
        field_name: str,
        value: bool,
        message: str,
    ) -> Dict[str, Any]:
        """Set boolean field on tab."""
        tab_result = self._get_existing_tab_result(context, tab_id)
        if not tab_result["success"]:
            return tab_result

        tab: BrowserTab = tab_result["data"]["tab"]

        if not hasattr(tab, field_name):
            return self._error_result(
                message=f"Invalid tab boolean field: {field_name}",
                error="INVALID_TAB_FIELD",
                metadata=context.to_metadata(),
            )

        setattr(tab, field_name, bool(value))
        tab.mark_updated()

        return self._safe_result(
            message=message,
            data={"tab": tab.to_dict()},
            metadata=context.to_metadata(),
        )

    def _sort_tabs(
        self,
        tabs: List[BrowserTab],
        sort_by: str,
    ) -> List[BrowserTab]:
        """Sort tabs by supported mode."""
        mode = str(sort_by or TabSortMode.PINNED_FIRST.value)

        if mode == TabSortMode.CREATED_ASC.value:
            return sorted(tabs, key=lambda tab: (tab.created_at, tab.position))

        if mode == TabSortMode.CREATED_DESC.value:
            return sorted(tabs, key=lambda tab: (tab.created_at, tab.position), reverse=True)

        if mode == TabSortMode.LAST_ACTIVE_ASC.value:
            return sorted(tabs, key=lambda tab: (tab.last_active_at or "", tab.position))

        if mode == TabSortMode.LAST_ACTIVE_DESC.value:
            return sorted(
                tabs,
                key=lambda tab: (tab.last_active_at or "", tab.position),
                reverse=True,
            )

        if mode == TabSortMode.DOMAIN_ASC.value:
            return sorted(tabs, key=lambda tab: (tab.domain.lower(), tab.position))

        if mode == TabSortMode.TITLE_ASC.value:
            return sorted(tabs, key=lambda tab: (tab.title.lower(), tab.position))

        if mode == TabSortMode.GROUP_ASC.value:
            return sorted(tabs, key=lambda tab: (tab.group.lower(), tab.position))

        if mode == TabSortMode.PINNED_FIRST.value:
            return sorted(
                tabs,
                key=lambda tab: (
                    not tab.is_pinned,
                    not tab.is_favorite,
                    tab.group.lower(),
                    tab.position,
                ),
            )

        return sorted(tabs, key=lambda tab: tab.position)

    def _tab_from_dict(
        self,
        context: TabTaskContext,
        raw_tab: Dict[str, Any],
    ) -> Optional[BrowserTab]:
        """Build BrowserTab from imported dictionary safely."""
        url = normalize_url(str(raw_tab.get("url") or ""))
        if not self._is_url_allowed(url):
            return None

        tab_id = str(raw_tab.get("tab_id") or self._generate_tab_id(context, url))

        return BrowserTab(
            tab_id=tab_id,
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            url=url,
            title=safe_string(raw_tab.get("title") or domain_from_url(url), self.config.max_title_length),
            label=safe_string(raw_tab.get("label") or "", self.config.max_label_length),
            group=safe_string(raw_tab.get("group") or "", self.config.max_group_length),
            status=str(raw_tab.get("status") or TabStatus.OPEN.value),
            is_active=bool(raw_tab.get("is_active", False)),
            is_pinned=bool(raw_tab.get("is_pinned", False)),
            is_favorite=bool(raw_tab.get("is_favorite", False)),
            position=int(raw_tab.get("position") or 0),
            domain=domain_from_url(url),
            notes=safe_string(raw_tab.get("notes") or "", self.config.max_notes_length),
            opener_task_id=raw_tab.get("opener_task_id"),
            external_page_id=raw_tab.get("external_page_id"),
            created_at=str(raw_tab.get("created_at") or utc_now_iso()),
            updated_at=str(raw_tab.get("updated_at") or utc_now_iso()),
            last_active_at=raw_tab.get("last_active_at"),
            closed_at=raw_tab.get("closed_at"),
            metadata=raw_tab.get("metadata") if isinstance(raw_tab.get("metadata"), dict) else {},
        )

    def _generate_tab_id(self, context: TabTaskContext, url: str) -> str:
        """Generate safe unique tab ID."""
        prefix = stable_hash(f"{context.scope_key()}::{url}")[:10]
        return f"tab_{prefix}_{uuid.uuid4().hex[:12]}"

    # ==================================================================================
    # URL policy helpers
    # ==================================================================================

    def _is_url_allowed(self, url: str) -> bool:
        """Check URL against TabManager safety policy."""
        if not is_valid_url(url):
            return False

        normalized = normalize_url(url)
        parsed = urllib.parse.urlparse(normalized)
        scheme = parsed.scheme.lower()
        domain = parsed.netloc.lower()

        if scheme == "http" and not self.config.allow_http:
            return False

        if scheme == "https" and not self.config.allow_https:
            return False

        if not self.config.allow_localhost:
            if domain.startswith("localhost") or domain.startswith("127."):
                return False

        if not self.config.allow_private_ips:
            private_patterns = (
                "10.",
                "172.16.",
                "172.17.",
                "172.18.",
                "172.19.",
                "172.20.",
                "172.21.",
                "172.22.",
                "172.23.",
                "172.24.",
                "172.25.",
                "172.26.",
                "172.27.",
                "172.28.",
                "172.29.",
                "172.30.",
                "172.31.",
                "192.168.",
            )
            if any(domain.startswith(pattern) for pattern in private_patterns):
                return False

        clean_domain = domain.replace("www.", "")

        if self.config.blocked_domains:
            for blocked in self.config.blocked_domains:
                blocked = blocked.lower().replace("www.", "")
                if clean_domain == blocked or clean_domain.endswith("." + blocked):
                    return False

        if self.config.allowed_domains:
            allowed_match = False
            for allowed in self.config.allowed_domains:
                allowed = allowed.lower().replace("www.", "")
                if clean_domain == allowed or clean_domain.endswith("." + allowed):
                    allowed_match = True
                    break
            if not allowed_match:
                return False

        return True

    # ==================================================================================
    # Browser session delegation
    # ==================================================================================

    def _delegate_browser_session(
        self,
        method_names: List[str],
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Safely delegate operation to injected browser_session.

        This keeps TabManager independent from a specific browser backend.
        """
        if self.browser_session is None:
            return self._safe_result(
                message="No browser_session connected.",
                data={"delegated": False},
            )

        try:
            for method_name in method_names:
                if not hasattr(self.browser_session, method_name):
                    continue

                method = getattr(self.browser_session, method_name)

                try:
                    result = method(**payload)
                except TypeError:
                    result = method(payload)

                if asyncio.iscoroutine(result):
                    return self._error_result(
                        message="Async browser_session methods must be awaited by caller integration.",
                        error="ASYNC_BROWSER_SESSION_NOT_AWAITED",
                    )

                if isinstance(result, dict):
                    return result

                return self._safe_result(
                    message=f"browser_session.{method_name} completed.",
                    data={"delegated": True, "result": result},
                )

            return self._safe_result(
                message="No compatible browser_session method found.",
                data={
                    "delegated": False,
                    "searched_methods": method_names,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Browser session delegation failed.",
                error=str(exc),
                data={"payload": payload, "method_names": method_names},
            )


# ======================================================================================
# Local manual test helper
# ======================================================================================

if __name__ == "__main__":
    async def _demo() -> None:
        manager = TabManager(
            config=TabManagerConfig(
                require_security_for_open=False,
                require_security_for_close=False,
                require_security_for_switch=False,
                require_security_for_organize=False,
                require_security_for_import=False,
            )
        )

        open_result = await manager.execute(
            {
                "action": "open_tab",
                "user_id": "demo-user",
                "workspace_id": "demo-workspace",
                "payload": {
                    "url": "https://example.com",
                    "title": "Example",
                    "label": "Demo",
                    "group": "Research",
                },
            }
        )

        print(json.dumps(open_result, indent=2, default=str))

        list_result = await manager.execute(
            {
                "action": "list_tabs",
                "user_id": "demo-user",
                "workspace_id": "demo-workspace",
                "payload": {},
            }
        )

        print(json.dumps(list_result, indent=2, default=str))

    asyncio.run(_demo())