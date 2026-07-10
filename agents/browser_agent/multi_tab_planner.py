"""
agents/browser_agent/multi_tab_planner.py

William / Jarvis Multi-Agent AI SaaS System - Browser Agent
Digital Promotix

Purpose:
    Plans and manages multi-tab research workspaces.

This module does NOT execute browser actions directly. It creates safe, structured,
auditable multi-tab research plans that can later be executed by BrowserSession,
TabManager, Automation, Scraper, PageAnalyzer, ContentExtractor, SEOAnalyzer, and
other Browser Agent submodules.

Architecture connections:
    - Master Agent / Router:
        Uses `run()` / `handle_task()` as generic entry points and returns
        structured dict results.
    - Security Agent:
        Sensitive or destructive planning actions pass through
        `_request_security_approval()`.
    - Memory Agent:
        Useful workspace plans are prepared with `_prepare_memory_payload()`.
    - Verification Agent:
        Completed plans include `_prepare_verification_payload()`.
    - Dashboard/API:
        Results are JSON-serializable and safe for FastAPI responses.
    - Registry / Loader:
        Import-safe with optional BaseAgent fallback.
"""

from __future__ import annotations

import copy
import hashlib
import logging
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallback stubs
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import safety
    class BaseAgent:  # type: ignore
        """
        Safe fallback BaseAgent.

        Real William/Jarvis projects should use agents/base_agent.py.
        This fallback keeps this file import-safe while the full system is
        still being generated file-by-file.
        """

        agent_name: str = "base_agent"
        agent_type: str = "generic"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.config = kwargs.get("config", {}) or {}

        async def run(self, task: Mapping[str, Any], context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent run() is not implemented.",
                "data": {},
                "error": "base_agent_missing",
                "metadata": {"fallback": True},
            }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MAX_TABS_PER_WORKSPACE = 12
DEFAULT_MAX_WORKSPACES = 100
DEFAULT_MAX_QUERY_LENGTH = 300
DEFAULT_MAX_URL_LENGTH = 2048
DEFAULT_PRIORITY = 5

SAFE_SEARCH_ENGINES = {
    "google": "https://www.google.com/search?q={query}",
    "bing": "https://www.bing.com/search?q={query}",
    "duckduckgo": "https://duckduckgo.com/?q={query}",
}

DANGEROUS_URL_SCHEMES = {"javascript", "data", "file", "ftp", "chrome", "about", "edge", "opera"}
ALLOWED_TAB_STATUSES = {"planned", "queued", "active", "paused", "completed", "failed", "cancelled"}
ALLOWED_WORKSPACE_STATUSES = {"planned", "active", "paused", "completed", "cancelled", "archived"}


# ---------------------------------------------------------------------------
# Enums and Data Models
# ---------------------------------------------------------------------------

class ResearchTabType(str, Enum):
    """Supported types of research tabs."""

    SEARCH = "search"
    SOURCE = "source"
    COMPETITOR = "competitor"
    REFERENCE = "reference"
    PRODUCT = "product"
    SOCIAL = "social"
    NEWS = "news"
    SEO = "seo"
    PRICE = "price"
    FORM = "form"
    CUSTOM = "custom"


class ResearchTabPriority(str, Enum):
    """Human-friendly priority labels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class TabPlan:
    """
    A safe plan for one browser tab.

    This is a plan only. It does not open, scrape, click, submit, download, or
    perform any browser action.
    """

    tab_id: str
    title: str
    tab_type: str = ResearchTabType.CUSTOM.value
    url: Optional[str] = None
    query: Optional[str] = None
    objective: str = ""
    priority: int = DEFAULT_PRIORITY
    status: str = "planned"
    depends_on: List[str] = field(default_factory=list)
    expected_outputs: List[str] = field(default_factory=list)
    extraction_targets: List[str] = field(default_factory=list)
    analysis_steps: List[str] = field(default_factory=list)
    safety_notes: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: _utc_now_iso())
    updated_at: str = field(default_factory=lambda: _utc_now_iso())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ResearchWorkspace:
    """A multi-tab research workspace scoped to one user and one workspace."""

    workspace_plan_id: str
    user_id: str
    workspace_id: str
    title: str
    objective: str
    tabs: List[TabPlan] = field(default_factory=list)
    status: str = "planned"
    strategy: str = "balanced"
    source_policy: Dict[str, Any] = field(default_factory=dict)
    isolation_key: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: _utc_now_iso())
    updated_at: str = field(default_factory=lambda: _utc_now_iso())

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["tabs"] = [tab.to_dict() for tab in self.tabs]
        return payload


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    """Return timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def _safe_text(value: Any, max_length: int = 500) -> str:
    """Convert input to a safe compact string for logs and metadata."""

    text = "" if value is None else str(value)
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_length]


def _stable_hash(value: str, length: int = 16) -> str:
    """Generate a stable short hash without exposing raw sensitive text."""

    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:length]


def _normalize_id(value: Any) -> str:
    """Normalize SaaS user/workspace identifiers."""

    text = _safe_text(value, max_length=120)
    if not text:
        return ""
    return re.sub(r"[^a-zA-Z0-9_\-:.@]", "_", text)


def _unique_preserve_order(values: Iterable[Any]) -> List[str]:
    """Return unique non-empty strings while preserving order."""

    seen: set[str] = set()
    output: List[str] = []
    for value in values:
        text = _safe_text(value, max_length=250)
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            output.append(text)
    return output


def _clamp_priority(value: Any) -> int:
    """Normalize priority into 1..10 where 10 is highest."""

    if isinstance(value, ResearchTabPriority):
        value = value.value
    if isinstance(value, str):
        mapping = {
            "critical": 10,
            "high": 8,
            "medium": 5,
            "normal": 5,
            "low": 2,
        }
        return mapping.get(value.lower().strip(), DEFAULT_PRIORITY)
    try:
        return max(1, min(10, int(value)))
    except Exception:
        return DEFAULT_PRIORITY


def _is_probably_url(value: str) -> bool:
    """Return True if text looks like a URL or domain."""

    text = value.strip()
    if not text:
        return False
    parsed = urlparse(text if "://" in text else f"https://{text}")
    return bool(parsed.netloc and "." in parsed.netloc)


def _normalize_url(value: str, max_length: int = DEFAULT_MAX_URL_LENGTH) -> Optional[str]:
    """
    Normalize and validate URLs.

    Blocks dangerous local/browser schemes because this planner must remain
    safe for future browser automation modules.
    """

    text = _safe_text(value, max_length=max_length)
    if not text:
        return None

    if "://" not in text:
        text = f"https://{text}"

    parsed = urlparse(text)
    scheme = parsed.scheme.lower()
    if scheme in DANGEROUS_URL_SCHEMES:
        return None
    if scheme not in {"http", "https"}:
        return None
    if not parsed.netloc:
        return None

    return text[:max_length]


def _guess_tab_type(source: Mapping[str, Any]) -> str:
    """Infer tab type from source metadata."""

    explicit = _safe_text(source.get("tab_type") or source.get("type"), max_length=60).lower()
    if explicit:
        for tab_type in ResearchTabType:
            if explicit == tab_type.value:
                return tab_type.value

    url = _safe_text(source.get("url"), max_length=500).lower()
    title = _safe_text(source.get("title") or source.get("name"), max_length=300).lower()
    query = _safe_text(source.get("query"), max_length=300).lower()
    combined = f"{url} {title} {query}"

    if any(word in combined for word in ("competitor", "vs ", "alternative", "compare")):
        return ResearchTabType.COMPETITOR.value
    if any(word in combined for word in ("price", "pricing", "cost", "plan")):
        return ResearchTabType.PRICE.value
    if any(word in combined for word in ("seo", "keyword", "serp", "ranking")):
        return ResearchTabType.SEO.value
    if any(word in combined for word in ("news", "press", "latest")):
        return ResearchTabType.NEWS.value
    if query:
        return ResearchTabType.SEARCH.value
    if url:
        return ResearchTabType.SOURCE.value
    return ResearchTabType.CUSTOM.value


# ---------------------------------------------------------------------------
# Main Planner
# ---------------------------------------------------------------------------

class MultiTabPlanner(BaseAgent):
    """
    Plans and manages multi-tab research workspaces for the Browser Agent.

    Design principles:
        - Import-safe while the wider system is being generated.
        - SaaS-safe: all workspaces are scoped by user_id and workspace_id.
        - Action-safe: this file creates plans only; it does not browse/click.
        - Registry-ready: exposes predictable public methods.
        - Dashboard-ready: all results are structured dicts.
    """

    agent_name = "multi_tab_planner"
    agent_type = "browser_agent"
    public_methods = (
        "run",
        "handle_task",
        "create_workspace_plan",
        "plan_workspace",
        "add_tab_plan",
        "update_tab_status",
        "update_workspace_status",
        "get_workspace_plan",
        "list_workspace_plans",
        "rebalance_workspace",
        "summarize_workspace",
        "close_workspace",
        "export_workspace_plan",
        "clear_user_workspace_cache",
    )

    def __init__(
        self,
        config: Optional[Mapping[str, Any]] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(config=dict(config or {}), **kwargs)
        self.config: Dict[str, Any] = dict(config or {})
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger

        self.max_tabs_per_workspace: int = int(
            self.config.get("max_tabs_per_workspace", DEFAULT_MAX_TABS_PER_WORKSPACE)
        )
        self.max_workspaces: int = int(self.config.get("max_workspaces", DEFAULT_MAX_WORKSPACES))
        self.default_search_engine: str = _safe_text(
            self.config.get("default_search_engine", "google"), max_length=40
        ).lower() or "google"
        if self.default_search_engine not in SAFE_SEARCH_ENGINES:
            self.default_search_engine = "google"

        self._workspace_store: Dict[str, ResearchWorkspace] = {}

    # ------------------------------------------------------------------
    # Master Agent / Router entry points
    # ------------------------------------------------------------------

    async def run(
        self,
        task: Mapping[str, Any],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Async-compatible entry point for Master Agent routing.

        The method is intentionally thin and delegates to `handle_task()` so
        synchronous tests and FastAPI handlers can also use the same behavior.
        """

        return self.handle_task(task=task, context=context)

    def handle_task(
        self,
        task: Mapping[str, Any],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generic command router for planner tasks.

        Supported actions:
            - create_workspace_plan / plan_workspace
            - add_tab_plan
            - update_tab_status
            - update_workspace_status
            - get_workspace_plan
            - list_workspace_plans
            - rebalance_workspace
            - summarize_workspace
            - close_workspace
            - export_workspace_plan
            - clear_user_workspace_cache
        """

        try:
            if not isinstance(task, Mapping):
                return self._error_result(
                    "Task must be a mapping/dict.",
                    error_code="invalid_task_type",
                )

            merged_context = self._merge_context(task, context)
            validation = self._validate_task_context(merged_context)
            if not validation["success"]:
                return validation

            action = _safe_text(
                task.get("action") or task.get("intent") or task.get("operation") or "create_workspace_plan",
                max_length=80,
            ).lower()

            if self._requires_security_check(action, task):
                approval = self._request_security_approval(action=action, task=task, context=merged_context)
                if not approval.get("success"):
                    return approval

            if action in {"create", "create_workspace", "create_workspace_plan", "plan", "plan_workspace"}:
                return self.create_workspace_plan(task=task, context=merged_context)
            if action in {"add_tab", "add_tab_plan"}:
                return self.add_tab_plan(
                    workspace_plan_id=_safe_text(task.get("workspace_plan_id"), max_length=120),
                    tab=task.get("tab") or task.get("source") or task,
                    context=merged_context,
                )
            if action in {"update_tab", "update_tab_status"}:
                return self.update_tab_status(
                    workspace_plan_id=_safe_text(task.get("workspace_plan_id"), max_length=120),
                    tab_id=_safe_text(task.get("tab_id"), max_length=120),
                    status=_safe_text(task.get("status"), max_length=60),
                    context=merged_context,
                    metadata=task.get("metadata") if isinstance(task.get("metadata"), Mapping) else None,
                )
            if action in {"update_workspace", "update_workspace_status"}:
                return self.update_workspace_status(
                    workspace_plan_id=_safe_text(task.get("workspace_plan_id"), max_length=120),
                    status=_safe_text(task.get("status"), max_length=60),
                    context=merged_context,
                    metadata=task.get("metadata") if isinstance(task.get("metadata"), Mapping) else None,
                )
            if action in {"get", "get_workspace", "get_workspace_plan"}:
                return self.get_workspace_plan(
                    workspace_plan_id=_safe_text(task.get("workspace_plan_id"), max_length=120),
                    context=merged_context,
                )
            if action in {"list", "list_workspace_plans"}:
                return self.list_workspace_plans(context=merged_context)
            if action in {"rebalance", "rebalance_workspace"}:
                return self.rebalance_workspace(
                    workspace_plan_id=_safe_text(task.get("workspace_plan_id"), max_length=120),
                    context=merged_context,
                    strategy=_safe_text(task.get("strategy") or "balanced", max_length=80),
                )
            if action in {"summary", "summarize", "summarize_workspace"}:
                return self.summarize_workspace(
                    workspace_plan_id=_safe_text(task.get("workspace_plan_id"), max_length=120),
                    context=merged_context,
                )
            if action in {"close", "close_workspace", "archive"}:
                return self.close_workspace(
                    workspace_plan_id=_safe_text(task.get("workspace_plan_id"), max_length=120),
                    context=merged_context,
                    archive=bool(task.get("archive", True)),
                )
            if action in {"export", "export_workspace_plan"}:
                return self.export_workspace_plan(
                    workspace_plan_id=_safe_text(task.get("workspace_plan_id"), max_length=120),
                    context=merged_context,
                )
            if action in {"clear_cache", "clear_user_workspace_cache"}:
                return self.clear_user_workspace_cache(context=merged_context)

            return self._error_result(
                f"Unsupported MultiTabPlanner action: {action}",
                error_code="unsupported_action",
                metadata={"action": action, "supported_actions": list(self.public_methods)},
            )

        except Exception as exc:
            logger.exception("MultiTabPlanner.handle_task failed")
            return self._error_result(
                "Multi-tab planner failed to handle task.",
                error=exc,
                error_code="handle_task_exception",
            )

    # ------------------------------------------------------------------
    # Public planning API
    # ------------------------------------------------------------------

    def create_workspace_plan(
        self,
        task: Mapping[str, Any],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a complete multi-tab research workspace plan.

        Accepted task fields:
            - title
            - objective
            - query
            - urls / sources / competitors / references
            - tabs
            - strategy
            - expected_outputs
            - extraction_targets
            - metadata
        """

        try:
            context_data = self._merge_context(task, context)
            validation = self._validate_task_context(context_data)
            if not validation["success"]:
                return validation

            user_id = _normalize_id(context_data["user_id"])
            workspace_id = _normalize_id(context_data["workspace_id"])

            if len(self._workspace_store) >= self.max_workspaces:
                self._prune_archived_workspaces()
                if len(self._workspace_store) >= self.max_workspaces:
                    return self._error_result(
                        "Workspace plan limit reached.",
                        error_code="workspace_limit_reached",
                        metadata={"max_workspaces": self.max_workspaces},
                    )

            title = _safe_text(task.get("title") or task.get("name") or "Research Workspace", max_length=180)
            objective = _safe_text(
                task.get("objective") or task.get("goal") or task.get("query") or title,
                max_length=1000,
            )
            strategy = _safe_text(task.get("strategy") or "balanced", max_length=80).lower() or "balanced"

            source_policy = self._build_source_policy(task)
            workspace_plan_id = self._new_workspace_plan_id(user_id, workspace_id, title, objective)
            isolation_key = self._build_isolation_key(user_id=user_id, workspace_id=workspace_id)

            tabs = self._build_tabs_from_task(
                task=task,
                user_id=user_id,
                workspace_id=workspace_id,
                workspace_plan_id=workspace_plan_id,
                strategy=strategy,
            )

            if not tabs:
                tabs = self._build_default_tabs_from_objective(
                    objective=objective,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    workspace_plan_id=workspace_plan_id,
                )

            tabs = self._limit_and_sort_tabs(tabs, strategy=strategy)
            tabs = self._apply_tab_dependencies(tabs=tabs, strategy=strategy)

            workspace = ResearchWorkspace(
                workspace_plan_id=workspace_plan_id,
                user_id=user_id,
                workspace_id=workspace_id,
                title=title,
                objective=objective,
                tabs=tabs,
                status="planned",
                strategy=strategy,
                source_policy=source_policy,
                isolation_key=isolation_key,
                metadata=self._safe_metadata(task.get("metadata")),
            )
            self._workspace_store[workspace_plan_id] = workspace

            verification_payload = self._prepare_verification_payload(
                action="create_workspace_plan",
                workspace=workspace,
                context=context_data,
            )
            memory_payload = self._prepare_memory_payload(
                action="create_workspace_plan",
                workspace=workspace,
                context=context_data,
            )

            self._emit_agent_event(
                "browser.multi_tab.workspace_created",
                {
                    "workspace_plan_id": workspace_plan_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "tab_count": len(tabs),
                    "strategy": strategy,
                },
            )
            self._log_audit_event(
                action="create_workspace_plan",
                context=context_data,
                status="success",
                metadata={"workspace_plan_id": workspace_plan_id, "tab_count": len(tabs)},
            )

            return self._safe_result(
                message="Multi-tab research workspace plan created successfully.",
                data={
                    "workspace": workspace.to_dict(),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "agent": self.agent_name,
                    "module": self.agent_type,
                    "workspace_plan_id": workspace_plan_id,
                    "tab_count": len(tabs),
                    "max_tabs_per_workspace": self.max_tabs_per_workspace,
                },
            )
        except Exception as exc:
            logger.exception("Failed to create workspace plan")
            return self._error_result(
                "Failed to create multi-tab workspace plan.",
                error=exc,
                error_code="create_workspace_plan_exception",
            )

    def plan_workspace(
        self,
        task: Mapping[str, Any],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Alias used by MasterAgent/Router naming conventions."""

        return self.create_workspace_plan(task=task, context=context)

    def add_tab_plan(
        self,
        workspace_plan_id: str,
        tab: Mapping[str, Any],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Add one planned tab to an existing workspace after isolation checks."""

        try:
            workspace = self._get_workspace_checked(workspace_plan_id, context)
            if isinstance(workspace, dict):
                return workspace

            if len(workspace.tabs) >= self.max_tabs_per_workspace:
                return self._error_result(
                    "Maximum tabs per workspace reached.",
                    error_code="tab_limit_reached",
                    metadata={
                        "workspace_plan_id": workspace_plan_id,
                        "max_tabs_per_workspace": self.max_tabs_per_workspace,
                    },
                )

            tab_plan = self._source_to_tab_plan(
                source=tab,
                user_id=workspace.user_id,
                workspace_id=workspace.workspace_id,
                workspace_plan_id=workspace.workspace_plan_id,
                default_objective=workspace.objective,
            )
            existing_ids = {item.tab_id for item in workspace.tabs}
            while tab_plan.tab_id in existing_ids:
                tab_plan.tab_id = self._new_tab_id(workspace.workspace_plan_id, tab_plan.title, str(time.time()))

            workspace.tabs.append(tab_plan)
            workspace.tabs = self._limit_and_sort_tabs(workspace.tabs, strategy=workspace.strategy)
            workspace.tabs = self._apply_tab_dependencies(workspace.tabs, strategy=workspace.strategy)
            workspace.updated_at = _utc_now_iso()

            self._emit_agent_event(
                "browser.multi_tab.tab_added",
                {
                    "workspace_plan_id": workspace.workspace_plan_id,
                    "tab_id": tab_plan.tab_id,
                    "user_id": workspace.user_id,
                    "workspace_id": workspace.workspace_id,
                },
            )
            self._log_audit_event(
                action="add_tab_plan",
                context=context,
                status="success",
                metadata={"workspace_plan_id": workspace.workspace_plan_id, "tab_id": tab_plan.tab_id},
            )

            return self._safe_result(
                message="Tab plan added successfully.",
                data={"workspace": workspace.to_dict(), "tab": tab_plan.to_dict()},
                metadata={"workspace_plan_id": workspace.workspace_plan_id, "tab_id": tab_plan.tab_id},
            )
        except Exception as exc:
            logger.exception("Failed to add tab plan")
            return self._error_result(
                "Failed to add tab plan.",
                error=exc,
                error_code="add_tab_plan_exception",
            )

    def update_tab_status(
        self,
        workspace_plan_id: str,
        tab_id: str,
        status: str,
        context: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update a tab status for dashboard/session tracking."""

        try:
            normalized_status = _safe_text(status, max_length=60).lower()
            if normalized_status not in ALLOWED_TAB_STATUSES:
                return self._error_result(
                    "Invalid tab status.",
                    error_code="invalid_tab_status",
                    metadata={"status": status, "allowed": sorted(ALLOWED_TAB_STATUSES)},
                )

            workspace = self._get_workspace_checked(workspace_plan_id, context)
            if isinstance(workspace, dict):
                return workspace

            target = next((tab for tab in workspace.tabs if tab.tab_id == tab_id), None)
            if not target:
                return self._error_result(
                    "Tab plan not found.",
                    error_code="tab_not_found",
                    metadata={"workspace_plan_id": workspace_plan_id, "tab_id": tab_id},
                )

            target.status = normalized_status
            target.updated_at = _utc_now_iso()
            if metadata:
                target.metadata.update(self._safe_metadata(metadata))

            workspace.updated_at = _utc_now_iso()

            self._emit_agent_event(
                "browser.multi_tab.tab_status_updated",
                {
                    "workspace_plan_id": workspace.workspace_plan_id,
                    "tab_id": tab_id,
                    "status": normalized_status,
                    "user_id": workspace.user_id,
                    "workspace_id": workspace.workspace_id,
                },
            )

            return self._safe_result(
                message="Tab status updated successfully.",
                data={"workspace": workspace.to_dict(), "tab": target.to_dict()},
                metadata={"workspace_plan_id": workspace.workspace_plan_id, "tab_id": tab_id},
            )
        except Exception as exc:
            logger.exception("Failed to update tab status")
            return self._error_result(
                "Failed to update tab status.",
                error=exc,
                error_code="update_tab_status_exception",
            )

    def update_workspace_status(
        self,
        workspace_plan_id: str,
        status: str,
        context: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update workspace lifecycle status."""

        try:
            normalized_status = _safe_text(status, max_length=60).lower()
            if normalized_status not in ALLOWED_WORKSPACE_STATUSES:
                return self._error_result(
                    "Invalid workspace status.",
                    error_code="invalid_workspace_status",
                    metadata={"status": status, "allowed": sorted(ALLOWED_WORKSPACE_STATUSES)},
                )

            workspace = self._get_workspace_checked(workspace_plan_id, context)
            if isinstance(workspace, dict):
                return workspace

            workspace.status = normalized_status
            workspace.updated_at = _utc_now_iso()
            if metadata:
                workspace.metadata.update(self._safe_metadata(metadata))

            self._emit_agent_event(
                "browser.multi_tab.workspace_status_updated",
                {
                    "workspace_plan_id": workspace.workspace_plan_id,
                    "status": normalized_status,
                    "user_id": workspace.user_id,
                    "workspace_id": workspace.workspace_id,
                },
            )
            self._log_audit_event(
                action="update_workspace_status",
                context=context,
                status="success",
                metadata={"workspace_plan_id": workspace.workspace_plan_id, "status": normalized_status},
            )

            return self._safe_result(
                message="Workspace status updated successfully.",
                data={"workspace": workspace.to_dict()},
                metadata={"workspace_plan_id": workspace.workspace_plan_id, "status": normalized_status},
            )
        except Exception as exc:
            logger.exception("Failed to update workspace status")
            return self._error_result(
                "Failed to update workspace status.",
                error=exc,
                error_code="update_workspace_status_exception",
            )

    def get_workspace_plan(
        self,
        workspace_plan_id: str,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Fetch one workspace plan with SaaS isolation validation."""

        workspace = self._get_workspace_checked(workspace_plan_id, context)
        if isinstance(workspace, dict):
            return workspace

        return self._safe_result(
            message="Workspace plan loaded successfully.",
            data={"workspace": workspace.to_dict()},
            metadata={"workspace_plan_id": workspace.workspace_plan_id},
        )

    def list_workspace_plans(
        self,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """List all workspace plans visible to the current user/workspace context."""

        validation = self._validate_task_context(context or {})
        if not validation["success"]:
            return validation

        user_id = _normalize_id((context or {}).get("user_id"))
        workspace_id = _normalize_id((context or {}).get("workspace_id"))

        plans = [
            workspace.to_dict()
            for workspace in self._workspace_store.values()
            if workspace.user_id == user_id and workspace.workspace_id == workspace_id
        ]

        plans.sort(key=lambda item: item.get("updated_at", ""), reverse=True)

        return self._safe_result(
            message="Workspace plans listed successfully.",
            data={"workspaces": plans},
            metadata={"count": len(plans), "user_id": user_id, "workspace_id": workspace_id},
        )

    def rebalance_workspace(
        self,
        workspace_plan_id: str,
        context: Optional[Mapping[str, Any]] = None,
        strategy: str = "balanced",
    ) -> Dict[str, Any]:
        """
        Reorder and adjust tab dependencies based on a strategy.

        Strategies:
            - balanced: search/reference first, then sources/competitors.
            - speed: highest priority and direct URLs first.
            - depth: search and references before competitors.
            - competitor: competitor tabs first after initial search.
            - seo: SEO/search tabs first.
        """

        try:
            workspace = self._get_workspace_checked(workspace_plan_id, context)
            if isinstance(workspace, dict):
                return workspace

            normalized_strategy = _safe_text(strategy or workspace.strategy or "balanced", max_length=80).lower()
            workspace.strategy = normalized_strategy
            workspace.tabs = self._limit_and_sort_tabs(workspace.tabs, strategy=normalized_strategy)
            workspace.tabs = self._apply_tab_dependencies(workspace.tabs, strategy=normalized_strategy)
            workspace.updated_at = _utc_now_iso()

            self._emit_agent_event(
                "browser.multi_tab.workspace_rebalanced",
                {
                    "workspace_plan_id": workspace.workspace_plan_id,
                    "strategy": normalized_strategy,
                    "user_id": workspace.user_id,
                    "workspace_id": workspace.workspace_id,
                },
            )

            return self._safe_result(
                message="Workspace plan rebalanced successfully.",
                data={"workspace": workspace.to_dict()},
                metadata={"workspace_plan_id": workspace.workspace_plan_id, "strategy": normalized_strategy},
            )
        except Exception as exc:
            logger.exception("Failed to rebalance workspace")
            return self._error_result(
                "Failed to rebalance workspace.",
                error=exc,
                error_code="rebalance_workspace_exception",
            )

    def summarize_workspace(
        self,
        workspace_plan_id: str,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a dashboard-friendly summary of a workspace plan."""

        workspace = self._get_workspace_checked(workspace_plan_id, context)
        if isinstance(workspace, dict):
            return workspace

        by_status: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        for tab in workspace.tabs:
            by_status[tab.status] = by_status.get(tab.status, 0) + 1
            by_type[tab.tab_type] = by_type.get(tab.tab_type, 0) + 1

        next_tabs = [
            tab.to_dict()
            for tab in sorted(workspace.tabs, key=lambda item: item.priority, reverse=True)
            if tab.status in {"planned", "queued", "paused"}
        ][:3]

        summary = {
            "workspace_plan_id": workspace.workspace_plan_id,
            "title": workspace.title,
            "objective": workspace.objective,
            "status": workspace.status,
            "strategy": workspace.strategy,
            "tab_count": len(workspace.tabs),
            "by_status": by_status,
            "by_type": by_type,
            "next_recommended_tabs": next_tabs,
            "created_at": workspace.created_at,
            "updated_at": workspace.updated_at,
        }

        return self._safe_result(
            message="Workspace summary prepared successfully.",
            data={"summary": summary},
            metadata={"workspace_plan_id": workspace.workspace_plan_id},
        )

    def close_workspace(
        self,
        workspace_plan_id: str,
        context: Optional[Mapping[str, Any]] = None,
        archive: bool = True,
    ) -> Dict[str, Any]:
        """
        Close or archive a workspace plan.

        This does not close real browser tabs. It only changes planner state.
        """

        workspace = self._get_workspace_checked(workspace_plan_id, context)
        if isinstance(workspace, dict):
            return workspace

        workspace.status = "archived" if archive else "cancelled"
        workspace.updated_at = _utc_now_iso()
        for tab in workspace.tabs:
            if tab.status in {"planned", "queued", "active", "paused"}:
                tab.status = "cancelled"
                tab.updated_at = _utc_now_iso()

        self._emit_agent_event(
            "browser.multi_tab.workspace_closed",
            {
                "workspace_plan_id": workspace.workspace_plan_id,
                "archive": archive,
                "user_id": workspace.user_id,
                "workspace_id": workspace.workspace_id,
            },
        )
        self._log_audit_event(
            action="close_workspace",
            context=context,
            status="success",
            metadata={"workspace_plan_id": workspace.workspace_plan_id, "archive": archive},
        )

        return self._safe_result(
            message="Workspace plan closed successfully.",
            data={"workspace": workspace.to_dict()},
            metadata={"workspace_plan_id": workspace.workspace_plan_id, "archive": archive},
        )

    def export_workspace_plan(
        self,
        workspace_plan_id: str,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Export workspace plan as JSON-serializable data for dashboard/API.

        A future DownloadManager can turn this payload into JSON/CSV/PDF.
        """

        workspace = self._get_workspace_checked(workspace_plan_id, context)
        if isinstance(workspace, dict):
            return workspace

        payload = {
            "export_type": "multi_tab_workspace_plan",
            "version": "1.0",
            "exported_at": _utc_now_iso(),
            "workspace": workspace.to_dict(),
            "verification_payload": self._prepare_verification_payload(
                action="export_workspace_plan",
                workspace=workspace,
                context=context,
            ),
        }

        return self._safe_result(
            message="Workspace plan export prepared successfully.",
            data=payload,
            metadata={"workspace_plan_id": workspace.workspace_plan_id},
        )

    def clear_user_workspace_cache(
        self,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Remove only the current user's current workspace plans from memory."""

        validation = self._validate_task_context(context or {})
        if not validation["success"]:
            return validation

        user_id = _normalize_id((context or {}).get("user_id"))
        workspace_id = _normalize_id((context or {}).get("workspace_id"))

        before = len(self._workspace_store)
        self._workspace_store = {
            key: workspace
            for key, workspace in self._workspace_store.items()
            if not (workspace.user_id == user_id and workspace.workspace_id == workspace_id)
        }
        removed = before - len(self._workspace_store)

        self._log_audit_event(
            action="clear_user_workspace_cache",
            context=context,
            status="success",
            metadata={"removed": removed},
        )

        return self._safe_result(
            message="User workspace planner cache cleared successfully.",
            data={"removed": removed},
            metadata={"user_id": user_id, "workspace_id": workspace_id},
        )

    # ------------------------------------------------------------------
    # Build tabs
    # ------------------------------------------------------------------

    def _build_tabs_from_task(
        self,
        task: Mapping[str, Any],
        user_id: str,
        workspace_id: str,
        workspace_plan_id: str,
        strategy: str,
    ) -> List[TabPlan]:
        """Build tab plans from task urls/sources/tabs/queries."""

        raw_sources: List[Mapping[str, Any]] = []

        for key in ("tabs", "sources", "urls", "references", "competitors", "products", "news_sources"):
            value = task.get(key)
            raw_sources.extend(self._normalize_sources(value, source_key=key))

        primary_query = _safe_text(task.get("query") or task.get("search_query"), max_length=DEFAULT_MAX_QUERY_LENGTH)
        if primary_query:
            raw_sources.insert(
                0,
                {
                    "title": f"Search: {primary_query}",
                    "query": primary_query,
                    "tab_type": ResearchTabType.SEARCH.value,
                    "objective": f"Find initial high-quality sources for: {primary_query}",
                    "priority": 9,
                    "expected_outputs": ["source list", "topic overview", "next research leads"],
                },
            )

        extra_queries = task.get("queries")
        if isinstance(extra_queries, Sequence) and not isinstance(extra_queries, (str, bytes, bytearray)):
            for query in extra_queries:
                text = _safe_text(query, max_length=DEFAULT_MAX_QUERY_LENGTH)
                if text:
                    raw_sources.append(
                        {
                            "title": f"Search: {text}",
                            "query": text,
                            "tab_type": ResearchTabType.SEARCH.value,
                            "objective": f"Research query: {text}",
                            "priority": 7,
                            "expected_outputs": ["source list", "relevant facts"],
                        }
                    )

        tabs: List[TabPlan] = []
        seen_fingerprints: set[str] = set()
        default_objective = _safe_text(task.get("objective") or task.get("goal") or primary_query, max_length=1000)

        for source in raw_sources:
            tab_plan = self._source_to_tab_plan(
                source=source,
                user_id=user_id,
                workspace_id=workspace_id,
                workspace_plan_id=workspace_plan_id,
                default_objective=default_objective,
            )
            fingerprint = self._tab_fingerprint(tab_plan)
            if fingerprint not in seen_fingerprints:
                seen_fingerprints.add(fingerprint)
                tabs.append(tab_plan)

        return tabs

    def _build_default_tabs_from_objective(
        self,
        objective: str,
        user_id: str,
        workspace_id: str,
        workspace_plan_id: str,
    ) -> List[TabPlan]:
        """Create sensible default tabs when the task provides no explicit sources."""

        query = _safe_text(objective or "research topic", max_length=DEFAULT_MAX_QUERY_LENGTH)
        default_sources = [
            {
                "title": f"Initial Search: {query}",
                "query": query,
                "tab_type": ResearchTabType.SEARCH.value,
                "objective": "Find trustworthy starting sources and understand the topic.",
                "priority": 9,
                "expected_outputs": ["source shortlist", "key entities", "important questions"],
            },
            {
                "title": f"Reference Review: {query}",
                "query": f"{query} official documentation OR primary source",
                "tab_type": ResearchTabType.REFERENCE.value,
                "objective": "Find official or primary references.",
                "priority": 8,
                "expected_outputs": ["official sources", "primary evidence"],
            },
            {
                "title": f"Competitor / Comparison Search: {query}",
                "query": f"{query} competitors alternatives comparison",
                "tab_type": ResearchTabType.COMPETITOR.value,
                "objective": "Compare competing sources, alternatives, or market positions.",
                "priority": 6,
                "expected_outputs": ["comparison notes", "competitor list"],
            },
        ]

        return [
            self._source_to_tab_plan(
                source=source,
                user_id=user_id,
                workspace_id=workspace_id,
                workspace_plan_id=workspace_plan_id,
                default_objective=objective,
            )
            for source in default_sources
        ]

    def _source_to_tab_plan(
        self,
        source: Mapping[str, Any],
        user_id: str,
        workspace_id: str,
        workspace_plan_id: str,
        default_objective: str = "",
    ) -> TabPlan:
        """Convert a loose source mapping into a strict TabPlan."""

        source_data = dict(source or {})
        raw_url = _safe_text(source_data.get("url") or source_data.get("link"), max_length=DEFAULT_MAX_URL_LENGTH)
        raw_query = _safe_text(source_data.get("query") or source_data.get("search"), max_length=DEFAULT_MAX_QUERY_LENGTH)

        url = _normalize_url(raw_url) if raw_url else None
        query = raw_query or None

        if not url and not query:
            candidate = _safe_text(source_data.get("value") or source_data.get("source"), max_length=DEFAULT_MAX_URL_LENGTH)
            if candidate and _is_probably_url(candidate):
                url = _normalize_url(candidate)
            elif candidate:
                query = candidate[:DEFAULT_MAX_QUERY_LENGTH]

        tab_type = _guess_tab_type({**source_data, "url": url or raw_url, "query": query or raw_query})
        title = _safe_text(
            source_data.get("title")
            or source_data.get("name")
            or self._build_tab_title(tab_type=tab_type, url=url, query=query),
            max_length=180,
        )

        objective = _safe_text(
            source_data.get("objective") or source_data.get("goal") or default_objective or title,
            max_length=1000,
        )

        priority = _clamp_priority(source_data.get("priority", DEFAULT_PRIORITY))
        if tab_type == ResearchTabType.SEARCH.value:
            priority = max(priority, 7)
        elif tab_type in {ResearchTabType.REFERENCE.value, ResearchTabType.SOURCE.value}:
            priority = max(priority, 6)

        expected_outputs = _unique_preserve_order(
            source_data.get("expected_outputs", [])
            if isinstance(source_data.get("expected_outputs"), Sequence) and not isinstance(source_data.get("expected_outputs"), str)
            else [source_data.get("expected_outputs")]
        )
        extraction_targets = _unique_preserve_order(
            source_data.get("extraction_targets", [])
            if isinstance(source_data.get("extraction_targets"), Sequence) and not isinstance(source_data.get("extraction_targets"), str)
            else [source_data.get("extraction_targets")]
        )
        analysis_steps = _unique_preserve_order(
            source_data.get("analysis_steps", [])
            if isinstance(source_data.get("analysis_steps"), Sequence) and not isinstance(source_data.get("analysis_steps"), str)
            else [source_data.get("analysis_steps")]
        )
        tags = _unique_preserve_order(
            source_data.get("tags", [])
            if isinstance(source_data.get("tags"), Sequence) and not isinstance(source_data.get("tags"), str)
            else [source_data.get("tags"), tab_type]
        )

        if not expected_outputs:
            expected_outputs = self._default_expected_outputs(tab_type)

        if not extraction_targets:
            extraction_targets = self._default_extraction_targets(tab_type)

        if not analysis_steps:
            analysis_steps = self._default_analysis_steps(tab_type)

        safety_notes = self._build_safety_notes(url=url, query=query, tab_type=tab_type)

        tab_id = _safe_text(source_data.get("tab_id"), max_length=120)
        if not tab_id:
            tab_id = self._new_tab_id(workspace_plan_id, title, url or query or str(uuid.uuid4()))

        metadata = self._safe_metadata(source_data.get("metadata"))
        metadata.update(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "workspace_plan_id": workspace_plan_id,
                "planner_generated": True,
            }
        )

        return TabPlan(
            tab_id=tab_id,
            title=title,
            tab_type=tab_type,
            url=url,
            query=query,
            objective=objective,
            priority=priority,
            status=_safe_text(source_data.get("status") or "planned", max_length=60).lower()
            if _safe_text(source_data.get("status") or "planned", max_length=60).lower() in ALLOWED_TAB_STATUSES
            else "planned",
            depends_on=_unique_preserve_order(
                source_data.get("depends_on", [])
                if isinstance(source_data.get("depends_on"), Sequence) and not isinstance(source_data.get("depends_on"), str)
                else [source_data.get("depends_on")]
            ),
            expected_outputs=expected_outputs,
            extraction_targets=extraction_targets,
            analysis_steps=analysis_steps,
            safety_notes=safety_notes,
            tags=tags,
            metadata=metadata,
        )

    def _normalize_sources(self, value: Any, source_key: str = "sources") -> List[Mapping[str, Any]]:
        """Normalize many possible source formats into mappings."""

        sources: List[Mapping[str, Any]] = []
        if value is None:
            return sources

        if isinstance(value, Mapping):
            return [value]

        if isinstance(value, str):
            if _is_probably_url(value):
                return [{"url": value, "tab_type": self._tab_type_from_source_key(source_key)}]
            return [{"query": value, "tab_type": ResearchTabType.SEARCH.value}]

        if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
            for item in value:
                if isinstance(item, Mapping):
                    item_data = dict(item)
                    item_data.setdefault("tab_type", self._tab_type_from_source_key(source_key))
                    sources.append(item_data)
                elif isinstance(item, str):
                    if _is_probably_url(item):
                        sources.append({"url": item, "tab_type": self._tab_type_from_source_key(source_key)})
                    else:
                        sources.append({"query": item, "tab_type": ResearchTabType.SEARCH.value})
        return sources

    def _tab_type_from_source_key(self, source_key: str) -> str:
        """Map input collection key to a tab type."""

        mapping = {
            "urls": ResearchTabType.SOURCE.value,
            "sources": ResearchTabType.SOURCE.value,
            "references": ResearchTabType.REFERENCE.value,
            "competitors": ResearchTabType.COMPETITOR.value,
            "products": ResearchTabType.PRODUCT.value,
            "news_sources": ResearchTabType.NEWS.value,
            "tabs": ResearchTabType.CUSTOM.value,
        }
        return mapping.get(source_key, ResearchTabType.CUSTOM.value)

    # ------------------------------------------------------------------
    # Sorting and dependencies
    # ------------------------------------------------------------------

    def _limit_and_sort_tabs(self, tabs: Sequence[TabPlan], strategy: str = "balanced") -> List[TabPlan]:
        """Sort tabs according to strategy and limit count."""

        strategy = _safe_text(strategy, max_length=80).lower() or "balanced"

        def type_weight(tab: TabPlan) -> int:
            if strategy == "speed":
                if tab.url:
                    return 100
                if tab.tab_type == ResearchTabType.SEARCH.value:
                    return 80
                return 50

            if strategy == "competitor":
                if tab.tab_type == ResearchTabType.SEARCH.value:
                    return 100
                if tab.tab_type == ResearchTabType.COMPETITOR.value:
                    return 95
                if tab.tab_type == ResearchTabType.SOURCE.value:
                    return 80
                return 50

            if strategy == "seo":
                if tab.tab_type == ResearchTabType.SEO.value:
                    return 100
                if tab.tab_type == ResearchTabType.SEARCH.value:
                    return 95
                if tab.tab_type == ResearchTabType.COMPETITOR.value:
                    return 85
                return 50

            if strategy == "depth":
                order = {
                    ResearchTabType.SEARCH.value: 100,
                    ResearchTabType.REFERENCE.value: 95,
                    ResearchTabType.SOURCE.value: 90,
                    ResearchTabType.NEWS.value: 75,
                    ResearchTabType.COMPETITOR.value: 65,
                }
                return order.get(tab.tab_type, 50)

            order = {
                ResearchTabType.SEARCH.value: 100,
                ResearchTabType.REFERENCE.value: 90,
                ResearchTabType.SOURCE.value: 85,
                ResearchTabType.COMPETITOR.value: 80,
                ResearchTabType.SEO.value: 75,
                ResearchTabType.NEWS.value: 70,
                ResearchTabType.PRICE.value: 60,
            }
            return order.get(tab.tab_type, 50)

        unique: Dict[str, TabPlan] = {}
        for tab in tabs:
            unique.setdefault(self._tab_fingerprint(tab), tab)

        sorted_tabs = sorted(
            unique.values(),
            key=lambda item: (type_weight(item), item.priority, item.created_at),
            reverse=True,
        )
        return list(sorted_tabs[: self.max_tabs_per_workspace])

    def _apply_tab_dependencies(self, tabs: Sequence[TabPlan], strategy: str = "balanced") -> List[TabPlan]:
        """Apply light dependency planning so future TabManager can schedule safely."""

        if not tabs:
            return []

        output = [copy.deepcopy(tab) for tab in tabs]
        search_tabs = [tab for tab in output if tab.tab_type == ResearchTabType.SEARCH.value]
        primary_search_id = search_tabs[0].tab_id if search_tabs else None

        for tab in output:
            if tab.tab_type != ResearchTabType.SEARCH.value and primary_search_id and tab.tab_id != primary_search_id:
                if primary_search_id not in tab.depends_on:
                    tab.depends_on.insert(0, primary_search_id)

            tab.depends_on = [dep for dep in _unique_preserve_order(tab.depends_on) if dep != tab.tab_id]
            tab.updated_at = _utc_now_iso()

        return output

    # ------------------------------------------------------------------
    # Defaults
    # ------------------------------------------------------------------

    def _build_tab_title(self, tab_type: str, url: Optional[str], query: Optional[str]) -> str:
        """Build readable tab title."""

        if url:
            parsed = urlparse(url)
            domain = parsed.netloc.replace("www.", "")
            return f"{tab_type.title()} Source: {domain}"
        if query:
            return f"{tab_type.title()} Search: {query[:80]}"
        return f"{tab_type.title()} Tab"

    def _default_expected_outputs(self, tab_type: str) -> List[str]:
        """Default outputs by tab type."""

        mapping = {
            ResearchTabType.SEARCH.value: ["relevant source URLs", "topic overview", "follow-up queries"],
            ResearchTabType.SOURCE.value: ["key facts", "source credibility notes", "important excerpts summary"],
            ResearchTabType.COMPETITOR.value: ["competitor positioning", "feature/pricing notes", "weaknesses/opportunities"],
            ResearchTabType.REFERENCE.value: ["primary evidence", "official details", "citation-ready facts"],
            ResearchTabType.PRODUCT.value: ["product details", "pricing notes", "availability signals"],
            ResearchTabType.NEWS.value: ["recent developments", "dates", "source attribution"],
            ResearchTabType.SEO.value: ["SERP observations", "keyword opportunities", "content gaps"],
            ResearchTabType.PRICE.value: ["pricing data", "plan differences", "monitoring targets"],
            ResearchTabType.FORM.value: ["form fields", "validation requirements", "risk notes"],
        }
        return mapping.get(tab_type, ["research notes", "important findings"])

    def _default_extraction_targets(self, tab_type: str) -> List[str]:
        """Default extraction targets by tab type."""

        mapping = {
            ResearchTabType.SEARCH.value: ["titles", "urls", "snippets"],
            ResearchTabType.SOURCE.value: ["headings", "facts", "links"],
            ResearchTabType.COMPETITOR.value: ["headlines", "features", "pricing", "claims"],
            ResearchTabType.REFERENCE.value: ["official statements", "dates", "definitions"],
            ResearchTabType.PRODUCT.value: ["name", "price", "features", "availability"],
            ResearchTabType.NEWS.value: ["headline", "published date", "summary", "publisher"],
            ResearchTabType.SEO.value: ["title tags", "meta descriptions", "H1/H2", "schema hints"],
            ResearchTabType.PRICE.value: ["price", "currency", "plan", "billing period"],
            ResearchTabType.FORM.value: ["field names", "required fields", "submit behavior"],
        }
        return mapping.get(tab_type, ["visible text", "links"])

    def _default_analysis_steps(self, tab_type: str) -> List[str]:
        """Default analysis steps by tab type."""

        mapping = {
            ResearchTabType.SEARCH.value: [
                "Review top results for relevance.",
                "Separate primary sources from secondary sources.",
                "Recommend tabs for deeper review.",
            ],
            ResearchTabType.SOURCE.value: [
                "Check source credibility.",
                "Extract key facts.",
                "Prepare summary for Verification Agent.",
            ],
            ResearchTabType.COMPETITOR.value: [
                "Identify positioning and offers.",
                "Compare strengths and weaknesses.",
                "Flag useful insights for Business/SEO agents.",
            ],
            ResearchTabType.REFERENCE.value: [
                "Prioritize official information.",
                "Capture citation-ready facts.",
                "Avoid unsupported interpretation.",
            ],
            ResearchTabType.SEO.value: [
                "Inspect headings and metadata.",
                "Identify keyword gaps.",
                "Prepare content opportunity notes.",
            ],
            ResearchTabType.PRICE.value: [
                "Capture visible pricing only.",
                "Record timestamp and source.",
                "Avoid checkout or purchase actions.",
            ],
        }
        return mapping.get(
            tab_type,
            ["Open only through approved BrowserSession.", "Extract allowed information.", "Prepare structured notes."],
        )

    def _build_safety_notes(self, url: Optional[str], query: Optional[str], tab_type: str) -> List[str]:
        """Attach safety notes for future automation modules."""

        notes = [
            "Planning only: this file does not open browsers, click links, submit forms, or download files.",
            "Future execution must preserve user_id/workspace_id isolation.",
            "Sensitive actions must be approved by Security Agent before execution.",
        ]
        if url:
            notes.append("URL was normalized to http/https only; unsafe schemes are blocked.")
        if query:
            notes.append("Search query should be executed only by approved Browser Agent components.")
        if tab_type == ResearchTabType.FORM.value:
            notes.append("Form submission must never happen without explicit Security Agent approval.")
        if tab_type == ResearchTabType.PRICE.value:
            notes.append("Price monitoring must avoid purchases, carts, or account changes.")
        return notes

    def _build_source_policy(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """Create source policy metadata for downstream browser modules."""

        allowed_domains = _unique_preserve_order(task.get("allowed_domains", []) or [])
        blocked_domains = _unique_preserve_order(task.get("blocked_domains", []) or [])
        require_citations = bool(task.get("require_citations", True))
        prefer_primary_sources = bool(task.get("prefer_primary_sources", True))

        return {
            "allowed_domains": allowed_domains,
            "blocked_domains": blocked_domains,
            "require_citations": require_citations,
            "prefer_primary_sources": prefer_primary_sources,
            "allow_downloads": bool(task.get("allow_downloads", False)),
            "allow_form_submission": bool(task.get("allow_form_submission", False)),
            "allow_login_required_pages": bool(task.get("allow_login_required_pages", False)),
            "search_engine": _safe_text(task.get("search_engine") or self.default_search_engine, max_length=40),
        }

    # ------------------------------------------------------------------
    # Validation / isolation / security
    # ------------------------------------------------------------------

    def _merge_context(
        self,
        task: Optional[Mapping[str, Any]],
        context: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Merge task-level and caller-level SaaS context safely."""

        merged: Dict[str, Any] = {}
        if isinstance(context, Mapping):
            merged.update(dict(context))
        if isinstance(task, Mapping):
            for key in ("user_id", "workspace_id", "role", "subscription", "permissions", "request_id"):
                if key in task and task.get(key) is not None:
                    merged[key] = task.get(key)
            task_context = task.get("context")
            if isinstance(task_context, Mapping):
                for key in ("user_id", "workspace_id", "role", "subscription", "permissions", "request_id"):
                    if key in task_context and task_context.get(key) is not None:
                        merged[key] = task_context.get(key)
        return merged

    def _validate_task_context(self, context: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS context.

        user_id and workspace_id are required to prevent accidental mixing of
        workspaces, logs, memory payloads, analytics, and audit data.
        """

        if not isinstance(context, Mapping):
            return self._error_result(
                "Context must be a mapping/dict.",
                error_code="invalid_context_type",
            )

        user_id = _normalize_id(context.get("user_id"))
        workspace_id = _normalize_id(context.get("workspace_id"))

        if not user_id:
            return self._error_result(
                "Missing required user_id for SaaS isolation.",
                error_code="missing_user_id",
            )
        if not workspace_id:
            return self._error_result(
                "Missing required workspace_id for SaaS isolation.",
                error_code="missing_workspace_id",
            )

        return self._safe_result(
            message="Task context validated.",
            data={"user_id": user_id, "workspace_id": workspace_id},
            metadata={"validation": "passed"},
        )

    def _requires_security_check(self, action: str, task: Mapping[str, Any]) -> bool:
        """
        Determine whether this planning request needs Security Agent approval.

        Planning is usually safe, but destructive cache clear/close actions and
        future execution-like flags are treated as sensitive.
        """

        action = _safe_text(action, max_length=80).lower()
        if action in {"close", "close_workspace", "archive", "clear_cache", "clear_user_workspace_cache"}:
            return True

        sensitive_flags = (
            "allow_downloads",
            "allow_form_submission",
            "allow_login_required_pages",
            "execute_now",
            "open_now",
            "submit_form",
            "download",
        )
        return any(bool(task.get(flag)) for flag in sensitive_flags)

    def _request_security_approval(
        self,
        action: str,
        task: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent if available.

        If no Security Agent is connected, safe planning actions may continue,
        but execution-like or risky flags are denied by default.
        """

        risk_payload = {
            "agent": self.agent_name,
            "action": action,
            "user_id": _normalize_id(context.get("user_id")),
            "workspace_id": _normalize_id(context.get("workspace_id")),
            "requested_at": _utc_now_iso(),
            "risk_flags": {
                "allow_downloads": bool(task.get("allow_downloads")),
                "allow_form_submission": bool(task.get("allow_form_submission")),
                "allow_login_required_pages": bool(task.get("allow_login_required_pages")),
                "execute_now": bool(task.get("execute_now") or task.get("open_now")),
            },
        }

        if self.security_client and hasattr(self.security_client, "approve"):
            try:
                approval = self.security_client.approve(risk_payload)
                if isinstance(approval, Mapping) and approval.get("success") is True:
                    return self._safe_result(
                        message="Security approval granted.",
                        data={"approval": dict(approval)},
                        metadata={"security_agent": "connected"},
                    )
                return self._error_result(
                    "Security Agent denied this planner action.",
                    error_code="security_denied",
                    metadata={"approval": dict(approval) if isinstance(approval, Mapping) else approval},
                )
            except Exception as exc:
                return self._error_result(
                    "Security Agent approval request failed.",
                    error=exc,
                    error_code="security_approval_exception",
                )

        risky_without_security = any(risk_payload["risk_flags"].values())
        if risky_without_security:
            return self._error_result(
                "Security Agent is required for this sensitive browser planning request.",
                error_code="security_agent_required",
                metadata=risk_payload,
            )

        return self._safe_result(
            message="Security check passed with safe local policy.",
            data={"approval": {"local_policy": "safe_planning_only"}},
            metadata={"security_agent": "not_connected"},
        )

    def _get_workspace_checked(
        self,
        workspace_plan_id: str,
        context: Optional[Mapping[str, Any]],
    ) -> Union[ResearchWorkspace, Dict[str, Any]]:
        """Load workspace and enforce user/workspace isolation."""

        plan_id = _safe_text(workspace_plan_id, max_length=120)
        if not plan_id:
            return self._error_result(
                "Missing workspace_plan_id.",
                error_code="missing_workspace_plan_id",
            )

        validation = self._validate_task_context(context or {})
        if not validation["success"]:
            return validation

        workspace = self._workspace_store.get(plan_id)
        if not workspace:
            return self._error_result(
                "Workspace plan not found.",
                error_code="workspace_plan_not_found",
                metadata={"workspace_plan_id": plan_id},
            )

        user_id = _normalize_id((context or {}).get("user_id"))
        workspace_id = _normalize_id((context or {}).get("workspace_id"))
        if workspace.user_id != user_id or workspace.workspace_id != workspace_id:
            self._log_audit_event(
                action="workspace_isolation_violation",
                context=context,
                status="blocked",
                metadata={"requested_workspace_plan_id": plan_id},
            )
            return self._error_result(
                "Access denied for this workspace plan.",
                error_code="workspace_isolation_violation",
                metadata={"workspace_plan_id": plan_id},
            )

        return workspace

    # ------------------------------------------------------------------
    # Agent compatibility hooks
    # ------------------------------------------------------------------

    def _prepare_verification_payload(
        self,
        action: str,
        workspace: ResearchWorkspace,
        context: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Prepare payload for Verification Agent."""

        return {
            "verification_type": "browser_multi_tab_plan",
            "agent": self.agent_name,
            "action": action,
            "user_id": workspace.user_id,
            "workspace_id": workspace.workspace_id,
            "workspace_plan_id": workspace.workspace_plan_id,
            "checks": {
                "has_user_id": bool(workspace.user_id),
                "has_workspace_id": bool(workspace.workspace_id),
                "tab_count": len(workspace.tabs),
                "safe_url_schemes_only": all(
                    not tab.url or urlparse(tab.url).scheme in {"http", "https"}
                    for tab in workspace.tabs
                ),
                "no_direct_browser_execution": True,
                "structured_outputs": True,
            },
            "created_at": _utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        action: str,
        workspace: ResearchWorkspace,
        context: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Prepare safe memory payload without cross-user leakage."""

        return {
            "memory_type": "browser_research_workspace_plan",
            "agent": self.agent_name,
            "action": action,
            "user_id": workspace.user_id,
            "workspace_id": workspace.workspace_id,
            "workspace_plan_id": workspace.workspace_plan_id,
            "title": workspace.title,
            "objective": workspace.objective,
            "strategy": workspace.strategy,
            "tab_titles": [tab.title for tab in workspace.tabs],
            "tab_types": [tab.tab_type for tab in workspace.tabs],
            "created_at": _utc_now_iso(),
        }

    def _emit_agent_event(self, event_name: str, payload: Mapping[str, Any]) -> None:
        """Emit event for dashboard/task history if event emitter exists."""

        event = {
            "event": _safe_text(event_name, max_length=160),
            "agent": self.agent_name,
            "module": self.agent_type,
            "timestamp": _utc_now_iso(),
            "payload": self._safe_metadata(payload),
        }
        try:
            if self.event_emitter:
                self.event_emitter(event)
            logger.debug("Agent event emitted: %s", event)
        except Exception:
            logger.exception("Failed to emit agent event")

    def _log_audit_event(
        self,
        action: str,
        context: Optional[Mapping[str, Any]],
        status: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Write audit event through injected logger or standard logger."""

        audit_payload = {
            "agent": self.agent_name,
            "module": self.agent_type,
            "action": _safe_text(action, max_length=160),
            "status": _safe_text(status, max_length=80),
            "user_id": _normalize_id((context or {}).get("user_id")),
            "workspace_id": _normalize_id((context or {}).get("workspace_id")),
            "request_id": _safe_text((context or {}).get("request_id"), max_length=160),
            "metadata": self._safe_metadata(metadata),
            "timestamp": _utc_now_iso(),
        }
        try:
            if self.audit_logger:
                self.audit_logger(audit_payload)
            logger.info("Audit event: %s", audit_payload)
        except Exception:
            logger.exception("Failed to log audit event")

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard William/Jarvis success response."""

        return {
            "success": True,
            "message": _safe_text(message, max_length=1000),
            "data": dict(data or {}),
            "error": None,
            "metadata": self._safe_metadata(metadata),
        }

    def _error_result(
        self,
        message: str,
        error: Optional[BaseException] = None,
        error_code: str = "error",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard William/Jarvis error response."""

        safe_error = _safe_text(str(error), max_length=1000) if error else error_code
        payload = self._safe_metadata(metadata)
        payload["error_code"] = error_code
        return {
            "success": False,
            "message": _safe_text(message, max_length=1000),
            "data": {},
            "error": safe_error,
            "metadata": payload,
        }

    # ------------------------------------------------------------------
    # Internal misc
    # ------------------------------------------------------------------

    def _safe_metadata(self, metadata: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        """Return JSON-safe metadata with conservative sanitization."""

        if not isinstance(metadata, Mapping):
            return {}

        def sanitize(value: Any, depth: int = 0) -> Any:
            if depth > 4:
                return _safe_text(value, max_length=250)
            if isinstance(value, Mapping):
                return {
                    _safe_text(key, max_length=120): sanitize(item, depth + 1)
                    for key, item in value.items()
                    if _safe_text(key, max_length=120)
                }
            if isinstance(value, list):
                return [sanitize(item, depth + 1) for item in value[:100]]
            if isinstance(value, tuple):
                return [sanitize(item, depth + 1) for item in value[:100]]
            if isinstance(value, (str, int, float, bool)) or value is None:
                if isinstance(value, str):
                    return _safe_text(value, max_length=1000)
                return value
            return _safe_text(value, max_length=500)

        return sanitize(dict(metadata))

    def _build_isolation_key(self, user_id: str, workspace_id: str) -> str:
        """Build stable isolation key for in-memory workspace separation."""

        return _stable_hash(f"{user_id}:{workspace_id}", length=24)

    def _new_workspace_plan_id(self, user_id: str, workspace_id: str, title: str, objective: str) -> str:
        """Generate unique workspace plan ID."""

        seed = f"{user_id}:{workspace_id}:{title}:{objective}:{time.time()}:{uuid.uuid4()}"
        return f"mtw_{_stable_hash(seed, length=20)}"

    def _new_tab_id(self, workspace_plan_id: str, title: str, identity: str) -> str:
        """Generate stable-ish tab ID."""

        seed = f"{workspace_plan_id}:{title}:{identity}:{uuid.uuid4()}"
        return f"tab_{_stable_hash(seed, length=18)}"

    def _tab_fingerprint(self, tab: TabPlan) -> str:
        """Deduplicate tabs by url/query/type/title."""

        base = f"{tab.tab_type}|{tab.url or ''}|{tab.query or ''}|{tab.title.lower()}"
        return _stable_hash(base, length=24)

    def _prune_archived_workspaces(self) -> None:
        """Remove old archived/cancelled workspaces if memory store is full."""

        removable = [
            (key, workspace.updated_at)
            for key, workspace in self._workspace_store.items()
            if workspace.status in {"archived", "cancelled", "completed"}
        ]
        removable.sort(key=lambda item: item[1])
        for key, _ in removable[: max(1, len(removable) // 2)]:
            self._workspace_store.pop(key, None)


# ---------------------------------------------------------------------------
# Standalone smoke test helper
# ---------------------------------------------------------------------------

def _smoke_test() -> Dict[str, Any]:
    """Small import-safe smoke test used by developers."""

    planner = MultiTabPlanner(config={"max_tabs_per_workspace": 6})
    return planner.create_workspace_plan(
        task={
            "title": "AI Click Fraud Protection Research",
            "objective": "Research competitors and SEO angles for an AI click fraud protection SaaS.",
            "query": "AI click fraud protection software",
            "competitors": ["clickcease.com", "lunio.ai"],
            "strategy": "competitor",
        },
        context={"user_id": "demo_user", "workspace_id": "demo_workspace"},
    )


if __name__ == "__main__":  # pragma: no cover
    import json

    print(json.dumps(_smoke_test(), indent=2))


"""
Agent/Module: Browser Agent
File Completed: multi_tab_planner.py
Completion: 26.3%
Completed Files: ['browser_agent.py', 'search_engine.py', 'scraper.py', 'page_analyzer.py', 'multi_tab_planner.py']
Remaining Files: ['automation.py', 'browser_session.py', 'tab_manager.py', 'content_extractor.py', 'seo_analyzer.py', 'competitor_analyzer.py', 'price_monitor.py', 'workflow_learner.py', 'form_handler.py', 'download_manager.py', 'screenshot_tool.py', 'browser_memory.py', 'permissions.py', 'config.py']
Next Recommended File: agents/browser_agent/automation.py
FILE COMPLETE
"""
