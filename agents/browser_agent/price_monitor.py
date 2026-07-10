"""
William / Jarvis Multi-Agent AI SaaS System
Browser Agent - Price Monitor

File: agents/browser_agent/price_monitor.py
Class: PriceMonitor

Purpose:
    Track competitor pricing changes, discounts, features, and alerts.

Architecture Compatibility:
    - Master Agent routing compatible
    - BaseAgent compatible with safe fallback
    - SaaS user/workspace isolation
    - Security Agent approval hook for external fetch/monitor tasks
    - Memory Agent compatible payloads
    - Verification Agent compatible payloads
    - Dashboard/API-ready structured results
    - Audit/event logging hooks
    - Import-safe even if future William files are not created yet

Important:
    This module is designed to safely monitor publicly available competitor
    pricing pages. It does not bypass paywalls, authentication, CAPTCHAs, robots
    protections, or restricted/private areas.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Optional William / Jarvis imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe when the full William/Jarvis project
        structure is not available yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())


try:
    import requests  # type: ignore
    REQUESTS_AVAILABLE = True
except Exception:
    requests = None  # type: ignore
    REQUESTS_AVAILABLE = False


try:
    from bs4 import BeautifulSoup  # type: ignore
    BS4_AVAILABLE = True
except Exception:
    BeautifulSoup = None  # type: ignore
    BS4_AVAILABLE = False


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class PriceMonitorAction(str, Enum):
    """Supported PriceMonitor action names."""

    ADD_TARGET = "add_target"
    REMOVE_TARGET = "remove_target"
    LIST_TARGETS = "list_targets"
    CHECK_TARGET = "check_target"
    CHECK_ALL = "check_all"
    GET_HISTORY = "get_history"
    GET_ALERTS = "get_alerts"
    CLEAR_ALERTS = "clear_alerts"
    COMPARE_SNAPSHOTS = "compare_snapshots"


class PriceChangeType(str, Enum):
    """Detected price change type."""

    INCREASE = "increase"
    DECREASE = "decrease"
    UNCHANGED = "unchanged"
    NEW_PRICE = "new_price"
    REMOVED_PRICE = "removed_price"
    UNKNOWN = "unknown"


class AlertSeverity(str, Enum):
    """Dashboard alert severity."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MonitorRiskLevel(str, Enum):
    """Risk level for Security Agent and audit logging."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class PriceMonitorConfig:
    """
    Configuration for PriceMonitor.

    Defaults are safe for SaaS use and public-page monitoring.
    """

    storage_dir: str = "storage/browser_price_monitor"
    request_timeout_seconds: int = 20
    user_agent: str = (
        "WilliamJarvisPriceMonitor/1.0 "
        "(public pricing monitor; contact Digital Promotix)"
    )

    allow_external_urls: bool = True
    allowed_domains: List[str] = field(default_factory=list)
    blocked_domains: List[str] = field(default_factory=list)

    max_targets_per_workspace: int = 200
    max_history_per_target: int = 100
    max_alerts_per_workspace: int = 500

    min_price_change_percent_for_alert: float = 5.0
    min_absolute_price_change_for_alert: float = 1.0

    require_security_for_external_fetch: bool = False
    require_security_for_target_changes: bool = False

    audit_enabled: bool = True
    event_enabled: bool = True
    memory_enabled: bool = True
    verification_enabled: bool = True

    save_to_disk: bool = True
    dry_run: bool = False

    default_currency: str = "USD"


@dataclass
class PriceMonitorRequest:
    """
    Normalized request object for Master Agent / Router / API compatibility.
    """

    action: PriceMonitorAction
    user_id: Union[str, int]
    workspace_id: Union[str, int]
    target_id: Optional[str] = None
    url: Optional[str] = None
    competitor_name: Optional[str] = None
    product_name: Optional[str] = None
    selectors: Dict[str, str] = field(default_factory=dict)
    html: Optional[str] = None
    snapshot_a: Optional[Dict[str, Any]] = None
    snapshot_b: Optional[Dict[str, Any]] = None
    options: Dict[str, Any] = field(default_factory=dict)
    task_id: Optional[str] = None
    approval_token: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MonitorTarget:
    """A competitor pricing page or product pricing target."""

    target_id: str
    user_id: Union[str, int]
    workspace_id: Union[str, int]
    competitor_name: str
    product_name: str
    url: str
    selectors: Dict[str, str] = field(default_factory=dict)
    currency: str = "USD"
    active: bool = True
    created_at: str = ""
    updated_at: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PriceSnapshot:
    """A captured pricing snapshot."""

    snapshot_id: str
    target_id: str
    user_id: Union[str, int]
    workspace_id: Union[str, int]
    competitor_name: str
    product_name: str
    url: str
    price: Optional[float]
    currency: str
    discount_text: Optional[str]
    features: List[str]
    raw_prices: List[str]
    page_title: Optional[str]
    content_hash: str
    captured_at: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PriceChange:
    """Comparison between two snapshots."""

    change_id: str
    target_id: str
    user_id: Union[str, int]
    workspace_id: Union[str, int]
    competitor_name: str
    product_name: str
    previous_price: Optional[float]
    current_price: Optional[float]
    currency: str
    change_type: PriceChangeType
    absolute_change: Optional[float]
    percent_change: Optional[float]
    discount_changed: bool
    previous_discount: Optional[str]
    current_discount: Optional[str]
    added_features: List[str]
    removed_features: List[str]
    changed_at: str
    severity: AlertSeverity
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PriceAlert:
    """Dashboard/API alert generated by PriceMonitor."""

    alert_id: str
    change_id: str
    target_id: str
    user_id: Union[str, int]
    workspace_id: Union[str, int]
    competitor_name: str
    product_name: str
    title: str
    message: str
    severity: AlertSeverity
    created_at: str
    acknowledged: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# PriceMonitor
# ---------------------------------------------------------------------------

class PriceMonitor(BaseAgent):
    """
    Production-ready competitor price monitor for William/Jarvis Browser Agent.

    Responsibilities:
        - Register competitor pricing targets
        - Fetch public pricing pages safely
        - Extract prices, discounts, and feature text
        - Store snapshots per user/workspace
        - Compare latest snapshots
        - Generate alerts for changes
        - Prepare Memory/Verification payloads
        - Emit audit/dashboard events

    Public methods are structured for:
        - Master Agent
        - Agent Router
        - FastAPI routes
        - Dashboard panels
        - Scheduled jobs
    """

    BLOCKED_SCHEMES: Tuple[str, ...] = (
        "file",
        "ftp",
        "javascript",
        "data",
    )

    PRICE_REGEX = re.compile(
        r"(?P<currency_symbol>[$£€₹]|AED|USD|EUR|GBP|CAD|AUD|PKR|INR)?\s*"
        r"(?P<amount>\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?|\d+(?:\.\d{1,2})?)"
        r"\s*(?P<currency_code>USD|EUR|GBP|CAD|AUD|AED|PKR|INR)?",
        re.IGNORECASE,
    )

    DISCOUNT_REGEX = re.compile(
        r"(\d{1,3}\s?%\s?(off|discount|save)|"
        r"save\s?[$£€₹]?\s?\d+(?:\.\d{1,2})?|"
        r"limited\s*time|sale|special\s?offer|promo|coupon|deal)",
        re.IGNORECASE,
    )

    FEATURE_HINTS = (
        "feature",
        "included",
        "includes",
        "unlimited",
        "support",
        "users",
        "seat",
        "storage",
        "dashboard",
        "analytics",
        "integration",
        "automation",
        "api",
        "report",
        "tracking",
        "protection",
        "monitoring",
        "security",
    )

    CURRENCY_SYMBOL_MAP = {
        "$": "USD",
        "£": "GBP",
        "€": "EUR",
        "₹": "INR",
    }

    def __init__(
        self,
        config: Optional[PriceMonitorConfig] = None,
        security_approval_callback: Optional[
            Callable[[Dict[str, Any]], Union[bool, Dict[str, Any], Awaitable[Union[bool, Dict[str, Any]]]]]
        ] = None,
        audit_callback: Optional[
            Callable[[Dict[str, Any]], Union[None, Awaitable[None]]]
        ] = None,
        event_callback: Optional[
            Callable[[Dict[str, Any]], Union[None, Awaitable[None]]]
        ] = None,
        memory_callback: Optional[
            Callable[[Dict[str, Any]], Union[None, Awaitable[None]]]
        ] = None,
        verification_callback: Optional[
            Callable[[Dict[str, Any]], Union[None, Awaitable[None]]]
        ] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name="PriceMonitor", agent_id="price_monitor", **kwargs)

        self.config = config or PriceMonitorConfig()
        self.security_approval_callback = security_approval_callback
        self.audit_callback = audit_callback
        self.event_callback = event_callback
        self.memory_callback = memory_callback
        self.verification_callback = verification_callback

        self._targets: Dict[str, MonitorTarget] = {}
        self._snapshots: Dict[str, List[PriceSnapshot]] = {}
        self._changes: Dict[str, List[PriceChange]] = {}
        self._alerts: Dict[str, List[PriceAlert]] = {}

        self._ensure_storage_dirs()
        self._load_state_from_disk()

    # -----------------------------------------------------------------------
    # Main Router Entry
    # -----------------------------------------------------------------------

    async def run_action(self, request: Union[PriceMonitorRequest, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Master Agent / Agent Router compatible entry point.
        """

        try:
            normalized = self._normalize_request(request)
        except Exception as exc:
            return self._error_result(
                message="Invalid PriceMonitor request.",
                error=str(exc),
                error_code="INVALID_PRICE_MONITOR_REQUEST",
            )

        validation = self._validate_task_context(normalized)
        if not validation["success"]:
            return validation

        if normalized.action == PriceMonitorAction.ADD_TARGET:
            return await self.add_target(
                user_id=normalized.user_id,
                workspace_id=normalized.workspace_id,
                url=normalized.url or "",
                competitor_name=normalized.competitor_name or "",
                product_name=normalized.product_name or "",
                selectors=normalized.selectors,
                options=normalized.options,
                task_id=normalized.task_id,
                approval_token=normalized.approval_token,
                metadata=normalized.metadata,
            )

        if normalized.action == PriceMonitorAction.REMOVE_TARGET:
            return await self.remove_target(
                user_id=normalized.user_id,
                workspace_id=normalized.workspace_id,
                target_id=normalized.target_id or "",
                task_id=normalized.task_id,
                approval_token=normalized.approval_token,
                metadata=normalized.metadata,
            )

        if normalized.action == PriceMonitorAction.LIST_TARGETS:
            return await self.list_targets(
                user_id=normalized.user_id,
                workspace_id=normalized.workspace_id,
                options=normalized.options,
                task_id=normalized.task_id,
                metadata=normalized.metadata,
            )

        if normalized.action == PriceMonitorAction.CHECK_TARGET:
            return await self.check_target(
                user_id=normalized.user_id,
                workspace_id=normalized.workspace_id,
                target_id=normalized.target_id or "",
                html=normalized.html,
                options=normalized.options,
                task_id=normalized.task_id,
                approval_token=normalized.approval_token,
                metadata=normalized.metadata,
            )

        if normalized.action == PriceMonitorAction.CHECK_ALL:
            return await self.check_all_targets(
                user_id=normalized.user_id,
                workspace_id=normalized.workspace_id,
                options=normalized.options,
                task_id=normalized.task_id,
                approval_token=normalized.approval_token,
                metadata=normalized.metadata,
            )

        if normalized.action == PriceMonitorAction.GET_HISTORY:
            return await self.get_history(
                user_id=normalized.user_id,
                workspace_id=normalized.workspace_id,
                target_id=normalized.target_id,
                options=normalized.options,
                task_id=normalized.task_id,
                metadata=normalized.metadata,
            )

        if normalized.action == PriceMonitorAction.GET_ALERTS:
            return await self.get_alerts(
                user_id=normalized.user_id,
                workspace_id=normalized.workspace_id,
                options=normalized.options,
                task_id=normalized.task_id,
                metadata=normalized.metadata,
            )

        if normalized.action == PriceMonitorAction.CLEAR_ALERTS:
            return await self.clear_alerts(
                user_id=normalized.user_id,
                workspace_id=normalized.workspace_id,
                options=normalized.options,
                task_id=normalized.task_id,
                metadata=normalized.metadata,
            )

        if normalized.action == PriceMonitorAction.COMPARE_SNAPSHOTS:
            return await self.compare_snapshot_dicts(
                user_id=normalized.user_id,
                workspace_id=normalized.workspace_id,
                snapshot_a=normalized.snapshot_a or {},
                snapshot_b=normalized.snapshot_b or {},
                task_id=normalized.task_id,
                metadata=normalized.metadata,
            )

        return self._error_result(
            message=f"Unsupported PriceMonitor action: {normalized.action}",
            error_code="UNSUPPORTED_PRICE_MONITOR_ACTION",
        )

    # -----------------------------------------------------------------------
    # Public Methods
    # -----------------------------------------------------------------------

    async def add_target(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        url: str,
        competitor_name: str,
        product_name: str,
        selectors: Optional[Dict[str, str]] = None,
        options: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
        approval_token: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Add a competitor pricing target for a user/workspace.
        """

        started_at = self._utc_now()
        request = PriceMonitorRequest(
            action=PriceMonitorAction.ADD_TARGET,
            user_id=user_id,
            workspace_id=workspace_id,
            url=url,
            competitor_name=competitor_name,
            product_name=product_name,
            selectors=selectors or {},
            options=options or {},
            task_id=task_id,
            approval_token=approval_token,
            metadata=metadata or {},
        )

        validation = self._validate_task_context(request)
        if not validation["success"]:
            return validation

        url_validation = self._validate_url(url)
        if not url_validation["success"]:
            return url_validation

        if not competitor_name.strip():
            return self._error_result(
                message="competitor_name is required.",
                error_code="MISSING_COMPETITOR_NAME",
            )

        if not product_name.strip():
            return self._error_result(
                message="product_name is required.",
                error_code="MISSING_PRODUCT_NAME",
            )

        workspace_key = self._workspace_key(user_id, workspace_id)
        existing_targets = [
            target for target in self._targets.values()
            if self._same_context(target.user_id, target.workspace_id, user_id, workspace_id)
        ]

        if len(existing_targets) >= self.config.max_targets_per_workspace:
            return self._error_result(
                message="Maximum targets reached for this workspace.",
                error_code="MAX_TARGETS_REACHED",
                metadata={
                    "max_targets_per_workspace": self.config.max_targets_per_workspace,
                },
            )

        risk_level = self._assess_risk(request)
        approval = await self._maybe_request_security_approval(request, risk_level)
        if not approval["success"]:
            return approval

        if self.config.dry_run or request.options.get("dry_run"):
            return self._safe_result(
                message="Dry-run: target validated but not added.",
                data={
                    "url": url,
                    "competitor_name": competitor_name,
                    "product_name": product_name,
                    "dry_run": True,
                },
                metadata=self._base_metadata(request, started_at, risk_level),
            )

        target_id = request.options.get("target_id") or self._new_id("target")
        now = self._utc_now()

        target = MonitorTarget(
            target_id=target_id,
            user_id=user_id,
            workspace_id=workspace_id,
            competitor_name=competitor_name.strip(),
            product_name=product_name.strip(),
            url=url.strip(),
            selectors=selectors or {},
            currency=str(request.options.get("currency") or self.config.default_currency).upper(),
            active=bool(request.options.get("active", True)),
            created_at=now,
            updated_at=now,
            metadata={
                **(metadata or {}),
                "workspace_key": workspace_key,
            },
        )

        self._targets[target_id] = target
        self._persist_state()

        result = self._safe_result(
            message="Price monitor target added successfully.",
            data={
                "target": asdict(target),
            },
            metadata=self._base_metadata(request, started_at, risk_level),
        )

        await self._after_action(request, result, risk_level)
        return result

    async def remove_target(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        target_id: str,
        task_id: Optional[str] = None,
        approval_token: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Deactivate/remove a target for this user/workspace.
        """

        started_at = self._utc_now()
        request = PriceMonitorRequest(
            action=PriceMonitorAction.REMOVE_TARGET,
            user_id=user_id,
            workspace_id=workspace_id,
            target_id=target_id,
            task_id=task_id,
            approval_token=approval_token,
            metadata=metadata or {},
        )

        validation = self._validate_task_context(request)
        if not validation["success"]:
            return validation

        risk_level = self._assess_risk(request)
        approval = await self._maybe_request_security_approval(request, risk_level)
        if not approval["success"]:
            return approval

        target = self._get_target_for_context(target_id, user_id, workspace_id)
        if target is None:
            return self._error_result(
                message="Target not found for this user/workspace.",
                error_code="TARGET_NOT_FOUND",
            )

        target.active = False
        target.updated_at = self._utc_now()
        self._targets[target_id] = target
        self._persist_state()

        result = self._safe_result(
            message="Price monitor target deactivated successfully.",
            data={
                "target": asdict(target),
            },
            metadata=self._base_metadata(request, started_at, risk_level),
        )

        await self._after_action(request, result, risk_level)
        return result

    async def list_targets(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        options: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        List targets for this user/workspace only.
        """

        started_at = self._utc_now()
        options = options or {}

        request = PriceMonitorRequest(
            action=PriceMonitorAction.LIST_TARGETS,
            user_id=user_id,
            workspace_id=workspace_id,
            options=options,
            task_id=task_id,
            metadata=metadata or {},
        )

        validation = self._validate_task_context(request)
        if not validation["success"]:
            return validation

        include_inactive = bool(options.get("include_inactive", False))

        targets = []
        for target in self._targets.values():
            if not self._same_context(target.user_id, target.workspace_id, user_id, workspace_id):
                continue
            if not include_inactive and not target.active:
                continue
            targets.append(asdict(target))

        result = self._safe_result(
            message="Price monitor targets fetched successfully.",
            data={
                "count": len(targets),
                "targets": targets,
            },
            metadata=self._base_metadata(request, started_at, MonitorRiskLevel.LOW),
        )

        await self._after_action(request, result, MonitorRiskLevel.LOW)
        return result

    async def check_target(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        target_id: str,
        html: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
        approval_token: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Check one competitor price target, create a snapshot, compare with the
        previous snapshot, and generate alerts when meaningful changes occur.
        """

        started_at = self._utc_now()
        options = options or {}

        request = PriceMonitorRequest(
            action=PriceMonitorAction.CHECK_TARGET,
            user_id=user_id,
            workspace_id=workspace_id,
            target_id=target_id,
            html=html,
            options=options,
            task_id=task_id,
            approval_token=approval_token,
            metadata=metadata or {},
        )

        validation = self._validate_task_context(request)
        if not validation["success"]:
            return validation

        target = self._get_target_for_context(target_id, user_id, workspace_id)
        if target is None:
            return self._error_result(
                message="Target not found for this user/workspace.",
                error_code="TARGET_NOT_FOUND",
            )

        if not target.active and not options.get("allow_inactive"):
            return self._error_result(
                message="Target is inactive.",
                error_code="TARGET_INACTIVE",
            )

        risk_level = self._assess_risk(request)
        approval = await self._maybe_request_security_approval(request, risk_level)
        if not approval["success"]:
            return approval

        if self.config.dry_run or options.get("dry_run"):
            return self._safe_result(
                message="Dry-run: target check validated but not executed.",
                data={
                    "target_id": target_id,
                    "url": target.url,
                    "dry_run": True,
                },
                metadata=self._base_metadata(request, started_at, risk_level),
            )

        if html is None:
            fetch_result = await self._fetch_public_page(target.url)
            if not fetch_result["success"]:
                return fetch_result
            html = str(fetch_result["data"].get("html", ""))

        snapshot = self._extract_snapshot_from_html(
            target=target,
            html=html or "",
            metadata={
                "source": "provided_html" if request.html is not None else "fetched_url",
                "task_id": task_id,
            },
        )

        history = self._snapshots.setdefault(target.target_id, [])
        previous_snapshot = history[-1] if history else None

        history.append(snapshot)
        self._snapshots[target.target_id] = history[-self.config.max_history_per_target:]

        change: Optional[PriceChange] = None
        alert: Optional[PriceAlert] = None

        if previous_snapshot is not None:
            change = self._compare_snapshots(previous_snapshot, snapshot)
            self._changes.setdefault(target.target_id, []).append(change)

            if self._should_create_alert(change):
                alert = self._create_alert_from_change(change)
                workspace_key = self._workspace_key(user_id, workspace_id)
                alerts = self._alerts.setdefault(workspace_key, [])
                alerts.append(alert)
                self._alerts[workspace_key] = alerts[-self.config.max_alerts_per_workspace:]

        self._persist_state()

        result = self._safe_result(
            message="Price target checked successfully.",
            data={
                "target": asdict(target),
                "snapshot": asdict(snapshot),
                "change": asdict(change) if change else None,
                "alert": asdict(alert) if alert else None,
                "previous_snapshot_id": previous_snapshot.snapshot_id if previous_snapshot else None,
            },
            metadata=self._base_metadata(request, started_at, risk_level),
        )

        await self._after_action(request, result, risk_level)
        return result

    async def check_all_targets(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        options: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
        approval_token: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Check all active targets for a user/workspace.
        """

        started_at = self._utc_now()
        options = options or {}

        request = PriceMonitorRequest(
            action=PriceMonitorAction.CHECK_ALL,
            user_id=user_id,
            workspace_id=workspace_id,
            options=options,
            task_id=task_id,
            approval_token=approval_token,
            metadata=metadata or {},
        )

        validation = self._validate_task_context(request)
        if not validation["success"]:
            return validation

        risk_level = self._assess_risk(request)
        approval = await self._maybe_request_security_approval(request, risk_level)
        if not approval["success"]:
            return approval

        targets = [
            target for target in self._targets.values()
            if self._same_context(target.user_id, target.workspace_id, user_id, workspace_id)
            and target.active
        ]

        max_targets = int(options.get("max_targets", len(targets)))
        max_targets = max(1, min(max_targets, len(targets))) if targets else 0

        results = []
        for target in targets[:max_targets]:
            check_result = await self.check_target(
                user_id=user_id,
                workspace_id=workspace_id,
                target_id=target.target_id,
                options={
                    **options,
                    "dry_run": options.get("dry_run", False),
                },
                task_id=task_id,
                approval_token=approval_token,
                metadata={
                    **(metadata or {}),
                    "bulk_check": True,
                },
            )
            results.append(check_result)

            delay_seconds = float(options.get("delay_seconds", 0))
            if delay_seconds > 0:
                await asyncio.sleep(delay_seconds)

        success_count = sum(1 for item in results if item.get("success"))
        failure_count = len(results) - success_count

        result = self._safe_result(
            success=failure_count == 0,
            message="All active price targets checked." if failure_count == 0 else "Price target bulk check completed with issues.",
            data={
                "checked_count": len(results),
                "success_count": success_count,
                "failure_count": failure_count,
                "results": results,
            },
            metadata=self._base_metadata(request, started_at, risk_level),
        )

        await self._after_action(request, result, risk_level)
        return result

    async def get_history(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        target_id: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Get snapshot and change history for this user/workspace.
        """

        started_at = self._utc_now()
        options = options or {}
        limit = max(1, min(int(options.get("limit", 50)), 500))

        request = PriceMonitorRequest(
            action=PriceMonitorAction.GET_HISTORY,
            user_id=user_id,
            workspace_id=workspace_id,
            target_id=target_id,
            options=options,
            task_id=task_id,
            metadata=metadata or {},
        )

        validation = self._validate_task_context(request)
        if not validation["success"]:
            return validation

        target_ids = []
        if target_id:
            target = self._get_target_for_context(target_id, user_id, workspace_id)
            if target is None:
                return self._error_result(
                    message="Target not found for this user/workspace.",
                    error_code="TARGET_NOT_FOUND",
                )
            target_ids = [target_id]
        else:
            target_ids = [
                target.target_id for target in self._targets.values()
                if self._same_context(target.user_id, target.workspace_id, user_id, workspace_id)
            ]

        snapshots: List[Dict[str, Any]] = []
        changes: List[Dict[str, Any]] = []

        for tid in target_ids:
            snapshots.extend([asdict(item) for item in self._snapshots.get(tid, [])])
            changes.extend([asdict(item) for item in self._changes.get(tid, [])])

        snapshots = sorted(snapshots, key=lambda item: item.get("captured_at", ""), reverse=True)[:limit]
        changes = sorted(changes, key=lambda item: item.get("changed_at", ""), reverse=True)[:limit]

        result = self._safe_result(
            message="Price monitor history fetched successfully.",
            data={
                "target_id": target_id,
                "snapshot_count": len(snapshots),
                "change_count": len(changes),
                "snapshots": snapshots,
                "changes": changes,
            },
            metadata=self._base_metadata(request, started_at, MonitorRiskLevel.LOW),
        )

        await self._after_action(request, result, MonitorRiskLevel.LOW)
        return result

    async def get_alerts(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        options: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Get alerts for this user/workspace.
        """

        started_at = self._utc_now()
        options = options or {}

        request = PriceMonitorRequest(
            action=PriceMonitorAction.GET_ALERTS,
            user_id=user_id,
            workspace_id=workspace_id,
            options=options,
            task_id=task_id,
            metadata=metadata or {},
        )

        validation = self._validate_task_context(request)
        if not validation["success"]:
            return validation

        workspace_key = self._workspace_key(user_id, workspace_id)
        include_acknowledged = bool(options.get("include_acknowledged", False))
        limit = max(1, min(int(options.get("limit", 100)), 500))

        alerts = self._alerts.get(workspace_key, [])
        if not include_acknowledged:
            alerts = [alert for alert in alerts if not alert.acknowledged]

        alert_dicts = [asdict(alert) for alert in alerts]
        alert_dicts = sorted(alert_dicts, key=lambda item: item.get("created_at", ""), reverse=True)[:limit]

        result = self._safe_result(
            message="Price monitor alerts fetched successfully.",
            data={
                "count": len(alert_dicts),
                "alerts": alert_dicts,
            },
            metadata=self._base_metadata(request, started_at, MonitorRiskLevel.LOW),
        )

        await self._after_action(request, result, MonitorRiskLevel.LOW)
        return result

    async def clear_alerts(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        options: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Acknowledge or clear alerts for this user/workspace.
        """

        started_at = self._utc_now()
        options = options or {}

        request = PriceMonitorRequest(
            action=PriceMonitorAction.CLEAR_ALERTS,
            user_id=user_id,
            workspace_id=workspace_id,
            options=options,
            task_id=task_id,
            metadata=metadata or {},
        )

        validation = self._validate_task_context(request)
        if not validation["success"]:
            return validation

        workspace_key = self._workspace_key(user_id, workspace_id)
        mode = str(options.get("mode", "acknowledge")).lower().strip()
        alerts = self._alerts.get(workspace_key, [])

        if mode == "delete":
            cleared_count = len(alerts)
            self._alerts[workspace_key] = []
        else:
            cleared_count = 0
            for alert in alerts:
                if not alert.acknowledged:
                    alert.acknowledged = True
                    cleared_count += 1
            self._alerts[workspace_key] = alerts

        self._persist_state()

        result = self._safe_result(
            message="Price monitor alerts updated successfully.",
            data={
                "mode": mode,
                "cleared_count": cleared_count,
            },
            metadata=self._base_metadata(request, started_at, MonitorRiskLevel.LOW),
        )

        await self._after_action(request, result, MonitorRiskLevel.LOW)
        return result

    async def compare_snapshot_dicts(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        snapshot_a: Dict[str, Any],
        snapshot_b: Dict[str, Any],
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Compare two snapshot dictionaries without saving them.
        """

        started_at = self._utc_now()

        request = PriceMonitorRequest(
            action=PriceMonitorAction.COMPARE_SNAPSHOTS,
            user_id=user_id,
            workspace_id=workspace_id,
            snapshot_a=snapshot_a,
            snapshot_b=snapshot_b,
            task_id=task_id,
            metadata=metadata or {},
        )

        validation = self._validate_task_context(request)
        if not validation["success"]:
            return validation

        try:
            previous = self._snapshot_from_dict(snapshot_a)
            current = self._snapshot_from_dict(snapshot_b)

            if not self._same_context(previous.user_id, previous.workspace_id, user_id, workspace_id):
                return self._error_result(
                    message="snapshot_a does not belong to this user/workspace.",
                    error_code="SNAPSHOT_CONTEXT_MISMATCH",
                )

            if not self._same_context(current.user_id, current.workspace_id, user_id, workspace_id):
                return self._error_result(
                    message="snapshot_b does not belong to this user/workspace.",
                    error_code="SNAPSHOT_CONTEXT_MISMATCH",
                )

            change = self._compare_snapshots(previous, current)

            result = self._safe_result(
                message="Snapshots compared successfully.",
                data={
                    "change": asdict(change),
                },
                metadata=self._base_metadata(request, started_at, MonitorRiskLevel.LOW),
            )

            await self._after_action(request, result, MonitorRiskLevel.LOW)
            return result

        except Exception as exc:
            return self._error_result(
                message="Failed to compare snapshots.",
                error=str(exc),
                error_code="SNAPSHOT_COMPARE_FAILED",
                metadata=self._base_metadata(request, started_at, MonitorRiskLevel.LOW),
            )

    # -----------------------------------------------------------------------
    # Extraction Logic
    # -----------------------------------------------------------------------

    def _extract_snapshot_from_html(
        self,
        target: MonitorTarget,
        html: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PriceSnapshot:
        """
        Extract pricing snapshot from raw HTML.

        Uses configured selectors when available, then safe regex fallback.
        """

        metadata = metadata or {}
        text = self._html_to_text(html)
        page_title = self._extract_title(html)

        selected_price_text = self._extract_with_selector(html, target.selectors.get("price"))
        selected_discount_text = self._extract_with_selector(html, target.selectors.get("discount"))
        selected_features_text = self._extract_multiple_with_selector(html, target.selectors.get("features"))

        raw_prices = self._extract_raw_prices(selected_price_text or text)
        price, currency = self._normalize_best_price(raw_prices, target.currency)

        discount_text = selected_discount_text or self._extract_discount_text(text)
        features = selected_features_text or self._extract_features(text)

        content_hash = hashlib.sha256(
            json.dumps(
                {
                    "price": price,
                    "currency": currency,
                    "discount_text": discount_text,
                    "features": features,
                    "title": page_title,
                },
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()

        return PriceSnapshot(
            snapshot_id=self._new_id("snapshot"),
            target_id=target.target_id,
            user_id=target.user_id,
            workspace_id=target.workspace_id,
            competitor_name=target.competitor_name,
            product_name=target.product_name,
            url=target.url,
            price=price,
            currency=currency,
            discount_text=discount_text,
            features=features,
            raw_prices=raw_prices,
            page_title=page_title,
            content_hash=content_hash,
            captured_at=self._utc_now(),
            metadata={
                **metadata,
                "extraction_method": "selector_plus_regex",
                "raw_price_count": len(raw_prices),
                "feature_count": len(features),
            },
        )

    def _html_to_text(self, html: str) -> str:
        """Convert HTML to readable text safely."""

        if not html:
            return ""

        if BS4_AVAILABLE and BeautifulSoup is not None:
            try:
                soup = BeautifulSoup(html, "html.parser")
                for tag in soup(["script", "style", "noscript", "svg"]):
                    tag.extract()
                return soup.get_text(separator="\n", strip=True)
            except Exception:
                pass

        cleaned = re.sub(r"<script.*?</script>", " ", html, flags=re.IGNORECASE | re.DOTALL)
        cleaned = re.sub(r"<style.*?</style>", " ", cleaned, flags=re.IGNORECASE | re.DOTALL)
        cleaned = re.sub(r"<[^>]+>", " ", cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned)
        return cleaned.strip()

    def _extract_title(self, html: str) -> Optional[str]:
        """Extract page title."""

        if not html:
            return None

        if BS4_AVAILABLE and BeautifulSoup is not None:
            try:
                soup = BeautifulSoup(html, "html.parser")
                if soup.title and soup.title.string:
                    return soup.title.string.strip()
            except Exception:
                pass

        match = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
        if match:
            return re.sub(r"\s+", " ", match.group(1)).strip()
        return None

    def _extract_with_selector(self, html: str, selector: Optional[str]) -> Optional[str]:
        """Extract text using CSS selector if BeautifulSoup is available."""

        if not html or not selector or not BS4_AVAILABLE or BeautifulSoup is None:
            return None

        try:
            soup = BeautifulSoup(html, "html.parser")
            element = soup.select_one(selector)
            if element:
                return element.get_text(" ", strip=True)
        except Exception as exc:
            logger.debug("Selector extraction failed for %s: %s", selector, exc)

        return None

    def _extract_multiple_with_selector(self, html: str, selector: Optional[str]) -> List[str]:
        """Extract multiple feature texts using CSS selector."""

        if not html or not selector or not BS4_AVAILABLE or BeautifulSoup is None:
            return []

        try:
            soup = BeautifulSoup(html, "html.parser")
            elements = soup.select(selector)
            values = []
            for element in elements:
                value = element.get_text(" ", strip=True)
                if value and len(value) >= 3:
                    values.append(value)
            return self._dedupe_keep_order(values)[:50]
        except Exception as exc:
            logger.debug("Multi-selector extraction failed for %s: %s", selector, exc)
            return []

    def _extract_raw_prices(self, text: str) -> List[str]:
        """Extract raw price strings from text."""

        if not text:
            return []

        matches = []
        for match in self.PRICE_REGEX.finditer(text):
            raw = match.group(0).strip()
            amount = match.group("amount")
            if not amount:
                continue

            value = self._to_float(amount)
            if value is None:
                continue

            if value <= 0 or value > 1_000_000:
                continue

            if len(raw) <= 1:
                continue

            matches.append(raw)

        return self._dedupe_keep_order(matches)[:30]

    def _normalize_best_price(
        self,
        raw_prices: List[str],
        default_currency: str,
    ) -> Tuple[Optional[float], str]:
        """
        Pick best/lowest usable price from extracted prices.

        For pricing pages, the first/lowest visible plan price is usually the
        most useful baseline for competitor monitoring.
        """

        parsed_prices: List[Tuple[float, str]] = []

        for raw in raw_prices:
            match = self.PRICE_REGEX.search(raw)
            if not match:
                continue

            amount = match.group("amount")
            value = self._to_float(amount)
            if value is None:
                continue

            currency_symbol = (match.group("currency_symbol") or "").upper()
            currency_code = (match.group("currency_code") or "").upper()

            currency = currency_code or self.CURRENCY_SYMBOL_MAP.get(currency_symbol, default_currency)
            parsed_prices.append((value, currency.upper()))

        if not parsed_prices:
            return None, default_currency.upper()

        best_price = min(parsed_prices, key=lambda item: item[0])
        return best_price[0], best_price[1]

    def _extract_discount_text(self, text: str) -> Optional[str]:
        """Extract discount or promo text."""

        if not text:
            return None

        matches = []
        for match in self.DISCOUNT_REGEX.finditer(text):
            value = match.group(0).strip()
            if value and len(value) >= 3:
                matches.append(value)

        matches = self._dedupe_keep_order(matches)
        return matches[0] if matches else None

    def _extract_features(self, text: str) -> List[str]:
        """
        Extract feature-like lines from page text.
        """

        if not text:
            return []

        lines = [re.sub(r"\s+", " ", line).strip() for line in text.splitlines()]
        lines = [line for line in lines if 4 <= len(line) <= 180]

        feature_lines = []
        for line in lines:
            lower = line.lower()
            if any(hint in lower for hint in self.FEATURE_HINTS):
                feature_lines.append(line)

        return self._dedupe_keep_order(feature_lines)[:50]

    # -----------------------------------------------------------------------
    # Comparison + Alerts
    # -----------------------------------------------------------------------

    def _compare_snapshots(
        self,
        previous: PriceSnapshot,
        current: PriceSnapshot,
    ) -> PriceChange:
        """Compare two snapshots and return structured change object."""

        previous_price = previous.price
        current_price = current.price

        change_type = PriceChangeType.UNKNOWN
        absolute_change: Optional[float] = None
        percent_change: Optional[float] = None

        if previous_price is None and current_price is not None:
            change_type = PriceChangeType.NEW_PRICE
        elif previous_price is not None and current_price is None:
            change_type = PriceChangeType.REMOVED_PRICE
        elif previous_price is not None and current_price is not None:
            absolute_change = round(current_price - previous_price, 4)
            if previous_price != 0:
                percent_change = round((absolute_change / previous_price) * 100, 4)

            if absolute_change > 0:
                change_type = PriceChangeType.INCREASE
            elif absolute_change < 0:
                change_type = PriceChangeType.DECREASE
            else:
                change_type = PriceChangeType.UNCHANGED

        previous_features = set(self._normalize_feature_list(previous.features))
        current_features = set(self._normalize_feature_list(current.features))

        added_features = sorted(list(current_features - previous_features))
        removed_features = sorted(list(previous_features - current_features))

        discount_changed = (previous.discount_text or "") != (current.discount_text or "")
        severity = self._calculate_severity(
            change_type=change_type,
            absolute_change=absolute_change,
            percent_change=percent_change,
            discount_changed=discount_changed,
            added_features=added_features,
            removed_features=removed_features,
        )

        return PriceChange(
            change_id=self._new_id("change"),
            target_id=current.target_id,
            user_id=current.user_id,
            workspace_id=current.workspace_id,
            competitor_name=current.competitor_name,
            product_name=current.product_name,
            previous_price=previous_price,
            current_price=current_price,
            currency=current.currency,
            change_type=change_type,
            absolute_change=absolute_change,
            percent_change=percent_change,
            discount_changed=discount_changed,
            previous_discount=previous.discount_text,
            current_discount=current.discount_text,
            added_features=added_features,
            removed_features=removed_features,
            changed_at=self._utc_now(),
            severity=severity,
            metadata={
                "previous_snapshot_id": previous.snapshot_id,
                "current_snapshot_id": current.snapshot_id,
                "content_changed": previous.content_hash != current.content_hash,
            },
        )

    def _calculate_severity(
        self,
        change_type: PriceChangeType,
        absolute_change: Optional[float],
        percent_change: Optional[float],
        discount_changed: bool,
        added_features: List[str],
        removed_features: List[str],
    ) -> AlertSeverity:
        """Calculate alert severity from change details."""

        if change_type in {PriceChangeType.NEW_PRICE, PriceChangeType.REMOVED_PRICE}:
            return AlertSeverity.MEDIUM

        if percent_change is not None:
            abs_percent = abs(percent_change)
            if abs_percent >= 30:
                return AlertSeverity.CRITICAL
            if abs_percent >= 15:
                return AlertSeverity.HIGH
            if abs_percent >= self.config.min_price_change_percent_for_alert:
                return AlertSeverity.MEDIUM

        if absolute_change is not None:
            if abs(absolute_change) >= 100:
                return AlertSeverity.HIGH
            if abs(absolute_change) >= self.config.min_absolute_price_change_for_alert:
                return AlertSeverity.MEDIUM

        if discount_changed:
            return AlertSeverity.MEDIUM

        if len(added_features) + len(removed_features) >= 5:
            return AlertSeverity.MEDIUM

        if added_features or removed_features:
            return AlertSeverity.LOW

        return AlertSeverity.INFO

    def _should_create_alert(self, change: PriceChange) -> bool:
        """Decide if a change deserves an alert."""

        if change.change_type in {
            PriceChangeType.INCREASE,
            PriceChangeType.DECREASE,
            PriceChangeType.NEW_PRICE,
            PriceChangeType.REMOVED_PRICE,
        }:
            if change.percent_change is not None:
                if abs(change.percent_change) >= self.config.min_price_change_percent_for_alert:
                    return True

            if change.absolute_change is not None:
                if abs(change.absolute_change) >= self.config.min_absolute_price_change_for_alert:
                    return True

            if change.change_type in {PriceChangeType.NEW_PRICE, PriceChangeType.REMOVED_PRICE}:
                return True

        if change.discount_changed:
            return True

        if change.added_features or change.removed_features:
            return True

        return False

    def _create_alert_from_change(self, change: PriceChange) -> PriceAlert:
        """Create dashboard/API alert from price change."""

        if change.change_type == PriceChangeType.INCREASE:
            title = "Competitor price increased"
        elif change.change_type == PriceChangeType.DECREASE:
            title = "Competitor price decreased"
        elif change.change_type == PriceChangeType.NEW_PRICE:
            title = "New competitor price detected"
        elif change.change_type == PriceChangeType.REMOVED_PRICE:
            title = "Competitor price removed"
        else:
            title = "Competitor pricing page changed"

        message_parts = [
            f"{change.competitor_name} / {change.product_name}",
            f"change_type={change.change_type.value}",
        ]

        if change.previous_price is not None or change.current_price is not None:
            message_parts.append(
                f"{change.previous_price} → {change.current_price} {change.currency}"
            )

        if change.percent_change is not None:
            message_parts.append(f"{change.percent_change}%")

        if change.discount_changed:
            message_parts.append("discount changed")

        if change.added_features:
            message_parts.append(f"{len(change.added_features)} feature(s) added")

        if change.removed_features:
            message_parts.append(f"{len(change.removed_features)} feature(s) removed")

        return PriceAlert(
            alert_id=self._new_id("alert"),
            change_id=change.change_id,
            target_id=change.target_id,
            user_id=change.user_id,
            workspace_id=change.workspace_id,
            competitor_name=change.competitor_name,
            product_name=change.product_name,
            title=title,
            message=" | ".join(message_parts),
            severity=change.severity,
            created_at=self._utc_now(),
            acknowledged=False,
            metadata={
                "change": asdict(change),
            },
        )

    # -----------------------------------------------------------------------
    # Fetching
    # -----------------------------------------------------------------------

    async def _fetch_public_page(self, url: str) -> Dict[str, Any]:
        """
        Fetch public page HTML.

        This method only performs a normal public HTTP GET. It does not bypass
        authentication, paywalls, CAPTCHA, robot restrictions, or blocked pages.
        """

        if not REQUESTS_AVAILABLE or requests is None:
            return self._error_result(
                message="requests is not installed. Install requests to fetch competitor pages.",
                error_code="REQUESTS_NOT_AVAILABLE",
                metadata={
                    "install": "pip install requests",
                },
            )

        validation = self._validate_url(url)
        if not validation["success"]:
            return validation

        try:
            def _do_request() -> Dict[str, Any]:
                response = requests.get(
                    url,
                    timeout=self.config.request_timeout_seconds,
                    headers={
                        "User-Agent": self.config.user_agent,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    },
                )

                content_type = response.headers.get("content-type", "")
                if "text/html" not in content_type and "application/xhtml" not in content_type:
                    return self._error_result(
                        message="Fetched URL did not return HTML content.",
                        error_code="NON_HTML_RESPONSE",
                        metadata={
                            "status_code": response.status_code,
                            "content_type": content_type,
                        },
                    )

                if response.status_code >= 400:
                    return self._error_result(
                        message="Failed to fetch competitor page.",
                        error_code="HTTP_FETCH_FAILED",
                        metadata={
                            "status_code": response.status_code,
                            "url": url,
                        },
                    )

                return self._safe_result(
                    message="Competitor page fetched successfully.",
                    data={
                        "url": response.url,
                        "html": response.text,
                        "status_code": response.status_code,
                        "content_type": content_type,
                    },
                )

            return await asyncio.to_thread(_do_request)

        except Exception as exc:
            return self._error_result(
                message="Failed to fetch competitor page.",
                error=str(exc),
                error_code="FETCH_FAILED",
                metadata={"url": url},
            )

    # -----------------------------------------------------------------------
    # Required Compatibility Hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(self, request: PriceMonitorRequest) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation.

        Required compatibility hook.
        """

        if request is None:
            return self._error_result(
                message="Task context is missing.",
                error_code="MISSING_TASK_CONTEXT",
            )

        if request.user_id is None or str(request.user_id).strip() == "":
            return self._error_result(
                message="user_id is required for PriceMonitor.",
                error_code="MISSING_USER_ID",
            )

        if request.workspace_id is None or str(request.workspace_id).strip() == "":
            return self._error_result(
                message="workspace_id is required for PriceMonitor.",
                error_code="MISSING_WORKSPACE_ID",
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": str(request.user_id),
                "workspace_id": str(request.workspace_id),
                "task_id": request.task_id,
            },
        )

    def _requires_security_check(
        self,
        request: PriceMonitorRequest,
        risk_level: Optional[MonitorRiskLevel] = None,
    ) -> bool:
        """
        Decide whether Security Agent approval is required.

        Required compatibility hook.
        """

        if self.config.dry_run or request.options.get("dry_run"):
            return False

        risk = risk_level or self._assess_risk(request)

        if request.approval_token:
            return False

        if risk in {MonitorRiskLevel.HIGH, MonitorRiskLevel.CRITICAL}:
            return True

        if request.action in {PriceMonitorAction.ADD_TARGET, PriceMonitorAction.REMOVE_TARGET}:
            return self.config.require_security_for_target_changes

        if request.action in {PriceMonitorAction.CHECK_TARGET, PriceMonitorAction.CHECK_ALL}:
            return self.config.require_security_for_external_fetch

        return False

    async def _request_security_approval(
        self,
        request: PriceMonitorRequest,
        risk_level: MonitorRiskLevel,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent.

        Required compatibility hook.
        """

        if request.approval_token:
            return self._safe_result(
                message="Security approval token provided.",
                data={
                    "approved": True,
                    "risk_level": risk_level.value,
                },
            )

        payload = {
            "request_id": self._new_id("security"),
            "agent": "PriceMonitor",
            "action": request.action.value,
            "risk_level": risk_level.value,
            "user_id": str(request.user_id),
            "workspace_id": str(request.workspace_id),
            "target_id": request.target_id,
            "url": request.url,
            "competitor_name": request.competitor_name,
            "product_name": request.product_name,
            "task_id": request.task_id,
            "timestamp": self._utc_now(),
            "metadata": request.metadata,
        }

        if self.security_approval_callback is not None:
            try:
                response = self.security_approval_callback(payload)
                if asyncio.iscoroutine(response):
                    response = await response

                if isinstance(response, bool):
                    if response:
                        return self._safe_result(
                            message="Security Agent approved PriceMonitor action.",
                            data={"approved": True},
                        )
                    return self._error_result(
                        message="Security Agent denied PriceMonitor action.",
                        error_code="SECURITY_DENIED",
                    )

                if isinstance(response, dict):
                    approved = bool(response.get("approved") or response.get("success"))
                    if approved:
                        return self._safe_result(
                            message=response.get("message", "Security Agent approved PriceMonitor action."),
                            data={
                                "approved": True,
                                "security_response": response,
                            },
                        )

                    return self._error_result(
                        message=response.get("message", "Security Agent denied PriceMonitor action."),
                        error_code=response.get("error_code", "SECURITY_DENIED"),
                        metadata={
                            "security_response": response,
                        },
                    )

            except Exception as exc:
                return self._error_result(
                    message="Security approval callback failed.",
                    error=str(exc),
                    error_code="SECURITY_CALLBACK_FAILED",
                )

        if risk_level in {MonitorRiskLevel.HIGH, MonitorRiskLevel.CRITICAL}:
            return self._error_result(
                message="PriceMonitor action requires Security Agent approval.",
                error_code="SECURITY_APPROVAL_REQUIRED",
                metadata={
                    "risk_level": risk_level.value,
                },
            )

        return self._safe_result(
            message="Security approval not required.",
            data={
                "approved": True,
                "risk_level": risk_level.value,
            },
        )

    def _prepare_verification_payload(
        self,
        request: PriceMonitorRequest,
        result: Dict[str, Any],
        risk_level: MonitorRiskLevel,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Required compatibility hook.
        """

        data = result.get("data") or {}

        return {
            "type": "price_monitor_verification",
            "agent": "PriceMonitor",
            "action": request.action.value,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "risk_level": risk_level.value,
            "user_id": str(request.user_id),
            "workspace_id": str(request.workspace_id),
            "task_id": request.task_id,
            "target_id": request.target_id or data.get("target_id"),
            "url": request.url or self._safe_get_nested(data, ["target", "url"]),
            "snapshot_id": self._safe_get_nested(data, ["snapshot", "snapshot_id"]),
            "change_id": self._safe_get_nested(data, ["change", "change_id"]),
            "alert_id": self._safe_get_nested(data, ["alert", "alert_id"]),
            "timestamp": self._utc_now(),
            "metadata": result.get("metadata", {}),
        }

    def _prepare_memory_payload(
        self,
        request: PriceMonitorRequest,
        result: Dict[str, Any],
        risk_level: MonitorRiskLevel,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Required compatibility hook.
        """

        data = result.get("data") or {}

        return {
            "type": "price_monitor_memory",
            "agent": "PriceMonitor",
            "action": request.action.value,
            "success": bool(result.get("success")),
            "summary": result.get("message"),
            "risk_level": risk_level.value,
            "user_id": str(request.user_id),
            "workspace_id": str(request.workspace_id),
            "task_id": request.task_id,
            "target_id": request.target_id or self._safe_get_nested(data, ["target", "target_id"]),
            "competitor_name": request.competitor_name or self._safe_get_nested(data, ["target", "competitor_name"]),
            "product_name": request.product_name or self._safe_get_nested(data, ["target", "product_name"]),
            "price": self._safe_get_nested(data, ["snapshot", "price"]),
            "currency": self._safe_get_nested(data, ["snapshot", "currency"]),
            "change_type": self._safe_get_nested(data, ["change", "change_type"]),
            "alert_title": self._safe_get_nested(data, ["alert", "title"]),
            "timestamp": self._utc_now(),
        }

    async def _emit_agent_event(self, event: Dict[str, Any]) -> None:
        """
        Emit dashboard/API event.

        Required compatibility hook.
        """

        if not self.config.event_enabled:
            return

        try:
            if self.event_callback is not None:
                response = self.event_callback(event)
                if asyncio.iscoroutine(response):
                    await response

            logger.info("PriceMonitor event: %s", event)

        except Exception as exc:
            logger.warning("Failed to emit PriceMonitor event: %s", exc)

    async def _log_audit_event(self, event: Dict[str, Any]) -> None:
        """
        Log audit event.

        Required compatibility hook.
        """

        if not self.config.audit_enabled:
            return

        try:
            if self.audit_callback is not None:
                response = self.audit_callback(event)
                if asyncio.iscoroutine(response):
                    await response

            logger.info("PriceMonitor audit: %s", event)

        except Exception as exc:
            logger.warning("Failed to log PriceMonitor audit event: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        success: bool = True,
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Standard success result.

        Required compatibility hook.
        """

        return {
            "success": bool(success),
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Optional[str] = None,
        error_code: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result.

        Required compatibility hook.
        """

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error or message,
            "metadata": {
                **(metadata or {}),
                "error_code": error_code,
            },
        }

    # -----------------------------------------------------------------------
    # Internal Action Processing
    # -----------------------------------------------------------------------

    async def _maybe_request_security_approval(
        self,
        request: PriceMonitorRequest,
        risk_level: MonitorRiskLevel,
    ) -> Dict[str, Any]:
        """Request Security Agent approval when required."""

        if self._requires_security_check(request, risk_level):
            return await self._request_security_approval(request, risk_level)

        return self._safe_result(
            message="Security approval not required.",
            data={
                "approved": True,
                "risk_level": risk_level.value,
            },
        )

    async def _after_action(
        self,
        request: PriceMonitorRequest,
        result: Dict[str, Any],
        risk_level: MonitorRiskLevel,
    ) -> None:
        """Post-action hooks for audit, events, memory, and verification."""

        event = {
            "type": "price_monitor_action",
            "agent": "PriceMonitor",
            "action": request.action.value,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "risk_level": risk_level.value,
            "user_id": str(request.user_id),
            "workspace_id": str(request.workspace_id),
            "task_id": request.task_id,
            "target_id": request.target_id,
            "timestamp": self._utc_now(),
            "metadata": result.get("metadata", {}),
        }

        await self._log_audit_event(event)
        await self._emit_agent_event(event)

        if self.config.memory_enabled and self.memory_callback is not None:
            try:
                payload = self._prepare_memory_payload(request, result, risk_level)
                response = self.memory_callback(payload)
                if asyncio.iscoroutine(response):
                    await response
            except Exception as exc:
                logger.warning("Failed to send PriceMonitor memory payload: %s", exc)

        if self.config.verification_enabled and self.verification_callback is not None:
            try:
                payload = self._prepare_verification_payload(request, result, risk_level)
                response = self.verification_callback(payload)
                if asyncio.iscoroutine(response):
                    await response
            except Exception as exc:
                logger.warning("Failed to send PriceMonitor verification payload: %s", exc)

    def _assess_risk(self, request: PriceMonitorRequest) -> MonitorRiskLevel:
        """Assess risk for Security Agent and audit."""

        if request.action in {PriceMonitorAction.ADD_TARGET, PriceMonitorAction.REMOVE_TARGET}:
            return MonitorRiskLevel.MEDIUM if self.config.require_security_for_target_changes else MonitorRiskLevel.LOW

        if request.action in {PriceMonitorAction.CHECK_TARGET, PriceMonitorAction.CHECK_ALL}:
            return MonitorRiskLevel.MEDIUM if self.config.require_security_for_external_fetch else MonitorRiskLevel.LOW

        return MonitorRiskLevel.LOW

    # -----------------------------------------------------------------------
    # URL / Context Validation
    # -----------------------------------------------------------------------

    def _validate_url(self, url: str) -> Dict[str, Any]:
        """Validate public URL and domain policy."""

        if not url or not isinstance(url, str):
            return self._error_result(
                message="A valid URL is required.",
                error_code="INVALID_URL",
            )

        parsed = urlparse(url.strip())

        if not parsed.scheme or not parsed.netloc:
            return self._error_result(
                message="URL must include scheme and hostname.",
                error_code="INVALID_URL_FORMAT",
            )

        if parsed.scheme.lower() in self.BLOCKED_SCHEMES:
            return self._error_result(
                message=f"Blocked URL scheme: {parsed.scheme}",
                error_code="BLOCKED_URL_SCHEME",
            )

        if parsed.scheme.lower() not in {"http", "https"}:
            return self._error_result(
                message="Only http and https URLs are allowed.",
                error_code="UNSUPPORTED_URL_SCHEME",
            )

        domain = parsed.netloc.lower()

        for blocked_domain in self.config.blocked_domains:
            if blocked_domain and blocked_domain.lower() in domain:
                return self._error_result(
                    message="URL domain is blocked by PriceMonitor config.",
                    error_code="BLOCKED_DOMAIN",
                    metadata={"domain": domain},
                )

        if self.config.allowed_domains:
            allowed = any(allowed_domain.lower() in domain for allowed_domain in self.config.allowed_domains)
            if not allowed:
                return self._error_result(
                    message="URL domain is not allowed by PriceMonitor config.",
                    error_code="DOMAIN_NOT_ALLOWED",
                    metadata={
                        "domain": domain,
                        "allowed_domains": self.config.allowed_domains,
                    },
                )

        if not self.config.allow_external_urls and not self.config.allowed_domains:
            return self._error_result(
                message="External URLs are disabled and no allowed_domains are configured.",
                error_code="EXTERNAL_URLS_DISABLED",
            )

        return self._safe_result(
            message="URL validated.",
            data={
                "url": url,
                "domain": domain,
            },
        )

    def _same_context(
        self,
        existing_user_id: Union[str, int],
        existing_workspace_id: Union[str, int],
        user_id: Union[str, int],
        workspace_id: Union[str, int],
    ) -> bool:
        """Check user/workspace isolation."""

        return (
            str(existing_user_id) == str(user_id)
            and str(existing_workspace_id) == str(workspace_id)
        )

    def _get_target_for_context(
        self,
        target_id: str,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
    ) -> Optional[MonitorTarget]:
        """Get target only if it belongs to the given user/workspace."""

        target = self._targets.get(target_id)
        if target is None:
            return None

        if not self._same_context(target.user_id, target.workspace_id, user_id, workspace_id):
            return None

        return target

    # -----------------------------------------------------------------------
    # Persistence
    # -----------------------------------------------------------------------

    def _ensure_storage_dirs(self) -> None:
        """Create storage directory safely."""

        try:
            Path(self.config.storage_dir).mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            logger.warning("Failed to create PriceMonitor storage dir: %s", exc)

    def _state_file(self) -> Path:
        """State file path."""

        return Path(self.config.storage_dir) / "price_monitor_state.json"

    def _persist_state(self) -> None:
        """
        Save state to disk if enabled.

        This is safe local JSON persistence for development/testing.
        In production SaaS, replace with database persistence through a repository.
        """

        if not self.config.save_to_disk:
            return

        try:
            state = {
                "targets": {key: asdict(value) for key, value in self._targets.items()},
                "snapshots": {
                    key: [asdict(item) for item in value]
                    for key, value in self._snapshots.items()
                },
                "changes": {
                    key: [asdict(item) for item in value]
                    for key, value in self._changes.items()
                },
                "alerts": {
                    key: [asdict(item) for item in value]
                    for key, value in self._alerts.items()
                },
                "updated_at": self._utc_now(),
            }

            tmp_file = self._state_file().with_suffix(".tmp")
            with open(tmp_file, "w", encoding="utf-8") as file:
                json.dump(state, file, indent=2, ensure_ascii=False)

            os.replace(tmp_file, self._state_file())

        except Exception as exc:
            logger.warning("Failed to persist PriceMonitor state: %s", exc)

    def _load_state_from_disk(self) -> None:
        """Load local JSON state if available."""

        if not self.config.save_to_disk:
            return

        state_file = self._state_file()
        if not state_file.exists():
            return

        try:
            with open(state_file, "r", encoding="utf-8") as file:
                state = json.load(file)

            self._targets = {
                key: MonitorTarget(**value)
                for key, value in state.get("targets", {}).items()
            }

            self._snapshots = {
                key: [self._snapshot_from_dict(item) for item in value]
                for key, value in state.get("snapshots", {}).items()
            }

            self._changes = {
                key: [self._change_from_dict(item) for item in value]
                for key, value in state.get("changes", {}).items()
            }

            self._alerts = {
                key: [self._alert_from_dict(item) for item in value]
                for key, value in state.get("alerts", {}).items()
            }

        except Exception as exc:
            logger.warning("Failed to load PriceMonitor state: %s", exc)
            self._targets = {}
            self._snapshots = {}
            self._changes = {}
            self._alerts = {}

    # -----------------------------------------------------------------------
    # Serialization Helpers
    # -----------------------------------------------------------------------

    def _snapshot_from_dict(self, data: Dict[str, Any]) -> PriceSnapshot:
        """Create PriceSnapshot from dict."""

        return PriceSnapshot(
            snapshot_id=str(data.get("snapshot_id") or self._new_id("snapshot")),
            target_id=str(data.get("target_id") or ""),
            user_id=data.get("user_id"),
            workspace_id=data.get("workspace_id"),
            competitor_name=str(data.get("competitor_name") or ""),
            product_name=str(data.get("product_name") or ""),
            url=str(data.get("url") or ""),
            price=self._none_or_float(data.get("price")),
            currency=str(data.get("currency") or self.config.default_currency).upper(),
            discount_text=data.get("discount_text"),
            features=list(data.get("features") or []),
            raw_prices=list(data.get("raw_prices") or []),
            page_title=data.get("page_title"),
            content_hash=str(data.get("content_hash") or ""),
            captured_at=str(data.get("captured_at") or self._utc_now()),
            metadata=dict(data.get("metadata") or {}),
        )

    def _change_from_dict(self, data: Dict[str, Any]) -> PriceChange:
        """Create PriceChange from dict."""

        return PriceChange(
            change_id=str(data.get("change_id") or self._new_id("change")),
            target_id=str(data.get("target_id") or ""),
            user_id=data.get("user_id"),
            workspace_id=data.get("workspace_id"),
            competitor_name=str(data.get("competitor_name") or ""),
            product_name=str(data.get("product_name") or ""),
            previous_price=self._none_or_float(data.get("previous_price")),
            current_price=self._none_or_float(data.get("current_price")),
            currency=str(data.get("currency") or self.config.default_currency).upper(),
            change_type=PriceChangeType(data.get("change_type") or PriceChangeType.UNKNOWN),
            absolute_change=self._none_or_float(data.get("absolute_change")),
            percent_change=self._none_or_float(data.get("percent_change")),
            discount_changed=bool(data.get("discount_changed", False)),
            previous_discount=data.get("previous_discount"),
            current_discount=data.get("current_discount"),
            added_features=list(data.get("added_features") or []),
            removed_features=list(data.get("removed_features") or []),
            changed_at=str(data.get("changed_at") or self._utc_now()),
            severity=AlertSeverity(data.get("severity") or AlertSeverity.INFO),
            metadata=dict(data.get("metadata") or {}),
        )

    def _alert_from_dict(self, data: Dict[str, Any]) -> PriceAlert:
        """Create PriceAlert from dict."""

        return PriceAlert(
            alert_id=str(data.get("alert_id") or self._new_id("alert")),
            change_id=str(data.get("change_id") or ""),
            target_id=str(data.get("target_id") or ""),
            user_id=data.get("user_id"),
            workspace_id=data.get("workspace_id"),
            competitor_name=str(data.get("competitor_name") or ""),
            product_name=str(data.get("product_name") or ""),
            title=str(data.get("title") or "Price monitor alert"),
            message=str(data.get("message") or ""),
            severity=AlertSeverity(data.get("severity") or AlertSeverity.INFO),
            created_at=str(data.get("created_at") or self._utc_now()),
            acknowledged=bool(data.get("acknowledged", False)),
            metadata=dict(data.get("metadata") or {}),
        )

    # -----------------------------------------------------------------------
    # Request Normalization
    # -----------------------------------------------------------------------

    def _normalize_request(self, request: Union[PriceMonitorRequest, Dict[str, Any]]) -> PriceMonitorRequest:
        """Normalize incoming request dict."""

        if isinstance(request, PriceMonitorRequest):
            return request

        if not isinstance(request, dict):
            raise TypeError("request must be PriceMonitorRequest or dict")

        raw_action = request.get("action")
        if isinstance(raw_action, PriceMonitorAction):
            action = raw_action
        else:
            action = PriceMonitorAction(str(raw_action))

        return PriceMonitorRequest(
            action=action,
            user_id=request.get("user_id"),
            workspace_id=request.get("workspace_id"),
            target_id=request.get("target_id"),
            url=request.get("url"),
            competitor_name=request.get("competitor_name"),
            product_name=request.get("product_name"),
            selectors=dict(request.get("selectors") or {}),
            html=request.get("html"),
            snapshot_a=request.get("snapshot_a"),
            snapshot_b=request.get("snapshot_b"),
            options=dict(request.get("options") or {}),
            task_id=request.get("task_id"),
            approval_token=request.get("approval_token"),
            metadata=dict(request.get("metadata") or {}),
        )

    # -----------------------------------------------------------------------
    # Utility Helpers
    # -----------------------------------------------------------------------

    def _base_metadata(
        self,
        request: PriceMonitorRequest,
        started_at: str,
        risk_level: MonitorRiskLevel,
    ) -> Dict[str, Any]:
        """Common metadata for public results."""

        ended_at = self._utc_now()

        return {
            "agent": "PriceMonitor",
            "action": request.action.value,
            "user_id": str(request.user_id),
            "workspace_id": str(request.workspace_id),
            "task_id": request.task_id,
            "risk_level": risk_level.value,
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_ms": self._duration_ms(started_at, ended_at),
        }

    def _workspace_key(self, user_id: Union[str, int], workspace_id: Union[str, int]) -> str:
        """Build stable workspace key."""

        return f"user_{self._safe_key(user_id)}__workspace_{self._safe_key(workspace_id)}"

    def _safe_key(self, value: Union[str, int]) -> str:
        """Create safe key from user/workspace id."""

        return re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(value)).strip("_") or "unknown"

    def _new_id(self, prefix: str) -> str:
        """Create unique id."""

        return f"{prefix}_{uuid.uuid4().hex}"

    def _utc_now(self) -> str:
        """UTC ISO timestamp."""

        return datetime.now(timezone.utc).isoformat()

    def _duration_ms(self, started_at: str, ended_at: str) -> Optional[int]:
        """Calculate duration in milliseconds."""

        try:
            start_dt = datetime.fromisoformat(started_at)
            end_dt = datetime.fromisoformat(ended_at)
            return int((end_dt - start_dt).total_seconds() * 1000)
        except Exception:
            return None

    def _to_float(self, value: Any) -> Optional[float]:
        """Convert price-like value to float safely."""

        if value is None:
            return None

        cleaned = str(value).replace(",", "").strip()
        cleaned = re.sub(r"[^0-9.\-]", "", cleaned)

        if cleaned in {"", ".", "-", "-."}:
            return None

        try:
            number = Decimal(cleaned)
            return float(number)
        except (InvalidOperation, ValueError):
            return None

    def _none_or_float(self, value: Any) -> Optional[float]:
        """Convert value to float or None."""

        if value is None:
            return None
        return self._to_float(value)

    def _dedupe_keep_order(self, values: List[str]) -> List[str]:
        """Deduplicate strings while keeping order."""

        seen = set()
        output = []

        for value in values:
            normalized = re.sub(r"\s+", " ", str(value).strip())
            key = normalized.lower()
            if not normalized or key in seen:
                continue
            seen.add(key)
            output.append(normalized)

        return output

    def _normalize_feature_list(self, values: List[str]) -> List[str]:
        """Normalize features for comparison."""

        normalized = []
        for value in values:
            item = re.sub(r"\s+", " ", str(value).strip().lower())
            item = re.sub(r"^[•\-\*\+\✓✔]+\s*", "", item)
            if item:
                normalized.append(item)
        return self._dedupe_keep_order(normalized)

    def _safe_get_nested(self, data: Dict[str, Any], path: List[str]) -> Any:
        """Safely read nested dict value."""

        current: Any = data
        for key in path:
            if not isinstance(current, dict):
                return None
            current = current.get(key)
        return current

    # -----------------------------------------------------------------------
    # Sync Wrappers
    # -----------------------------------------------------------------------

    def run_action_sync(self, request: Union[PriceMonitorRequest, Dict[str, Any]]) -> Dict[str, Any]:
        """Synchronous wrapper for run_action()."""

        return self._run_async_safely(self.run_action(request))

    def add_target_sync(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        url: str,
        competitor_name: str,
        product_name: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for add_target()."""

        return self._run_async_safely(
            self.add_target(
                user_id=user_id,
                workspace_id=workspace_id,
                url=url,
                competitor_name=competitor_name,
                product_name=product_name,
                **kwargs,
            )
        )

    def check_target_sync(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        target_id: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for check_target()."""

        return self._run_async_safely(
            self.check_target(
                user_id=user_id,
                workspace_id=workspace_id,
                target_id=target_id,
                **kwargs,
            )
        )

    def _run_async_safely(self, coro: Awaitable[Dict[str, Any]]) -> Dict[str, Any]:
        """Run async coroutine from sync context safely."""

        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                return self._error_result(
                    message="Cannot use sync wrapper inside a running event loop. Use async method instead.",
                    error_code="EVENT_LOOP_ALREADY_RUNNING",
                )
        except RuntimeError:
            pass

        return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Module Exports
# ---------------------------------------------------------------------------

__all__ = [
    "PriceMonitor",
    "PriceMonitorConfig",
    "PriceMonitorRequest",
    "MonitorTarget",
    "PriceSnapshot",
    "PriceChange",
    "PriceAlert",
    "PriceMonitorAction",
    "PriceChangeType",
    "AlertSeverity",
    "MonitorRiskLevel",
]


# ---------------------------------------------------------------------------
# Minimal Self-Test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    async def _demo() -> None:
        monitor = PriceMonitor(
            config=PriceMonitorConfig(
                save_to_disk=False,
                dry_run=False,
                require_security_for_external_fetch=False,
                require_security_for_target_changes=False,
            )
        )

        add_result = await monitor.add_target(
            user_id="demo_user",
            workspace_id="demo_workspace",
            url="https://example.com/pricing",
            competitor_name="Example Competitor",
            product_name="Starter Plan",
            selectors={
                "price": ".price",
                "discount": ".discount",
                "features": ".features li",
            },
            options={
                "currency": "USD",
            },
        )

        print("ADD RESULT")
        print(json.dumps(add_result, indent=2))

        target_id = add_result["data"]["target"]["target_id"]

        html_v1 = """
        <html>
            <head><title>Example Pricing</title></head>
            <body>
                <h1>Starter Plan</h1>
                <div class="price">$49</div>
                <div class="discount">Save 10%</div>
                <ul class="features">
                    <li>Dashboard included</li>
                    <li>Email support</li>
                    <li>Basic analytics</li>
                </ul>
            </body>
        </html>
        """

        html_v2 = """
        <html>
            <head><title>Example Pricing</title></head>
            <body>
                <h1>Starter Plan</h1>
                <div class="price">$39</div>
                <div class="discount">Save 25%</div>
                <ul class="features">
                    <li>Dashboard included</li>
                    <li>Email support</li>
                    <li>Advanced analytics</li>
                    <li>API access</li>
                </ul>
            </body>
        </html>
        """

        first_check = await monitor.check_target(
            user_id="demo_user",
            workspace_id="demo_workspace",
            target_id=target_id,
            html=html_v1,
        )

        print("FIRST CHECK")
        print(json.dumps(first_check, indent=2))

        second_check = await monitor.check_target(
            user_id="demo_user",
            workspace_id="demo_workspace",
            target_id=target_id,
            html=html_v2,
        )

        print("SECOND CHECK")
        print(json.dumps(second_check, indent=2))

        alerts = await monitor.get_alerts(
            user_id="demo_user",
            workspace_id="demo_workspace",
        )

        print("ALERTS")
        print(json.dumps(alerts, indent=2))

    asyncio.run(_demo())