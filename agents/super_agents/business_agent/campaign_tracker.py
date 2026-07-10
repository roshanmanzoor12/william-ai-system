"""
William / Jarvis Multi-Agent AI SaaS System
Business Agent - Campaign Tracker

File:
    agents/super_agents/business_agent/campaign_tracker.py

Purpose:
    Tracks Google Ads, SEO, social media, and landing page campaign performance
    for SaaS users/workspaces with strict user_id/workspace_id isolation.

Architecture Compatibility:
    - BaseAgent compatible with safe fallback if BaseAgent is unavailable.
    - Agent Registry / Agent Loader / Agent Router import-safe.
    - Master Agent routing ready through clear public methods and metadata.
    - Security Agent compatible through approval hooks for sensitive operations.
    - Verification Agent compatible through structured verification payloads.
    - Memory Agent compatible through memory-safe campaign context payloads.
    - Dashboard/API ready through structured JSON-style results.

Important Safety Rules:
    - No real ad platform, analytics, browser, payment, message, or destructive
      external actions are performed directly in this file.
    - This file stores and processes provided campaign data in memory by default.
    - Integrations can later connect through adapters with Security Agent checks.
"""

from __future__ import annotations

import copy
import csv
import io
import logging
import math
import statistics
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import safety
    class BaseAgent:  # type: ignore
        """
        Safe fallback BaseAgent.

        This allows campaign_tracker.py to import cleanly even when the full
        William/Jarvis BaseAgent has not been generated yet.
        """

        agent_name: str = "base_agent_fallback"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_id = kwargs.get("agent_id", self.__class__.__name__)
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.metadata = kwargs.get("metadata", {})

        def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent does not implement run().",
                "data": {},
                "error": "BASE_AGENT_FALLBACK_RUN_NOT_IMPLEMENTED",
                "metadata": {},
            }


try:
    from agents.super_agents.business_agent.config import BUSINESS_AGENT_CONFIG  # type: ignore
except Exception:  # pragma: no cover - fallback for import safety
    BUSINESS_AGENT_CONFIG: Dict[str, Any] = {
        "campaign_tracker": {
            "max_campaigns_per_workspace": 10000,
            "max_events_per_campaign": 50000,
            "default_currency": "USD",
            "allowed_channels": [
                "google_ads",
                "seo",
                "social",
                "landing_page",
                "email",
                "referral",
                "direct",
                "other",
            ],
            "sensitive_actions": [
                "delete_campaign",
                "bulk_import_campaigns",
                "sync_external_campaign_source",
                "export_campaign_data",
            ],
        }
    }


class CampaignChannel(str, Enum):
    """Supported marketing campaign channels."""

    GOOGLE_ADS = "google_ads"
    SEO = "seo"
    SOCIAL = "social"
    LANDING_PAGE = "landing_page"
    EMAIL = "email"
    REFERRAL = "referral"
    DIRECT = "direct"
    OTHER = "other"


class CampaignStatus(str, Enum):
    """Lifecycle status for a campaign."""

    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class CampaignMetricType(str, Enum):
    """Common metric event types tracked by this module."""

    IMPRESSIONS = "impressions"
    CLICKS = "clicks"
    SPEND = "spend"
    CONVERSIONS = "conversions"
    REVENUE = "revenue"
    LEADS = "leads"
    SESSIONS = "sessions"
    BOUNCES = "bounces"
    PAGE_VIEWS = "page_views"
    FORM_SUBMITS = "form_submits"
    CALLS = "calls"
    MESSAGES = "messages"
    RANKING_POSITION = "ranking_position"
    ORGANIC_TRAFFIC = "organic_traffic"
    SOCIAL_REACH = "social_reach"
    ENGAGEMENTS = "engagements"


class AttributionModel(str, Enum):
    """Basic attribution models used for reporting."""

    LAST_TOUCH = "last_touch"
    FIRST_TOUCH = "first_touch"
    LINEAR = "linear"


@dataclass
class CampaignRecord:
    """
    Represents a marketing campaign owned by a user and workspace.

    This record is intentionally integration-neutral. External IDs from Google
    Ads, SEO tools, Meta, LinkedIn, landing page builders, analytics tools, or
    CRM systems can be saved in external_refs without hardcoding any vendor.
    """

    campaign_id: str
    user_id: str
    workspace_id: str
    name: str
    channel: str
    status: str = CampaignStatus.DRAFT.value
    objective: Optional[str] = None
    source: Optional[str] = None
    medium: Optional[str] = None
    landing_page_url: Optional[str] = None
    budget: float = 0.0
    currency: str = "USD"
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    external_refs: Dict[str, Any] = field(default_factory=dict)
    notes: List[Dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: _utc_now_iso())
    updated_at: str = field(default_factory=lambda: _utc_now_iso())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CampaignMetricEvent:
    """
    Represents a campaign metric snapshot/event.

    Metric events are separated from campaign records so dashboards can ingest
    daily/hourly snapshots from ad platforms, SEO tools, landing pages, social
    sources, and manual uploads.
    """

    event_id: str
    user_id: str
    workspace_id: str
    campaign_id: str
    metric_type: str
    value: float
    occurred_at: str
    source: Optional[str] = None
    dimensions: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: _utc_now_iso())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CampaignGoal:
    """
    Represents a measurable campaign goal.

    Example:
        - max_cpa <= 25
        - min_roas >= 2.5
        - min_conversion_rate >= 3.0
    """

    goal_id: str
    user_id: str
    workspace_id: str
    campaign_id: str
    name: str
    metric: str
    operator: str
    target_value: float
    enabled: bool = True
    created_at: str = field(default_factory=lambda: _utc_now_iso())
    metadata: Dict[str, Any] = field(default_factory=dict)


def _utc_now_iso() -> str:
    """Return timezone-aware UTC ISO timestamp."""
    return datetime.now(timezone.utc).isoformat()


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert a value to float."""
    try:
        if value is None:
            return default
        result = float(value)
        if math.isnan(result) or math.isinf(result):
            return default
        return result
    except (TypeError, ValueError):
        return default


def _safe_str(value: Any, default: str = "") -> str:
    """Safely convert a value to a trimmed string."""
    if value is None:
        return default
    try:
        return str(value).strip()
    except Exception:
        return default


def _normalize_list(value: Any) -> List[str]:
    """Normalize a string/list/tuple into a clean list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        raw_items = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        raw_items = list(value)
    else:
        raw_items = [value]
    return [str(item).strip() for item in raw_items if str(item).strip()]


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-like datetime/date string safely."""
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


class CampaignTracker(BaseAgent):
    """
    Tracks marketing campaign performance for Google Ads, SEO, social, and
    landing page campaigns.

    Master Agent:
        Can route campaign-related tasks here through public methods such as:
        - create_campaign()
        - update_campaign()
        - record_metric()
        - get_campaign_performance()
        - compare_campaigns()
        - generate_campaign_dashboard()

    Security Agent:
        Sensitive actions call _requires_security_check() and
        _request_security_approval() before proceeding.

    Memory Agent:
        Successful actions can produce _prepare_memory_payload() so approved
        campaign insights, notes, and stable preferences can be stored.

    Verification Agent:
        Completed actions produce _prepare_verification_payload() so another
        agent can verify results before user-facing completion.

    Dashboard/API:
        All public methods return structured dict results with:
        success, message, data, error, metadata.
    """

    agent_name = "business_campaign_tracker"
    agent_type = "business_agent_helper"
    public_name = "Campaign Tracker"
    file_path = "agents/super_agents/business_agent/campaign_tracker.py"

    def __init__(
        self,
        storage: Optional[MutableCampaignStorage] = None,
        security_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        memory_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        verification_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        config: Optional[Mapping[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.config = dict(config or BUSINESS_AGENT_CONFIG.get("campaign_tracker", {}))
        self.storage = storage or InMemoryCampaignStorage()
        self.security_callback = security_callback
        self.audit_callback = audit_callback
        self.event_callback = event_callback
        self.memory_callback = memory_callback
        self.verification_callback = verification_callback

        self.max_campaigns_per_workspace = int(
            self.config.get("max_campaigns_per_workspace", 10000)
        )
        self.max_events_per_campaign = int(
            self.config.get("max_events_per_campaign", 50000)
        )
        self.default_currency = str(self.config.get("default_currency", "USD")).upper()
        self.allowed_channels = set(
            self.config.get(
                "allowed_channels",
                [channel.value for channel in CampaignChannel],
            )
        )
        self.sensitive_actions = set(
            self.config.get(
                "sensitive_actions",
                [
                    "delete_campaign",
                    "bulk_import_campaigns",
                    "sync_external_campaign_source",
                    "export_campaign_data",
                ],
            )
        )

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        task_name: str = "campaign_task",
    ) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """
        Validate SaaS user/workspace isolation requirements.

        Every user-specific campaign operation must include both user_id and
        workspace_id so campaign data never leaks across users/workspaces.
        """
        clean_user_id = _safe_str(user_id)
        clean_workspace_id = _safe_str(workspace_id)

        if not clean_user_id:
            return False, "Missing required user_id.", {
                "task_name": task_name,
                "isolation_valid": False,
            }

        if not clean_workspace_id:
            return False, "Missing required workspace_id.", {
                "task_name": task_name,
                "isolation_valid": False,
            }

        return True, None, {
            "task_name": task_name,
            "user_id": clean_user_id,
            "workspace_id": clean_workspace_id,
            "isolation_valid": True,
        }

    def _requires_security_check(self, action: str, payload: Optional[Dict[str, Any]] = None) -> bool:
        """
        Determine whether a campaign action requires Security Agent approval.
        """
        if action in self.sensitive_actions:
            return True

        payload = payload or {}
        if payload.get("external_sync") is True:
            return True

        if payload.get("contains_export") is True:
            return True

        if payload.get("destructive") is True:
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent or use safe local denial/approval.

        If a security_callback is supplied, this method delegates to it.
        Otherwise, it safely approves non-sensitive actions and denies sensitive
        actions by default.
        """
        request_payload = {
            "action": action,
            "agent": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": payload or {},
            "requested_at": _utc_now_iso(),
        }

        if self.security_callback:
            try:
                response = self.security_callback(request_payload)
                if isinstance(response, dict):
                    return {
                        "approved": bool(response.get("approved")),
                        "reason": response.get("reason"),
                        "raw": response,
                    }
            except Exception as exc:
                logger.exception("Security callback failed for action=%s", action)
                return {
                    "approved": False,
                    "reason": f"Security callback failed: {exc}",
                    "raw": {},
                }

        if self._requires_security_check(action, payload):
            return {
                "approved": False,
                "reason": "Security approval required but no Security Agent callback is configured.",
                "raw": request_payload,
            }

        return {
            "approved": True,
            "reason": "No elevated security approval required.",
            "raw": request_payload,
        }

    def _prepare_verification_payload(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload after completed campaign actions.
        """
        return {
            "verification_type": "business_campaign_action",
            "agent": self.agent_name,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "data": data or {},
            "created_at": _utc_now_iso(),
            "checks": [
                "verify_user_workspace_isolation",
                "verify_campaign_id_belongs_to_workspace",
                "verify_metrics_are_numeric",
                "verify_result_schema",
            ],
        }

    def _prepare_memory_payload(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        This does not store memory directly unless memory_callback is configured.
        It keeps campaign context structured for future approved persistence.
        """
        return {
            "memory_type": "business_campaign_context",
            "agent": self.agent_name,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "data": data or {},
            "created_at": _utc_now_iso(),
            "privacy": {
                "scope": "workspace",
                "contains_campaign_performance": True,
                "contains_cross_user_data": False,
            },
        }

    def _emit_agent_event(
        self,
        event_name: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit event for dashboard, analytics, task history, or Agent Registry.
        """
        event = {
            "event_name": event_name,
            "agent": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": payload or {},
            "created_at": _utc_now_iso(),
        }

        if self.event_callback:
            try:
                self.event_callback(event)
            except Exception:
                logger.exception("Agent event callback failed: %s", event_name)

    def _log_audit_event(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> None:
        """
        Log audit event without mixing users/workspaces.
        """
        audit_event = {
            "action": action,
            "agent": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": payload or {},
            "success": success,
            "created_at": _utc_now_iso(),
        }

        if self.audit_callback:
            try:
                self.audit_callback(audit_event)
            except Exception:
                logger.exception("Audit callback failed for action=%s", action)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard successful result.
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
        error: Union[str, Exception, Dict[str, Any]],
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard error result.
        """
        if isinstance(error, Exception):
            error_value: Union[str, Dict[str, Any]] = f"{error.__class__.__name__}: {error}"
        else:
            error_value = error

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error_value,
            "metadata": metadata or {},
        }

    # -------------------------------------------------------------------------
    # Master Agent routing entrypoint
    # -------------------------------------------------------------------------

    def run(
        self,
        task: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generic Master Agent routing entrypoint.

        Supported task names:
            - create_campaign
            - update_campaign
            - delete_campaign
            - get_campaign
            - list_campaigns
            - record_metric
            - bulk_record_metrics
            - get_campaign_performance
            - compare_campaigns
            - generate_campaign_dashboard
            - set_campaign_goal
            - evaluate_campaign_goals
            - export_campaign_data
        """
        payload = payload or {}
        task = _safe_str(task)

        routes: Dict[str, Callable[..., Dict[str, Any]]] = {
            "create_campaign": self.create_campaign,
            "update_campaign": self.update_campaign,
            "delete_campaign": self.delete_campaign,
            "get_campaign": self.get_campaign,
            "list_campaigns": self.list_campaigns,
            "record_metric": self.record_metric,
            "bulk_record_metrics": self.bulk_record_metrics,
            "get_campaign_performance": self.get_campaign_performance,
            "compare_campaigns": self.compare_campaigns,
            "generate_campaign_dashboard": self.generate_campaign_dashboard,
            "set_campaign_goal": self.set_campaign_goal,
            "evaluate_campaign_goals": self.evaluate_campaign_goals,
            "export_campaign_data": self.export_campaign_data,
        }

        handler = routes.get(task)
        if not handler:
            return self._error_result(
                message="Unsupported CampaignTracker task.",
                error="UNSUPPORTED_CAMPAIGN_TRACKER_TASK",
                metadata={
                    "task": task,
                    "supported_tasks": sorted(routes.keys()),
                },
            )

        try:
            return handler(user_id=user_id, workspace_id=workspace_id, **payload)
        except TypeError as exc:
            logger.exception("Invalid payload for task=%s", task)
            return self._error_result(
                message="Invalid payload for CampaignTracker task.",
                error=exc,
                metadata={"task": task},
            )
        except Exception as exc:
            logger.exception("CampaignTracker task failed: %s", task)
            return self._error_result(
                message="CampaignTracker task failed.",
                error=exc,
                metadata={"task": task},
            )

    # -------------------------------------------------------------------------
    # Campaign CRUD
    # -------------------------------------------------------------------------

    def create_campaign(
        self,
        user_id: str,
        workspace_id: str,
        name: str,
        channel: str,
        status: str = CampaignStatus.DRAFT.value,
        objective: Optional[str] = None,
        source: Optional[str] = None,
        medium: Optional[str] = None,
        landing_page_url: Optional[str] = None,
        budget: Union[int, float, str] = 0.0,
        currency: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        external_refs: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a campaign record.

        This does not create campaigns inside Google Ads, Meta Ads, or any real
        external platform. It safely tracks campaign metadata inside the current
        workspace.
        """
        valid, error, context_meta = self._validate_task_context(
            user_id, workspace_id, "create_campaign"
        )
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT", metadata=context_meta)

        name = _safe_str(name)
        channel = _safe_str(channel).lower()
        status = _safe_str(status).lower() or CampaignStatus.DRAFT.value
        clean_user_id = context_meta["user_id"]
        clean_workspace_id = context_meta["workspace_id"]

        if not name:
            return self._error_result(
                "Campaign name is required.",
                "MISSING_CAMPAIGN_NAME",
                metadata=context_meta,
            )

        if channel not in self.allowed_channels:
            return self._error_result(
                "Unsupported campaign channel.",
                "UNSUPPORTED_CAMPAIGN_CHANNEL",
                metadata={
                    **context_meta,
                    "channel": channel,
                    "allowed_channels": sorted(self.allowed_channels),
                },
            )

        if status not in {item.value for item in CampaignStatus}:
            return self._error_result(
                "Unsupported campaign status.",
                "UNSUPPORTED_CAMPAIGN_STATUS",
                metadata={
                    **context_meta,
                    "status": status,
                    "allowed_statuses": [item.value for item in CampaignStatus],
                },
            )

        campaign_count = self.storage.count_campaigns(clean_user_id, clean_workspace_id)
        if campaign_count >= self.max_campaigns_per_workspace:
            return self._error_result(
                "Workspace campaign limit reached.",
                "CAMPAIGN_LIMIT_REACHED",
                metadata={
                    **context_meta,
                    "max_campaigns_per_workspace": self.max_campaigns_per_workspace,
                },
            )

        date_error = self._validate_date_range(start_date, end_date)
        if date_error:
            return self._error_result("Invalid campaign date range.", date_error, metadata=context_meta)

        campaign = CampaignRecord(
            campaign_id=self._new_id("cmp"),
            user_id=clean_user_id,
            workspace_id=clean_workspace_id,
            name=name,
            channel=channel,
            status=status,
            objective=_safe_str(objective) or None,
            source=_safe_str(source) or None,
            medium=_safe_str(medium) or None,
            landing_page_url=_safe_str(landing_page_url) or None,
            budget=max(_safe_float(budget), 0.0),
            currency=(_safe_str(currency) or self.default_currency).upper(),
            start_date=start_date,
            end_date=end_date,
            tags=list(tags or []),
            external_refs=copy.deepcopy(external_refs or {}),
            metadata=copy.deepcopy(metadata or {}),
        )

        self.storage.save_campaign(campaign)

        data = {"campaign": asdict(campaign)}
        self._after_successful_action("create_campaign", clean_user_id, clean_workspace_id, data)

        return self._safe_result(
            "Campaign created successfully.",
            data=data,
            metadata=context_meta,
        )

    def update_campaign(
        self,
        user_id: str,
        workspace_id: str,
        campaign_id: str,
        updates: Optional[Dict[str, Any]] = None,
        **direct_updates: Any,
    ) -> Dict[str, Any]:
        """
        Update an existing campaign safely within the user's workspace.

        Supports either:
            update_campaign(..., updates={"status": "active"})
        or:
            update_campaign(..., status="active")
        """
        valid, error, context_meta = self._validate_task_context(
            user_id, workspace_id, "update_campaign"
        )
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT", metadata=context_meta)

        campaign_id = _safe_str(campaign_id)
        clean_user_id = context_meta["user_id"]
        clean_workspace_id = context_meta["workspace_id"]
        campaign = self.storage.get_campaign(clean_user_id, clean_workspace_id, campaign_id)

        if not campaign:
            return self._error_result(
                "Campaign not found.",
                "CAMPAIGN_NOT_FOUND",
                metadata={**context_meta, "campaign_id": campaign_id},
            )

        merged_updates = dict(updates or {})
        merged_updates.update(direct_updates)

        allowed_fields = {
            "name",
            "channel",
            "status",
            "objective",
            "source",
            "medium",
            "landing_page_url",
            "budget",
            "currency",
            "start_date",
            "end_date",
            "tags",
            "external_refs",
            "metadata",
        }

        rejected_fields = sorted(set(merged_updates.keys()) - allowed_fields)
        if rejected_fields:
            return self._error_result(
                "Update contains unsupported fields.",
                "UNSUPPORTED_UPDATE_FIELDS",
                metadata={
                    **context_meta,
                    "campaign_id": campaign_id,
                    "rejected_fields": rejected_fields,
                    "allowed_fields": sorted(allowed_fields),
                },
            )

        if "channel" in merged_updates:
            channel = _safe_str(merged_updates["channel"]).lower()
            if channel not in self.allowed_channels:
                return self._error_result(
                    "Unsupported campaign channel.",
                    "UNSUPPORTED_CAMPAIGN_CHANNEL",
                    metadata={**context_meta, "channel": channel},
                )
            campaign.channel = channel

        if "status" in merged_updates:
            status = _safe_str(merged_updates["status"]).lower()
            if status not in {item.value for item in CampaignStatus}:
                return self._error_result(
                    "Unsupported campaign status.",
                    "UNSUPPORTED_CAMPAIGN_STATUS",
                    metadata={**context_meta, "status": status},
                )
            campaign.status = status

        if "name" in merged_updates:
            name = _safe_str(merged_updates["name"])
            if not name:
                return self._error_result(
                    "Campaign name cannot be empty.",
                    "EMPTY_CAMPAIGN_NAME",
                    metadata=context_meta,
                )
            campaign.name = name

        if "objective" in merged_updates:
            campaign.objective = _safe_str(merged_updates["objective"]) or None

        if "source" in merged_updates:
            campaign.source = _safe_str(merged_updates["source"]) or None

        if "medium" in merged_updates:
            campaign.medium = _safe_str(merged_updates["medium"]) or None

        if "landing_page_url" in merged_updates:
            campaign.landing_page_url = _safe_str(merged_updates["landing_page_url"]) or None

        if "budget" in merged_updates:
            campaign.budget = max(_safe_float(merged_updates["budget"]), 0.0)

        if "currency" in merged_updates:
            campaign.currency = (_safe_str(merged_updates["currency"]) or self.default_currency).upper()

        next_start_date = merged_updates.get("start_date", campaign.start_date)
        next_end_date = merged_updates.get("end_date", campaign.end_date)
        date_error = self._validate_date_range(next_start_date, next_end_date)
        if date_error:
            return self._error_result("Invalid campaign date range.", date_error, metadata=context_meta)

        if "start_date" in merged_updates:
            campaign.start_date = merged_updates["start_date"]

        if "end_date" in merged_updates:
            campaign.end_date = merged_updates["end_date"]

        if "tags" in merged_updates:
            campaign.tags = _normalize_list(merged_updates["tags"])

        if "external_refs" in merged_updates:
            if not isinstance(merged_updates["external_refs"], dict):
                return self._error_result(
                    "external_refs must be a dictionary.",
                    "INVALID_EXTERNAL_REFS",
                    metadata=context_meta,
                )
            campaign.external_refs = copy.deepcopy(merged_updates["external_refs"])

        if "metadata" in merged_updates:
            if not isinstance(merged_updates["metadata"], dict):
                return self._error_result(
                    "metadata must be a dictionary.",
                    "INVALID_METADATA",
                    metadata=context_meta,
                )
            campaign.metadata = copy.deepcopy(merged_updates["metadata"])

        campaign.updated_at = _utc_now_iso()
        self.storage.save_campaign(campaign)

        data = {"campaign": asdict(campaign), "updated_fields": sorted(merged_updates.keys())}
        self._after_successful_action("update_campaign", clean_user_id, clean_workspace_id, data)

        return self._safe_result(
            "Campaign updated successfully.",
            data=data,
            metadata={**context_meta, "campaign_id": campaign_id},
        )

    def delete_campaign(
        self,
        user_id: str,
        workspace_id: str,
        campaign_id: str,
        hard_delete: bool = False,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Archive or delete a campaign.

        By default, this archives campaigns. hard_delete=True requires Security
        Agent approval and removes campaign metrics/goals from local storage.
        """
        valid, error, context_meta = self._validate_task_context(
            user_id, workspace_id, "delete_campaign"
        )
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT", metadata=context_meta)

        clean_user_id = context_meta["user_id"]
        clean_workspace_id = context_meta["workspace_id"]
        campaign_id = _safe_str(campaign_id)

        campaign = self.storage.get_campaign(clean_user_id, clean_workspace_id, campaign_id)
        if not campaign:
            return self._error_result(
                "Campaign not found.",
                "CAMPAIGN_NOT_FOUND",
                metadata={**context_meta, "campaign_id": campaign_id},
            )

        payload = {
            "campaign_id": campaign_id,
            "hard_delete": hard_delete,
            "reason": reason,
            "destructive": bool(hard_delete),
        }

        if self._requires_security_check("delete_campaign", payload):
            approval = self._request_security_approval(
                "delete_campaign",
                clean_user_id,
                clean_workspace_id,
                payload,
            )
            if not approval.get("approved"):
                self._log_audit_event(
                    "delete_campaign_denied",
                    clean_user_id,
                    clean_workspace_id,
                    payload,
                    success=False,
                )
                return self._error_result(
                    "Security approval denied campaign deletion.",
                    "SECURITY_APPROVAL_DENIED",
                    metadata={**context_meta, "approval": approval},
                )

        if hard_delete:
            self.storage.delete_campaign(clean_user_id, clean_workspace_id, campaign_id)
            data = {
                "campaign_id": campaign_id,
                "deleted": True,
                "hard_delete": True,
            }
            message = "Campaign permanently deleted from local tracker storage."
        else:
            campaign.status = CampaignStatus.ARCHIVED.value
            campaign.updated_at = _utc_now_iso()
            campaign.notes.append(
                {
                    "note_id": self._new_id("note"),
                    "note": _safe_str(reason) or "Campaign archived.",
                    "created_at": _utc_now_iso(),
                    "type": "archive_reason",
                }
            )
            self.storage.save_campaign(campaign)
            data = {
                "campaign": asdict(campaign),
                "deleted": False,
                "hard_delete": False,
            }
            message = "Campaign archived successfully."

        self._after_successful_action("delete_campaign", clean_user_id, clean_workspace_id, data)

        return self._safe_result(
            message,
            data=data,
            metadata={**context_meta, "campaign_id": campaign_id},
        )

    def get_campaign(
        self,
        user_id: str,
        workspace_id: str,
        campaign_id: str,
        include_metrics_summary: bool = True,
    ) -> Dict[str, Any]:
        """
        Retrieve one campaign by ID within user/workspace scope.
        """
        valid, error, context_meta = self._validate_task_context(
            user_id, workspace_id, "get_campaign"
        )
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT", metadata=context_meta)

        clean_user_id = context_meta["user_id"]
        clean_workspace_id = context_meta["workspace_id"]
        campaign_id = _safe_str(campaign_id)

        campaign = self.storage.get_campaign(clean_user_id, clean_workspace_id, campaign_id)
        if not campaign:
            return self._error_result(
                "Campaign not found.",
                "CAMPAIGN_NOT_FOUND",
                metadata={**context_meta, "campaign_id": campaign_id},
            )

        data: Dict[str, Any] = {"campaign": asdict(campaign)}

        if include_metrics_summary:
            summary = self._build_performance_summary(clean_user_id, clean_workspace_id, campaign_id)
            data["performance_summary"] = summary

        return self._safe_result(
            "Campaign retrieved successfully.",
            data=data,
            metadata={**context_meta, "campaign_id": campaign_id},
        )

    def list_campaigns(
        self,
        user_id: str,
        workspace_id: str,
        channel: Optional[str] = None,
        status: Optional[str] = None,
        tag: Optional[str] = None,
        search: Optional[str] = None,
        include_archived: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        List campaigns in the current workspace with optional filters.
        """
        valid, error, context_meta = self._validate_task_context(
            user_id, workspace_id, "list_campaigns"
        )
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT", metadata=context_meta)

        clean_user_id = context_meta["user_id"]
        clean_workspace_id = context_meta["workspace_id"]

        campaigns = self.storage.list_campaigns(clean_user_id, clean_workspace_id)
        filtered = []

        channel_filter = _safe_str(channel).lower()
        status_filter = _safe_str(status).lower()
        tag_filter = _safe_str(tag).lower()
        search_filter = _safe_str(search).lower()

        for campaign in campaigns:
            if not include_archived and campaign.status == CampaignStatus.ARCHIVED.value:
                continue
            if channel_filter and campaign.channel != channel_filter:
                continue
            if status_filter and campaign.status != status_filter:
                continue
            if tag_filter and tag_filter not in [item.lower() for item in campaign.tags]:
                continue
            if search_filter:
                haystack = " ".join(
                    [
                        campaign.name,
                        campaign.objective or "",
                        campaign.source or "",
                        campaign.medium or "",
                        " ".join(campaign.tags),
                    ]
                ).lower()
                if search_filter not in haystack:
                    continue
            filtered.append(campaign)

        total = len(filtered)
        safe_limit = max(1, min(int(limit or 100), 500))
        safe_offset = max(0, int(offset or 0))
        page = filtered[safe_offset : safe_offset + safe_limit]

        return self._safe_result(
            "Campaigns listed successfully.",
            data={
                "campaigns": [asdict(campaign) for campaign in page],
                "total": total,
                "limit": safe_limit,
                "offset": safe_offset,
            },
            metadata={
                **context_meta,
                "filters": {
                    "channel": channel_filter or None,
                    "status": status_filter or None,
                    "tag": tag_filter or None,
                    "search": search_filter or None,
                    "include_archived": include_archived,
                },
            },
        )

    # -------------------------------------------------------------------------
    # Metrics tracking
    # -------------------------------------------------------------------------

    def record_metric(
        self,
        user_id: str,
        workspace_id: str,
        campaign_id: str,
        metric_type: str,
        value: Union[int, float, str],
        occurred_at: Optional[str] = None,
        source: Optional[str] = None,
        dimensions: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Record a metric event/snapshot for a campaign.

        Examples:
            - metric_type="clicks", value=25
            - metric_type="spend", value=50.75
            - metric_type="conversions", value=3
            - metric_type="ranking_position", value=7
        """
        valid, error, context_meta = self._validate_task_context(
            user_id, workspace_id, "record_metric"
        )
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT", metadata=context_meta)

        clean_user_id = context_meta["user_id"]
        clean_workspace_id = context_meta["workspace_id"]
        campaign_id = _safe_str(campaign_id)

        campaign = self.storage.get_campaign(clean_user_id, clean_workspace_id, campaign_id)
        if not campaign:
            return self._error_result(
                "Campaign not found.",
                "CAMPAIGN_NOT_FOUND",
                metadata={**context_meta, "campaign_id": campaign_id},
            )

        clean_metric_type = _safe_str(metric_type).lower()
        if not clean_metric_type:
            return self._error_result(
                "Metric type is required.",
                "MISSING_METRIC_TYPE",
                metadata=context_meta,
            )

        metric_value = _safe_float(value)
        if metric_value < 0 and clean_metric_type != CampaignMetricType.RANKING_POSITION.value:
            return self._error_result(
                "Metric value cannot be negative.",
                "NEGATIVE_METRIC_VALUE",
                metadata={
                    **context_meta,
                    "metric_type": clean_metric_type,
                    "value": metric_value,
                },
            )

        existing_events_count = self.storage.count_metrics(
            clean_user_id,
            clean_workspace_id,
            campaign_id,
        )
        if existing_events_count >= self.max_events_per_campaign:
            return self._error_result(
                "Campaign metric event limit reached.",
                "METRIC_EVENT_LIMIT_REACHED",
                metadata={
                    **context_meta,
                    "campaign_id": campaign_id,
                    "max_events_per_campaign": self.max_events_per_campaign,
                },
            )

        occurred = occurred_at or _utc_now_iso()
        if not _parse_datetime(occurred):
            return self._error_result(
                "Invalid occurred_at datetime.",
                "INVALID_OCCURRED_AT",
                metadata={**context_meta, "occurred_at": occurred},
            )

        event = CampaignMetricEvent(
            event_id=self._new_id("met"),
            user_id=clean_user_id,
            workspace_id=clean_workspace_id,
            campaign_id=campaign_id,
            metric_type=clean_metric_type,
            value=metric_value,
            occurred_at=occurred,
            source=_safe_str(source) or None,
            dimensions=copy.deepcopy(dimensions or {}),
            metadata=copy.deepcopy(metadata or {}),
        )

        self.storage.save_metric(event)

        data = {"metric_event": asdict(event)}
        self._after_successful_action("record_metric", clean_user_id, clean_workspace_id, data)

        return self._safe_result(
            "Campaign metric recorded successfully.",
            data=data,
            metadata={
                **context_meta,
                "campaign_id": campaign_id,
                "metric_type": clean_metric_type,
            },
        )

    def bulk_record_metrics(
        self,
        user_id: str,
        workspace_id: str,
        campaign_id: str,
        metrics: Sequence[Dict[str, Any]],
        source: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Bulk record metric events for one campaign.

        This is treated as sensitive by default because bulk imports can affect
        dashboards, reports, and automated recommendations.
        """
        valid, error, context_meta = self._validate_task_context(
            user_id, workspace_id, "bulk_record_metrics"
        )
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT", metadata=context_meta)

        clean_user_id = context_meta["user_id"]
        clean_workspace_id = context_meta["workspace_id"]
        campaign_id = _safe_str(campaign_id)

        payload = {
            "campaign_id": campaign_id,
            "records_count": len(metrics or []),
            "source": source,
        }

        if self._requires_security_check("bulk_import_campaigns", payload):
            approval = self._request_security_approval(
                "bulk_import_campaigns",
                clean_user_id,
                clean_workspace_id,
                payload,
            )
            if not approval.get("approved"):
                return self._error_result(
                    "Security approval denied bulk metric import.",
                    "SECURITY_APPROVAL_DENIED",
                    metadata={**context_meta, "approval": approval},
                )

        campaign = self.storage.get_campaign(clean_user_id, clean_workspace_id, campaign_id)
        if not campaign:
            return self._error_result(
                "Campaign not found.",
                "CAMPAIGN_NOT_FOUND",
                metadata={**context_meta, "campaign_id": campaign_id},
            )

        if not isinstance(metrics, Sequence) or isinstance(metrics, (str, bytes)):
            return self._error_result(
                "metrics must be a sequence of dictionaries.",
                "INVALID_METRICS_PAYLOAD",
                metadata=context_meta,
            )

        created_events: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []

        for index, item in enumerate(metrics):
            if not isinstance(item, dict):
                errors.append({"index": index, "error": "Metric item must be a dictionary."})
                continue

            metric_type = _safe_str(item.get("metric_type")).lower()
            value = _safe_float(item.get("value"), default=math.nan)
            occurred_at = item.get("occurred_at") or _utc_now_iso()

            if not metric_type:
                errors.append({"index": index, "error": "Missing metric_type."})
                continue

            if math.isnan(value):
                errors.append({"index": index, "error": "Invalid numeric value."})
                continue

            if not _parse_datetime(occurred_at):
                errors.append({"index": index, "error": "Invalid occurred_at."})
                continue

            event = CampaignMetricEvent(
                event_id=self._new_id("met"),
                user_id=clean_user_id,
                workspace_id=clean_workspace_id,
                campaign_id=campaign_id,
                metric_type=metric_type,
                value=value,
                occurred_at=occurred_at,
                source=_safe_str(item.get("source")) or _safe_str(source) or None,
                dimensions=copy.deepcopy(item.get("dimensions") or {}),
                metadata=copy.deepcopy(item.get("metadata") or {}),
            )
            self.storage.save_metric(event)
            created_events.append(asdict(event))

        data = {
            "created_events": created_events,
            "created_count": len(created_events),
            "error_count": len(errors),
            "errors": errors,
        }

        self._after_successful_action("bulk_record_metrics", clean_user_id, clean_workspace_id, data)

        return self._safe_result(
            "Bulk campaign metrics processed.",
            data=data,
            metadata={
                **context_meta,
                "campaign_id": campaign_id,
                "source": source,
            },
        )

    # -------------------------------------------------------------------------
    # Performance analytics
    # -------------------------------------------------------------------------

    def get_campaign_performance(
        self,
        user_id: str,
        workspace_id: str,
        campaign_id: str,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        group_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get performance summary for one campaign.
        """
        valid, error, context_meta = self._validate_task_context(
            user_id, workspace_id, "get_campaign_performance"
        )
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT", metadata=context_meta)

        clean_user_id = context_meta["user_id"]
        clean_workspace_id = context_meta["workspace_id"]
        campaign_id = _safe_str(campaign_id)

        campaign = self.storage.get_campaign(clean_user_id, clean_workspace_id, campaign_id)
        if not campaign:
            return self._error_result(
                "Campaign not found.",
                "CAMPAIGN_NOT_FOUND",
                metadata={**context_meta, "campaign_id": campaign_id},
            )

        date_error = self._validate_date_range(start_date, end_date)
        if date_error:
            return self._error_result("Invalid performance date range.", date_error, metadata=context_meta)

        summary = self._build_performance_summary(
            clean_user_id,
            clean_workspace_id,
            campaign_id,
            start_date=start_date,
            end_date=end_date,
        )

        grouped = {}
        if group_by:
            grouped = self._group_metrics(
                self.storage.list_metrics(
                    clean_user_id,
                    clean_workspace_id,
                    campaign_id,
                    start_date=start_date,
                    end_date=end_date,
                ),
                group_by=group_by,
            )

        data = {
            "campaign": asdict(campaign),
            "summary": summary,
            "grouped": grouped,
        }

        return self._safe_result(
            "Campaign performance calculated successfully.",
            data=data,
            metadata={
                **context_meta,
                "campaign_id": campaign_id,
                "start_date": start_date,
                "end_date": end_date,
                "group_by": group_by,
            },
        )

    def compare_campaigns(
        self,
        user_id: str,
        workspace_id: str,
        campaign_ids: Sequence[str],
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        sort_by: str = "conversions",
        descending: bool = True,
    ) -> Dict[str, Any]:
        """
        Compare multiple campaigns within the same user/workspace.
        """
        valid, error, context_meta = self._validate_task_context(
            user_id, workspace_id, "compare_campaigns"
        )
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT", metadata=context_meta)

        clean_user_id = context_meta["user_id"]
        clean_workspace_id = context_meta["workspace_id"]

        clean_campaign_ids = [_safe_str(item) for item in campaign_ids if _safe_str(item)]
        if not clean_campaign_ids:
            return self._error_result(
                "At least one campaign_id is required.",
                "MISSING_CAMPAIGN_IDS",
                metadata=context_meta,
            )

        rows = []
        missing = []

        for campaign_id in clean_campaign_ids:
            campaign = self.storage.get_campaign(clean_user_id, clean_workspace_id, campaign_id)
            if not campaign:
                missing.append(campaign_id)
                continue

            summary = self._build_performance_summary(
                clean_user_id,
                clean_workspace_id,
                campaign_id,
                start_date=start_date,
                end_date=end_date,
            )
            row = {
                "campaign_id": campaign_id,
                "name": campaign.name,
                "channel": campaign.channel,
                "status": campaign.status,
                "budget": campaign.budget,
                "currency": campaign.currency,
                **summary,
            }
            rows.append(row)

        sort_key = _safe_str(sort_by) or "conversions"
        rows.sort(
            key=lambda item: _safe_float(item.get(sort_key)),
            reverse=bool(descending),
        )

        data = {
            "campaigns": rows,
            "missing_campaign_ids": missing,
            "sort_by": sort_key,
            "descending": bool(descending),
            "winner": rows[0] if rows else None,
        }

        return self._safe_result(
            "Campaign comparison generated successfully.",
            data=data,
            metadata={
                **context_meta,
                "campaign_ids": clean_campaign_ids,
                "start_date": start_date,
                "end_date": end_date,
            },
        )

    def generate_campaign_dashboard(
        self,
        user_id: str,
        workspace_id: str,
        channel: Optional[str] = None,
        status: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        include_recommendations: bool = True,
    ) -> Dict[str, Any]:
        """
        Generate dashboard-ready campaign performance data for current workspace.
        """
        valid, error, context_meta = self._validate_task_context(
            user_id, workspace_id, "generate_campaign_dashboard"
        )
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT", metadata=context_meta)

        clean_user_id = context_meta["user_id"]
        clean_workspace_id = context_meta["workspace_id"]

        list_result = self.list_campaigns(
            user_id=clean_user_id,
            workspace_id=clean_workspace_id,
            channel=channel,
            status=status,
            include_archived=False,
            limit=500,
            offset=0,
        )
        if not list_result.get("success"):
            return list_result

        campaigns = list_result["data"]["campaigns"]
        rows = []
        totals = self._empty_summary()

        channel_breakdown: Dict[str, Dict[str, Any]] = {}
        status_breakdown: Dict[str, int] = {}

        for campaign_dict in campaigns:
            campaign_id = campaign_dict["campaign_id"]
            summary = self._build_performance_summary(
                clean_user_id,
                clean_workspace_id,
                campaign_id,
                start_date=start_date,
                end_date=end_date,
            )
            row = {
                "campaign": campaign_dict,
                "summary": summary,
            }
            rows.append(row)

            totals = self._merge_summary(totals, summary)

            campaign_channel = campaign_dict.get("channel") or "unknown"
            if campaign_channel not in channel_breakdown:
                channel_breakdown[campaign_channel] = self._empty_summary()
            channel_breakdown[campaign_channel] = self._merge_summary(
                channel_breakdown[campaign_channel],
                summary,
            )

            campaign_status = campaign_dict.get("status") or "unknown"
            status_breakdown[campaign_status] = status_breakdown.get(campaign_status, 0) + 1

        totals = self._finalize_derived_metrics(totals)

        for breakdown_channel, summary in list(channel_breakdown.items()):
            channel_breakdown[breakdown_channel] = self._finalize_derived_metrics(summary)

        recommendations = []
        if include_recommendations:
            recommendations = self._generate_recommendations(rows, totals)

        data = {
            "dashboard": {
                "totals": totals,
                "campaigns": rows,
                "channel_breakdown": channel_breakdown,
                "status_breakdown": status_breakdown,
                "recommendations": recommendations,
                "generated_at": _utc_now_iso(),
            }
        }

        return self._safe_result(
            "Campaign dashboard generated successfully.",
            data=data,
            metadata={
                **context_meta,
                "filters": {
                    "channel": channel,
                    "status": status,
                    "start_date": start_date,
                    "end_date": end_date,
                },
            },
        )

    # -------------------------------------------------------------------------
    # Goals
    # -------------------------------------------------------------------------

    def set_campaign_goal(
        self,
        user_id: str,
        workspace_id: str,
        campaign_id: str,
        name: str,
        metric: str,
        operator: str,
        target_value: Union[int, float, str],
        enabled: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a measurable campaign goal.
        """
        valid, error, context_meta = self._validate_task_context(
            user_id, workspace_id, "set_campaign_goal"
        )
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT", metadata=context_meta)

        clean_user_id = context_meta["user_id"]
        clean_workspace_id = context_meta["workspace_id"]
        campaign_id = _safe_str(campaign_id)

        campaign = self.storage.get_campaign(clean_user_id, clean_workspace_id, campaign_id)
        if not campaign:
            return self._error_result(
                "Campaign not found.",
                "CAMPAIGN_NOT_FOUND",
                metadata={**context_meta, "campaign_id": campaign_id},
            )

        clean_name = _safe_str(name)
        clean_metric = _safe_str(metric).lower()
        clean_operator = _safe_str(operator)

        if not clean_name:
            return self._error_result("Goal name is required.", "MISSING_GOAL_NAME", metadata=context_meta)

        if clean_operator not in {">", ">=", "<", "<=", "==", "!="}:
            return self._error_result(
                "Unsupported goal operator.",
                "UNSUPPORTED_GOAL_OPERATOR",
                metadata={
                    **context_meta,
                    "operator": clean_operator,
                    "allowed_operators": [">", ">=", "<", "<=", "==", "!="],
                },
            )

        goal = CampaignGoal(
            goal_id=self._new_id("goal"),
            user_id=clean_user_id,
            workspace_id=clean_workspace_id,
            campaign_id=campaign_id,
            name=clean_name,
            metric=clean_metric,
            operator=clean_operator,
            target_value=_safe_float(target_value),
            enabled=bool(enabled),
            metadata=copy.deepcopy(metadata or {}),
        )

        self.storage.save_goal(goal)

        data = {"goal": asdict(goal)}
        self._after_successful_action("set_campaign_goal", clean_user_id, clean_workspace_id, data)

        return self._safe_result(
            "Campaign goal saved successfully.",
            data=data,
            metadata={**context_meta, "campaign_id": campaign_id},
        )

    def evaluate_campaign_goals(
        self,
        user_id: str,
        workspace_id: str,
        campaign_id: str,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate enabled goals for a campaign against current performance summary.
        """
        valid, error, context_meta = self._validate_task_context(
            user_id, workspace_id, "evaluate_campaign_goals"
        )
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT", metadata=context_meta)

        clean_user_id = context_meta["user_id"]
        clean_workspace_id = context_meta["workspace_id"]
        campaign_id = _safe_str(campaign_id)

        campaign = self.storage.get_campaign(clean_user_id, clean_workspace_id, campaign_id)
        if not campaign:
            return self._error_result(
                "Campaign not found.",
                "CAMPAIGN_NOT_FOUND",
                metadata={**context_meta, "campaign_id": campaign_id},
            )

        summary = self._build_performance_summary(
            clean_user_id,
            clean_workspace_id,
            campaign_id,
            start_date=start_date,
            end_date=end_date,
        )
        goals = self.storage.list_goals(clean_user_id, clean_workspace_id, campaign_id)

        evaluations = []
        for goal in goals:
            if not goal.enabled:
                continue
            current_value = _safe_float(summary.get(goal.metric))
            passed = self._compare(current_value, goal.operator, goal.target_value)
            evaluations.append(
                {
                    "goal": asdict(goal),
                    "current_value": current_value,
                    "target_value": goal.target_value,
                    "passed": passed,
                    "status": "passed" if passed else "missed",
                }
            )

        data = {
            "campaign": asdict(campaign),
            "summary": summary,
            "evaluations": evaluations,
            "passed_count": sum(1 for item in evaluations if item["passed"]),
            "missed_count": sum(1 for item in evaluations if not item["passed"]),
        }

        return self._safe_result(
            "Campaign goals evaluated successfully.",
            data=data,
            metadata={**context_meta, "campaign_id": campaign_id},
        )

    # -------------------------------------------------------------------------
    # Notes, imports, exports, adapters
    # -------------------------------------------------------------------------

    def add_campaign_note(
        self,
        user_id: str,
        workspace_id: str,
        campaign_id: str,
        note: str,
        note_type: str = "general",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Add workspace-scoped campaign note.
        """
        valid, error, context_meta = self._validate_task_context(
            user_id, workspace_id, "add_campaign_note"
        )
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT", metadata=context_meta)

        clean_user_id = context_meta["user_id"]
        clean_workspace_id = context_meta["workspace_id"]
        campaign_id = _safe_str(campaign_id)

        campaign = self.storage.get_campaign(clean_user_id, clean_workspace_id, campaign_id)
        if not campaign:
            return self._error_result(
                "Campaign not found.",
                "CAMPAIGN_NOT_FOUND",
                metadata={**context_meta, "campaign_id": campaign_id},
            )

        clean_note = _safe_str(note)
        if not clean_note:
            return self._error_result("Note cannot be empty.", "EMPTY_NOTE", metadata=context_meta)

        note_payload = {
            "note_id": self._new_id("note"),
            "note": clean_note,
            "type": _safe_str(note_type) or "general",
            "metadata": copy.deepcopy(metadata or {}),
            "created_at": _utc_now_iso(),
        }
        campaign.notes.append(note_payload)
        campaign.updated_at = _utc_now_iso()
        self.storage.save_campaign(campaign)

        data = {"campaign": asdict(campaign), "note": note_payload}
        self._after_successful_action("add_campaign_note", clean_user_id, clean_workspace_id, data)

        return self._safe_result(
            "Campaign note added successfully.",
            data=data,
            metadata={**context_meta, "campaign_id": campaign_id},
        )

    def export_campaign_data(
        self,
        user_id: str,
        workspace_id: str,
        campaign_id: Optional[str] = None,
        format_type: str = "dict",
        include_metrics: bool = True,
    ) -> Dict[str, Any]:
        """
        Export campaign data for dashboard/API use.

        Supported format_type:
            - dict
            - csv

        This is protected because campaign exports can contain business data.
        """
        valid, error, context_meta = self._validate_task_context(
            user_id, workspace_id, "export_campaign_data"
        )
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT", metadata=context_meta)

        clean_user_id = context_meta["user_id"]
        clean_workspace_id = context_meta["workspace_id"]
        clean_campaign_id = _safe_str(campaign_id) or None

        payload = {
            "campaign_id": clean_campaign_id,
            "format_type": format_type,
            "include_metrics": include_metrics,
            "contains_export": True,
        }
        approval = self._request_security_approval(
            "export_campaign_data",
            clean_user_id,
            clean_workspace_id,
            payload,
        )
        if not approval.get("approved"):
            return self._error_result(
                "Security approval denied campaign data export.",
                "SECURITY_APPROVAL_DENIED",
                metadata={**context_meta, "approval": approval},
            )

        campaigns = (
            [self.storage.get_campaign(clean_user_id, clean_workspace_id, clean_campaign_id)]
            if clean_campaign_id
            else self.storage.list_campaigns(clean_user_id, clean_workspace_id)
        )
        campaigns = [campaign for campaign in campaigns if campaign is not None]

        export_rows = []
        for campaign in campaigns:
            campaign_dict = asdict(campaign)
            row: Dict[str, Any] = {"campaign": campaign_dict}
            if include_metrics:
                row["metrics"] = [
                    asdict(event)
                    for event in self.storage.list_metrics(
                        clean_user_id,
                        clean_workspace_id,
                        campaign.campaign_id,
                    )
                ]
                row["summary"] = self._build_performance_summary(
                    clean_user_id,
                    clean_workspace_id,
                    campaign.campaign_id,
                )
            export_rows.append(row)

        if format_type == "dict":
            export_data: Union[List[Dict[str, Any]], str] = export_rows
        elif format_type == "csv":
            export_data = self._campaigns_to_csv(export_rows)
        else:
            return self._error_result(
                "Unsupported export format.",
                "UNSUPPORTED_EXPORT_FORMAT",
                metadata={
                    **context_meta,
                    "format_type": format_type,
                    "allowed_formats": ["dict", "csv"],
                },
            )

        data = {
            "export": export_data,
            "format_type": format_type,
            "campaign_count": len(campaigns),
            "include_metrics": include_metrics,
        }

        self._after_successful_action("export_campaign_data", clean_user_id, clean_workspace_id, data)

        return self._safe_result(
            "Campaign data exported successfully.",
            data=data,
            metadata={**context_meta, "campaign_id": clean_campaign_id},
        )

    def sync_external_campaign_source(
        self,
        user_id: str,
        workspace_id: str,
        source_name: str,
        records: Sequence[Dict[str, Any]],
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """
        Normalize externally provided campaign records.

        This method does not call external APIs. It accepts records already
        provided by a connector/adapter and optionally imports them after
        Security Agent approval.
        """
        valid, error, context_meta = self._validate_task_context(
            user_id, workspace_id, "sync_external_campaign_source"
        )
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT", metadata=context_meta)

        clean_user_id = context_meta["user_id"]
        clean_workspace_id = context_meta["workspace_id"]
        clean_source_name = _safe_str(source_name) or "external"

        payload = {
            "source_name": clean_source_name,
            "records_count": len(records or []),
            "dry_run": dry_run,
            "external_sync": True,
        }

        approval = self._request_security_approval(
            "sync_external_campaign_source",
            clean_user_id,
            clean_workspace_id,
            payload,
        )
        if not approval.get("approved"):
            return self._error_result(
                "Security approval denied external campaign sync.",
                "SECURITY_APPROVAL_DENIED",
                metadata={**context_meta, "approval": approval},
            )

        normalized = []
        errors = []

        for index, record in enumerate(records):
            try:
                normalized_record = self._normalize_external_campaign_record(
                    record,
                    clean_user_id,
                    clean_workspace_id,
                    clean_source_name,
                )
                normalized.append(normalized_record)
            except Exception as exc:
                errors.append({"index": index, "error": str(exc)})

        created = []
        if not dry_run:
            for item in normalized:
                result = self.create_campaign(
                    user_id=clean_user_id,
                    workspace_id=clean_workspace_id,
                    name=item["name"],
                    channel=item["channel"],
                    status=item["status"],
                    objective=item.get("objective"),
                    source=item.get("source"),
                    medium=item.get("medium"),
                    landing_page_url=item.get("landing_page_url"),
                    budget=item.get("budget", 0.0),
                    currency=item.get("currency", self.default_currency),
                    start_date=item.get("start_date"),
                    end_date=item.get("end_date"),
                    tags=item.get("tags"),
                    external_refs=item.get("external_refs"),
                    metadata=item.get("metadata"),
                )
                if result.get("success"):
                    created.append(result["data"]["campaign"])
                else:
                    errors.append({"record": item, "error": result.get("error")})

        data = {
            "dry_run": dry_run,
            "normalized_records": normalized,
            "created_campaigns": created,
            "normalized_count": len(normalized),
            "created_count": len(created),
            "error_count": len(errors),
            "errors": errors,
        }

        self._after_successful_action(
            "sync_external_campaign_source",
            clean_user_id,
            clean_workspace_id,
            data,
        )

        return self._safe_result(
            "External campaign source processed successfully.",
            data=data,
            metadata={**context_meta, "source_name": clean_source_name},
        )

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _after_successful_action(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        data: Dict[str, Any],
    ) -> None:
        """
        Shared post-success pipeline for events, audit, memory, and verification.
        """
        self._emit_agent_event(
            f"campaign_tracker.{action}",
            user_id,
            workspace_id,
            {"action": action, "data": data},
        )
        self._log_audit_event(action, user_id, workspace_id, {"data": data}, success=True)

        memory_payload = self._prepare_memory_payload(action, user_id, workspace_id, data)
        verification_payload = self._prepare_verification_payload(action, user_id, workspace_id, data)

        if self.memory_callback:
            try:
                self.memory_callback(memory_payload)
            except Exception:
                logger.exception("Memory callback failed for action=%s", action)

        if self.verification_callback:
            try:
                self.verification_callback(verification_payload)
            except Exception:
                logger.exception("Verification callback failed for action=%s", action)

    def _new_id(self, prefix: str) -> str:
        """Generate a stable prefixed ID."""
        return f"{prefix}_{uuid.uuid4().hex}"

    def _validate_date_range(
        self,
        start_date: Optional[str],
        end_date: Optional[str],
    ) -> Optional[str]:
        """Validate optional date range."""
        start = _parse_datetime(start_date) if start_date else None
        end = _parse_datetime(end_date) if end_date else None

        if start_date and not start:
            return "INVALID_START_DATE"

        if end_date and not end:
            return "INVALID_END_DATE"

        if start and end and start > end:
            return "START_DATE_AFTER_END_DATE"

        return None

    def _build_performance_summary(
        self,
        user_id: str,
        workspace_id: str,
        campaign_id: str,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build a campaign performance summary from metric events.
        """
        events = self.storage.list_metrics(
            user_id,
            workspace_id,
            campaign_id,
            start_date=start_date,
            end_date=end_date,
        )

        summary = self._empty_summary()

        ranking_positions = []

        for event in events:
            metric = event.metric_type
            value = _safe_float(event.value)

            if metric == CampaignMetricType.RANKING_POSITION.value:
                if value > 0:
                    ranking_positions.append(value)
                continue

            if metric in summary:
                summary[metric] += value
            else:
                summary[metric] = summary.get(metric, 0.0) + value

        if ranking_positions:
            summary["average_ranking_position"] = round(statistics.mean(ranking_positions), 2)
            summary["best_ranking_position"] = round(min(ranking_positions), 2)
            summary["worst_ranking_position"] = round(max(ranking_positions), 2)
        else:
            summary["average_ranking_position"] = None
            summary["best_ranking_position"] = None
            summary["worst_ranking_position"] = None

        summary["event_count"] = len(events)

        return self._finalize_derived_metrics(summary)

    def _empty_summary(self) -> Dict[str, Any]:
        """Create empty performance summary structure."""
        return {
            "impressions": 0.0,
            "clicks": 0.0,
            "spend": 0.0,
            "conversions": 0.0,
            "revenue": 0.0,
            "leads": 0.0,
            "sessions": 0.0,
            "bounces": 0.0,
            "page_views": 0.0,
            "form_submits": 0.0,
            "calls": 0.0,
            "messages": 0.0,
            "organic_traffic": 0.0,
            "social_reach": 0.0,
            "engagements": 0.0,
            "ctr": 0.0,
            "cpc": 0.0,
            "cpa": 0.0,
            "cpl": 0.0,
            "conversion_rate": 0.0,
            "lead_rate": 0.0,
            "bounce_rate": 0.0,
            "roas": 0.0,
            "roi": 0.0,
            "revenue_per_click": 0.0,
            "event_count": 0,
        }

    def _merge_summary(self, base: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge additive fields from two summaries.
        """
        additive_fields = {
            "impressions",
            "clicks",
            "spend",
            "conversions",
            "revenue",
            "leads",
            "sessions",
            "bounces",
            "page_views",
            "form_submits",
            "calls",
            "messages",
            "organic_traffic",
            "social_reach",
            "engagements",
            "event_count",
        }

        merged = copy.deepcopy(base)
        for field_name in additive_fields:
            merged[field_name] = _safe_float(merged.get(field_name)) + _safe_float(
                incoming.get(field_name)
            )

        return self._finalize_derived_metrics(merged)

    def _finalize_derived_metrics(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate derived marketing KPIs.
        """
        impressions = _safe_float(summary.get("impressions"))
        clicks = _safe_float(summary.get("clicks"))
        spend = _safe_float(summary.get("spend"))
        conversions = _safe_float(summary.get("conversions"))
        revenue = _safe_float(summary.get("revenue"))
        leads = _safe_float(summary.get("leads"))
        sessions = _safe_float(summary.get("sessions"))
        bounces = _safe_float(summary.get("bounces"))

        summary["ctr"] = self._percentage(clicks, impressions)
        summary["cpc"] = self._ratio(spend, clicks)
        summary["cpa"] = self._ratio(spend, conversions)
        summary["cpl"] = self._ratio(spend, leads)
        summary["conversion_rate"] = self._percentage(conversions, clicks or sessions)
        summary["lead_rate"] = self._percentage(leads, clicks or sessions)
        summary["bounce_rate"] = self._percentage(bounces, sessions)
        summary["roas"] = self._ratio(revenue, spend)
        summary["roi"] = self._percentage(revenue - spend, spend) if spend else 0.0
        summary["revenue_per_click"] = self._ratio(revenue, clicks)

        for key, value in list(summary.items()):
            if isinstance(value, float):
                summary[key] = round(value, 4)

        return summary

    def _percentage(self, numerator: float, denominator: float) -> float:
        """Calculate percentage safely."""
        if not denominator:
            return 0.0
        return (numerator / denominator) * 100.0

    def _ratio(self, numerator: float, denominator: float) -> float:
        """Calculate ratio safely."""
        if not denominator:
            return 0.0
        return numerator / denominator

    def _group_metrics(
        self,
        events: Sequence[CampaignMetricEvent],
        group_by: str,
    ) -> Dict[str, Dict[str, float]]:
        """
        Group metrics by date, metric_type, source, or a dimension key.
        """
        clean_group_by = _safe_str(group_by)
        grouped: Dict[str, Dict[str, float]] = {}

        for event in events:
            if clean_group_by == "date":
                parsed = _parse_datetime(event.occurred_at)
                group_key = parsed.date().isoformat() if parsed else "unknown"
            elif clean_group_by == "metric_type":
                group_key = event.metric_type
            elif clean_group_by == "source":
                group_key = event.source or "unknown"
            else:
                group_key = _safe_str(event.dimensions.get(clean_group_by)) or "unknown"

            if group_key not in grouped:
                grouped[group_key] = {}

            grouped[group_key][event.metric_type] = grouped[group_key].get(event.metric_type, 0.0) + event.value

        return grouped

    def _generate_recommendations(
        self,
        campaign_rows: Sequence[Dict[str, Any]],
        totals: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Generate safe campaign optimization recommendations.

        These are advisory only. They do not modify campaigns or budgets.
        """
        recommendations: List[Dict[str, Any]] = []

        if _safe_float(totals.get("spend")) > 0 and _safe_float(totals.get("conversions")) == 0:
            recommendations.append(
                {
                    "type": "conversion_tracking",
                    "priority": "high",
                    "message": "Spend is recorded but conversions are zero. Review conversion tracking, landing page form tracking, and offer alignment.",
                }
            )

        if _safe_float(totals.get("impressions")) > 0 and _safe_float(totals.get("ctr")) < 1:
            recommendations.append(
                {
                    "type": "creative_or_keyword",
                    "priority": "medium",
                    "message": "Overall CTR is below 1%. Review ad copy, keywords, targeting, and creative relevance.",
                }
            )

        if _safe_float(totals.get("sessions")) > 0 and _safe_float(totals.get("bounce_rate")) > 70:
            recommendations.append(
                {
                    "type": "landing_page",
                    "priority": "high",
                    "message": "Landing page bounce rate is high. Review page speed, above-the-fold message, trust signals, and CTA clarity.",
                }
            )

        for row in campaign_rows:
            campaign = row.get("campaign", {})
            summary = row.get("summary", {})
            spend = _safe_float(summary.get("spend"))
            conversions = _safe_float(summary.get("conversions"))
            clicks = _safe_float(summary.get("clicks"))

            if spend > 0 and clicks == 0:
                recommendations.append(
                    {
                        "type": "traffic_quality",
                        "priority": "high",
                        "campaign_id": campaign.get("campaign_id"),
                        "message": f"Campaign '{campaign.get('name')}' has spend but no clicks. Check tracking source, campaign setup, or imported metrics.",
                    }
                )

            if clicks >= 100 and conversions == 0:
                recommendations.append(
                    {
                        "type": "offer_or_page",
                        "priority": "high",
                        "campaign_id": campaign.get("campaign_id"),
                        "message": f"Campaign '{campaign.get('name')}' has at least 100 clicks with no conversions. Review landing page, offer, and lead capture flow.",
                    }
                )

        return recommendations

    def _normalize_external_campaign_record(
        self,
        record: Dict[str, Any],
        user_id: str,
        workspace_id: str,
        source_name: str,
    ) -> Dict[str, Any]:
        """
        Normalize external campaign record into CampaignRecord-compatible data.
        """
        if not isinstance(record, dict):
            raise ValueError("External record must be a dictionary.")

        name = _safe_str(record.get("name") or record.get("campaign_name"))
        if not name:
            raise ValueError("External record missing campaign name.")

        channel = _safe_str(record.get("channel") or record.get("type") or CampaignChannel.OTHER.value).lower()
        if channel not in self.allowed_channels:
            channel = CampaignChannel.OTHER.value

        status = _safe_str(record.get("status") or CampaignStatus.DRAFT.value).lower()
        if status not in {item.value for item in CampaignStatus}:
            status = CampaignStatus.DRAFT.value

        external_id = record.get("external_id") or record.get("id") or record.get("campaign_id")

        return {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "name": name,
            "channel": channel,
            "status": status,
            "objective": record.get("objective"),
            "source": source_name,
            "medium": record.get("medium"),
            "landing_page_url": record.get("landing_page_url") or record.get("url"),
            "budget": _safe_float(record.get("budget")),
            "currency": _safe_str(record.get("currency") or self.default_currency).upper(),
            "start_date": record.get("start_date"),
            "end_date": record.get("end_date"),
            "tags": _normalize_list(record.get("tags")),
            "external_refs": {
                "source_name": source_name,
                "external_id": external_id,
                "raw_source": source_name,
            },
            "metadata": {
                "imported_from": source_name,
                "raw_record": copy.deepcopy(record),
            },
        }

    def _campaigns_to_csv(self, export_rows: Sequence[Dict[str, Any]]) -> str:
        """
        Convert campaign export rows to CSV.
        """
        output = io.StringIO()
        fieldnames = [
            "campaign_id",
            "name",
            "channel",
            "status",
            "objective",
            "source",
            "medium",
            "landing_page_url",
            "budget",
            "currency",
            "impressions",
            "clicks",
            "spend",
            "conversions",
            "revenue",
            "leads",
            "ctr",
            "cpc",
            "cpa",
            "cpl",
            "conversion_rate",
            "roas",
            "roi",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for row in export_rows:
            campaign = row.get("campaign", {})
            summary = row.get("summary", {})
            writer.writerow(
                {
                    "campaign_id": campaign.get("campaign_id"),
                    "name": campaign.get("name"),
                    "channel": campaign.get("channel"),
                    "status": campaign.get("status"),
                    "objective": campaign.get("objective"),
                    "source": campaign.get("source"),
                    "medium": campaign.get("medium"),
                    "landing_page_url": campaign.get("landing_page_url"),
                    "budget": campaign.get("budget"),
                    "currency": campaign.get("currency"),
                    "impressions": summary.get("impressions"),
                    "clicks": summary.get("clicks"),
                    "spend": summary.get("spend"),
                    "conversions": summary.get("conversions"),
                    "revenue": summary.get("revenue"),
                    "leads": summary.get("leads"),
                    "ctr": summary.get("ctr"),
                    "cpc": summary.get("cpc"),
                    "cpa": summary.get("cpa"),
                    "cpl": summary.get("cpl"),
                    "conversion_rate": summary.get("conversion_rate"),
                    "roas": summary.get("roas"),
                    "roi": summary.get("roi"),
                }
            )

        return output.getvalue()

    def _compare(self, current: float, operator: str, target: float) -> bool:
        """Evaluate goal condition."""
        if operator == ">":
            return current > target
        if operator == ">=":
            return current >= target
        if operator == "<":
            return current < target
        if operator == "<=":
            return current <= target
        if operator == "==":
            return current == target
        if operator == "!=":
            return current != target
        return False


class MutableCampaignStorage:
    """
    Storage interface for CampaignTracker.

    Production can replace InMemoryCampaignStorage with a database-backed
    implementation while preserving this interface.
    """

    def save_campaign(self, campaign: CampaignRecord) -> None:
        raise NotImplementedError

    def get_campaign(self, user_id: str, workspace_id: str, campaign_id: str) -> Optional[CampaignRecord]:
        raise NotImplementedError

    def list_campaigns(self, user_id: str, workspace_id: str) -> List[CampaignRecord]:
        raise NotImplementedError

    def delete_campaign(self, user_id: str, workspace_id: str, campaign_id: str) -> None:
        raise NotImplementedError

    def count_campaigns(self, user_id: str, workspace_id: str) -> int:
        raise NotImplementedError

    def save_metric(self, metric: CampaignMetricEvent) -> None:
        raise NotImplementedError

    def list_metrics(
        self,
        user_id: str,
        workspace_id: str,
        campaign_id: str,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> List[CampaignMetricEvent]:
        raise NotImplementedError

    def count_metrics(self, user_id: str, workspace_id: str, campaign_id: str) -> int:
        raise NotImplementedError

    def save_goal(self, goal: CampaignGoal) -> None:
        raise NotImplementedError

    def list_goals(self, user_id: str, workspace_id: str, campaign_id: str) -> List[CampaignGoal]:
        raise NotImplementedError


class InMemoryCampaignStorage(MutableCampaignStorage):
    """
    Import-safe in-memory storage.

    This is suitable for unit tests, local development, and agent-loader safety.
    Production should replace this with a database/repository implementation.
    """

    def __init__(self) -> None:
        self._campaigns: Dict[Tuple[str, str, str], CampaignRecord] = {}
        self._metrics: Dict[Tuple[str, str, str], List[CampaignMetricEvent]] = {}
        self._goals: Dict[Tuple[str, str, str], List[CampaignGoal]] = {}

    def save_campaign(self, campaign: CampaignRecord) -> None:
        key = self._campaign_key(campaign.user_id, campaign.workspace_id, campaign.campaign_id)
        self._campaigns[key] = copy.deepcopy(campaign)

    def get_campaign(self, user_id: str, workspace_id: str, campaign_id: str) -> Optional[CampaignRecord]:
        key = self._campaign_key(user_id, workspace_id, campaign_id)
        campaign = self._campaigns.get(key)
        return copy.deepcopy(campaign) if campaign else None

    def list_campaigns(self, user_id: str, workspace_id: str) -> List[CampaignRecord]:
        return [
            copy.deepcopy(campaign)
            for (stored_user_id, stored_workspace_id, _), campaign in self._campaigns.items()
            if stored_user_id == user_id and stored_workspace_id == workspace_id
        ]

    def delete_campaign(self, user_id: str, workspace_id: str, campaign_id: str) -> None:
        campaign_key = self._campaign_key(user_id, workspace_id, campaign_id)
        metric_key = self._campaign_key(user_id, workspace_id, campaign_id)
        goal_key = self._campaign_key(user_id, workspace_id, campaign_id)

        self._campaigns.pop(campaign_key, None)
        self._metrics.pop(metric_key, None)
        self._goals.pop(goal_key, None)

    def count_campaigns(self, user_id: str, workspace_id: str) -> int:
        return len(self.list_campaigns(user_id, workspace_id))

    def save_metric(self, metric: CampaignMetricEvent) -> None:
        key = self._campaign_key(metric.user_id, metric.workspace_id, metric.campaign_id)
        self._metrics.setdefault(key, []).append(copy.deepcopy(metric))

    def list_metrics(
        self,
        user_id: str,
        workspace_id: str,
        campaign_id: str,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> List[CampaignMetricEvent]:
        key = self._campaign_key(user_id, workspace_id, campaign_id)
        events = [copy.deepcopy(event) for event in self._metrics.get(key, [])]

        start = _parse_datetime(start_date) if start_date else None
        end = _parse_datetime(end_date) if end_date else None

        filtered = []
        for event in events:
            occurred = _parse_datetime(event.occurred_at)
            if not occurred:
                continue
            if start and occurred < start:
                continue
            if end and occurred > end:
                continue
            filtered.append(event)

        filtered.sort(key=lambda item: item.occurred_at)
        return filtered

    def count_metrics(self, user_id: str, workspace_id: str, campaign_id: str) -> int:
        key = self._campaign_key(user_id, workspace_id, campaign_id)
        return len(self._metrics.get(key, []))

    def save_goal(self, goal: CampaignGoal) -> None:
        key = self._campaign_key(goal.user_id, goal.workspace_id, goal.campaign_id)
        goals = self._goals.setdefault(key, [])

        for index, existing in enumerate(goals):
            if existing.goal_id == goal.goal_id:
                goals[index] = copy.deepcopy(goal)
                return

        goals.append(copy.deepcopy(goal))

    def list_goals(self, user_id: str, workspace_id: str, campaign_id: str) -> List[CampaignGoal]:
        key = self._campaign_key(user_id, workspace_id, campaign_id)
        return [copy.deepcopy(goal) for goal in self._goals.get(key, [])]

    def _campaign_key(self, user_id: str, workspace_id: str, campaign_id: str) -> Tuple[str, str, str]:
        return (_safe_str(user_id), _safe_str(workspace_id), _safe_str(campaign_id))


__all__ = [
    "AttributionModel",
    "CampaignChannel",
    "CampaignGoal",
    "CampaignMetricEvent",
    "CampaignMetricType",
    "CampaignRecord",
    "CampaignStatus",
    "CampaignTracker",
    "InMemoryCampaignStorage",
    "MutableCampaignStorage",
]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    tracker = CampaignTracker()

    create_result = tracker.create_campaign(
        user_id="demo_user",
        workspace_id="demo_workspace",
        name="Demo Google Ads Campaign",
        channel=CampaignChannel.GOOGLE_ADS.value,
        status=CampaignStatus.ACTIVE.value,
        objective="Lead generation",
        budget=500,
        currency="USD",
        tags=["google", "lead-gen"],
    )

    print(create_result)

    if create_result["success"]:
        demo_campaign_id = create_result["data"]["campaign"]["campaign_id"]

        tracker.record_metric(
            user_id="demo_user",
            workspace_id="demo_workspace",
            campaign_id=demo_campaign_id,
            metric_type=CampaignMetricType.IMPRESSIONS.value,
            value=10000,
        )
        tracker.record_metric(
            user_id="demo_user",
            workspace_id="demo_workspace",
            campaign_id=demo_campaign_id,
            metric_type=CampaignMetricType.CLICKS.value,
            value=250,
        )
        tracker.record_metric(
            user_id="demo_user",
            workspace_id="demo_workspace",
            campaign_id=demo_campaign_id,
            metric_type=CampaignMetricType.SPEND.value,
            value=300,
        )
        tracker.record_metric(
            user_id="demo_user",
            workspace_id="demo_workspace",
            campaign_id=demo_campaign_id,
            metric_type=CampaignMetricType.CONVERSIONS.value,
            value=12,
        )
        tracker.record_metric(
            user_id="demo_user",
            workspace_id="demo_workspace",
            campaign_id=demo_campaign_id,
            metric_type=CampaignMetricType.REVENUE.value,
            value=1200,
        )

        performance = tracker.get_campaign_performance(
            user_id="demo_user",
            workspace_id="demo_workspace",
            campaign_id=demo_campaign_id,
        )

        print(performance)