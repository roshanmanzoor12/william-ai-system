"""
William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

File:
    agents/super_agents/creator_agent/content_planner.py

Purpose:
    Content calendar, topics, platform plans, campaigns, and scheduling helper
    for the Creator Agent.

This module is designed to be:
    - Import-safe even if the rest of the William/Jarvis codebase is incomplete.
    - Compatible with BaseAgent-style execution.
    - Compatible with Master Agent routing, Agent Registry, Agent Loader, and dashboard/API use.
    - Safe for SaaS multi-tenant user/workspace isolation.
    - Ready for Security Agent approval handoff where publishing/scheduling actions are sensitive.
    - Ready for Memory Agent and Verification Agent payload preparation.

Important:
    This file does NOT directly publish content, send messages, call external APIs,
    modify calendars, or perform destructive actions. It prepares structured plans,
    schedules, campaigns, topics, briefs, and approval/verification payloads only.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import-safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        The real William/Jarvis system should provide agents.base_agent.BaseAgent.
        This stub keeps the file import-safe during early development.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "creator")
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            raise NotImplementedError("Fallback BaseAgent does not implement run().")


try:
    from agents.agent_registry import register_agent  # type: ignore
except Exception:  # pragma: no cover - fallback decorator
    def register_agent(*args: Any, **kwargs: Any):
        """
        Fallback register_agent decorator.

        The real registry can replace this automatically when available.
        """
        def decorator(cls: Any) -> Any:
            return cls

        if args and isinstance(args[0], type):
            return args[0]
        return decorator


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants and enums
# ---------------------------------------------------------------------------

DEFAULT_TIMEZONE = "UTC"

DEFAULT_CONTENT_PILLARS: Tuple[str, ...] = (
    "education",
    "authority",
    "case_study",
    "offer",
    "behind_the_scenes",
    "community",
    "trend",
)

DEFAULT_PLATFORMS: Tuple[str, ...] = (
    "youtube",
    "youtube_shorts",
    "instagram",
    "facebook",
    "tiktok",
    "linkedin",
    "x",
    "blog",
    "email",
)

DEFAULT_CONTENT_FORMATS: Tuple[str, ...] = (
    "short_video",
    "long_video",
    "carousel",
    "single_image",
    "text_post",
    "thread",
    "blog_article",
    "email_newsletter",
    "live_stream",
    "story",
)

DEFAULT_CAMPAIGN_OBJECTIVES: Tuple[str, ...] = (
    "awareness",
    "engagement",
    "lead_generation",
    "conversion",
    "retention",
    "authority_building",
    "community_growth",
)

SENSITIVE_ACTIONS: Tuple[str, ...] = (
    "publish",
    "schedule_publish",
    "send_email_campaign",
    "boost_post",
    "paid_campaign",
    "delete_calendar",
    "external_api_push",
)

PUBLIC_METHODS: Tuple[str, ...] = (
    "run",
    "create_content_calendar",
    "generate_topic_ideas",
    "create_platform_plan",
    "create_campaign_plan",
    "create_scheduling_plan",
    "expand_topic_into_posts",
    "audit_calendar",
    "prepare_dashboard_payload",
)


class ContentPriority(str, Enum):
    """Priority levels for content tasks."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class ContentStatus(str, Enum):
    """Lifecycle status for planned content."""

    IDEA = "idea"
    PLANNED = "planned"
    BRIEF_READY = "brief_ready"
    IN_PRODUCTION = "in_production"
    REVIEW_REQUIRED = "review_required"
    APPROVED = "approved"
    SCHEDULED = "scheduled"
    PUBLISHED = "published"
    PAUSED = "paused"
    ARCHIVED = "archived"


class PlatformType(str, Enum):
    """Supported platform identifiers."""

    YOUTUBE = "youtube"
    YOUTUBE_SHORTS = "youtube_shorts"
    INSTAGRAM = "instagram"
    FACEBOOK = "facebook"
    TIKTOK = "tiktok"
    LINKEDIN = "linkedin"
    X = "x"
    BLOG = "blog"
    EMAIL = "email"


class CalendarCadence(str, Enum):
    """Common planning cadences."""

    DAILY = "daily"
    WEEKLY = "weekly"
    BIWEEKLY = "biweekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SaaSContext:
    """
    User/workspace context for tenant isolation.

    Every task that involves user-specific planning must include user_id and
    workspace_id. This prevents mixing content, calendars, memory, analytics,
    audit logs, or planning artifacts across tenants.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    subscription_plan: Optional[str] = None
    permissions: Dict[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ContentTopic:
    """A generated or supplied content topic."""

    topic_id: str
    title: str
    pillar: str
    objective: str
    audience: str
    funnel_stage: str
    angle: str
    hook: str
    keywords: List[str] = field(default_factory=list)
    formats: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    priority: str = ContentPriority.NORMAL.value
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ContentItem:
    """A planned content calendar item."""

    content_id: str
    title: str
    platform: str
    content_format: str
    scheduled_date: str
    scheduled_time: Optional[str]
    timezone: str
    pillar: str
    objective: str
    funnel_stage: str
    audience: str
    hook: str
    caption_brief: str
    creative_brief: str
    call_to_action: str
    keywords: List[str] = field(default_factory=list)
    hashtags: List[str] = field(default_factory=list)
    status: str = ContentStatus.PLANNED.value
    priority: str = ContentPriority.NORMAL.value
    owner_agent: str = "creator_agent"
    requires_security_approval: bool = False
    approval_reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CampaignPlan:
    """Structured campaign plan."""

    campaign_id: str
    campaign_name: str
    objective: str
    start_date: str
    end_date: str
    timezone: str
    target_audience: str
    platforms: List[str]
    content_pillars: List[str]
    content_items: List[Dict[str, Any]]
    weekly_themes: List[Dict[str, Any]]
    kpis: Dict[str, Any]
    budget_notes: Optional[str] = None
    approval_required: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    """Return current UTC timestamp as ISO string."""
    return datetime.now(timezone.utc).isoformat()


def _safe_slug(value: str, max_length: int = 80) -> str:
    """Create a safe slug from arbitrary text."""
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-")
    return value[:max_length] or "item"


def _stable_id(prefix: str, payload: Any) -> str:
    """Generate stable readable ID from payload."""
    raw = json.dumps(payload, sort_keys=True, default=str)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def _coerce_list(value: Any, default: Optional[Sequence[str]] = None) -> List[str]:
    """Coerce a value into a clean list of strings."""
    if value is None:
        return list(default or [])
    if isinstance(value, str):
        if "," in value:
            return [v.strip() for v in value.split(",") if v.strip()]
        return [value.strip()] if value.strip() else list(default or [])
    if isinstance(value, Iterable):
        items: List[str] = []
        for item in value:
            if item is None:
                continue
            text = str(item).strip()
            if text:
                items.append(text)
        return items or list(default or [])
    return list(default or [])


def _parse_date(value: Union[str, date, datetime, None], fallback: Optional[date] = None) -> date:
    """Parse date-like value into a date."""
    if value is None:
        return fallback or date.today()
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return fallback or date.today()
        try:
            return datetime.fromisoformat(cleaned.replace("Z", "+00:00")).date()
        except ValueError:
            try:
                return datetime.strptime(cleaned, "%Y-%m-%d").date()
            except ValueError:
                return fallback or date.today()
    return fallback or date.today()


def _date_range(start: date, end: date) -> List[date]:
    """Return inclusive date range."""
    if end < start:
        start, end = end, start
    days = (end - start).days
    return [start + timedelta(days=i) for i in range(days + 1)]


def _round_robin(items: Sequence[str], index: int, fallback: str) -> str:
    """Return item by index with round-robin behavior."""
    clean = [i for i in items if i]
    if not clean:
        return fallback
    return clean[index % len(clean)]


def _dedupe_keep_order(items: Sequence[str]) -> List[str]:
    """Dedupe list while preserving order."""
    seen = set()
    output: List[str] = []
    for item in items:
        key = item.strip().lower()
        if key and key not in seen:
            seen.add(key)
            output.append(item.strip())
    return output


# ---------------------------------------------------------------------------
# Content Planner
# ---------------------------------------------------------------------------

@register_agent(name="content_planner", agent_type="creator", version="1.0.0")
class ContentPlanner(BaseAgent):
    """
    Content calendar and campaign planning helper for Creator Agent.

    This class prepares:
        - Content calendars
        - Topic ideas
        - Platform-specific plans
        - Campaign plans
        - Scheduling plans
        - Dashboard/API payloads
        - Memory and verification payloads

    It does not directly publish or schedule externally. Any sensitive action is
    routed through security approval payloads so the Master Agent or Security
    Agent can approve, deny, or escalate.

    Master Agent connection:
        The Master Agent can call run(task) with an action field such as:
            - create_content_calendar
            - generate_topic_ideas
            - create_platform_plan
            - create_campaign_plan
            - create_scheduling_plan
            - expand_topic_into_posts
            - audit_calendar

    Security Agent connection:
        _requires_security_check() detects publish/schedule/paid/external actions.
        _request_security_approval() prepares approval payload only.

    Memory Agent connection:
        _prepare_memory_payload() returns safe preferences and reusable planning
        context without mixing tenants.

    Verification Agent connection:
        _prepare_verification_payload() returns structured output for later review.

    Dashboard/API connection:
        prepare_dashboard_payload() returns compact UI-ready cards, tables, and
        metrics suitable for FastAPI or a dashboard frontend.

    Registry/Loader connection:
        Class is decorated with register_agent when the real registry exists.
    """

    agent_name = "content_planner"
    agent_type = "creator"
    version = "1.0.0"

    def __init__(
        self,
        *,
        default_timezone: str = DEFAULT_TIMEZONE,
        default_platforms: Optional[Sequence[str]] = None,
        default_pillars: Optional[Sequence[str]] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=self.agent_name,
            agent_type=self.agent_type,
            **kwargs,
        )
        self.default_timezone = default_timezone or DEFAULT_TIMEZONE
        self.default_platforms = list(default_platforms or DEFAULT_PLATFORMS)
        self.default_pillars = list(default_pillars or DEFAULT_CONTENT_PILLARS)
        self.logger = logger_instance or logging.getLogger(
            "william.creator_agent.content_planner"
        )

    # ------------------------------------------------------------------
    # Main router
    # ------------------------------------------------------------------

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a content planner task.

        Expected task shape:
            {
                "action": "create_content_calendar",
                "user_id": "...",
                "workspace_id": "...",
                "payload": {...}
            }
        """
        try:
            context_result = self._validate_task_context(task)
            if not context_result["success"]:
                return context_result

            context = context_result["data"]["context"]
            action = str(task.get("action") or "").strip()
            payload = task.get("payload") or {}

            if not isinstance(payload, dict):
                return self._error_result(
                    message="Invalid payload. Expected dictionary.",
                    error_code="INVALID_PAYLOAD",
                    context=context,
                )

            self._emit_agent_event(
                event_name="creator.content_planner.task_received",
                context=context,
                payload={"action": action},
            )

            if self._requires_security_check(action=action, payload=payload):
                approval = self._request_security_approval(
                    action=action,
                    payload=payload,
                    context=context,
                )
                if approval.get("approval_required"):
                    return self._safe_result(
                        message="Security approval required before this action can proceed.",
                        data={
                            "approval_required": True,
                            "security_approval": approval,
                        },
                        context=context,
                        metadata={
                            "action": action,
                            "agent": self.agent_name,
                            "version": self.version,
                        },
                    )

            if action == "create_content_calendar":
                return self.create_content_calendar(context=context, **payload)

            if action == "generate_topic_ideas":
                return self.generate_topic_ideas(context=context, **payload)

            if action == "create_platform_plan":
                return self.create_platform_plan(context=context, **payload)

            if action == "create_campaign_plan":
                return self.create_campaign_plan(context=context, **payload)

            if action == "create_scheduling_plan":
                return self.create_scheduling_plan(context=context, **payload)

            if action == "expand_topic_into_posts":
                return self.expand_topic_into_posts(context=context, **payload)

            if action == "audit_calendar":
                return self.audit_calendar(context=context, **payload)

            if action == "prepare_dashboard_payload":
                return self.prepare_dashboard_payload(context=context, **payload)

            return self._error_result(
                message=f"Unsupported content planner action: {action}",
                error_code="UNSUPPORTED_ACTION",
                context=context,
                metadata={
                    "supported_actions": list(PUBLIC_METHODS),
                },
            )

        except Exception as exc:
            self.logger.exception("ContentPlanner.run failed")
            return self._error_result(
                message="Content planner task failed.",
                error_code="CONTENT_PLANNER_RUN_FAILED",
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Public planning methods
    # ------------------------------------------------------------------

    def create_content_calendar(
        self,
        *,
        context: Union[SaaSContext, Dict[str, Any]],
        brand_name: str,
        campaign_name: Optional[str] = None,
        start_date: Optional[Union[str, date, datetime]] = None,
        end_date: Optional[Union[str, date, datetime]] = None,
        duration_days: int = 30,
        platforms: Optional[Sequence[str]] = None,
        posts_per_week: int = 5,
        content_pillars: Optional[Sequence[str]] = None,
        objectives: Optional[Sequence[str]] = None,
        audience: str = "target audience",
        niche: Optional[str] = None,
        funnel_stages: Optional[Sequence[str]] = None,
        preferred_times: Optional[Sequence[str]] = None,
        timezone_name: Optional[str] = None,
        keywords: Optional[Sequence[str]] = None,
        call_to_action: Optional[str] = None,
        constraints: Optional[Dict[str, Any]] = None,
        include_briefs: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a structured content calendar.

        This prepares planned content items only. It does not schedule or publish
        content on external platforms.
        """
        ctx = self._normalize_context(context)

        if not brand_name or not str(brand_name).strip():
            return self._error_result(
                message="brand_name is required.",
                error_code="MISSING_BRAND_NAME",
                context=ctx,
            )

        safe_platforms = self._validate_platforms(platforms or self.default_platforms)
        safe_pillars = _dedupe_keep_order(
            _coerce_list(content_pillars, self.default_pillars)
        )
        safe_objectives = _dedupe_keep_order(
            _coerce_list(objectives, ["awareness", "engagement", "lead_generation"])
        )
        safe_funnel_stages = _dedupe_keep_order(
            _coerce_list(funnel_stages, ["tof", "mof", "bof"])
        )
        safe_keywords = _dedupe_keep_order(_coerce_list(keywords, []))
        safe_times = _dedupe_keep_order(
            _coerce_list(preferred_times, ["09:00", "12:00", "15:00", "18:00"])
        )
        tz = timezone_name or self.default_timezone

        start = _parse_date(start_date, fallback=date.today())
        if end_date:
            end = _parse_date(end_date, fallback=start + timedelta(days=duration_days - 1))
        else:
            end = start + timedelta(days=max(1, duration_days) - 1)

        all_days = _date_range(start, end)
        selected_days = self._select_calendar_days(
            days=all_days,
            posts_per_week=max(1, int(posts_per_week)),
        )

        items: List[Dict[str, Any]] = []
        for index, scheduled_day in enumerate(selected_days):
            platform = _round_robin(safe_platforms, index, PlatformType.INSTAGRAM.value)
            pillar = _round_robin(safe_pillars, index, "education")
            objective = _round_robin(safe_objectives, index, "awareness")
            funnel_stage = _round_robin(safe_funnel_stages, index, "tof")
            scheduled_time = _round_robin(safe_times, index, "09:00")
            content_format = self._suggest_format_for_platform(platform, index)

            title = self._build_content_title(
                brand_name=brand_name,
                niche=niche,
                pillar=pillar,
                objective=objective,
                funnel_stage=funnel_stage,
                index=index,
            )
            hook = self._build_hook(
                brand_name=brand_name,
                niche=niche,
                pillar=pillar,
                objective=objective,
                audience=audience,
                index=index,
            )
            caption_brief = self._build_caption_brief(
                title=title,
                platform=platform,
                audience=audience,
                objective=objective,
                funnel_stage=funnel_stage,
            )
            creative_brief = self._build_creative_brief(
                title=title,
                platform=platform,
                content_format=content_format,
                pillar=pillar,
                include_briefs=include_briefs,
            )
            item_cta = call_to_action or self._default_cta(objective)

            item = ContentItem(
                content_id=_stable_id(
                    "content",
                    {
                        "user_id": ctx.user_id,
                        "workspace_id": ctx.workspace_id,
                        "brand_name": brand_name,
                        "scheduled_day": scheduled_day.isoformat(),
                        "platform": platform,
                        "title": title,
                    },
                ),
                title=title,
                platform=platform,
                content_format=content_format,
                scheduled_date=scheduled_day.isoformat(),
                scheduled_time=scheduled_time,
                timezone=tz,
                pillar=pillar,
                objective=objective,
                funnel_stage=funnel_stage,
                audience=audience,
                hook=hook,
                caption_brief=caption_brief,
                creative_brief=creative_brief,
                call_to_action=item_cta,
                keywords=self._select_keywords_for_item(safe_keywords, index),
                hashtags=self._suggest_hashtags(
                    brand_name=brand_name,
                    niche=niche,
                    pillar=pillar,
                    platform=platform,
                    keywords=safe_keywords,
                ),
                requires_security_approval=False,
                metadata={
                    "campaign_name": campaign_name,
                    "niche": niche,
                    "constraints": constraints or {},
                    "created_by": self.agent_name,
                },
            )
            items.append(asdict(item))

        calendar_id = _stable_id(
            "calendar",
            {
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "brand_name": brand_name,
                "campaign_name": campaign_name,
                "start": start.isoformat(),
                "end": end.isoformat(),
            },
        )

        data = {
            "calendar_id": calendar_id,
            "brand_name": brand_name,
            "campaign_name": campaign_name,
            "start_date": start.isoformat(),
            "end_date": end.isoformat(),
            "timezone": tz,
            "platforms": safe_platforms,
            "content_pillars": safe_pillars,
            "objectives": safe_objectives,
            "audience": audience,
            "niche": niche,
            "total_items": len(items),
            "items": items,
            "summary": self._summarize_calendar(items),
            "memory_payload": self._prepare_memory_payload(
                context=ctx,
                memory_type="content_calendar_preferences",
                payload={
                    "brand_name": brand_name,
                    "platforms": safe_platforms,
                    "content_pillars": safe_pillars,
                    "preferred_times": safe_times,
                    "audience": audience,
                    "niche": niche,
                },
            ),
            "verification_payload": self._prepare_verification_payload(
                context=ctx,
                action="create_content_calendar",
                artifact_id=calendar_id,
                artifact_type="content_calendar",
                payload={"total_items": len(items), "date_range": [start.isoformat(), end.isoformat()]},
            ),
        }

        self._log_audit_event(
            event_name="creator.content_calendar.created",
            context=ctx,
            payload={
                "calendar_id": calendar_id,
                "brand_name": brand_name,
                "total_items": len(items),
            },
        )

        return self._safe_result(
            message="Content calendar created successfully.",
            data=data,
            context=ctx,
            metadata={
                "agent": self.agent_name,
                "version": self.version,
                "generated_at": _utc_now_iso(),
                **(metadata or {}),
            },
        )

    def generate_topic_ideas(
        self,
        *,
        context: Union[SaaSContext, Dict[str, Any]],
        brand_name: str,
        niche: str,
        audience: str,
        count: int = 20,
        platforms: Optional[Sequence[str]] = None,
        content_pillars: Optional[Sequence[str]] = None,
        objectives: Optional[Sequence[str]] = None,
        keywords: Optional[Sequence[str]] = None,
        funnel_stages: Optional[Sequence[str]] = None,
        tone: str = "professional",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generate structured topic ideas.

        Topics are deterministic and safe to use as briefs for script writer,
        caption generator, thumbnail designer, or VEO prompt builder.
        """
        ctx = self._normalize_context(context)

        if not brand_name.strip():
            return self._error_result(
                message="brand_name is required.",
                error_code="MISSING_BRAND_NAME",
                context=ctx,
            )

        if not niche.strip():
            return self._error_result(
                message="niche is required.",
                error_code="MISSING_NICHE",
                context=ctx,
            )

        safe_count = min(max(int(count), 1), 100)
        safe_platforms = self._validate_platforms(platforms or self.default_platforms)
        safe_pillars = _dedupe_keep_order(
            _coerce_list(content_pillars, self.default_pillars)
        )
        safe_objectives = _dedupe_keep_order(
            _coerce_list(objectives, ["awareness", "engagement", "lead_generation"])
        )
        safe_funnel_stages = _dedupe_keep_order(
            _coerce_list(funnel_stages, ["tof", "mof", "bof"])
        )
        safe_keywords = _dedupe_keep_order(_coerce_list(keywords, []))

        templates = self._topic_templates()
        topics: List[Dict[str, Any]] = []

        for index in range(safe_count):
            pillar = _round_robin(safe_pillars, index, "education")
            objective = _round_robin(safe_objectives, index, "awareness")
            funnel_stage = _round_robin(safe_funnel_stages, index, "tof")
            platform = _round_robin(safe_platforms, index, PlatformType.INSTAGRAM.value)
            template = templates[index % len(templates)]

            keyword_phrase = (
                safe_keywords[index % len(safe_keywords)]
                if safe_keywords
                else niche
            )

            title = template.format(
                brand_name=brand_name,
                niche=niche,
                audience=audience,
                keyword=keyword_phrase,
                pillar=pillar.replace("_", " "),
            )

            angle = self._topic_angle(
                pillar=pillar,
                objective=objective,
                funnel_stage=funnel_stage,
                audience=audience,
                niche=niche,
            )

            topic = ContentTopic(
                topic_id=_stable_id(
                    "topic",
                    {
                        "user_id": ctx.user_id,
                        "workspace_id": ctx.workspace_id,
                        "title": title,
                        "index": index,
                    },
                ),
                title=title,
                pillar=pillar,
                objective=objective,
                audience=audience,
                funnel_stage=funnel_stage,
                angle=angle,
                hook=self._build_hook(
                    brand_name=brand_name,
                    niche=niche,
                    pillar=pillar,
                    objective=objective,
                    audience=audience,
                    index=index,
                ),
                keywords=self._select_keywords_for_item(safe_keywords, index),
                formats=[
                    self._suggest_format_for_platform(platform, index),
                    self._alternate_format(platform),
                ],
                platforms=[platform],
                priority=self._suggest_priority(objective, funnel_stage),
                metadata={
                    "tone": tone,
                    "niche": niche,
                    "source": "content_planner.generate_topic_ideas",
                },
            )
            topics.append(asdict(topic))

        topic_set_id = _stable_id(
            "topic_set",
            {
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "brand_name": brand_name,
                "niche": niche,
                "count": safe_count,
            },
        )

        return self._safe_result(
            message="Topic ideas generated successfully.",
            data={
                "topic_set_id": topic_set_id,
                "brand_name": brand_name,
                "niche": niche,
                "audience": audience,
                "count": len(topics),
                "topics": topics,
                "memory_payload": self._prepare_memory_payload(
                    context=ctx,
                    memory_type="content_topic_preferences",
                    payload={
                        "brand_name": brand_name,
                        "niche": niche,
                        "audience": audience,
                        "platforms": safe_platforms,
                        "tone": tone,
                    },
                ),
                "verification_payload": self._prepare_verification_payload(
                    context=ctx,
                    action="generate_topic_ideas",
                    artifact_id=topic_set_id,
                    artifact_type="topic_set",
                    payload={"count": len(topics)},
                ),
            },
            context=ctx,
            metadata={
                "agent": self.agent_name,
                "version": self.version,
                "generated_at": _utc_now_iso(),
                **(metadata or {}),
            },
        )

    def create_platform_plan(
        self,
        *,
        context: Union[SaaSContext, Dict[str, Any]],
        brand_name: str,
        platform: str,
        niche: str,
        audience: str,
        objective: str = "lead_generation",
        posting_frequency: Optional[str] = None,
        content_pillars: Optional[Sequence[str]] = None,
        keywords: Optional[Sequence[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a platform-specific content strategy plan.
        """
        ctx = self._normalize_context(context)
        safe_platform = self._normalize_platform(platform)

        if safe_platform not in DEFAULT_PLATFORMS:
            return self._error_result(
                message=f"Unsupported platform: {platform}",
                error_code="UNSUPPORTED_PLATFORM",
                context=ctx,
                metadata={"supported_platforms": list(DEFAULT_PLATFORMS)},
            )

        pillars = _dedupe_keep_order(_coerce_list(content_pillars, self.default_pillars))
        safe_keywords = _dedupe_keep_order(_coerce_list(keywords, []))

        profile = self._platform_profile(safe_platform)

        plan = {
            "platform_plan_id": _stable_id(
                "platform_plan",
                {
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                    "brand_name": brand_name,
                    "platform": safe_platform,
                    "objective": objective,
                },
            ),
            "brand_name": brand_name,
            "platform": safe_platform,
            "niche": niche,
            "audience": audience,
            "objective": objective,
            "recommended_posting_frequency": posting_frequency or profile["recommended_frequency"],
            "best_formats": profile["best_formats"],
            "recommended_content_mix": self._platform_content_mix(
                platform=safe_platform,
                pillars=pillars,
                objective=objective,
            ),
            "hook_style": profile["hook_style"],
            "caption_style": profile["caption_style"],
            "creative_guidelines": profile["creative_guidelines"],
            "hashtag_strategy": self._hashtag_strategy(
                platform=safe_platform,
                brand_name=brand_name,
                niche=niche,
                keywords=safe_keywords,
            ),
            "cta_examples": self._cta_examples(objective),
            "weekly_structure": self._weekly_platform_structure(
                platform=safe_platform,
                pillars=pillars,
            ),
            "repurposing_notes": self._repurposing_notes(safe_platform),
        }

        return self._safe_result(
            message="Platform plan created successfully.",
            data={
                "plan": plan,
                "memory_payload": self._prepare_memory_payload(
                    context=ctx,
                    memory_type="platform_plan_preferences",
                    payload={
                        "brand_name": brand_name,
                        "platform": safe_platform,
                        "objective": objective,
                        "posting_frequency": plan["recommended_posting_frequency"],
                    },
                ),
                "verification_payload": self._prepare_verification_payload(
                    context=ctx,
                    action="create_platform_plan",
                    artifact_id=plan["platform_plan_id"],
                    artifact_type="platform_plan",
                    payload={"platform": safe_platform, "objective": objective},
                ),
            },
            context=ctx,
            metadata={
                "agent": self.agent_name,
                "version": self.version,
                "generated_at": _utc_now_iso(),
                **(metadata or {}),
            },
        )

    def create_campaign_plan(
        self,
        *,
        context: Union[SaaSContext, Dict[str, Any]],
        campaign_name: str,
        brand_name: str,
        objective: str,
        start_date: Union[str, date, datetime],
        end_date: Optional[Union[str, date, datetime]] = None,
        duration_days: int = 30,
        target_audience: str = "target audience",
        platforms: Optional[Sequence[str]] = None,
        content_pillars: Optional[Sequence[str]] = None,
        posts_per_week: int = 5,
        timezone_name: Optional[str] = None,
        niche: Optional[str] = None,
        keywords: Optional[Sequence[str]] = None,
        budget_notes: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create an end-to-end campaign plan with calendar items and KPIs.

        Paid campaign or budget-sensitive actions are marked for approval but
        no external paid action is executed.
        """
        ctx = self._normalize_context(context)

        start = _parse_date(start_date)
        end = _parse_date(end_date, fallback=start + timedelta(days=max(1, duration_days) - 1))
        tz = timezone_name or self.default_timezone

        safe_platforms = self._validate_platforms(platforms or self.default_platforms[:5])
        safe_pillars = _dedupe_keep_order(_coerce_list(content_pillars, self.default_pillars))
        safe_keywords = _dedupe_keep_order(_coerce_list(keywords, []))

        approval_required = objective in {"conversion", "lead_generation"} and bool(budget_notes)

        calendar_result = self.create_content_calendar(
            context=ctx,
            brand_name=brand_name,
            campaign_name=campaign_name,
            start_date=start,
            end_date=end,
            platforms=safe_platforms,
            posts_per_week=posts_per_week,
            content_pillars=safe_pillars,
            objectives=[objective],
            audience=target_audience,
            niche=niche,
            keywords=safe_keywords,
            timezone_name=tz,
            metadata={"nested_call": True},
        )

        if not calendar_result.get("success"):
            return calendar_result

        calendar_data = calendar_result["data"]
        content_items = calendar_data.get("items", [])

        weekly_themes = self._build_weekly_themes(
            start=start,
            end=end,
            pillars=safe_pillars,
            objective=objective,
            niche=niche,
        )

        campaign = CampaignPlan(
            campaign_id=_stable_id(
                "campaign",
                {
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                    "campaign_name": campaign_name,
                    "brand_name": brand_name,
                    "start": start.isoformat(),
                    "end": end.isoformat(),
                },
            ),
            campaign_name=campaign_name,
            objective=objective,
            start_date=start.isoformat(),
            end_date=end.isoformat(),
            timezone=tz,
            target_audience=target_audience,
            platforms=safe_platforms,
            content_pillars=safe_pillars,
            content_items=content_items,
            weekly_themes=weekly_themes,
            kpis=self._suggest_campaign_kpis(objective),
            budget_notes=budget_notes,
            approval_required=approval_required,
            metadata={
                "brand_name": brand_name,
                "niche": niche,
                "keywords": safe_keywords,
                "created_by": self.agent_name,
            },
        )

        approval_payload = None
        if approval_required:
            approval_payload = self._request_security_approval(
                action="paid_campaign",
                payload={
                    "campaign_name": campaign_name,
                    "objective": objective,
                    "budget_notes": budget_notes,
                },
                context=ctx,
            )

        data = {
            "campaign": asdict(campaign),
            "security_approval": approval_payload,
            "memory_payload": self._prepare_memory_payload(
                context=ctx,
                memory_type="campaign_plan_preferences",
                payload={
                    "brand_name": brand_name,
                    "campaign_name": campaign_name,
                    "objective": objective,
                    "platforms": safe_platforms,
                    "target_audience": target_audience,
                },
            ),
            "verification_payload": self._prepare_verification_payload(
                context=ctx,
                action="create_campaign_plan",
                artifact_id=campaign.campaign_id,
                artifact_type="campaign_plan",
                payload={
                    "campaign_name": campaign_name,
                    "total_items": len(content_items),
                    "approval_required": approval_required,
                },
            ),
        }

        self._log_audit_event(
            event_name="creator.campaign_plan.created",
            context=ctx,
            payload={
                "campaign_id": campaign.campaign_id,
                "campaign_name": campaign_name,
                "approval_required": approval_required,
            },
        )

        return self._safe_result(
            message="Campaign plan created successfully.",
            data=data,
            context=ctx,
            metadata={
                "agent": self.agent_name,
                "version": self.version,
                "generated_at": _utc_now_iso(),
                **(metadata or {}),
            },
        )

    def create_scheduling_plan(
        self,
        *,
        context: Union[SaaSContext, Dict[str, Any]],
        content_items: Sequence[Dict[str, Any]],
        timezone_name: Optional[str] = None,
        approval_before_publish: bool = True,
        group_by_platform: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare scheduling plan from content items.

        This does not push to external scheduling tools. It creates an internal
        schedule-ready structure and marks approval gates.
        """
        ctx = self._normalize_context(context)
        tz = timezone_name or self.default_timezone

        if not isinstance(content_items, Sequence) or isinstance(content_items, (str, bytes)):
            return self._error_result(
                message="content_items must be a sequence of dictionaries.",
                error_code="INVALID_CONTENT_ITEMS",
                context=ctx,
            )

        schedule_entries: List[Dict[str, Any]] = []
        for index, item in enumerate(content_items):
            if not isinstance(item, dict):
                continue

            platform = self._normalize_platform(str(item.get("platform") or "instagram"))
            scheduled_date = str(item.get("scheduled_date") or date.today().isoformat())
            scheduled_time = str(item.get("scheduled_time") or "09:00")

            entry = {
                "schedule_id": _stable_id(
                    "schedule",
                    {
                        "user_id": ctx.user_id,
                        "workspace_id": ctx.workspace_id,
                        "content_id": item.get("content_id"),
                        "platform": platform,
                        "scheduled_date": scheduled_date,
                        "scheduled_time": scheduled_time,
                    },
                ),
                "content_id": item.get("content_id") or _stable_id("content", item),
                "title": item.get("title") or f"Content Item {index + 1}",
                "platform": platform,
                "scheduled_date": scheduled_date,
                "scheduled_time": scheduled_time,
                "timezone": item.get("timezone") or tz,
                "status": ContentStatus.REVIEW_REQUIRED.value if approval_before_publish else ContentStatus.PLANNED.value,
                "approval_required": approval_before_publish,
                "approval_gate": {
                    "required": approval_before_publish,
                    "reason": "Approval before publish is enabled."
                    if approval_before_publish
                    else None,
                    "security_action": "schedule_publish" if approval_before_publish else None,
                },
                "source_item": copy.deepcopy(item),
            }
            schedule_entries.append(entry)

        grouped = self._group_schedule_by_platform(schedule_entries) if group_by_platform else {}

        data = {
            "scheduling_plan_id": _stable_id(
                "scheduling_plan",
                {
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                    "entries": [
                        {
                            "content_id": e["content_id"],
                            "platform": e["platform"],
                            "date": e["scheduled_date"],
                        }
                        for e in schedule_entries
                    ],
                },
            ),
            "timezone": tz,
            "total_entries": len(schedule_entries),
            "approval_before_publish": approval_before_publish,
            "entries": schedule_entries,
            "grouped_by_platform": grouped,
            "security_approval": self._request_security_approval(
                action="schedule_publish",
                payload={
                    "total_entries": len(schedule_entries),
                    "platforms": sorted({entry["platform"] for entry in schedule_entries}),
                },
                context=ctx,
            ) if approval_before_publish else None,
        }

        return self._safe_result(
            message="Scheduling plan prepared successfully.",
            data={
                **data,
                "verification_payload": self._prepare_verification_payload(
                    context=ctx,
                    action="create_scheduling_plan",
                    artifact_id=data["scheduling_plan_id"],
                    artifact_type="scheduling_plan",
                    payload={
                        "total_entries": len(schedule_entries),
                        "approval_before_publish": approval_before_publish,
                    },
                ),
            },
            context=ctx,
            metadata={
                "agent": self.agent_name,
                "version": self.version,
                "generated_at": _utc_now_iso(),
                **(metadata or {}),
            },
        )

    def expand_topic_into_posts(
        self,
        *,
        context: Union[SaaSContext, Dict[str, Any]],
        topic: Union[str, Dict[str, Any]],
        brand_name: str,
        platforms: Optional[Sequence[str]] = None,
        variations_per_platform: int = 2,
        audience: str = "target audience",
        objective: str = "engagement",
        niche: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Expand one topic into multiple platform-specific post briefs.
        """
        ctx = self._normalize_context(context)

        topic_title = topic.get("title") if isinstance(topic, dict) else str(topic)
        if not topic_title or not topic_title.strip():
            return self._error_result(
                message="A valid topic title is required.",
                error_code="MISSING_TOPIC",
                context=ctx,
            )

        safe_platforms = self._validate_platforms(platforms or self.default_platforms[:5])
        safe_variations = min(max(int(variations_per_platform), 1), 10)

        posts: List[Dict[str, Any]] = []
        for platform in safe_platforms:
            for variation in range(safe_variations):
                content_format = self._suggest_format_for_platform(platform, variation)
                title = self._variation_title(topic_title, platform, variation)
                post = {
                    "content_id": _stable_id(
                        "content",
                        {
                            "user_id": ctx.user_id,
                            "workspace_id": ctx.workspace_id,
                            "topic": topic_title,
                            "platform": platform,
                            "variation": variation,
                        },
                    ),
                    "title": title,
                    "source_topic": topic_title,
                    "platform": platform,
                    "content_format": content_format,
                    "objective": objective,
                    "audience": audience,
                    "hook": self._build_hook(
                        brand_name=brand_name,
                        niche=niche,
                        pillar="education",
                        objective=objective,
                        audience=audience,
                        index=variation,
                    ),
                    "caption_brief": self._build_caption_brief(
                        title=title,
                        platform=platform,
                        audience=audience,
                        objective=objective,
                        funnel_stage="mof",
                    ),
                    "creative_brief": self._build_creative_brief(
                        title=title,
                        platform=platform,
                        content_format=content_format,
                        pillar="education",
                        include_briefs=True,
                    ),
                    "call_to_action": self._default_cta(objective),
                    "status": ContentStatus.IDEA.value,
                    "metadata": {
                        "brand_name": brand_name,
                        "niche": niche,
                        "variation": variation + 1,
                    },
                }
                posts.append(post)

        expansion_id = _stable_id(
            "topic_expansion",
            {
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "topic": topic_title,
                "platforms": safe_platforms,
            },
        )

        return self._safe_result(
            message="Topic expanded into platform-specific post briefs.",
            data={
                "expansion_id": expansion_id,
                "topic": topic_title,
                "brand_name": brand_name,
                "total_posts": len(posts),
                "posts": posts,
                "verification_payload": self._prepare_verification_payload(
                    context=ctx,
                    action="expand_topic_into_posts",
                    artifact_id=expansion_id,
                    artifact_type="topic_expansion",
                    payload={"total_posts": len(posts)},
                ),
            },
            context=ctx,
            metadata={
                "agent": self.agent_name,
                "version": self.version,
                "generated_at": _utc_now_iso(),
                **(metadata or {}),
            },
        )

    def audit_calendar(
        self,
        *,
        context: Union[SaaSContext, Dict[str, Any]],
        calendar_items: Sequence[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Audit a content calendar for platform balance, missing fields,
        scheduling conflicts, content pillar balance, and approval risk.
        """
        ctx = self._normalize_context(context)

        if not isinstance(calendar_items, Sequence) or isinstance(calendar_items, (str, bytes)):
            return self._error_result(
                message="calendar_items must be a sequence of dictionaries.",
                error_code="INVALID_CALENDAR_ITEMS",
                context=ctx,
            )

        items = [item for item in calendar_items if isinstance(item, dict)]

        missing_fields: List[Dict[str, Any]] = []
        slot_map: Dict[str, List[str]] = {}
        platform_counts: Dict[str, int] = {}
        pillar_counts: Dict[str, int] = {}
        approval_items: List[Dict[str, Any]] = []

        required_fields = ["title", "platform", "scheduled_date", "pillar", "objective"]

        for item in items:
            content_id = str(item.get("content_id") or _stable_id("content", item))
            for field_name in required_fields:
                if not item.get(field_name):
                    missing_fields.append(
                        {
                            "content_id": content_id,
                            "field": field_name,
                            "severity": "medium",
                        }
                    )

            platform = self._normalize_platform(str(item.get("platform") or "unknown"))
            pillar = str(item.get("pillar") or "unknown")
            platform_counts[platform] = platform_counts.get(platform, 0) + 1
            pillar_counts[pillar] = pillar_counts.get(pillar, 0) + 1

            slot_key = "|".join(
                [
                    platform,
                    str(item.get("scheduled_date") or ""),
                    str(item.get("scheduled_time") or ""),
                ]
            )
            slot_map.setdefault(slot_key, []).append(content_id)

            if item.get("requires_security_approval") or item.get("approval_required"):
                approval_items.append(
                    {
                        "content_id": content_id,
                        "title": item.get("title"),
                        "platform": platform,
                        "reason": item.get("approval_reason") or "Approval required.",
                    }
                )

        conflicts = [
            {
                "slot": slot,
                "content_ids": content_ids,
                "severity": "high",
                "message": "Multiple items share the same platform/date/time slot.",
            }
            for slot, content_ids in slot_map.items()
            if len(content_ids) > 1
        ]

        recommendations = self._calendar_recommendations(
            total_items=len(items),
            platform_counts=platform_counts,
            pillar_counts=pillar_counts,
            conflicts=conflicts,
            missing_fields=missing_fields,
            approval_items=approval_items,
        )

        audit_id = _stable_id(
            "calendar_audit",
            {
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "items": len(items),
                "timestamp": _utc_now_iso(),
            },
        )

        return self._safe_result(
            message="Calendar audit completed.",
            data={
                "audit_id": audit_id,
                "total_items": len(items),
                "platform_counts": platform_counts,
                "pillar_counts": pillar_counts,
                "missing_fields": missing_fields,
                "conflicts": conflicts,
                "approval_items": approval_items,
                "recommendations": recommendations,
                "health_score": self._calendar_health_score(
                    total_items=len(items),
                    missing_fields=missing_fields,
                    conflicts=conflicts,
                    approval_items=approval_items,
                ),
                "verification_payload": self._prepare_verification_payload(
                    context=ctx,
                    action="audit_calendar",
                    artifact_id=audit_id,
                    artifact_type="calendar_audit",
                    payload={
                        "total_items": len(items),
                        "conflicts": len(conflicts),
                        "missing_fields": len(missing_fields),
                    },
                ),
            },
            context=ctx,
            metadata={
                "agent": self.agent_name,
                "version": self.version,
                "generated_at": _utc_now_iso(),
                **(metadata or {}),
            },
        )

    def prepare_dashboard_payload(
        self,
        *,
        context: Union[SaaSContext, Dict[str, Any]],
        calendar_items: Optional[Sequence[Dict[str, Any]]] = None,
        campaigns: Optional[Sequence[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare dashboard/API-friendly payload for Creator Agent UI.
        """
        ctx = self._normalize_context(context)

        items = [item for item in (calendar_items or []) if isinstance(item, dict)]
        campaign_list = [campaign for campaign in (campaigns or []) if isinstance(campaign, dict)]

        upcoming_items = sorted(
            items,
            key=lambda item: (
                str(item.get("scheduled_date") or "9999-12-31"),
                str(item.get("scheduled_time") or "23:59"),
            ),
        )[:10]

        platform_counts: Dict[str, int] = {}
        status_counts: Dict[str, int] = {}
        for item in items:
            platform = self._normalize_platform(str(item.get("platform") or "unknown"))
            status = str(item.get("status") or "unknown")
            platform_counts[platform] = platform_counts.get(platform, 0) + 1
            status_counts[status] = status_counts.get(status, 0) + 1

        payload = {
            "dashboard_id": _stable_id(
                "creator_dashboard",
                {
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                    "items": len(items),
                    "campaigns": len(campaign_list),
                },
            ),
            "cards": {
                "planned_content": len(items),
                "active_campaigns": len(campaign_list),
                "approval_required": sum(
                    1 for item in items if item.get("approval_required") or item.get("requires_security_approval")
                ),
                "platforms_used": len(platform_counts),
            },
            "charts": {
                "platform_counts": platform_counts,
                "status_counts": status_counts,
            },
            "upcoming_items": upcoming_items,
            "campaigns": campaign_list[:10],
            "agent": {
                "name": self.agent_name,
                "type": self.agent_type,
                "version": self.version,
            },
        }

        return self._safe_result(
            message="Dashboard payload prepared successfully.",
            data=payload,
            context=ctx,
            metadata={
                "generated_at": _utc_now_iso(),
                **(metadata or {}),
            },
        )

    # ------------------------------------------------------------------
    # Compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate task context for SaaS isolation.

        Required:
            - user_id
            - workspace_id
        """
        if not isinstance(task, dict):
            return self._error_result(
                message="Task must be a dictionary.",
                error_code="INVALID_TASK",
            )

        user_id = str(task.get("user_id") or "").strip()
        workspace_id = str(task.get("workspace_id") or "").strip()

        if not user_id:
            return self._error_result(
                message="user_id is required for Creator Agent content planning.",
                error_code="MISSING_USER_ID",
            )

        if not workspace_id:
            return self._error_result(
                message="workspace_id is required for Creator Agent content planning.",
                error_code="MISSING_WORKSPACE_ID",
            )

        context = SaaSContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=task.get("role"),
            subscription_plan=task.get("subscription_plan"),
            permissions=task.get("permissions") or {},
            request_id=str(task.get("request_id") or uuid.uuid4()),
        )

        return self._safe_result(
            message="Task context validated.",
            data={"context": context},
            context=context,
        )

    def _requires_security_check(
        self,
        *,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Decide whether a task needs Security Agent approval.

        Planning is safe. External publishing, paid campaign, deletion, or
        platform push actions are sensitive.
        """
        payload = payload or {}
        normalized_action = str(action or "").strip().lower()

        if normalized_action in SENSITIVE_ACTIONS:
            return True

        requested_action = str(payload.get("requested_action") or "").strip().lower()
        if requested_action in SENSITIVE_ACTIONS:
            return True

        if payload.get("publish_now") is True:
            return True

        if payload.get("external_api_push") is True:
            return True

        if payload.get("paid_budget") or payload.get("ad_spend") or payload.get("budget_notes"):
            if normalized_action in {"create_campaign_plan", "schedule_publish", "paid_campaign"}:
                return True

        return False

    def _request_security_approval(
        self,
        *,
        action: str,
        payload: Dict[str, Any],
        context: Union[SaaSContext, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Prepare Security Agent approval request.

        This method does not approve anything by itself. The Master Agent or
        Security Agent should consume this payload.
        """
        ctx = self._normalize_context(context)
        approval_id = _stable_id(
            "security_approval",
            {
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "action": action,
                "payload": payload,
                "request_id": ctx.request_id,
            },
        )

        return {
            "approval_required": True,
            "approval_id": approval_id,
            "target_agent": "security_agent",
            "source_agent": self.agent_name,
            "action": action,
            "risk_level": self._risk_level_for_action(action, payload),
            "reason": self._security_reason(action, payload),
            "context": ctx.to_dict(),
            "payload_summary": self._redact_payload(payload),
            "created_at": _utc_now_iso(),
        }

    def _prepare_verification_payload(
        self,
        *,
        context: Union[SaaSContext, Dict[str, Any]],
        action: str,
        artifact_id: str,
        artifact_type: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent.

        Verification Agent can use this to check completeness, policy compliance,
        schedule consistency, and tenant isolation.
        """
        ctx = self._normalize_context(context)

        return {
            "verification_id": _stable_id(
                "verification",
                {
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                    "action": action,
                    "artifact_id": artifact_id,
                },
            ),
            "target_agent": "verification_agent",
            "source_agent": self.agent_name,
            "action": action,
            "artifact_id": artifact_id,
            "artifact_type": artifact_type,
            "checks_requested": [
                "tenant_isolation",
                "required_fields",
                "content_policy_safety",
                "schedule_conflicts",
                "approval_requirements",
            ],
            "context": ctx.to_dict(),
            "payload": payload or {},
            "created_at": _utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        *,
        context: Union[SaaSContext, Dict[str, Any]],
        memory_type: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare safe Memory Agent payload.

        Only reusable planning preferences are included. This avoids storing
        sensitive secrets or mixing workspace data.
        """
        ctx = self._normalize_context(context)

        safe_payload = self._redact_payload(payload)

        return {
            "memory_id": _stable_id(
                "memory",
                {
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                    "memory_type": memory_type,
                    "payload": safe_payload,
                },
            ),
            "target_agent": "memory_agent",
            "source_agent": self.agent_name,
            "memory_type": memory_type,
            "scope": {
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
            "payload": safe_payload,
            "retention_hint": "workspace_content_preferences",
            "created_at": _utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        *,
        event_name: str,
        context: Union[SaaSContext, Dict[str, Any]],
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit an internal agent event.

        This fallback logs only. A future event bus can replace this method.
        """
        ctx = self._normalize_context(context)
        self.logger.info(
            "Agent event emitted",
            extra={
                "event_name": event_name,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "request_id": ctx.request_id,
                "payload": self._redact_payload(payload or {}),
            },
        )

    def _log_audit_event(
        self,
        *,
        event_name: str,
        context: Union[SaaSContext, Dict[str, Any]],
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event.

        The real Audit Log service can consume the same structured shape later.
        """
        ctx = self._normalize_context(context)
        self.logger.info(
            "Audit event",
            extra={
                "event_name": event_name,
                "agent": self.agent_name,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "request_id": ctx.request_id,
                "payload": self._redact_payload(payload or {}),
                "created_at": _utc_now_iso(),
            },
        )

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        context: Optional[Union[SaaSContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard success result.
        """
        ctx = self._normalize_context(context) if context is not None else None

        result = {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "version": self.version,
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

        if ctx:
            result["metadata"]["user_id"] = ctx.user_id
            result["metadata"]["workspace_id"] = ctx.workspace_id
            result["metadata"]["request_id"] = ctx.request_id

        return result

    def _error_result(
        self,
        *,
        message: str,
        error_code: str = "ERROR",
        error: Optional[str] = None,
        context: Optional[Union[SaaSContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard error result.
        """
        ctx = self._normalize_context(context) if context is not None else None

        result = {
            "success": False,
            "message": message,
            "data": {},
            "error": {
                "code": error_code,
                "detail": error or message,
            },
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "version": self.version,
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

        if ctx:
            result["metadata"]["user_id"] = ctx.user_id
            result["metadata"]["workspace_id"] = ctx.workspace_id
            result["metadata"]["request_id"] = ctx.request_id

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _normalize_context(self, context: Union[SaaSContext, Dict[str, Any], None]) -> SaaSContext:
        """Normalize context into SaaSContext."""
        if isinstance(context, SaaSContext):
            return context

        if isinstance(context, dict):
            return SaaSContext(
                user_id=str(context.get("user_id") or "unknown_user"),
                workspace_id=str(context.get("workspace_id") or "unknown_workspace"),
                role=context.get("role"),
                subscription_plan=context.get("subscription_plan"),
                permissions=context.get("permissions") or {},
                request_id=str(context.get("request_id") or uuid.uuid4()),
            )

        return SaaSContext(
            user_id="unknown_user",
            workspace_id="unknown_workspace",
            request_id=str(uuid.uuid4()),
        )

    def _validate_platforms(self, platforms: Sequence[str]) -> List[str]:
        """Validate and normalize platform names."""
        normalized = []
        for platform in platforms:
            safe = self._normalize_platform(str(platform))
            if safe in DEFAULT_PLATFORMS:
                normalized.append(safe)
        return _dedupe_keep_order(normalized) or [PlatformType.INSTAGRAM.value]

    def _normalize_platform(self, platform: str) -> str:
        """Normalize common platform aliases."""
        value = platform.strip().lower().replace("-", "_").replace(" ", "_")
        aliases = {
            "yt": "youtube",
            "youtube_short": "youtube_shorts",
            "shorts": "youtube_shorts",
            "ig": "instagram",
            "insta": "instagram",
            "fb": "facebook",
            "facebook_page": "facebook",
            "twitter": "x",
            "newsletter": "email",
            "mail": "email",
            "article": "blog",
            "website_blog": "blog",
        }
        return aliases.get(value, value)

    def _select_calendar_days(self, *, days: Sequence[date], posts_per_week: int) -> List[date]:
        """Select dates across a range according to weekly posting frequency."""
        if not days:
            return []

        posts_per_week = min(max(posts_per_week, 1), 14)
        total_weeks = max(1, int(len(days) / 7) + (1 if len(days) % 7 else 0))
        target_count = min(len(days), posts_per_week * total_weeks)

        if target_count >= len(days):
            return list(days)

        step = max(1, len(days) / target_count)
        selected = []
        cursor = 0.0
        while len(selected) < target_count and int(cursor) < len(days):
            selected.append(days[int(cursor)])
            cursor += step

        return _dedupe_dates(selected)

    def _suggest_format_for_platform(self, platform: str, index: int = 0) -> str:
        """Suggest content format by platform."""
        platform = self._normalize_platform(platform)
        formats_by_platform = {
            "youtube": ["long_video", "short_video", "live_stream"],
            "youtube_shorts": ["short_video"],
            "instagram": ["reel", "carousel", "story", "single_image"],
            "facebook": ["short_video", "text_post", "carousel", "single_image"],
            "tiktok": ["short_video"],
            "linkedin": ["text_post", "carousel", "short_video", "document_post"],
            "x": ["text_post", "thread", "short_video"],
            "blog": ["blog_article"],
            "email": ["email_newsletter"],
        }
        options = formats_by_platform.get(platform, ["text_post"])
        return options[index % len(options)]

    def _alternate_format(self, platform: str) -> str:
        """Return alternate format for a platform."""
        platform = self._normalize_platform(platform)
        alternates = {
            "youtube": "short_video",
            "youtube_shorts": "repurposed_clip",
            "instagram": "carousel",
            "facebook": "single_image",
            "tiktok": "short_video",
            "linkedin": "document_post",
            "x": "thread",
            "blog": "supporting_social_post",
            "email": "summary_email",
        }
        return alternates.get(platform, "text_post")

    def _build_content_title(
        self,
        *,
        brand_name: str,
        niche: Optional[str],
        pillar: str,
        objective: str,
        funnel_stage: str,
        index: int,
    ) -> str:
        """Build deterministic content title."""
        subject = niche or brand_name
        pillar_text = pillar.replace("_", " ")
        objective_text = objective.replace("_", " ")

        patterns = [
            f"How {subject} Can Win More Attention With {pillar_text.title()}",
            f"{brand_name} Guide: A Simple {objective_text.title()} Tip for {subject}",
            f"Before You Choose {subject}: Know This",
            f"3 Mistakes People Make With {subject}",
            f"Why {subject} Matters More Than Ever",
            f"A Practical {funnel_stage.upper()} Post About {subject}",
        ]
        return patterns[index % len(patterns)]

    def _build_hook(
        self,
        *,
        brand_name: str,
        niche: Optional[str],
        pillar: str,
        objective: str,
        audience: str,
        index: int,
    ) -> str:
        """Build a hook line for content."""
        subject = niche or brand_name
        pillar_text = pillar.replace("_", " ")
        objective_text = objective.replace("_", " ")

        hooks = [
            f"Most {audience} miss this simple {subject} opportunity.",
            f"Here is one {pillar_text} idea that can improve your {objective_text}.",
            f"Before you spend more on {subject}, check this first.",
            f"This is what separates average content from content that converts.",
            f"If you want better results from {subject}, start here.",
            f"One small change can make your {subject} strategy much clearer.",
        ]
        return hooks[index % len(hooks)]

    def _build_caption_brief(
        self,
        *,
        title: str,
        platform: str,
        audience: str,
        objective: str,
        funnel_stage: str,
    ) -> str:
        """Build caption brief."""
        return (
            f"Write a {platform} caption for '{title}'. Speak to {audience}. "
            f"Keep the objective focused on {objective.replace('_', ' ')} and match "
            f"the {funnel_stage.upper()} funnel stage. Use a clear opening line, "
            f"one practical insight, and a soft CTA."
        )

    def _build_creative_brief(
        self,
        *,
        title: str,
        platform: str,
        content_format: str,
        pillar: str,
        include_briefs: bool,
    ) -> str:
        """Build creative brief."""
        if not include_briefs:
            return ""

        return (
            f"Create a {content_format} for {platform} around '{title}'. "
            f"Content pillar: {pillar.replace('_', ' ')}. Use strong visual hierarchy, "
            f"brand-safe design, readable text, and a clear first-frame hook."
        )

    def _default_cta(self, objective: str) -> str:
        """Return default CTA by objective."""
        objective = objective.strip().lower()
        ctas = {
            "awareness": "Follow for more helpful insights.",
            "engagement": "Comment your thoughts below.",
            "lead_generation": "Message us to discuss your project.",
            "conversion": "Book a consultation today.",
            "retention": "Save this for your next planning session.",
            "authority_building": "Share this with someone who needs it.",
            "community_growth": "Join the conversation and follow for more.",
        }
        return ctas.get(objective, "Contact us to learn more.")

    def _select_keywords_for_item(self, keywords: Sequence[str], index: int) -> List[str]:
        """Select up to five keywords for one content item."""
        if not keywords:
            return []
        rotated = list(keywords[index % len(keywords):]) + list(keywords[:index % len(keywords)])
        return rotated[:5]

    def _suggest_hashtags(
        self,
        *,
        brand_name: str,
        niche: Optional[str],
        pillar: str,
        platform: str,
        keywords: Sequence[str],
    ) -> List[str]:
        """Suggest safe hashtags."""
        if platform in {"blog", "email"}:
            return []

        base = [
            brand_name,
            niche or "",
            pillar,
            "contentmarketing",
            "digitalmarketing",
        ]
        base.extend(list(keywords[:4]))

        hashtags = []
        for item in base:
            slug = re.sub(r"[^a-zA-Z0-9]", "", str(item).title())
            if slug:
                hashtags.append(f"#{slug}")

        limit = 5 if platform in {"linkedin", "x"} else 12
        return _dedupe_keep_order(hashtags)[:limit]

    def _summarize_calendar(self, items: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize calendar items."""
        platform_counts: Dict[str, int] = {}
        pillar_counts: Dict[str, int] = {}
        objective_counts: Dict[str, int] = {}

        for item in items:
            platform = str(item.get("platform") or "unknown")
            pillar = str(item.get("pillar") or "unknown")
            objective = str(item.get("objective") or "unknown")
            platform_counts[platform] = platform_counts.get(platform, 0) + 1
            pillar_counts[pillar] = pillar_counts.get(pillar, 0) + 1
            objective_counts[objective] = objective_counts.get(objective, 0) + 1

        return {
            "platform_counts": platform_counts,
            "pillar_counts": pillar_counts,
            "objective_counts": objective_counts,
        }

    def _topic_templates(self) -> List[str]:
        """Topic title templates."""
        return [
            "How {audience} Can Use {keyword} to Grow Faster",
            "The Simple {niche} Checklist Most People Ignore",
            "Why {pillar} Content Works for {audience}",
            "{brand_name}'s Practical Guide to Better {keyword}",
            "Before You Invest in {niche}, Watch This",
            "3 Ways {audience} Can Improve {keyword}",
            "The Biggest Mistake in {niche} Marketing",
            "What Successful {audience} Do Differently With {keyword}",
            "A Beginner-Friendly Breakdown of {niche}",
            "How to Turn {keyword} Into More Leads",
        ]

    def _topic_angle(
        self,
        *,
        pillar: str,
        objective: str,
        funnel_stage: str,
        audience: str,
        niche: str,
    ) -> str:
        """Generate topic angle."""
        return (
            f"Use a {pillar.replace('_', ' ')} angle for {audience}, focused on "
            f"{objective.replace('_', ' ')} in the {funnel_stage.upper()} stage of "
            f"the {niche} journey."
        )

    def _suggest_priority(self, objective: str, funnel_stage: str) -> str:
        """Suggest content priority."""
        if objective in {"conversion", "lead_generation"} and funnel_stage in {"mof", "bof"}:
            return ContentPriority.HIGH.value
        if objective in {"awareness", "engagement"}:
            return ContentPriority.NORMAL.value
        return ContentPriority.NORMAL.value

    def _platform_profile(self, platform: str) -> Dict[str, Any]:
        """Return platform strategy profile."""
        profiles = {
            "youtube": {
                "recommended_frequency": "1-2 long videos per week plus Shorts repurposing",
                "best_formats": ["long_video", "short_video", "live_stream"],
                "hook_style": "Clear problem statement within first 10 seconds.",
                "caption_style": "SEO title, keyword-rich description, chapters, CTA.",
                "creative_guidelines": "Strong thumbnail, clear title promise, structured video flow.",
            },
            "youtube_shorts": {
                "recommended_frequency": "3-7 Shorts per week",
                "best_formats": ["short_video"],
                "hook_style": "Fast visual hook in first 1-2 seconds.",
                "caption_style": "Short caption with keyword and engagement prompt.",
                "creative_guidelines": "Vertical 9:16, captions on screen, one idea per video.",
            },
            "instagram": {
                "recommended_frequency": "4-7 posts per week plus stories",
                "best_formats": ["reel", "carousel", "story", "single_image"],
                "hook_style": "Bold first frame or first line.",
                "caption_style": "Conversational caption with value and CTA.",
                "creative_guidelines": "Brand colors, clean layouts, readable mobile text.",
            },
            "facebook": {
                "recommended_frequency": "3-5 posts per week",
                "best_formats": ["short_video", "text_post", "carousel", "single_image"],
                "hook_style": "Relatable opening problem.",
                "caption_style": "Direct, benefit-led, easy to respond to.",
                "creative_guidelines": "Readable visuals and community-friendly tone.",
            },
            "tiktok": {
                "recommended_frequency": "5-10 short videos per week",
                "best_formats": ["short_video"],
                "hook_style": "Pattern interrupt or direct statement.",
                "caption_style": "Short, native, curiosity-driven.",
                "creative_guidelines": "Fast cuts, native style, captions, strong retention.",
            },
            "linkedin": {
                "recommended_frequency": "3-5 posts per week",
                "best_formats": ["text_post", "carousel", "document_post", "short_video"],
                "hook_style": "Authority-driven first line.",
                "caption_style": "Professional insight with clear formatting.",
                "creative_guidelines": "Clean design, proof, frameworks, practical examples.",
            },
            "x": {
                "recommended_frequency": "5-14 posts per week",
                "best_formats": ["text_post", "thread", "short_video"],
                "hook_style": "Sharp opinion or useful statement.",
                "caption_style": "Concise, direct, easy to share.",
                "creative_guidelines": "Simple text-first content and threads.",
            },
            "blog": {
                "recommended_frequency": "1-3 articles per week",
                "best_formats": ["blog_article"],
                "hook_style": "Search-intent headline.",
                "caption_style": "SEO meta-style intro and structured headings.",
                "creative_guidelines": "Helpful article, internal links, CTA, FAQ section.",
            },
            "email": {
                "recommended_frequency": "1-3 emails per week",
                "best_formats": ["email_newsletter"],
                "hook_style": "Benefit-led subject line.",
                "caption_style": "Personal, concise, useful, CTA-focused.",
                "creative_guidelines": "Readable layout, one main CTA, segmentation-ready.",
            },
        }
        return profiles.get(platform, profiles["instagram"])

    def _platform_content_mix(
        self,
        *,
        platform: str,
        pillars: Sequence[str],
        objective: str,
    ) -> List[Dict[str, Any]]:
        """Create recommended content mix."""
        mix = []
        for index, pillar in enumerate(pillars):
            mix.append(
                {
                    "pillar": pillar,
                    "recommended_share": self._recommended_share(index, len(pillars)),
                    "example_format": self._suggest_format_for_platform(platform, index),
                    "objective": objective,
                }
            )
        return mix

    def _recommended_share(self, index: int, total: int) -> str:
        """Return rough share percentage."""
        if total <= 0:
            return "0%"
        base = int(100 / total)
        return f"{base}%"

    def _hashtag_strategy(
        self,
        *,
        platform: str,
        brand_name: str,
        niche: str,
        keywords: Sequence[str],
    ) -> Dict[str, Any]:
        """Create hashtag strategy."""
        if platform in {"blog", "email"}:
            return {
                "use_hashtags": False,
                "notes": "Hashtags are not needed for this platform.",
                "examples": [],
            }

        examples = self._suggest_hashtags(
            brand_name=brand_name,
            niche=niche,
            pillar="marketing",
            platform=platform,
            keywords=keywords,
        )

        return {
            "use_hashtags": True,
            "recommended_count": 3 if platform in {"linkedin", "x"} else 8,
            "mix": ["brand", "niche", "problem", "solution", "audience"],
            "examples": examples,
        }

    def _cta_examples(self, objective: str) -> List[str]:
        """Return CTA examples."""
        base = self._default_cta(objective)
        return [
            base,
            "Save this post for later.",
            "Send us a message if you want help with this.",
            "Share this with someone who needs it.",
        ]

    def _weekly_platform_structure(
        self,
        *,
        platform: str,
        pillars: Sequence[str],
    ) -> List[Dict[str, Any]]:
        """Return weekly structure for a platform."""
        days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        structure = []
        for index, day in enumerate(days):
            pillar = _round_robin(pillars, index, "education")
            structure.append(
                {
                    "day": day,
                    "pillar": pillar,
                    "format": self._suggest_format_for_platform(platform, index),
                    "goal": self._day_goal(index),
                }
            )
        return structure

    def _day_goal(self, index: int) -> str:
        """Return content goal by day index."""
        goals = [
            "Start the week with education.",
            "Build trust with proof or practical advice.",
            "Create engagement with a question or opinion.",
            "Show authority with a framework.",
            "Drive action with an offer or CTA.",
            "Use lighter community content.",
            "Repurpose or recap top insight.",
        ]
        return goals[index % len(goals)]

    def _repurposing_notes(self, platform: str) -> List[str]:
        """Return repurposing notes by platform."""
        notes = {
            "youtube": [
                "Cut long videos into Shorts, Reels, TikToks, and LinkedIn clips.",
                "Turn video outline into blog article and email newsletter.",
            ],
            "blog": [
                "Turn article sections into LinkedIn posts and carousels.",
                "Use FAQ answers as short-form video scripts.",
            ],
            "email": [
                "Turn email insights into LinkedIn posts and X threads.",
                "Use campaign emails as landing page copy inspiration.",
            ],
        }
        return notes.get(
            platform,
            [
                "Repurpose high-performing posts into short videos, carousels, and emails.",
                "Turn comments and FAQs into future topic ideas.",
            ],
        )

    def _build_weekly_themes(
        self,
        *,
        start: date,
        end: date,
        pillars: Sequence[str],
        objective: str,
        niche: Optional[str],
    ) -> List[Dict[str, Any]]:
        """Build weekly campaign themes."""
        weeks: List[Dict[str, Any]] = []
        current = start
        week_number = 1

        while current <= end:
            week_end = min(current + timedelta(days=6), end)
            pillar = _round_robin(pillars, week_number - 1, "education")
            weeks.append(
                {
                    "week": week_number,
                    "start_date": current.isoformat(),
                    "end_date": week_end.isoformat(),
                    "theme": f"{pillar.replace('_', ' ').title()} for {niche or 'the audience'}",
                    "objective": objective,
                    "content_focus": self._weekly_focus(pillar, objective),
                }
            )
            current = week_end + timedelta(days=1)
            week_number += 1

        return weeks

    def _weekly_focus(self, pillar: str, objective: str) -> str:
        """Return weekly content focus."""
        return (
            f"Use {pillar.replace('_', ' ')} content to support "
            f"{objective.replace('_', ' ')} with clear hooks, proof, and CTA."
        )

    def _suggest_campaign_kpis(self, objective: str) -> Dict[str, Any]:
        """Suggest KPIs by campaign objective."""
        objective = objective.strip().lower()
        common = {
            "content_output": "Number of planned posts published after approval",
            "consistency": "Posts completed on schedule",
            "engagement_rate": "Likes, comments, shares, saves, replies",
        }

        objective_kpis = {
            "awareness": {
                "reach": "Total unique viewers",
                "impressions": "Total content views",
                "follower_growth": "New followers from campaign period",
            },
            "engagement": {
                "comments": "Meaningful comments and replies",
                "shares": "Content shares",
                "saves": "Saved posts",
            },
            "lead_generation": {
                "inquiries": "Inbound DMs, forms, calls, or booked calls",
                "cost_per_lead": "Paid KPI only if ads are approved",
                "conversion_rate": "Lead conversion from content CTA",
            },
            "conversion": {
                "sales_calls": "Booked sales calls",
                "qualified_leads": "Qualified prospects",
                "revenue_attribution": "Revenue influenced by content",
            },
        }

        return {
            **common,
            **objective_kpis.get(objective, objective_kpis["engagement"]),
        }

    def _group_schedule_by_platform(
        self,
        entries: Sequence[Dict[str, Any]],
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Group schedule entries by platform."""
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for entry in entries:
            platform = str(entry.get("platform") or "unknown")
            grouped.setdefault(platform, []).append(entry)
        return grouped

    def _variation_title(self, topic_title: str, platform: str, variation: int) -> str:
        """Create platform-specific variation title."""
        platform_label = platform.replace("_", " ").title()
        patterns = [
            f"{topic_title} — {platform_label} Quick Tip",
            f"{topic_title} — Practical Breakdown",
            f"{topic_title} — Mistakes to Avoid",
            f"{topic_title} — Step-by-Step",
            f"{topic_title} — Before and After",
        ]
        return patterns[variation % len(patterns)]

    def _calendar_recommendations(
        self,
        *,
        total_items: int,
        platform_counts: Dict[str, int],
        pillar_counts: Dict[str, int],
        conflicts: Sequence[Dict[str, Any]],
        missing_fields: Sequence[Dict[str, Any]],
        approval_items: Sequence[Dict[str, Any]],
    ) -> List[str]:
        """Build audit recommendations."""
        recommendations: List[str] = []

        if total_items == 0:
            recommendations.append("Add content items before launching the calendar.")
            return recommendations

        if missing_fields:
            recommendations.append("Complete missing required fields before production starts.")

        if conflicts:
            recommendations.append("Fix scheduling conflicts where multiple posts share the same platform/date/time.")

        if approval_items:
            recommendations.append("Send approval-required items to Security Agent or human reviewer before scheduling.")

        if len(platform_counts) < 2 and total_items >= 5:
            recommendations.append("Consider adding at least one more platform for repurposing and reach.")

        if len(pillar_counts) < 3 and total_items >= 10:
            recommendations.append("Add more content pillar variety to avoid repetitive messaging.")

        if not recommendations:
            recommendations.append("Calendar looks balanced and ready for review.")

        return recommendations

    def _calendar_health_score(
        self,
        *,
        total_items: int,
        missing_fields: Sequence[Dict[str, Any]],
        conflicts: Sequence[Dict[str, Any]],
        approval_items: Sequence[Dict[str, Any]],
    ) -> int:
        """Calculate simple calendar health score."""
        if total_items <= 0:
            return 0

        score = 100
        score -= min(40, len(missing_fields) * 5)
        score -= min(30, len(conflicts) * 10)
        score -= min(10, len(approval_items) * 2)
        return max(0, min(100, score))

    def _risk_level_for_action(self, action: str, payload: Dict[str, Any]) -> str:
        """Return risk level for sensitive action."""
        action = action.strip().lower()
        if action in {"delete_calendar", "external_api_push"}:
            return "high"
        if action in {"publish", "schedule_publish", "send_email_campaign"}:
            return "medium"
        if action in {"paid_campaign", "boost_post"} or payload.get("ad_spend"):
            return "high"
        return "low"

    def _security_reason(self, action: str, payload: Dict[str, Any]) -> str:
        """Return human-readable security reason."""
        action = action.strip().lower()
        if action == "schedule_publish":
            return "Scheduling or publishing content externally requires approval."
        if action == "publish":
            return "Publishing content externally requires approval."
        if action in {"paid_campaign", "boost_post"}:
            return "Paid promotion or ad spend requires approval."
        if action == "send_email_campaign":
            return "Sending campaign emails requires approval."
        if action == "delete_calendar":
            return "Deleting calendar data is destructive and requires approval."
        if payload.get("external_api_push"):
            return "External API push requires approval."
        return "Sensitive action requires Security Agent approval."

    def _redact_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Redact secrets and sensitive keys from payload."""
        sensitive_keys = {
            "password",
            "token",
            "secret",
            "api_key",
            "apikey",
            "authorization",
            "access_token",
            "refresh_token",
            "private_key",
        }

        def redact(value: Any) -> Any:
            if isinstance(value, dict):
                clean = {}
                for key, nested_value in value.items():
                    normalized_key = str(key).lower()
                    if any(secret_key in normalized_key for secret_key in sensitive_keys):
                        clean[key] = "***REDACTED***"
                    else:
                        clean[key] = redact(nested_value)
                return clean

            if isinstance(value, list):
                return [redact(item) for item in value]

            return value

        return redact(copy.deepcopy(payload))


def _dedupe_dates(items: Sequence[date]) -> List[date]:
    """Dedupe dates while preserving order."""
    seen = set()
    output: List[date] = []
    for item in items:
        key = item.isoformat()
        if key not in seen:
            seen.add(key)
            output.append(item)
    return output


# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------

__all__ = [
    "ContentPlanner",
    "SaaSContext",
    "ContentTopic",
    "ContentItem",
    "CampaignPlan",
    "ContentPriority",
    "ContentStatus",
    "PlatformType",
    "CalendarCadence",
]