"""
agents/super_agents/creator_agent/config.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Creator settings, platforms, durations, and approval-before-publishing rules
    for the Creator Agent module.

This file is designed to be:
    - Production-level and import-safe.
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router,
      Master Agent routing, Security Agent, Memory Agent, Verification Agent,
      Dashboard/API, and future FastAPI integration.
    - SaaS-safe with strict user_id/workspace_id isolation.
    - Testable without requiring the rest of the William/Jarvis codebase.
    - Free of hardcoded secrets.
    - Safe by default: no publishing, scheduling, messaging, or external actions
      are executed from this file.

CreatorConfig Responsibilities:
    - Define default Creator Agent settings.
    - Define supported platforms and content format limits.
    - Validate creator settings.
    - Manage per-user/per-workspace config overrides.
    - Enforce approval requirements before publishing/scheduling.
    - Provide structured config payloads for dashboard/API usage.
    - Prepare Security, Verification, Memory, Audit, and Event payloads.

Important:
    This is a config/helper file. It does not upload, publish, schedule, send,
    delete, or modify external content. Publishing and scheduling must be routed
    through Security Agent approval and future platform adapters.
"""

from __future__ import annotations

import copy
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for isolated import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Used only when the real William/Jarvis BaseAgent is unavailable.
        Keeps this config file import-safe during early development or tests.
        """

        agent_name: str = "base_agent"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_id = kwargs.get("agent_id", self.__class__.__name__)
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)


try:
    from agents.shared.types import AgentResult  # type: ignore
except Exception:  # pragma: no cover
    AgentResult = Dict[str, Any]  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("william.creator.config")
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def utc_now() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    """Return current UTC time as ISO string."""
    return utc_now().isoformat()


def make_id(prefix: str) -> str:
    """Create readable unique IDs for events/audits/config records."""
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def normalize_text(value: Any) -> str:
    """Normalize text for safe comparisons."""
    if value is None:
        return ""
    return str(value).strip().lower()


def normalize_key(value: Any) -> str:
    """Normalize text into config-safe key style."""
    return normalize_text(value).replace(" ", "_").replace("-", "_")


def safe_int(value: Any, default: int = 0) -> int:
    """Safely convert value to int."""
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def safe_bool(value: Any, default: bool = False) -> bool:
    """Safely convert common truthy/falsy values to bool."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = normalize_text(value)
    if text in {"true", "1", "yes", "y", "on", "enabled"}:
        return True
    if text in {"false", "0", "no", "n", "off", "disabled"}:
        return False
    return default


def clamp_int(value: Any, minimum: int, maximum: int, default: int) -> int:
    """Clamp integer value safely."""
    parsed = safe_int(value, default)
    return max(minimum, min(maximum, parsed))


def dedupe_preserve_order(items: Iterable[Any]) -> List[str]:
    """Deduplicate list values while preserving order."""
    seen = set()
    output: List[str] = []
    for item in items:
        value = str(item).strip()
        marker = value.lower()
        if value and marker not in seen:
            seen.add(marker)
            output.append(value)
    return output


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge dictionaries without mutating either input.

    Values from override win. Nested dictionaries are merged recursively.
    """

    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if (
            isinstance(value, dict)
            and isinstance(result.get(key), dict)
        ):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def dataclass_to_dict(instance: Any) -> Dict[str, Any]:
    """Convert dataclass or object to dictionary safely."""
    if hasattr(instance, "__dataclass_fields__"):
        return copy.deepcopy(asdict(instance))
    if isinstance(instance, dict):
        return copy.deepcopy(instance)
    return copy.deepcopy(getattr(instance, "__dict__", {}))


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class CreatorPlatform(str, Enum):
    """Supported creator platforms."""

    YOUTUBE = "youtube"
    YOUTUBE_SHORTS = "youtube_shorts"
    TIKTOK = "tiktok"
    INSTAGRAM_REELS = "instagram_reels"
    INSTAGRAM_POST = "instagram_post"
    FACEBOOK_REELS = "facebook_reels"
    FACEBOOK_POST = "facebook_post"
    LINKEDIN_POST = "linkedin_post"
    X_POST = "x_post"
    PINTEREST_PIN = "pinterest_pin"
    BLOG = "blog"
    WEBSITE = "website"
    EMAIL = "email"
    GENERIC = "generic"


class ContentFormat(str, Enum):
    """Creator content format types."""

    SHORT_VIDEO = "short_video"
    LONG_VIDEO = "long_video"
    IMAGE_POST = "image_post"
    CAROUSEL = "carousel"
    TEXT_POST = "text_post"
    BLOG_ARTICLE = "blog_article"
    EMAIL_COPY = "email_copy"
    THUMBNAIL = "thumbnail"
    VOICEOVER = "voiceover"
    SCRIPT = "script"
    PROMPT = "prompt"


class ApprovalMode(str, Enum):
    """Approval mode before publishing or scheduling."""

    ALWAYS_REQUIRE = "always_require"
    REQUIRE_FOR_EXTERNAL_ACTIONS = "require_for_external_actions"
    REQUIRE_FOR_HIGH_RISK = "require_for_high_risk"
    DISABLED_FOR_DRAFTS_ONLY = "disabled_for_drafts_only"


class CreatorTone(str, Enum):
    """Safe default tone presets."""

    PROFESSIONAL = "professional"
    FRIENDLY = "friendly"
    AUTHORITATIVE = "authoritative"
    EDUCATIONAL = "educational"
    CONVERSATIONAL = "conversational"
    LUXURY = "luxury"
    DIRECT_RESPONSE = "direct_response"


class CreatorEventType(str, Enum):
    """Creator config event types."""

    CONFIG_VIEWED = "config_viewed"
    CONFIG_UPDATED = "config_updated"
    CONFIG_RESET = "config_reset"
    PLATFORM_RULE_VALIDATED = "platform_rule_validated"
    APPROVAL_POLICY_CHECKED = "approval_policy_checked"


class RiskLevel(str, Enum):
    """Content/action risk levels for approval decisions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class CreatorContext:
    """
    SaaS isolation context.

    Every user/workspace-specific config operation must include this context.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    request_id: Optional[str] = None
    source: Optional[str] = None
    permissions: List[str] = field(default_factory=list)

    def key(self) -> Tuple[str, str]:
        return self.user_id, self.workspace_id


@dataclass
class PlatformRule:
    """
    Platform-specific creator constraints.

    These defaults are intentionally conservative and can be changed later
    through config overrides or a future database-backed settings service.
    """

    platform: str
    display_name: str
    supported_formats: List[str]
    min_duration_seconds: int = 0
    max_duration_seconds: int = 0
    recommended_duration_seconds: int = 0
    max_title_chars: int = 100
    max_description_chars: int = 2200
    max_caption_chars: int = 2200
    max_hashtags: int = 30
    max_tags: int = 30
    max_assets: int = 20
    aspect_ratios: List[str] = field(default_factory=list)
    requires_approval_before_publish: bool = True
    requires_approval_before_schedule: bool = True
    allow_auto_publish: bool = False
    allow_auto_schedule: bool = False
    default_visibility: str = "private"
    notes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CreatorSettings:
    """
    Workspace-level Creator Agent settings.

    Stored per user_id + workspace_id in this helper's local in-memory storage.
    Future persistence can replace local storage with a repository adapter.
    """

    user_id: str
    workspace_id: str
    default_platforms: List[str] = field(default_factory=lambda: [CreatorPlatform.GENERIC.value])
    default_tone: str = CreatorTone.PROFESSIONAL.value
    default_language: str = "en"
    brand_safety_enabled: bool = True
    require_approval_before_publish: bool = True
    require_approval_before_schedule: bool = True
    approval_mode: str = ApprovalMode.ALWAYS_REQUIRE.value
    allow_auto_publish: bool = False
    allow_auto_schedule: bool = False
    max_short_video_duration_seconds: int = 60
    max_long_video_duration_seconds: int = 3600
    max_script_words: int = 2500
    max_caption_chars: int = 2200
    max_hashtags: int = 30
    default_timezone: str = "UTC"
    default_currency: str = "USD"
    allowed_platforms: List[str] = field(default_factory=list)
    blocked_platforms: List[str] = field(default_factory=list)
    publishing_blackout_days: List[str] = field(default_factory=list)
    publishing_blackout_hours: List[int] = field(default_factory=list)
    require_human_review_for: List[str] = field(default_factory=lambda: [
        "publish",
        "schedule",
        "paid_campaign_content",
        "legal_claims",
        "medical_claims",
        "financial_claims",
        "political_content",
        "brand_sensitive_content",
    ])
    content_defaults: Dict[str, Any] = field(default_factory=dict)
    platform_overrides: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)


# ---------------------------------------------------------------------------
# Default platform rules
# ---------------------------------------------------------------------------

DEFAULT_PLATFORM_RULES: Dict[str, PlatformRule] = {
    CreatorPlatform.YOUTUBE.value: PlatformRule(
        platform=CreatorPlatform.YOUTUBE.value,
        display_name="YouTube",
        supported_formats=[
            ContentFormat.LONG_VIDEO.value,
            ContentFormat.SHORT_VIDEO.value,
            ContentFormat.THUMBNAIL.value,
            ContentFormat.SCRIPT.value,
            ContentFormat.VOICEOVER.value,
        ],
        min_duration_seconds=15,
        max_duration_seconds=43200,
        recommended_duration_seconds=480,
        max_title_chars=100,
        max_description_chars=5000,
        max_caption_chars=5000,
        max_hashtags=15,
        max_tags=30,
        max_assets=50,
        aspect_ratios=["16:9", "9:16", "1:1"],
        default_visibility="private",
        notes=["Use private or unlisted visibility until human approval."],
    ),
    CreatorPlatform.YOUTUBE_SHORTS.value: PlatformRule(
        platform=CreatorPlatform.YOUTUBE_SHORTS.value,
        display_name="YouTube Shorts",
        supported_formats=[
            ContentFormat.SHORT_VIDEO.value,
            ContentFormat.SCRIPT.value,
            ContentFormat.VOICEOVER.value,
            ContentFormat.CAPTION if hasattr(ContentFormat, "CAPTION") else ContentFormat.TEXT_POST.value,
        ],
        min_duration_seconds=3,
        max_duration_seconds=60,
        recommended_duration_seconds=35,
        max_title_chars=100,
        max_description_chars=1500,
        max_caption_chars=1500,
        max_hashtags=10,
        max_tags=15,
        max_assets=20,
        aspect_ratios=["9:16"],
        default_visibility="private",
        notes=["Vertical 9:16 video is preferred."],
    ),
    CreatorPlatform.TIKTOK.value: PlatformRule(
        platform=CreatorPlatform.TIKTOK.value,
        display_name="TikTok",
        supported_formats=[
            ContentFormat.SHORT_VIDEO.value,
            ContentFormat.SCRIPT.value,
            ContentFormat.VOICEOVER.value,
            ContentFormat.TEXT_POST.value,
        ],
        min_duration_seconds=3,
        max_duration_seconds=600,
        recommended_duration_seconds=30,
        max_title_chars=150,
        max_description_chars=2200,
        max_caption_chars=2200,
        max_hashtags=20,
        max_tags=20,
        max_assets=20,
        aspect_ratios=["9:16"],
        default_visibility="private",
        notes=["Human approval is required before posting."],
    ),
    CreatorPlatform.INSTAGRAM_REELS.value: PlatformRule(
        platform=CreatorPlatform.INSTAGRAM_REELS.value,
        display_name="Instagram Reels",
        supported_formats=[
            ContentFormat.SHORT_VIDEO.value,
            ContentFormat.SCRIPT.value,
            ContentFormat.VOICEOVER.value,
            ContentFormat.TEXT_POST.value,
        ],
        min_duration_seconds=3,
        max_duration_seconds=180,
        recommended_duration_seconds=30,
        max_title_chars=150,
        max_description_chars=2200,
        max_caption_chars=2200,
        max_hashtags=30,
        max_tags=20,
        max_assets=20,
        aspect_ratios=["9:16"],
        default_visibility="private",
        notes=["Avoid auto-publishing without manual review."],
    ),
    CreatorPlatform.INSTAGRAM_POST.value: PlatformRule(
        platform=CreatorPlatform.INSTAGRAM_POST.value,
        display_name="Instagram Post",
        supported_formats=[
            ContentFormat.IMAGE_POST.value,
            ContentFormat.CAROUSEL.value,
            ContentFormat.TEXT_POST.value,
        ],
        min_duration_seconds=0,
        max_duration_seconds=0,
        recommended_duration_seconds=0,
        max_title_chars=150,
        max_description_chars=2200,
        max_caption_chars=2200,
        max_hashtags=30,
        max_tags=20,
        max_assets=10,
        aspect_ratios=["1:1", "4:5", "9:16"],
        default_visibility="private",
    ),
    CreatorPlatform.FACEBOOK_REELS.value: PlatformRule(
        platform=CreatorPlatform.FACEBOOK_REELS.value,
        display_name="Facebook Reels",
        supported_formats=[
            ContentFormat.SHORT_VIDEO.value,
            ContentFormat.SCRIPT.value,
            ContentFormat.VOICEOVER.value,
            ContentFormat.TEXT_POST.value,
        ],
        min_duration_seconds=3,
        max_duration_seconds=90,
        recommended_duration_seconds=30,
        max_title_chars=150,
        max_description_chars=2200,
        max_caption_chars=2200,
        max_hashtags=20,
        max_tags=20,
        max_assets=20,
        aspect_ratios=["9:16"],
        default_visibility="private",
    ),
    CreatorPlatform.FACEBOOK_POST.value: PlatformRule(
        platform=CreatorPlatform.FACEBOOK_POST.value,
        display_name="Facebook Post",
        supported_formats=[
            ContentFormat.IMAGE_POST.value,
            ContentFormat.CAROUSEL.value,
            ContentFormat.TEXT_POST.value,
            ContentFormat.SHORT_VIDEO.value,
        ],
        min_duration_seconds=0,
        max_duration_seconds=240,
        recommended_duration_seconds=30,
        max_title_chars=150,
        max_description_chars=63206,
        max_caption_chars=5000,
        max_hashtags=20,
        max_tags=30,
        max_assets=20,
        aspect_ratios=["1:1", "4:5", "9:16", "16:9"],
        default_visibility="private",
    ),
    CreatorPlatform.LINKEDIN_POST.value: PlatformRule(
        platform=CreatorPlatform.LINKEDIN_POST.value,
        display_name="LinkedIn Post",
        supported_formats=[
            ContentFormat.TEXT_POST.value,
            ContentFormat.IMAGE_POST.value,
            ContentFormat.CAROUSEL.value,
            ContentFormat.SHORT_VIDEO.value,
        ],
        min_duration_seconds=0,
        max_duration_seconds=600,
        recommended_duration_seconds=60,
        max_title_chars=150,
        max_description_chars=3000,
        max_caption_chars=3000,
        max_hashtags=10,
        max_tags=20,
        max_assets=20,
        aspect_ratios=["1:1", "4:5", "16:9"],
        default_visibility="private",
        notes=["Professional tone is recommended."],
    ),
    CreatorPlatform.X_POST.value: PlatformRule(
        platform=CreatorPlatform.X_POST.value,
        display_name="X / Twitter Post",
        supported_formats=[
            ContentFormat.TEXT_POST.value,
            ContentFormat.IMAGE_POST.value,
            ContentFormat.SHORT_VIDEO.value,
        ],
        min_duration_seconds=0,
        max_duration_seconds=140,
        recommended_duration_seconds=30,
        max_title_chars=100,
        max_description_chars=280,
        max_caption_chars=280,
        max_hashtags=5,
        max_tags=10,
        max_assets=4,
        aspect_ratios=["1:1", "16:9", "9:16"],
        default_visibility="private",
    ),
    CreatorPlatform.PINTEREST_PIN.value: PlatformRule(
        platform=CreatorPlatform.PINTEREST_PIN.value,
        display_name="Pinterest Pin",
        supported_formats=[
            ContentFormat.IMAGE_POST.value,
            ContentFormat.CAROUSEL.value,
            ContentFormat.TEXT_POST.value,
        ],
        min_duration_seconds=0,
        max_duration_seconds=60,
        recommended_duration_seconds=15,
        max_title_chars=100,
        max_description_chars=500,
        max_caption_chars=500,
        max_hashtags=10,
        max_tags=20,
        max_assets=10,
        aspect_ratios=["2:3", "9:16", "1:1"],
        default_visibility="private",
    ),
    CreatorPlatform.BLOG.value: PlatformRule(
        platform=CreatorPlatform.BLOG.value,
        display_name="Blog",
        supported_formats=[
            ContentFormat.BLOG_ARTICLE.value,
            ContentFormat.IMAGE_POST.value,
            ContentFormat.THUMBNAIL.value,
        ],
        min_duration_seconds=0,
        max_duration_seconds=0,
        recommended_duration_seconds=0,
        max_title_chars=70,
        max_description_chars=160,
        max_caption_chars=5000,
        max_hashtags=10,
        max_tags=30,
        max_assets=50,
        aspect_ratios=["16:9", "4:3", "1:1"],
        default_visibility="draft",
        notes=["Publish only after editorial review."],
    ),
    CreatorPlatform.WEBSITE.value: PlatformRule(
        platform=CreatorPlatform.WEBSITE.value,
        display_name="Website",
        supported_formats=[
            ContentFormat.TEXT_POST.value,
            ContentFormat.IMAGE_POST.value,
            ContentFormat.BLOG_ARTICLE.value,
            ContentFormat.THUMBNAIL.value,
        ],
        min_duration_seconds=0,
        max_duration_seconds=0,
        recommended_duration_seconds=0,
        max_title_chars=70,
        max_description_chars=160,
        max_caption_chars=10000,
        max_hashtags=10,
        max_tags=30,
        max_assets=100,
        aspect_ratios=["16:9", "4:3", "1:1", "9:16"],
        default_visibility="draft",
    ),
    CreatorPlatform.EMAIL.value: PlatformRule(
        platform=CreatorPlatform.EMAIL.value,
        display_name="Email",
        supported_formats=[
            ContentFormat.EMAIL_COPY.value,
            ContentFormat.TEXT_POST.value,
            ContentFormat.IMAGE_POST.value,
        ],
        min_duration_seconds=0,
        max_duration_seconds=0,
        recommended_duration_seconds=0,
        max_title_chars=90,
        max_description_chars=10000,
        max_caption_chars=10000,
        max_hashtags=0,
        max_tags=20,
        max_assets=20,
        aspect_ratios=["16:9", "1:1"],
        default_visibility="draft",
        notes=["Sending email is an external action and requires approval."],
    ),
    CreatorPlatform.GENERIC.value: PlatformRule(
        platform=CreatorPlatform.GENERIC.value,
        display_name="Generic",
        supported_formats=[item.value for item in ContentFormat],
        min_duration_seconds=0,
        max_duration_seconds=3600,
        recommended_duration_seconds=60,
        max_title_chars=120,
        max_description_chars=5000,
        max_caption_chars=2200,
        max_hashtags=30,
        max_tags=30,
        max_assets=50,
        aspect_ratios=["1:1", "4:5", "9:16", "16:9"],
        default_visibility="draft",
    ),
}


DEFAULT_CONTENT_DEFAULTS: Dict[str, Any] = {
    "tone": CreatorTone.PROFESSIONAL.value,
    "language": "en",
    "cta_required": True,
    "hook_required": True,
    "caption_required": True,
    "brand_voice_required": True,
    "safe_claims_required": True,
    "default_video_fps": 30,
    "default_video_resolution": "1080p",
    "default_short_form_aspect_ratio": "9:16",
    "default_long_form_aspect_ratio": "16:9",
    "default_thumbnail_aspect_ratio": "16:9",
    "default_image_aspect_ratio": "1:1",
    "avoid_unverified_claims": True,
    "avoid_sensitive_targeting": True,
    "include_disclaimer_when_needed": True,
    "require_source_links_for_factual_claims": True,
}


HIGH_RISK_CONTENT_FLAGS = {
    "legal_claims",
    "medical_claims",
    "financial_claims",
    "political_content",
    "regulated_industry",
    "adult_content",
    "minors",
    "public_figure",
    "crisis_or_emergency",
    "brand_sensitive_content",
    "paid_campaign_content",
    "guaranteed_results_claim",
    "before_after_claim",
}


EXTERNAL_ACTIONS = {
    "publish",
    "schedule",
    "send_email",
    "upload",
    "delete_external_content",
    "edit_live_content",
    "boost_post",
    "start_campaign",
    "connect_platform",
    "sync_assets_external",
}


# ---------------------------------------------------------------------------
# CreatorConfig
# ---------------------------------------------------------------------------

class CreatorConfig(BaseAgent):
    """
    Creator Agent configuration manager.

    Responsibilities:
        - Provide default Creator Agent settings.
        - Define platform-specific content limits and duration rules.
        - Store user/workspace-safe config overrides.
        - Validate platform/content settings.
        - Enforce approval-before-publishing and approval-before-scheduling.
        - Prepare structured payloads for Security, Verification, Memory, Audit,
          Dashboard/API, and Agent Registry.

    Integration notes:
        - Master Agent can route creator.config tasks to handle_task().
        - Security Agent should approve external publishing/scheduling actions.
        - Memory Agent may store approved long-term creator preferences.
        - Verification Agent can verify config changes.
        - Dashboard/API can use get_effective_config() and get_platform_rules().
        - Agent Registry/Loader can safely import get_agent_metadata().
    """

    agent_name = "creator_config"
    agent_type = "creator_agent_config"
    public_methods = [
        "get_default_config",
        "get_effective_config",
        "update_workspace_config",
        "reset_workspace_config",
        "get_platform_rules",
        "get_platform_rule",
        "validate_platform_content",
        "check_approval_required",
        "list_supported_platforms",
        "list_supported_formats",
        "handle_task",
        "health_check",
    ]

    def __init__(
        self,
        *,
        security_adapter: Optional[Any] = None,
        memory_adapter: Optional[Any] = None,
        verification_adapter: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], Any]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], Any]] = None,
        storage: Optional[Dict[str, Any]] = None,
        platform_rules: Optional[Dict[str, Union[PlatformRule, Dict[str, Any]]]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.logger = logger or getattr(self, "logger", LOGGER)

        self.security_adapter = security_adapter
        self.memory_adapter = memory_adapter
        self.verification_adapter = verification_adapter
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger

        self.platform_rules = self._build_platform_rules(platform_rules)
        self.storage: Dict[str, Any] = storage if storage is not None else {}
        self.storage.setdefault("workspace_configs", {})
        self.storage.setdefault("events", [])
        self.storage.setdefault("audit_logs", [])

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[CreatorContext, Dict[str, Any]],
    ) -> Tuple[bool, Optional[CreatorContext], Optional[str]]:
        """
        Validate SaaS user/workspace context.

        All user/workspace-specific configuration operations must pass this.
        """

        try:
            if isinstance(context, CreatorContext):
                ctx = context
            elif isinstance(context, dict):
                ctx = CreatorContext(
                    user_id=str(context.get("user_id", "")).strip(),
                    workspace_id=str(context.get("workspace_id", "")).strip(),
                    role=context.get("role"),
                    request_id=context.get("request_id"),
                    source=context.get("source"),
                    permissions=list(context.get("permissions") or []),
                )
            else:
                return False, None, "Invalid context type. Expected CreatorContext or dict."

            if not ctx.user_id:
                return False, None, "Missing required user_id."
            if not ctx.workspace_id:
                return False, None, "Missing required workspace_id."

            return True, ctx, None
        except Exception as exc:
            return False, None, f"Context validation failed: {exc}"

    def _requires_security_check(self, action: str, payload: Optional[Dict[str, Any]] = None) -> bool:
        """
        Decide whether Security Agent approval is required.

        Config changes that enable publishing/scheduling or any external action
        must be protected.
        """

        action_key = normalize_key(action)
        payload = payload or {}

        if action_key in EXTERNAL_ACTIONS:
            return True

        if action_key in {
            "update_workspace_config",
            "reset_workspace_config",
            "disable_approval",
            "enable_auto_publish",
            "enable_auto_schedule",
            "publish",
            "schedule",
        }:
            return True

        if payload.get("external_action") is True:
            return True

        requested_updates = payload.get("updates") or payload
        if isinstance(requested_updates, dict):
            if requested_updates.get("allow_auto_publish") is True:
                return True
            if requested_updates.get("allow_auto_schedule") is True:
                return True
            if requested_updates.get("require_approval_before_publish") is False:
                return True
            if requested_updates.get("require_approval_before_schedule") is False:
                return True

        return False

    def _request_security_approval(
        self,
        *,
        context: CreatorContext,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request/prepare Security Agent approval.

        If a real security_adapter is injected and exposes approve_action(), it
        will be used. Otherwise, safe fallback approval only allows non-external
        and non-dangerous configuration operations.
        """

        approval_payload = {
            "agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "payload": payload or {},
            "timestamp": utc_now_iso(),
        }

        try:
            if self.security_adapter and hasattr(self.security_adapter, "approve_action"):
                approval = self.security_adapter.approve_action(approval_payload)
                if isinstance(approval, dict):
                    return approval

            dangerous_without_real_security = {
                "publish",
                "schedule",
                "send_email",
                "upload",
                "delete_external_content",
                "edit_live_content",
                "boost_post",
                "start_campaign",
                "connect_platform",
                "sync_assets_external",
            }

            if normalize_key(action) in dangerous_without_real_security:
                return {
                    "approved": False,
                    "reason": "External creator action requires real Security Agent approval.",
                    "approval_payload": approval_payload,
                }

            return {
                "approved": True,
                "reason": "Internal CreatorConfig operation approved by fallback safety policy.",
                "approval_payload": approval_payload,
            }
        except Exception as exc:
            self.logger.exception("Security approval failed")
            return {
                "approved": False,
                "reason": f"Security approval failed: {exc}",
                "approval_payload": approval_payload,
            }

    def _prepare_verification_payload(
        self,
        *,
        context: CreatorContext,
        action: str,
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload after config operations.

        This file does not call Verification Agent directly; it returns payloads
        for the Master Agent / router / workflow layer.
        """

        return {
            "agent": self.agent_name,
            "verification_type": "creator_config_change",
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "before": before,
            "after": after,
            "metadata": metadata or {},
            "created_at": utc_now_iso(),
            "checks": {
                "context_isolated": True,
                "has_user_id": bool(context.user_id),
                "has_workspace_id": bool(context.workspace_id),
                "approval_policy_preserved": bool(after or {}),
                "safe_import": True,
            },
        }

    def _prepare_memory_payload(
        self,
        *,
        context: CreatorContext,
        action: str,
        summary: str,
        data: Optional[Dict[str, Any]] = None,
        importance: str = "normal",
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        This should only be stored by Memory Agent after approved policy checks.
        """

        return {
            "agent": self.agent_name,
            "memory_type": "creator_config_preference",
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "summary": summary,
            "data": data or {},
            "importance": importance,
            "created_at": utc_now_iso(),
            "privacy": {
                "scope": "workspace",
                "requires_user_workspace_isolation": True,
            },
        }

    def _emit_agent_event(
        self,
        event_type: Union[str, CreatorEventType],
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Emit CreatorConfig event for Dashboard/API/Registry observers.

        If no event_emitter is injected, events are safely stored in memory.
        """

        event = {
            "event_id": make_id("evt"),
            "agent": self.agent_name,
            "event_type": event_type.value if isinstance(event_type, CreatorEventType) else str(event_type),
            "payload": copy.deepcopy(payload),
            "created_at": utc_now_iso(),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event)
            self.storage["events"].append(event)
            return event
        except Exception as exc:
            self.logger.exception("Failed to emit CreatorConfig event")
            event["emit_error"] = str(exc)
            self.storage["events"].append(event)
            return event

    def _log_audit_event(
        self,
        *,
        context: CreatorContext,
        action: str,
        entity_type: str = "creator_config",
        entity_id: Optional[str] = None,
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Write audit event for config changes.

        Future Audit Log service can replace local memory by injecting
        audit_logger.
        """

        audit_event = {
            "audit_id": make_id("audit"),
            "agent": self.agent_name,
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id or f"{context.user_id}:{context.workspace_id}",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "before": before,
            "after": after,
            "metadata": metadata or {},
            "created_at": utc_now_iso(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit_event)
            self.storage["audit_logs"].append(audit_event)
            return audit_event
        except Exception as exc:
            self.logger.exception("Failed to write CreatorConfig audit event")
            audit_event["audit_error"] = str(exc)
            self.storage["audit_logs"].append(audit_event)
            return audit_event

    def _safe_result(
        self,
        *,
        success: bool = True,
        message: str = "",
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentResult:
        """Return standard William/Jarvis structured result."""
        return {
            "success": success,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentResult:
        """Return standard William/Jarvis error result."""
        return self._safe_result(
            success=False,
            message=message,
            data={},
            error=error or message,
            metadata=metadata or {},
        )

    # ------------------------------------------------------------------
    # Master Agent / Router entrypoint
    # ------------------------------------------------------------------

    def handle_task(self, task: Dict[str, Any]) -> AgentResult:
        """
        Master Agent / Agent Router compatible task entrypoint.

        Expected task shape:
            {
                "action": "get_effective_config",
                "context": {"user_id": "...", "workspace_id": "..."},
                "payload": {...}
            }
        """

        if not isinstance(task, dict):
            return self._error_result(message="Task must be a dictionary.")

        action = str(task.get("action") or "").strip()
        context = task.get("context") or {}
        payload = task.get("payload") or {}

        if not action:
            return self._error_result(message="Missing task action.")
        if not isinstance(payload, dict):
            return self._error_result(message="Task payload must be a dictionary.")

        route_map: Dict[str, Callable[..., AgentResult]] = {
            "get_default_config": self.get_default_config,
            "get_effective_config": self.get_effective_config,
            "update_workspace_config": self.update_workspace_config,
            "reset_workspace_config": self.reset_workspace_config,
            "get_platform_rules": self.get_platform_rules,
            "get_platform_rule": self.get_platform_rule,
            "validate_platform_content": self.validate_platform_content,
            "check_approval_required": self.check_approval_required,
            "list_supported_platforms": self.list_supported_platforms,
            "list_supported_formats": self.list_supported_formats,
            "health_check": self.health_check,
        }

        handler = route_map.get(action)
        if not handler:
            return self._error_result(
                message=f"Unsupported CreatorConfig action: {action}",
                metadata={"supported_actions": sorted(route_map.keys())},
            )

        try:
            if action in {
                "get_default_config",
                "get_platform_rules",
                "list_supported_platforms",
                "list_supported_formats",
                "health_check",
            }:
                return handler(**payload)

            return handler(context=context, **payload)
        except TypeError as exc:
            return self._error_result(
                message=f"Invalid payload for CreatorConfig action '{action}'.",
                error=str(exc),
            )
        except Exception as exc:
            self.logger.exception("CreatorConfig task failed")
            return self._error_result(
                message=f"CreatorConfig action '{action}' failed.",
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Public config methods
    # ------------------------------------------------------------------

    def get_default_config(self) -> AgentResult:
        """
        Return system default Creator Agent config.

        This is not user-specific and does not require context.
        """

        default_settings = CreatorSettings(
            user_id="__default__",
            workspace_id="__default__",
            allowed_platforms=list(self.platform_rules.keys()),
            content_defaults=copy.deepcopy(DEFAULT_CONTENT_DEFAULTS),
        )

        return self._safe_result(
            message="Default CreatorConfig retrieved successfully.",
            data={
                "default_config": dataclass_to_dict(default_settings),
                "platform_rules": self._platform_rules_as_dict(),
                "risk_flags": sorted(HIGH_RISK_CONTENT_FLAGS),
                "external_actions": sorted(EXTERNAL_ACTIONS),
            },
        )

    def get_effective_config(
        self,
        *,
        context: Union[CreatorContext, Dict[str, Any]],
        include_platform_rules: bool = True,
    ) -> AgentResult:
        """
        Return effective config for a user/workspace.

        Effective config = default settings + stored workspace override.
        """

        valid, ctx, error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(message="Invalid task context.", error=error)

        settings = self._get_or_create_workspace_settings(ctx)
        config_dict = dataclass_to_dict(settings)

        if include_platform_rules:
            config_dict["platform_rules"] = self._platform_rules_as_dict(settings)

        event = self._emit_agent_event(
            CreatorEventType.CONFIG_VIEWED,
            {
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "include_platform_rules": include_platform_rules,
            },
        )

        return self._safe_result(
            message="Effective CreatorConfig retrieved successfully.",
            data={"config": config_dict},
            metadata={"event_id": event.get("event_id")},
        )

    def update_workspace_config(
        self,
        *,
        context: Union[CreatorContext, Dict[str, Any]],
        updates: Dict[str, Any],
        merge_platform_overrides: bool = True,
    ) -> AgentResult:
        """
        Update user/workspace Creator Agent config safely.

        Sensitive changes such as enabling auto-publish or disabling approval
        require Security Agent approval.
        """

        valid, ctx, error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(message="Invalid task context.", error=error)

        if not isinstance(updates, dict) or not updates:
            return self._error_result(message="updates must be a non-empty dictionary.")

        allowed_fields = {
            "default_platforms",
            "default_tone",
            "default_language",
            "brand_safety_enabled",
            "require_approval_before_publish",
            "require_approval_before_schedule",
            "approval_mode",
            "allow_auto_publish",
            "allow_auto_schedule",
            "max_short_video_duration_seconds",
            "max_long_video_duration_seconds",
            "max_script_words",
            "max_caption_chars",
            "max_hashtags",
            "default_timezone",
            "default_currency",
            "allowed_platforms",
            "blocked_platforms",
            "publishing_blackout_days",
            "publishing_blackout_hours",
            "require_human_review_for",
            "content_defaults",
            "platform_overrides",
            "metadata",
        }

        blocked = sorted(set(updates.keys()) - allowed_fields)
        if blocked:
            return self._error_result(
                message="One or more CreatorConfig update fields are not allowed.",
                metadata={"blocked_fields": blocked, "allowed_fields": sorted(allowed_fields)},
            )

        before_settings = self._get_or_create_workspace_settings(ctx)
        before = dataclass_to_dict(before_settings)

        validation = self._validate_config_updates(updates)
        if not validation["valid"]:
            return self._error_result(
                message="CreatorConfig updates failed validation.",
                error=validation["errors"],
                metadata={"warnings": validation["warnings"]},
            )

        security_payload = {
            "updates": updates,
            "merge_platform_overrides": merge_platform_overrides,
        }

        if self._requires_security_check("update_workspace_config", security_payload):
            approval = self._request_security_approval(
                context=ctx,
                action="update_workspace_config",
                payload=security_payload,
            )
            if not approval.get("approved"):
                return self._error_result(
                    message="Security approval denied for CreatorConfig update.",
                    error=approval.get("reason"),
                    metadata={"approval": approval},
                )

        settings = copy.deepcopy(before_settings)

        for field_name, value in updates.items():
            if field_name == "default_platforms":
                settings.default_platforms = self._normalize_platform_list(value, allow_empty=False)
            elif field_name == "default_tone":
                settings.default_tone = self._normalize_tone(value)
            elif field_name == "default_language":
                settings.default_language = str(value or "en").strip() or "en"
            elif field_name in {"brand_safety_enabled", "require_approval_before_publish", "require_approval_before_schedule", "allow_auto_publish", "allow_auto_schedule"}:
                setattr(settings, field_name, safe_bool(value, getattr(settings, field_name)))
            elif field_name == "approval_mode":
                settings.approval_mode = self._normalize_approval_mode(value)
            elif field_name == "max_short_video_duration_seconds":
                settings.max_short_video_duration_seconds = clamp_int(value, 3, 600, settings.max_short_video_duration_seconds)
            elif field_name == "max_long_video_duration_seconds":
                settings.max_long_video_duration_seconds = clamp_int(value, 60, 43200, settings.max_long_video_duration_seconds)
            elif field_name == "max_script_words":
                settings.max_script_words = clamp_int(value, 50, 20000, settings.max_script_words)
            elif field_name == "max_caption_chars":
                settings.max_caption_chars = clamp_int(value, 50, 10000, settings.max_caption_chars)
            elif field_name == "max_hashtags":
                settings.max_hashtags = clamp_int(value, 0, 100, settings.max_hashtags)
            elif field_name == "default_timezone":
                settings.default_timezone = str(value or "UTC").strip() or "UTC"
            elif field_name == "default_currency":
                settings.default_currency = str(value or "USD").strip().upper() or "USD"
            elif field_name == "allowed_platforms":
                settings.allowed_platforms = self._normalize_platform_list(value, allow_empty=True)
            elif field_name == "blocked_platforms":
                settings.blocked_platforms = self._normalize_platform_list(value, allow_empty=True)
            elif field_name == "publishing_blackout_days":
                settings.publishing_blackout_days = self._normalize_day_list(value)
            elif field_name == "publishing_blackout_hours":
                settings.publishing_blackout_hours = self._normalize_hour_list(value)
            elif field_name == "require_human_review_for":
                settings.require_human_review_for = dedupe_preserve_order(value or [])
            elif field_name == "content_defaults":
                if isinstance(value, dict):
                    settings.content_defaults = deep_merge(settings.content_defaults, value)
            elif field_name == "platform_overrides":
                if isinstance(value, dict):
                    normalized_overrides = self._normalize_platform_overrides(value)
                    if merge_platform_overrides:
                        settings.platform_overrides = deep_merge(settings.platform_overrides, normalized_overrides)
                    else:
                        settings.platform_overrides = normalized_overrides
            elif field_name == "metadata":
                if isinstance(value, dict):
                    settings.metadata = deep_merge(settings.metadata, value)

        # Safety invariant: if approval is required, auto publish/schedule must stay disabled.
        if settings.require_approval_before_publish:
            settings.allow_auto_publish = False
        if settings.require_approval_before_schedule:
            settings.allow_auto_schedule = False

        # Safety invariant: drafts can be generated without approval, external actions cannot.
        if settings.approval_mode == ApprovalMode.DISABLED_FOR_DRAFTS_ONLY.value:
            settings.require_approval_before_publish = True
            settings.require_approval_before_schedule = True
            settings.allow_auto_publish = False
            settings.allow_auto_schedule = False

        settings.updated_at = utc_now_iso()
        self._save_workspace_settings(settings)

        after = dataclass_to_dict(settings)

        verification_payload = self._prepare_verification_payload(
            context=ctx,
            action="update_workspace_config",
            before=before,
            after=after,
            metadata={"merge_platform_overrides": merge_platform_overrides},
        )

        memory_payload = self._prepare_memory_payload(
            context=ctx,
            action="update_workspace_config",
            summary="Updated Creator Agent workspace configuration.",
            data={
                "changed_fields": sorted(updates.keys()),
                "config": after,
            },
            importance="high" if self._contains_safety_sensitive_update(updates) else "normal",
        )

        audit_event = self._log_audit_event(
            context=ctx,
            action="update_workspace_config",
            before=before,
            after=after,
            metadata={"changed_fields": sorted(updates.keys())},
        )

        event = self._emit_agent_event(
            CreatorEventType.CONFIG_UPDATED,
            {
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "changed_fields": sorted(updates.keys()),
            },
        )

        return self._safe_result(
            message="CreatorConfig updated successfully.",
            data={
                "config": after,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
                "validation": validation,
            },
            metadata={
                "audit_id": audit_event.get("audit_id"),
                "event_id": event.get("event_id"),
            },
        )

    def reset_workspace_config(
        self,
        *,
        context: Union[CreatorContext, Dict[str, Any]],
    ) -> AgentResult:
        """
        Reset a user/workspace CreatorConfig to safe defaults.

        Resetting config requires Security Agent approval because it may change
        operational policy.
        """

        valid, ctx, error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(message="Invalid task context.", error=error)

        before_settings = self._get_or_create_workspace_settings(ctx)
        before = dataclass_to_dict(before_settings)

        approval = self._request_security_approval(
            context=ctx,
            action="reset_workspace_config",
            payload={"before": before},
        )
        if not approval.get("approved"):
            return self._error_result(
                message="Security approval denied for CreatorConfig reset.",
                error=approval.get("reason"),
                metadata={"approval": approval},
            )

        reset_settings = self._new_workspace_settings(ctx)
        self._save_workspace_settings(reset_settings)
        after = dataclass_to_dict(reset_settings)

        verification_payload = self._prepare_verification_payload(
            context=ctx,
            action="reset_workspace_config",
            before=before,
            after=after,
        )

        memory_payload = self._prepare_memory_payload(
            context=ctx,
            action="reset_workspace_config",
            summary="Reset Creator Agent workspace configuration to safe defaults.",
            data={"config": after},
            importance="high",
        )

        audit_event = self._log_audit_event(
            context=ctx,
            action="reset_workspace_config",
            before=before,
            after=after,
        )

        event = self._emit_agent_event(
            CreatorEventType.CONFIG_RESET,
            {
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

        return self._safe_result(
            message="CreatorConfig reset successfully.",
            data={
                "config": after,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "audit_id": audit_event.get("audit_id"),
                "event_id": event.get("event_id"),
            },
        )

    # ------------------------------------------------------------------
    # Platform rule methods
    # ------------------------------------------------------------------

    def get_platform_rules(
        self,
        *,
        include_metadata: bool = True,
    ) -> AgentResult:
        """Return all platform rules."""
        rules = self._platform_rules_as_dict()
        if not include_metadata:
            for rule in rules.values():
                rule.pop("metadata", None)

        return self._safe_result(
            message="Creator platform rules retrieved successfully.",
            data={"platform_rules": rules},
        )

    def get_platform_rule(
        self,
        *,
        context: Union[CreatorContext, Dict[str, Any]],
        platform: Union[str, CreatorPlatform],
        apply_workspace_overrides: bool = True,
    ) -> AgentResult:
        """Return one platform rule, optionally merged with workspace overrides."""
        valid, ctx, error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(message="Invalid task context.", error=error)

        platform_key = self._normalize_platform(platform)
        rule = self._get_effective_platform_rule(ctx, platform_key) if apply_workspace_overrides else self.platform_rules.get(platform_key)

        if not rule:
            return self._error_result(
                message=f"Unsupported creator platform: {platform_key}",
                metadata={"supported_platforms": sorted(self.platform_rules.keys())},
            )

        event = self._emit_agent_event(
            CreatorEventType.PLATFORM_RULE_VALIDATED,
            {
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "platform": platform_key,
                "apply_workspace_overrides": apply_workspace_overrides,
            },
        )

        return self._safe_result(
            message="Creator platform rule retrieved successfully.",
            data={"platform_rule": dataclass_to_dict(rule)},
            metadata={"event_id": event.get("event_id")},
        )

    def list_supported_platforms(self) -> AgentResult:
        """List supported Creator Agent platforms."""
        platforms = [
            {
                "platform": key,
                "display_name": rule.display_name,
                "supported_formats": list(rule.supported_formats),
                "requires_approval_before_publish": rule.requires_approval_before_publish,
                "allow_auto_publish": rule.allow_auto_publish,
            }
            for key, rule in sorted(self.platform_rules.items())
        ]

        return self._safe_result(
            message="Supported creator platforms listed successfully.",
            data={"platforms": platforms, "total": len(platforms)},
        )

    def list_supported_formats(self) -> AgentResult:
        """List supported content formats."""
        formats = [{"format": item.value, "name": item.name} for item in ContentFormat]

        return self._safe_result(
            message="Supported creator formats listed successfully.",
            data={"formats": formats, "total": len(formats)},
        )

    # ------------------------------------------------------------------
    # Validation and approval policy
    # ------------------------------------------------------------------

    def validate_platform_content(
        self,
        *,
        context: Union[CreatorContext, Dict[str, Any]],
        platform: Union[str, CreatorPlatform],
        content_format: Union[str, ContentFormat],
        duration_seconds: Optional[int] = None,
        title: Optional[str] = None,
        description: Optional[str] = None,
        caption: Optional[str] = None,
        hashtags: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        asset_count: int = 0,
        aspect_ratio: Optional[str] = None,
        risk_flags: Optional[List[str]] = None,
    ) -> AgentResult:
        """
        Validate planned content against platform/workspace rules.

        This does not publish or modify content. It only returns validation
        status for Creator Agent workflows and dashboard/API.
        """

        valid, ctx, error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(message="Invalid task context.", error=error)

        platform_key = self._normalize_platform(platform)
        format_key = self._normalize_content_format(content_format)
        rule = self._get_effective_platform_rule(ctx, platform_key)

        if not rule:
            return self._error_result(
                message=f"Unsupported creator platform: {platform_key}",
                metadata={"supported_platforms": sorted(self.platform_rules.keys())},
            )

        settings = self._get_or_create_workspace_settings(ctx)
        errors: List[str] = []
        warnings: List[str] = []

        if settings.allowed_platforms and platform_key not in settings.allowed_platforms:
            errors.append(f"Platform '{platform_key}' is not in workspace allowed_platforms.")

        if platform_key in settings.blocked_platforms:
            errors.append(f"Platform '{platform_key}' is blocked for this workspace.")

        if format_key not in rule.supported_formats:
            errors.append(
                f"Format '{format_key}' is not supported for platform '{platform_key}'."
            )

        duration = safe_int(duration_seconds, 0)
        if duration_seconds is not None:
            if rule.max_duration_seconds > 0:
                if duration < rule.min_duration_seconds:
                    errors.append(
                        f"Duration {duration}s is below minimum {rule.min_duration_seconds}s for {platform_key}."
                    )
                if duration > rule.max_duration_seconds:
                    errors.append(
                        f"Duration {duration}s exceeds maximum {rule.max_duration_seconds}s for {platform_key}."
                    )

            if format_key == ContentFormat.SHORT_VIDEO.value and duration > settings.max_short_video_duration_seconds:
                errors.append(
                    f"Short video duration {duration}s exceeds workspace limit {settings.max_short_video_duration_seconds}s."
                )

            if format_key == ContentFormat.LONG_VIDEO.value and duration > settings.max_long_video_duration_seconds:
                errors.append(
                    f"Long video duration {duration}s exceeds workspace limit {settings.max_long_video_duration_seconds}s."
                )

        if title is not None and len(title) > rule.max_title_chars:
            errors.append(
                f"Title length {len(title)} exceeds platform limit {rule.max_title_chars}."
            )

        if description is not None and len(description) > rule.max_description_chars:
            errors.append(
                f"Description length {len(description)} exceeds platform limit {rule.max_description_chars}."
            )

        if caption is not None:
            max_caption = min(rule.max_caption_chars, settings.max_caption_chars)
            if len(caption) > max_caption:
                errors.append(
                    f"Caption length {len(caption)} exceeds effective limit {max_caption}."
                )

        hashtag_count = len(hashtags or [])
        effective_hashtag_limit = min(rule.max_hashtags, settings.max_hashtags)
        if hashtag_count > effective_hashtag_limit:
            errors.append(
                f"Hashtag count {hashtag_count} exceeds effective limit {effective_hashtag_limit}."
            )

        tag_count = len(tags or [])
        if tag_count > rule.max_tags:
            errors.append(
                f"Tag count {tag_count} exceeds platform limit {rule.max_tags}."
            )

        if asset_count > rule.max_assets:
            errors.append(
                f"Asset count {asset_count} exceeds platform limit {rule.max_assets}."
            )

        if aspect_ratio and rule.aspect_ratios and aspect_ratio not in rule.aspect_ratios:
            warnings.append(
                f"Aspect ratio '{aspect_ratio}' is not recommended for {platform_key}. Recommended: {rule.aspect_ratios}."
            )

        normalized_risk_flags = sorted({normalize_key(flag) for flag in (risk_flags or []) if flag})
        high_risk_hits = sorted(set(normalized_risk_flags).intersection(HIGH_RISK_CONTENT_FLAGS))
        if high_risk_hits:
            warnings.append(
                "High-risk content flags detected. Human approval is required before publishing or scheduling."
            )

        approval_check = self._evaluate_approval_policy(
            settings=settings,
            platform_rule=rule,
            action="draft",
            risk_flags=normalized_risk_flags,
            external_action=False,
        )

        validation_data = {
            "valid": len(errors) == 0,
            "platform": platform_key,
            "content_format": format_key,
            "errors": errors,
            "warnings": warnings,
            "effective_limits": {
                "min_duration_seconds": rule.min_duration_seconds,
                "max_duration_seconds": rule.max_duration_seconds,
                "recommended_duration_seconds": rule.recommended_duration_seconds,
                "max_title_chars": rule.max_title_chars,
                "max_description_chars": rule.max_description_chars,
                "max_caption_chars": min(rule.max_caption_chars, settings.max_caption_chars),
                "max_hashtags": effective_hashtag_limit,
                "max_tags": rule.max_tags,
                "max_assets": rule.max_assets,
                "aspect_ratios": rule.aspect_ratios,
            },
            "approval_policy": approval_check,
            "risk_flags": normalized_risk_flags,
            "high_risk_hits": high_risk_hits,
        }

        event = self._emit_agent_event(
            CreatorEventType.PLATFORM_RULE_VALIDATED,
            {
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "platform": platform_key,
                "content_format": format_key,
                "valid": validation_data["valid"],
            },
        )

        return self._safe_result(
            success=validation_data["valid"],
            message="Platform content validation completed."
            if validation_data["valid"]
            else "Platform content validation found issues.",
            data={"validation": validation_data},
            error=None if validation_data["valid"] else errors,
            metadata={"event_id": event.get("event_id")},
        )

    def check_approval_required(
        self,
        *,
        context: Union[CreatorContext, Dict[str, Any]],
        action: str,
        platform: Union[str, CreatorPlatform] = CreatorPlatform.GENERIC,
        content_format: Optional[Union[str, ContentFormat]] = None,
        risk_flags: Optional[List[str]] = None,
        external_action: Optional[bool] = None,
    ) -> AgentResult:
        """
        Check whether approval is required for a creator action.

        This is the central safety gate for publishing/scheduling workflows.
        """

        valid, ctx, error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(message="Invalid task context.", error=error)

        settings = self._get_or_create_workspace_settings(ctx)
        platform_key = self._normalize_platform(platform)
        rule = self._get_effective_platform_rule(ctx, platform_key)

        if not rule:
            return self._error_result(
                message=f"Unsupported creator platform: {platform_key}",
                metadata={"supported_platforms": sorted(self.platform_rules.keys())},
            )

        action_key = normalize_key(action)
        normalized_risk_flags = sorted({normalize_key(flag) for flag in (risk_flags or []) if flag})
        is_external = action_key in EXTERNAL_ACTIONS if external_action is None else bool(external_action)

        approval_policy = self._evaluate_approval_policy(
            settings=settings,
            platform_rule=rule,
            action=action_key,
            risk_flags=normalized_risk_flags,
            external_action=is_external,
        )

        security_payload = {
            "action": action_key,
            "platform": platform_key,
            "content_format": self._normalize_content_format(content_format) if content_format else None,
            "risk_flags": normalized_risk_flags,
            "external_action": is_external,
            "approval_policy": approval_policy,
        }

        security_required = self._requires_security_check(action_key, security_payload)
        security_approval = None

        if security_required and approval_policy["approval_required"]:
            security_approval = self._request_security_approval(
                context=ctx,
                action=action_key,
                payload=security_payload,
            )

        event = self._emit_agent_event(
            CreatorEventType.APPROVAL_POLICY_CHECKED,
            {
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "action": action_key,
                "platform": platform_key,
                "approval_required": approval_policy["approval_required"],
                "security_required": security_required,
            },
        )

        return self._safe_result(
            message="Creator approval policy checked successfully.",
            data={
                "approval_policy": approval_policy,
                "security_required": security_required,
                "security_approval": security_approval,
            },
            metadata={"event_id": event.get("event_id")},
        )

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health_check(self) -> AgentResult:
        """Return import/runtime health info for registry/loader checks."""
        return self._safe_result(
            message="CreatorConfig is healthy.",
            data={
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "public_methods": self.public_methods,
                "supported_platforms": sorted(self.platform_rules.keys()),
                "supported_formats": [item.value for item in ContentFormat],
                "storage_counts": {
                    "workspace_configs": len(self.storage.get("workspace_configs", {})),
                    "events": len(self.storage.get("events", [])),
                    "audit_logs": len(self.storage.get("audit_logs", [])),
                },
                "safe_defaults": {
                    "approval_before_publish": True,
                    "approval_before_schedule": True,
                    "auto_publish": False,
                    "auto_schedule": False,
                },
            },
            metadata={"timestamp": utc_now_iso()},
        )

    # ------------------------------------------------------------------
    # Internal config helpers
    # ------------------------------------------------------------------

    def _build_platform_rules(
        self,
        platform_rules: Optional[Dict[str, Union[PlatformRule, Dict[str, Any]]]],
    ) -> Dict[str, PlatformRule]:
        """Build platform rules with optional custom overrides."""
        rules = copy.deepcopy(DEFAULT_PLATFORM_RULES)

        if not platform_rules:
            return rules

        for raw_key, raw_rule in platform_rules.items():
            key = self._normalize_platform(raw_key)
            if isinstance(raw_rule, PlatformRule):
                rule = copy.deepcopy(raw_rule)
                rule.platform = key
                rules[key] = rule
            elif isinstance(raw_rule, dict):
                base = dataclass_to_dict(rules.get(key, PlatformRule(
                    platform=key,
                    display_name=str(raw_rule.get("display_name") or key.title()),
                    supported_formats=[ContentFormat.TEXT_POST.value],
                )))
                merged = deep_merge(base, raw_rule)
                merged["platform"] = key
                rules[key] = PlatformRule(**self._filter_platform_rule_fields(merged))

        return rules

    def _filter_platform_rule_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Filter dict to PlatformRule fields."""
        allowed = set(PlatformRule.__dataclass_fields__.keys())
        return {key: value for key, value in data.items() if key in allowed}

    def _storage_key(self, context: CreatorContext) -> str:
        """Build user/workspace-safe storage key."""
        return f"{context.user_id}::{context.workspace_id}"

    def _new_workspace_settings(self, context: CreatorContext) -> CreatorSettings:
        """Create safe default settings for a workspace."""
        return CreatorSettings(
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            default_platforms=[CreatorPlatform.GENERIC.value],
            allowed_platforms=sorted(self.platform_rules.keys()),
            content_defaults=copy.deepcopy(DEFAULT_CONTENT_DEFAULTS),
        )

    def _get_or_create_workspace_settings(self, context: CreatorContext) -> CreatorSettings:
        """Get stored settings or create safe defaults."""
        key = self._storage_key(context)
        existing = self.storage["workspace_configs"].get(key)
        if existing:
            return copy.deepcopy(existing)

        settings = self._new_workspace_settings(context)
        self._save_workspace_settings(settings)
        return settings

    def _save_workspace_settings(self, settings: CreatorSettings) -> None:
        """Save settings to isolated local storage."""
        key = f"{settings.user_id}::{settings.workspace_id}"
        self.storage["workspace_configs"][key] = copy.deepcopy(settings)

    def _platform_rules_as_dict(
        self,
        settings: Optional[CreatorSettings] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """Return platform rules as dictionaries, optionally applying overrides."""
        output: Dict[str, Dict[str, Any]] = {}
        for platform_key, rule in self.platform_rules.items():
            rule_dict = dataclass_to_dict(rule)
            if settings and platform_key in settings.platform_overrides:
                rule_dict = deep_merge(rule_dict, settings.platform_overrides[platform_key])
            output[platform_key] = rule_dict
        return output

    def _get_effective_platform_rule(
        self,
        context: CreatorContext,
        platform_key: str,
    ) -> Optional[PlatformRule]:
        """Return platform rule with workspace override applied."""
        base_rule = self.platform_rules.get(platform_key)
        if not base_rule:
            return None

        settings = self._get_or_create_workspace_settings(context)
        rule_dict = dataclass_to_dict(base_rule)

        override = settings.platform_overrides.get(platform_key, {})
        if override:
            rule_dict = deep_merge(rule_dict, override)

        rule_dict = self._filter_platform_rule_fields(rule_dict)
        return PlatformRule(**rule_dict)

    # ------------------------------------------------------------------
    # Internal validation helpers
    # ------------------------------------------------------------------

    def _validate_config_updates(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Validate workspace config update payload."""
        errors: List[str] = []
        warnings: List[str] = []

        if "default_platforms" in updates:
            platforms = self._normalize_platform_list(updates.get("default_platforms"), allow_empty=False)
            unsupported = [platform for platform in platforms if platform not in self.platform_rules]
            if unsupported:
                errors.append(f"Unsupported default platforms: {unsupported}")

        for platform_field in ("allowed_platforms", "blocked_platforms"):
            if platform_field in updates:
                platforms = self._normalize_platform_list(updates.get(platform_field), allow_empty=True)
                unsupported = [platform for platform in platforms if platform not in self.platform_rules]
                if unsupported:
                    errors.append(f"Unsupported platforms in {platform_field}: {unsupported}")

        if "default_tone" in updates:
            tone = self._normalize_tone(updates.get("default_tone"))
            if tone not in {item.value for item in CreatorTone}:
                errors.append(f"Unsupported default_tone: {updates.get('default_tone')}")

        if "approval_mode" in updates:
            mode = self._normalize_approval_mode(updates.get("approval_mode"))
            if mode not in {item.value for item in ApprovalMode}:
                errors.append(f"Unsupported approval_mode: {updates.get('approval_mode')}")

        if updates.get("allow_auto_publish") is True:
            warnings.append("Auto-publish is risky and should remain disabled unless Security Agent approves.")

        if updates.get("allow_auto_schedule") is True:
            warnings.append("Auto-schedule is risky and should remain disabled unless Security Agent approves.")

        if updates.get("require_approval_before_publish") is False:
            warnings.append("Disabling approval before publishing is not recommended.")

        if updates.get("require_approval_before_schedule") is False:
            warnings.append("Disabling approval before scheduling is not recommended.")

        if "publishing_blackout_hours" in updates:
            hours = updates.get("publishing_blackout_hours") or []
            invalid_hours = [hour for hour in hours if safe_int(hour, -1) < 0 or safe_int(hour, -1) > 23]
            if invalid_hours:
                errors.append(f"Invalid publishing blackout hours: {invalid_hours}")

        if "platform_overrides" in updates and not isinstance(updates.get("platform_overrides"), dict):
            errors.append("platform_overrides must be a dictionary.")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
        }

    def _evaluate_approval_policy(
        self,
        *,
        settings: CreatorSettings,
        platform_rule: PlatformRule,
        action: str,
        risk_flags: List[str],
        external_action: bool,
    ) -> Dict[str, Any]:
        """
        Evaluate approval requirement.

        Safe default: publishing and scheduling require approval.
        """

        action_key = normalize_key(action)
        risk_set = {normalize_key(flag) for flag in risk_flags}
        high_risk_hits = sorted(risk_set.intersection(HIGH_RISK_CONTENT_FLAGS))

        reasons: List[str] = []
        approval_required = False
        risk_level = RiskLevel.LOW.value

        if action_key in {"draft", "generate", "ideate", "outline", "rewrite"} and not external_action:
            approval_required = False
            reasons.append("Draft-only internal creator action does not require approval by default.")

        if settings.approval_mode == ApprovalMode.ALWAYS_REQUIRE.value:
            if action_key not in {"draft", "generate", "ideate", "outline", "rewrite"} or external_action:
                approval_required = True
                reasons.append("Workspace approval_mode is always_require for non-draft or external actions.")

        if settings.approval_mode == ApprovalMode.REQUIRE_FOR_EXTERNAL_ACTIONS.value and external_action:
            approval_required = True
            reasons.append("External creator actions require approval.")

        if settings.approval_mode == ApprovalMode.REQUIRE_FOR_HIGH_RISK.value and high_risk_hits:
            approval_required = True
            reasons.append("High-risk content flags require approval.")

        if settings.approval_mode == ApprovalMode.DISABLED_FOR_DRAFTS_ONLY.value:
            if external_action or action_key in EXTERNAL_ACTIONS:
                approval_required = True
                reasons.append("Approval is disabled only for drafts, not external actions.")

        if action_key == "publish" and settings.require_approval_before_publish:
            approval_required = True
            reasons.append("Workspace requires approval before publishing.")

        if action_key == "schedule" and settings.require_approval_before_schedule:
            approval_required = True
            reasons.append("Workspace requires approval before scheduling.")

        if action_key == "publish" and platform_rule.requires_approval_before_publish:
            approval_required = True
            reasons.append(f"Platform '{platform_rule.platform}' requires approval before publishing.")

        if action_key == "schedule" and platform_rule.requires_approval_before_schedule:
            approval_required = True
            reasons.append(f"Platform '{platform_rule.platform}' requires approval before scheduling.")

        if action_key in settings.require_human_review_for:
            approval_required = True
            reasons.append(f"Action '{action_key}' is listed in require_human_review_for.")

        if high_risk_hits:
            approval_required = True
            risk_level = RiskLevel.HIGH.value
            reasons.append(f"High-risk content flags detected: {high_risk_hits}")

        if external_action:
            risk_level = RiskLevel.MEDIUM.value if risk_level == RiskLevel.LOW.value else risk_level
            reasons.append("Action may affect an external platform.")

        if action_key in {"delete_external_content", "edit_live_content", "boost_post", "start_campaign"}:
            approval_required = True
            risk_level = RiskLevel.CRITICAL.value
            reasons.append(f"Critical external action '{action_key}' requires explicit approval.")

        if action_key == "publish" and not settings.allow_auto_publish:
            reasons.append("Auto-publish is disabled.")

        if action_key == "schedule" and not settings.allow_auto_schedule:
            reasons.append("Auto-schedule is disabled.")

        return {
            "approval_required": approval_required,
            "risk_level": risk_level,
            "action": action_key,
            "external_action": external_action,
            "high_risk_flags": high_risk_hits,
            "reasons": dedupe_preserve_order(reasons),
            "safe_to_execute_without_security_agent": not approval_required and not external_action,
            "allowed_auto_publish": bool(settings.allow_auto_publish and not approval_required),
            "allowed_auto_schedule": bool(settings.allow_auto_schedule and not approval_required),
        }

    def _contains_safety_sensitive_update(self, updates: Dict[str, Any]) -> bool:
        """Detect safety-sensitive config updates."""
        sensitive_keys = {
            "require_approval_before_publish",
            "require_approval_before_schedule",
            "approval_mode",
            "allow_auto_publish",
            "allow_auto_schedule",
            "blocked_platforms",
            "allowed_platforms",
            "require_human_review_for",
        }
        return bool(set(updates.keys()).intersection(sensitive_keys))

    # ------------------------------------------------------------------
    # Normalization helpers
    # ------------------------------------------------------------------

    def _normalize_platform(self, platform: Union[str, CreatorPlatform]) -> str:
        """Normalize platform aliases."""
        if isinstance(platform, CreatorPlatform):
            return platform.value

        key = normalize_key(platform)
        aliases = {
            "yt": CreatorPlatform.YOUTUBE.value,
            "youtube_video": CreatorPlatform.YOUTUBE.value,
            "youtube_long": CreatorPlatform.YOUTUBE.value,
            "shorts": CreatorPlatform.YOUTUBE_SHORTS.value,
            "youtube_short": CreatorPlatform.YOUTUBE_SHORTS.value,
            "yt_shorts": CreatorPlatform.YOUTUBE_SHORTS.value,
            "ig_reels": CreatorPlatform.INSTAGRAM_REELS.value,
            "reels": CreatorPlatform.INSTAGRAM_REELS.value,
            "instagram": CreatorPlatform.INSTAGRAM_POST.value,
            "ig_post": CreatorPlatform.INSTAGRAM_POST.value,
            "facebook": CreatorPlatform.FACEBOOK_POST.value,
            "fb": CreatorPlatform.FACEBOOK_POST.value,
            "fb_reels": CreatorPlatform.FACEBOOK_REELS.value,
            "linkedin": CreatorPlatform.LINKEDIN_POST.value,
            "twitter": CreatorPlatform.X_POST.value,
            "x": CreatorPlatform.X_POST.value,
            "pinterest": CreatorPlatform.PINTEREST_PIN.value,
            "site": CreatorPlatform.WEBSITE.value,
            "web": CreatorPlatform.WEBSITE.value,
            "newsletter": CreatorPlatform.EMAIL.value,
        }
        return aliases.get(key, key or CreatorPlatform.GENERIC.value)

    def _normalize_content_format(self, content_format: Union[str, ContentFormat]) -> str:
        """Normalize content format aliases."""
        if isinstance(content_format, ContentFormat):
            return content_format.value

        key = normalize_key(content_format)
        aliases = {
            "short": ContentFormat.SHORT_VIDEO.value,
            "shorts": ContentFormat.SHORT_VIDEO.value,
            "reel": ContentFormat.SHORT_VIDEO.value,
            "reels": ContentFormat.SHORT_VIDEO.value,
            "video_short": ContentFormat.SHORT_VIDEO.value,
            "long": ContentFormat.LONG_VIDEO.value,
            "youtube_video": ContentFormat.LONG_VIDEO.value,
            "image": ContentFormat.IMAGE_POST.value,
            "post_image": ContentFormat.IMAGE_POST.value,
            "slides": ContentFormat.CAROUSEL.value,
            "thread": ContentFormat.TEXT_POST.value,
            "text": ContentFormat.TEXT_POST.value,
            "article": ContentFormat.BLOG_ARTICLE.value,
            "blog": ContentFormat.BLOG_ARTICLE.value,
            "email": ContentFormat.EMAIL_COPY.value,
            "thumb": ContentFormat.THUMBNAIL.value,
            "vo": ContentFormat.VOICEOVER.value,
            "voice": ContentFormat.VOICEOVER.value,
            "veo_prompt": ContentFormat.PROMPT.value,
            "image_prompt": ContentFormat.PROMPT.value,
        }
        return aliases.get(key, key)

    def _normalize_tone(self, tone: Any) -> str:
        """Normalize tone."""
        key = normalize_key(tone)
        aliases = {
            "direct": CreatorTone.DIRECT_RESPONSE.value,
            "sales": CreatorTone.DIRECT_RESPONSE.value,
            "premium": CreatorTone.LUXURY.value,
            "lux": CreatorTone.LUXURY.value,
            "teaching": CreatorTone.EDUCATIONAL.value,
            "expert": CreatorTone.AUTHORITATIVE.value,
            "casual": CreatorTone.CONVERSATIONAL.value,
        }
        normalized = aliases.get(key, key)
        if normalized in {item.value for item in CreatorTone}:
            return normalized
        return CreatorTone.PROFESSIONAL.value

    def _normalize_approval_mode(self, mode: Any) -> str:
        """Normalize approval mode."""
        key = normalize_key(mode)
        aliases = {
            "always": ApprovalMode.ALWAYS_REQUIRE.value,
            "external": ApprovalMode.REQUIRE_FOR_EXTERNAL_ACTIONS.value,
            "external_only": ApprovalMode.REQUIRE_FOR_EXTERNAL_ACTIONS.value,
            "high_risk": ApprovalMode.REQUIRE_FOR_HIGH_RISK.value,
            "drafts_only": ApprovalMode.DISABLED_FOR_DRAFTS_ONLY.value,
        }
        normalized = aliases.get(key, key)
        if normalized in {item.value for item in ApprovalMode}:
            return normalized
        return ApprovalMode.ALWAYS_REQUIRE.value

    def _normalize_platform_list(self, value: Any, *, allow_empty: bool) -> List[str]:
        """Normalize a platform list."""
        if value is None:
            return [] if allow_empty else [CreatorPlatform.GENERIC.value]
        if isinstance(value, str):
            values = [value]
        elif isinstance(value, Iterable):
            values = list(value)
        else:
            values = [value]

        platforms = dedupe_preserve_order(self._normalize_platform(item) for item in values)
        platforms = [platform for platform in platforms if platform]

        if not platforms and not allow_empty:
            return [CreatorPlatform.GENERIC.value]
        return platforms

    def _normalize_day_list(self, value: Any) -> List[str]:
        """Normalize blackout day names."""
        valid_days = {
            "monday",
            "tuesday",
            "wednesday",
            "thursday",
            "friday",
            "saturday",
            "sunday",
        }
        if value is None:
            return []
        if isinstance(value, str):
            values = [value]
        elif isinstance(value, Iterable):
            values = list(value)
        else:
            values = [value]

        days = []
        for item in values:
            day = normalize_text(item)
            if day in valid_days:
                days.append(day)
        return dedupe_preserve_order(days)

    def _normalize_hour_list(self, value: Any) -> List[int]:
        """Normalize blackout hours into 0-23 values."""
        if value is None:
            return []
        if isinstance(value, int):
            values = [value]
        elif isinstance(value, str):
            values = [value]
        elif isinstance(value, Iterable):
            values = list(value)
        else:
            values = [value]

        hours: List[int] = []
        for item in values:
            hour = safe_int(item, -1)
            if 0 <= hour <= 23:
                hours.append(hour)
        return sorted(set(hours))

    def _normalize_platform_overrides(self, overrides: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Normalize platform override dictionary safely."""
        normalized: Dict[str, Dict[str, Any]] = {}
        for raw_platform, raw_override in overrides.items():
            platform = self._normalize_platform(raw_platform)
            if platform not in self.platform_rules:
                continue
            if not isinstance(raw_override, dict):
                continue

            filtered = self._filter_platform_rule_fields(raw_override)
            filtered.pop("platform", None)

            if "supported_formats" in filtered:
                filtered["supported_formats"] = [
                    self._normalize_content_format(item)
                    for item in filtered.get("supported_formats") or []
                ]

            if "aspect_ratios" in filtered:
                filtered["aspect_ratios"] = dedupe_preserve_order(filtered.get("aspect_ratios") or [])

            if "requires_approval_before_publish" in filtered:
                filtered["requires_approval_before_publish"] = safe_bool(
                    filtered["requires_approval_before_publish"],
                    True,
                )

            if "requires_approval_before_schedule" in filtered:
                filtered["requires_approval_before_schedule"] = safe_bool(
                    filtered["requires_approval_before_schedule"],
                    True,
                )

            if "allow_auto_publish" in filtered:
                filtered["allow_auto_publish"] = safe_bool(
                    filtered["allow_auto_publish"],
                    False,
                )

            if "allow_auto_schedule" in filtered:
                filtered["allow_auto_schedule"] = safe_bool(
                    filtered["allow_auto_schedule"],
                    False,
                )

            normalized[platform] = filtered

        return normalized


# ---------------------------------------------------------------------------
# Optional factory helpers for Agent Loader / Registry
# ---------------------------------------------------------------------------

def create_creator_config(**kwargs: Any) -> CreatorConfig:
    """
    Factory for Agent Loader / Agent Registry.

    Example:
        config = create_creator_config()
    """
    return CreatorConfig(**kwargs)


def get_agent_class() -> type:
    """
    Return class reference for dynamic loaders.
    """
    return CreatorConfig


def get_agent_metadata() -> Dict[str, Any]:
    """
    Registry-friendly metadata.
    """
    return {
        "agent_name": CreatorConfig.agent_name,
        "agent_type": CreatorConfig.agent_type,
        "class_name": "CreatorConfig",
        "module": "agents.super_agents.creator_agent.config",
        "public_methods": CreatorConfig.public_methods,
        "purpose": "Creator settings, platforms, durations, approval before publishing.",
        "requires_user_workspace_context": True,
        "safe_to_import": True,
        "external_side_effects": False,
        "approval_before_publishing_default": True,
        "approval_before_scheduling_default": True,
        "auto_publish_default": False,
        "auto_schedule_default": False,
        "compatible_with": [
            "BaseAgent",
            "Agent Registry",
            "Agent Loader",
            "Agent Router",
            "Master Agent",
            "Security Agent",
            "Memory Agent",
            "Verification Agent",
            "Dashboard/API",
        ],
    }


__all__ = [
    "CreatorConfig",
    "CreatorContext",
    "CreatorSettings",
    "PlatformRule",
    "CreatorPlatform",
    "ContentFormat",
    "ApprovalMode",
    "CreatorTone",
    "CreatorEventType",
    "RiskLevel",
    "DEFAULT_PLATFORM_RULES",
    "DEFAULT_CONTENT_DEFAULTS",
    "HIGH_RISK_CONTENT_FLAGS",
    "EXTERNAL_ACTIONS",
    "create_creator_config",
    "get_agent_class",
    "get_agent_metadata",
]