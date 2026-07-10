"""
agents/super_agents/creator_agent/caption_generator.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Creator Agent - Caption Generator

Purpose:
    Captions, subtitles, social post captions, hooks.

This module is production-oriented, import-safe, SaaS-isolated, and compatible
with the William/Jarvis multi-agent architecture.

Core responsibilities:
    - Generate social media captions
    - Generate short-form hooks
    - Generate subtitle segments from transcript text
    - Export subtitle formats such as SRT and WebVTT
    - Generate hashtags and CTA lines
    - Produce platform-specific caption packages
    - Prepare Memory Agent payloads
    - Prepare Verification Agent payloads
    - Emit audit/dashboard events
    - Support Master Agent routing through handle_task()

Safety and SaaS isolation:
    Every user-specific operation requires user_id and workspace_id.
    This file never mixes data between users/workspaces and does not execute
    real external publishing, messaging, file deletion, financial, call,
    browser, or destructive actions.

Import safety:
    If BaseAgent or future William modules are not available yet, fallback
    stubs keep this file importable and testable.
"""

from __future__ import annotations

import html
import logging
import math
import re
import textwrap
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


# =============================================================================
# Safe optional imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - safe fallback for early development
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        The real William/Jarvis BaseAgent can provide richer lifecycle,
        permissions, tracing, registry, and routing behavior. This fallback
        ensures this file can be imported before the full project is assembled.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.metadata = kwargs.get("metadata", {})

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            return None


# =============================================================================
# Constants
# =============================================================================

CAPTION_GENERATOR_VERSION = "1.0.0"

DEFAULT_LANGUAGE = "en"
DEFAULT_TONE = "professional"
DEFAULT_PLATFORM = "general"
DEFAULT_BRAND_NAME = "Digital Promotix"

MAX_CAPTION_LENGTHS = {
    "instagram": 2200,
    "facebook": 63206,
    "linkedin": 3000,
    "tiktok": 2200,
    "youtube": 5000,
    "youtube_shorts": 1000,
    "x": 280,
    "twitter": 280,
    "threads": 500,
    "pinterest": 500,
    "general": 1500,
}

PLATFORM_HASHTAG_LIMITS = {
    "instagram": 20,
    "facebook": 8,
    "linkedin": 6,
    "tiktok": 8,
    "youtube": 12,
    "youtube_shorts": 8,
    "x": 3,
    "twitter": 3,
    "threads": 5,
    "pinterest": 10,
    "general": 8,
}

DEFAULT_HOOK_TEMPLATES = [
    "Most people miss this simple truth:",
    "Here is what nobody tells you about {topic}:",
    "Stop scrolling if you care about {topic}.",
    "This one change can improve your {topic}.",
    "Before you spend more money on {topic}, watch this.",
    "You are probably doing {topic} the hard way.",
    "The fastest way to understand {topic} is this:",
    "If you want better results from {topic}, start here.",
]

DEFAULT_CTA_TEMPLATES = {
    "soft": [
        "Save this for later.",
        "Share this with someone who needs it.",
        "Follow for more practical tips.",
        "Comment your biggest question below.",
    ],
    "business": [
        "Need help with this? Let’s talk.",
        "Message us to plan your next step.",
        "Book a quick strategy call to discuss your goals.",
        "Want this done for your business? Send us a message.",
    ],
    "educational": [
        "Save this checklist and use it on your next project.",
        "Follow for more simple breakdowns.",
        "Comment “guide” if you want a deeper version.",
        "Share this with your team.",
    ],
    "direct": [
        "Contact us today.",
        "Send a message now.",
        "Get started today.",
        "Request a free consultation.",
    ],
}

COMMON_STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has",
    "he", "in", "is", "it", "its", "of", "on", "or", "that", "the", "this",
    "to", "was", "were", "will", "with", "you", "your", "we", "our", "they",
    "their", "i", "me", "my", "us", "about", "into", "than", "then", "so",
    "if", "but", "not", "can", "just", "more", "most", "very", "how", "why",
    "what", "when", "where", "who", "which",
}


# =============================================================================
# Enums
# =============================================================================

class CaptionFormat(str, Enum):
    SOCIAL = "social"
    SHORT_FORM = "short_form"
    SUBTITLE = "subtitle"
    HOOK = "hook"
    HASHTAGS = "hashtags"
    SRT = "srt"
    VTT = "vtt"


class CaptionTone(str, Enum):
    PROFESSIONAL = "professional"
    FRIENDLY = "friendly"
    BOLD = "bold"
    EDUCATIONAL = "educational"
    LUXURY = "luxury"
    URGENT = "urgent"
    STORYTELLING = "storytelling"
    DIRECT_RESPONSE = "direct_response"


class SecuritySensitiveAction(str, Enum):
    EXPORT_CAPTIONS = "export_captions"
    BULK_GENERATE = "bulk_generate"
    PUBLISH_CAPTION = "publish_caption"


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class CreatorTaskContext:
    """
    Required SaaS execution context.

    Every generation task must include user_id and workspace_id to keep all
    generated creative data, logs, memory payloads, and audit trails isolated.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    request_id: Optional[str] = None
    source: str = "creator_agent"
    permissions: List[str] = field(default_factory=list)
    brand_id: Optional[str] = None
    project_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SubtitleSegment:
    """
    Subtitle segment model used for dashboard preview, SRT, and WebVTT export.
    """

    index: int
    start_seconds: float
    end_seconds: float
    text: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CaptionPackage:
    """
    Structured caption output package.

    This can be consumed by the Creator Agent, dashboard, API routes, task
    history, Verification Agent, and Memory Agent.
    """

    id: str
    user_id: str
    workspace_id: str
    platform: str
    language: str
    tone: str
    topic: str
    hook: str
    caption: str
    hashtags: List[str]
    cta: str
    variants: List[str]
    subtitles: List[Dict[str, Any]] = field(default_factory=list)
    srt: Optional[str] = None
    vtt: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: utc_now_iso())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =============================================================================
# Utility functions
# =============================================================================

def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    """Generate readable unique IDs for caption packages and generation tasks."""
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def clean_text(value: Any) -> str:
    """Normalize whitespace and convert any value into safe plain text."""
    text = str(value or "")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def split_sentences(text: str) -> List[str]:
    """
    Split text into simple sentence-like chunks.

    This intentionally avoids external NLP dependencies to keep the file
    import-safe and lightweight.
    """
    text = clean_text(text)
    if not text:
        return []
    parts = re.split(r"(?<=[.!?])\s+", text)
    cleaned = [part.strip() for part in parts if part.strip()]
    if len(cleaned) == 1:
        return smart_wrap_chunks(cleaned[0], max_chars=96)
    return cleaned


def smart_wrap_chunks(text: str, max_chars: int = 90) -> List[str]:
    """
    Split long text into readable chunks.

    Used for subtitle generation and caption formatting.
    """
    text = clean_text(text)
    if not text:
        return []

    if len(text) <= max_chars:
        return [text]

    wrapped = textwrap.wrap(
        text,
        width=max_chars,
        break_long_words=False,
        break_on_hyphens=False,
    )
    return [chunk.strip() for chunk in wrapped if chunk.strip()]


def seconds_to_srt_time(seconds: float) -> str:
    """Convert seconds to SRT timestamp format: HH:MM:SS,mmm."""
    seconds = max(0.0, float(seconds))
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    millis = int(round((seconds - math.floor(seconds)) * 1000))
    if millis >= 1000:
        secs += 1
        millis -= 1000
    return f"{hours:02d}:{minutes:02d}:{secs:02d},{millis:03d}"


def seconds_to_vtt_time(seconds: float) -> str:
    """Convert seconds to WebVTT timestamp format: HH:MM:SS.mmm."""
    return seconds_to_srt_time(seconds).replace(",", ".")


def strip_hashtag_symbols(tag: str) -> str:
    """Normalize a hashtag by removing symbols and spaces."""
    value = str(tag or "").strip()
    value = value.replace("#", "")
    value = re.sub(r"[^A-Za-z0-9_ ]+", "", value)
    value = "".join(word.capitalize() for word in value.split())
    return value


def truncate_text(text: str, max_length: int) -> str:
    """Truncate text safely without cutting too aggressively."""
    text = clean_text(text)
    if len(text) <= max_length:
        return text
    if max_length <= 3:
        return text[:max_length]
    return text[: max_length - 3].rstrip() + "..."


def dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    """Remove duplicates while preserving original order."""
    seen = set()
    output: List[str] = []
    for item in items:
        key = item.lower().strip()
        if not key or key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


# =============================================================================
# Caption Generator
# =============================================================================

class CaptionGenerator(BaseAgent):
    """
    Creator Agent Caption Generator.

    This class provides deterministic, safe, no-external-API caption utilities.
    It can later be upgraded to use LLM providers, brand style modules, asset
    managers, or project databases while keeping the same public interface.

    Connections:
        - Master Agent:
            Uses handle_task() for action-based routing.
        - Security Agent:
            Sensitive actions pass through _request_security_approval().
        - Memory Agent:
            Successful outputs prepare memory payloads with useful creative context.
        - Verification Agent:
            Successful outputs prepare verification payloads for QA checks.
        - Dashboard/API:
            All methods return structured JSON-style dictionaries.
        - Agent Registry/Loader:
            get_agent_manifest() exposes capabilities and import metadata.
    """

    def __init__(
        self,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        brand_profile: Optional[Dict[str, Any]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=kwargs.get("agent_name", "CaptionGenerator"),
            agent_id=kwargs.get("agent_id", "creator_agent.caption_generator"),
            metadata=kwargs.get("metadata", {"version": CAPTION_GENERATOR_VERSION}),
        )
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger
        self.brand_profile = brand_profile or {}
        self.logger = logger or logging.getLogger(__name__)

    # -------------------------------------------------------------------------
    # Structured result helpers
    # -------------------------------------------------------------------------

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Any] = None,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William/Jarvis standard structured result."""
        return {
            "success": bool(success),
            "message": message,
            "data": data,
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William/Jarvis standard structured error result."""
        error_text = str(error) if error is not None else message
        self.logger.error("%s | error=%s", message, error_text)
        return self._safe_result(
            success=False,
            message=message,
            data=None,
            error=error_text,
            metadata=metadata or {},
        )

    # -------------------------------------------------------------------------
    # Compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Dict[str, Any],
    ) -> Tuple[bool, Optional[CreatorTaskContext], Optional[str]]:
        """
        Validate SaaS user/workspace context.

        This is mandatory for user-specific execution to prevent mixing creative
        outputs, task history, analytics, memory, or audit logs between tenants.
        """
        if not isinstance(context, dict):
            return False, None, "context must be a dictionary"

        user_id = clean_text(context.get("user_id"))
        workspace_id = clean_text(context.get("workspace_id"))

        if not user_id:
            return False, None, "user_id is required"
        if not workspace_id:
            return False, None, "workspace_id is required"

        permissions = context.get("permissions") or []
        if not isinstance(permissions, list):
            permissions = []

        task_context = CreatorTaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=context.get("role"),
            request_id=context.get("request_id"),
            source=context.get("source", "creator_agent"),
            permissions=[str(permission) for permission in permissions],
            brand_id=context.get("brand_id"),
            project_id=context.get("project_id"),
        )
        return True, task_context, None

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Determine whether the requested action requires Security Agent approval.

        Caption generation itself is safe. Publishing, export workflows, and
        bulk generation are treated as sensitive because they may affect external
        channels, user quotas, brand reputation, or workspace data movement.
        """
        sensitive = {item.value for item in SecuritySensitiveAction}
        return action in sensitive

    def _request_security_approval(
        self,
        action: str,
        context: CreatorTaskContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If no Security Agent is connected, local safe policy permits normal
        caption generation and blocks sensitive actions unless the context has
        one of:
            - creator:admin
            - creator:export
            - creator:publish
            - creator:bulk
        """
        payload = payload or {}

        if not self._requires_security_check(action, payload):
            return {
                "approved": True,
                "reason": "security_check_not_required",
                "metadata": {"action": action},
            }

        if self.security_agent and hasattr(self.security_agent, "approve_action"):
            try:
                approval = self.security_agent.approve_action(
                    action=action,
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    payload=payload,
                )
                if isinstance(approval, dict):
                    return {
                        "approved": bool(approval.get("approved")),
                        "reason": approval.get("reason", "security_agent_response"),
                        "metadata": approval,
                    }
            except Exception as exc:
                self.logger.exception("Security Agent approval failed.")
                return {
                    "approved": False,
                    "reason": f"security_agent_error: {exc}",
                    "metadata": {"action": action},
                }

        permissions = set(context.permissions)
        allowed = bool(
            "creator:admin" in permissions
            or (action == SecuritySensitiveAction.EXPORT_CAPTIONS.value and "creator:export" in permissions)
            or (action == SecuritySensitiveAction.PUBLISH_CAPTION.value and "creator:publish" in permissions)
            or (action == SecuritySensitiveAction.BULK_GENERATE.value and "creator:bulk" in permissions)
        )

        return {
            "approved": allowed,
            "reason": "local_permission_policy" if allowed else "missing_required_permission",
            "metadata": {
                "action": action,
                "required_any": [
                    "creator:admin",
                    "creator:export",
                    "creator:publish",
                    "creator:bulk",
                ],
            },
        }

    def _prepare_verification_payload(
        self,
        action: str,
        context: CreatorTaskContext,
        result_data: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification can later check platform length, subtitle timing, prohibited
        publishing behavior, brand fit, formatting quality, and completeness.
        """
        return {
            "agent": "creator_agent.caption_generator",
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "brand_id": context.brand_id,
            "project_id": context.project_id,
            "request_id": context.request_id,
            "timestamp": utc_now_iso(),
            "checks_recommended": [
                "platform_length_check",
                "subtitle_timing_check",
                "caption_completeness_check",
                "brand_safety_check",
                "workspace_isolation_check",
            ],
            "result_data": result_data,
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: CreatorTaskContext,
        useful_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Stores useful creative preferences and output context without mixing
        tenants. Memory Agent can later use this for brand voice, caption style,
        preferred hooks, CTA patterns, and platform preferences.
        """
        return {
            "agent": "creator_agent.caption_generator",
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "brand_id": context.brand_id,
            "project_id": context.project_id,
            "request_id": context.request_id,
            "timestamp": utc_now_iso(),
            "memory_type": "creator_caption_context",
            "context": useful_context or {},
        }

    def _emit_agent_event(
        self,
        event_name: str,
        context: CreatorTaskContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit events for dashboard analytics, task history, observability, and
        Agent Registry listeners.
        """
        event_payload = {
            "event": event_name,
            "agent": "creator_agent.caption_generator",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "brand_id": context.brand_id,
            "project_id": context.project_id,
            "request_id": context.request_id,
            "timestamp": utc_now_iso(),
            "payload": payload or {},
        }

        try:
            if self.event_bus and hasattr(self.event_bus, "emit"):
                self.event_bus.emit(event_name, event_payload)
            elif hasattr(self, "emit_event"):
                self.emit_event(event_name, event_payload)
        except Exception:
            self.logger.exception("Failed to emit CaptionGenerator event: %s", event_name)

    def _log_audit_event(
        self,
        action: str,
        context: CreatorTaskContext,
        payload: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> None:
        """
        Log audit events for traceability, dashboard history, and future security
        reviews. This does not write sensitive external data.
        """
        audit_payload = {
            "agent": "creator_agent.caption_generator",
            "action": action,
            "success": success,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "brand_id": context.brand_id,
            "project_id": context.project_id,
            "request_id": context.request_id,
            "timestamp": utc_now_iso(),
            "payload": payload or {},
        }

        try:
            if self.audit_logger and hasattr(self.audit_logger, "log"):
                self.audit_logger.log(audit_payload)
            else:
                self.logger.info("CAPTION_GENERATOR_AUDIT %s", audit_payload)
        except Exception:
            self.logger.exception("Failed to log CaptionGenerator audit event.")

    def _after_success(
        self,
        action: str,
        context: CreatorTaskContext,
        data: Optional[Any],
        memory_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Shared success hook.

        Prepares verification and memory payloads, emits events, writes audit
        logs, and optionally calls connected Memory/Verification agents.
        """
        verification_payload = self._prepare_verification_payload(action, context, data)
        memory_payload = self._prepare_memory_payload(action, context, memory_context or {})

        self._emit_agent_event(f"caption_generator.{action}", context, {"data": data})
        self._log_audit_event(action, context, {"data": data}, success=True)

        if self.memory_agent and hasattr(self.memory_agent, "store_context"):
            try:
                self.memory_agent.store_context(memory_payload)
            except Exception:
                self.logger.exception("Memory Agent store_context failed.")

        if self.verification_agent and hasattr(self.verification_agent, "prepare_verification"):
            try:
                self.verification_agent.prepare_verification(verification_payload)
            except Exception:
                self.logger.exception("Verification Agent prepare_verification failed.")

        return {
            "verification_payload": verification_payload,
            "memory_payload": memory_payload,
        }

    # -------------------------------------------------------------------------
    # Internal generation helpers
    # -------------------------------------------------------------------------

    def _get_brand_name(self, brand_name: Optional[str] = None) -> str:
        value = clean_text(brand_name)
        if value:
            return value
        profile_brand = clean_text(self.brand_profile.get("brand_name"))
        return profile_brand or DEFAULT_BRAND_NAME

    def _normalize_platform(self, platform: Optional[str]) -> str:
        value = clean_text(platform).lower().replace(" ", "_")
        return value or DEFAULT_PLATFORM

    def _normalize_tone(self, tone: Optional[str]) -> str:
        value = clean_text(tone).lower().replace(" ", "_")
        return value or DEFAULT_TONE

    def _platform_max_length(self, platform: str) -> int:
        return MAX_CAPTION_LENGTHS.get(platform, MAX_CAPTION_LENGTHS["general"])

    def _platform_hashtag_limit(self, platform: str) -> int:
        return PLATFORM_HASHTAG_LIMITS.get(platform, PLATFORM_HASHTAG_LIMITS["general"])

    def _extract_keywords(
        self,
        text: str,
        topic: Optional[str] = None,
        max_keywords: int = 12,
    ) -> List[str]:
        """
        Extract simple keywords from topic/transcript/caption text.

        No external dependency is used. This is intentionally deterministic and
        easy to test.
        """
        source = f"{topic or ''} {text or ''}".lower()
        tokens = re.findall(r"[a-zA-Z][a-zA-Z0-9]{2,}", source)

        frequency: Dict[str, int] = {}
        for token in tokens:
            if token in COMMON_STOPWORDS:
                continue
            frequency[token] = frequency.get(token, 0) + 1

        sorted_tokens = sorted(
            frequency.items(),
            key=lambda item: (-item[1], item[0]),
        )

        keywords = [token for token, _count in sorted_tokens[:max_keywords]]
        if topic:
            topic_words = [
                word.lower()
                for word in re.findall(r"[a-zA-Z][a-zA-Z0-9]{2,}", topic)
                if word.lower() not in COMMON_STOPWORDS
            ]
            keywords = dedupe_preserve_order(topic_words + keywords)

        return keywords[:max_keywords]

    def _tone_intro(self, tone: str, topic: str) -> str:
        topic_text = topic or "this"
        mapping = {
            CaptionTone.PROFESSIONAL.value: f"Here is a clear breakdown of {topic_text}.",
            CaptionTone.FRIENDLY.value: f"Let’s make {topic_text} simple.",
            CaptionTone.BOLD.value: f"Most people are getting {topic_text} wrong.",
            CaptionTone.EDUCATIONAL.value: f"Here is what you need to understand about {topic_text}.",
            CaptionTone.LUXURY.value: f"Premium results in {topic_text} start with the right strategy.",
            CaptionTone.URGENT.value: f"Do not ignore this if {topic_text} matters to your results.",
            CaptionTone.STORYTELLING.value: f"Every strong result in {topic_text} starts with one decision.",
            CaptionTone.DIRECT_RESPONSE.value: f"Want better results from {topic_text}? Start here.",
        }
        return mapping.get(tone, mapping[CaptionTone.PROFESSIONAL.value])

    def _select_cta(self, cta_style: Optional[str], tone: str, platform: str) -> str:
        style = clean_text(cta_style).lower()
        if not style:
            if tone in {CaptionTone.EDUCATIONAL.value, CaptionTone.PROFESSIONAL.value}:
                style = "educational"
            elif tone in {CaptionTone.DIRECT_RESPONSE.value, CaptionTone.URGENT.value}:
                style = "direct"
            else:
                style = "soft"

        options = DEFAULT_CTA_TEMPLATES.get(style, DEFAULT_CTA_TEMPLATES["soft"])
        index = abs(hash(f"{tone}:{platform}:{style}")) % len(options)
        return options[index]

    def _build_hashtags(
        self,
        text: str,
        topic: Optional[str],
        platform: str,
        industry: Optional[str] = None,
        extra_hashtags: Optional[List[str]] = None,
    ) -> List[str]:
        """
        Generate platform-aware hashtag list.
        """
        keywords = self._extract_keywords(text=text, topic=topic, max_keywords=16)
        tags: List[str] = []

        if industry:
            tags.append(strip_hashtag_symbols(industry))

        for keyword in keywords:
            tags.append(strip_hashtag_symbols(keyword))

        for tag in extra_hashtags or []:
            tags.append(strip_hashtag_symbols(tag))

        cleaned = []
        for tag in tags:
            if not tag:
                continue
            if len(tag) > 40:
                continue
            cleaned.append(f"#{tag}")

        cleaned = dedupe_preserve_order(cleaned)
        return cleaned[: self._platform_hashtag_limit(platform)]

    def _compose_caption(
        self,
        topic: str,
        transcript: Optional[str],
        hook: str,
        tone: str,
        platform: str,
        brand_name: str,
        cta: str,
        hashtags: List[str],
        include_emojis: bool,
        include_hashtags: bool,
        max_length: Optional[int] = None,
    ) -> str:
        """
        Compose a polished social caption from deterministic building blocks.
        """
        topic_text = clean_text(topic) or "your next idea"
        transcript_text = clean_text(transcript)

        intro = self._tone_intro(tone, topic_text)
        emoji_prefix = "🚀 " if include_emojis and tone in {
            CaptionTone.BOLD.value,
            CaptionTone.DIRECT_RESPONSE.value,
            CaptionTone.URGENT.value,
        } else "✨ " if include_emojis else ""

        insights = []
        if transcript_text:
            sentences = split_sentences(transcript_text)
            for sentence in sentences[:3]:
                sentence = truncate_text(sentence, 170)
                if sentence:
                    insights.append(sentence)

        if not insights:
            insights = [
                f"Strong content around {topic_text} needs a clear message, a simple structure, and a reason for the audience to act.",
                f"The goal is not just attention. The goal is attention that turns into trust.",
            ]

        if platform in {"x", "twitter"}:
            base = f"{hook} {insights[0]} {cta}"
            if include_hashtags and hashtags:
                base = f"{base} {' '.join(hashtags[:2])}"
            return truncate_text(base, max_length or self._platform_max_length(platform))

        caption_parts = [
            f"{emoji_prefix}{hook}",
            "",
            intro,
            "",
        ]

        for insight in insights:
            caption_parts.append(f"• {insight}")

        caption_parts.extend(["", cta])

        if brand_name and platform in {"linkedin", "facebook", "youtube", "general"}:
            caption_parts.extend(["", f"— {brand_name}"])

        if include_hashtags and hashtags:
            caption_parts.extend(["", " ".join(hashtags)])

        caption = "\n".join(caption_parts).strip()
        return truncate_text(caption, max_length or self._platform_max_length(platform))

    def _generate_variants(
        self,
        base_caption: str,
        topic: str,
        hook: str,
        cta: str,
        tone: str,
        platform: str,
        count: int = 3,
    ) -> List[str]:
        """
        Generate caption variants for A/B testing.
        """
        count = max(1, min(int(count), 10))
        topic_text = clean_text(topic) or "this topic"

        templates = [
            f"{hook}\n\nHere is the simple version: {topic_text} works best when your message is clear, your offer is easy to understand, and your next step is obvious.\n\n{cta}",
            f"Want better results with {topic_text}?\n\nStart with clarity. Then build trust. Then make the action easy.\n\n{cta}",
            f"The mistake most people make with {topic_text}: they focus on noise instead of strategy.\n\nKeep it simple. Make it useful. Give people a reason to act.\n\n{cta}",
            f"If {topic_text} is part of your growth plan, do not overcomplicate it.\n\nOne clear message can outperform ten confusing ones.\n\n{cta}",
            f"Your audience does not need more confusion.\n\nThey need a clear reason to care about {topic_text}, trust your message, and take the next step.\n\n{cta}",
        ]

        if tone == CaptionTone.LUXURY.value:
            templates.insert(
                0,
                f"Premium {topic_text} results are built on clarity, consistency, and trust.\n\nMake the message feel valuable before asking people to act.\n\n{cta}",
            )

        if tone == CaptionTone.URGENT.value:
            templates.insert(
                0,
                f"Do not wait to fix your {topic_text} strategy.\n\nEvery unclear message can cost attention, trust, and conversions.\n\n{cta}",
            )

        variants = dedupe_preserve_order([truncate_text(item, self._platform_max_length(platform)) for item in templates])
        if base_caption not in variants:
            variants.insert(0, base_caption)
        return variants[:count]

    def _choose_hook(self, topic: str, hook_style: Optional[str] = None) -> str:
        """
        Choose a hook for social posts and short-form captions.
        """
        topic_text = clean_text(topic) or "your content"
        style = clean_text(hook_style).lower()

        style_templates = {
            "question": [
                "What if your {topic} strategy is missing one simple thing?",
                "Are you making this {topic} mistake?",
                "Want better results from {topic}?",
            ],
            "bold": [
                "Most people are doing {topic} backwards.",
                "This is why your {topic} is not converting.",
                "Stop wasting effort on weak {topic}.",
            ],
            "educational": [
                "Here is the simple framework for {topic}:",
                "Learn this before you work on {topic}.",
                "The easiest way to improve {topic} starts here:",
            ],
            "curiosity": [
                "Nobody tells you this about {topic}:",
                "The hidden reason {topic} fails:",
                "This changes how you look at {topic}.",
            ],
        }

        templates = style_templates.get(style, DEFAULT_HOOK_TEMPLATES)
        index = abs(hash(f"{topic_text}:{style}")) % len(templates)
        return templates[index].format(topic=topic_text)

    def _estimate_segment_duration(
        self,
        text: str,
        words_per_minute: int = 155,
        min_duration: float = 1.2,
        max_duration: float = 6.0,
    ) -> float:
        """
        Estimate subtitle segment duration based on readable speech speed.
        """
        words = max(1, len(re.findall(r"\w+", text)))
        seconds = (words / max(80, words_per_minute)) * 60.0
        return min(max(seconds, min_duration), max_duration)

    def _segments_to_srt(self, segments: Sequence[SubtitleSegment]) -> str:
        """Convert subtitle segments to SRT format."""
        lines: List[str] = []
        for segment in segments:
            lines.append(str(segment.index))
            lines.append(
                f"{seconds_to_srt_time(segment.start_seconds)} --> "
                f"{seconds_to_srt_time(segment.end_seconds)}"
            )
            lines.append(segment.text)
            lines.append("")
        return "\n".join(lines).strip() + "\n"

    def _segments_to_vtt(self, segments: Sequence[SubtitleSegment]) -> str:
        """Convert subtitle segments to WebVTT format."""
        lines: List[str] = ["WEBVTT", ""]
        for segment in segments:
            lines.append(
                f"{seconds_to_vtt_time(segment.start_seconds)} --> "
                f"{seconds_to_vtt_time(segment.end_seconds)}"
            )
            lines.append(html.escape(segment.text, quote=False))
            lines.append("")
        return "\n".join(lines).strip() + "\n"

    # -------------------------------------------------------------------------
    # Public generation methods
    # -------------------------------------------------------------------------

    def generate_hook(
        self,
        context: Dict[str, Any],
        topic: str,
        hook_style: Optional[str] = None,
        count: int = 5,
    ) -> Dict[str, Any]:
        """Generate multiple hooks for a topic."""
        valid, task_context, error = self._validate_task_context(context)
        if not valid or task_context is None:
            return self._error_result("Invalid Creator Agent context.", error)

        try:
            topic_text = clean_text(topic)
            if not topic_text:
                raise ValueError("topic is required")

            count = max(1, min(int(count), 20))
            hooks = []

            styles = [hook_style] if hook_style else ["question", "bold", "educational", "curiosity", "default"]
            while len(hooks) < count:
                for style in styles:
                    if len(hooks) >= count:
                        break
                    hook = self._choose_hook(topic_text, None if style == "default" else style)
                    hooks.append(hook)

                if len(hooks) < count:
                    hooks.append(DEFAULT_HOOK_TEMPLATES[len(hooks) % len(DEFAULT_HOOK_TEMPLATES)].format(topic=topic_text))

            hooks = dedupe_preserve_order(hooks)[:count]

            data = {
                "topic": topic_text,
                "hook_style": hook_style or "mixed",
                "hooks": hooks,
                "count": len(hooks),
            }

            metadata = self._after_success(
                "generate_hook",
                task_context,
                data,
                {
                    "topic": topic_text,
                    "hook_style": hook_style or "mixed",
                    "generated_count": len(hooks),
                },
            )

            return self._safe_result(True, "Hooks generated successfully.", data, metadata=metadata)
        except Exception as exc:
            self._log_audit_event("generate_hook", task_context, {"topic": topic}, success=False)
            return self._error_result("Failed to generate hooks.", exc)

    def generate_hashtags(
        self,
        context: Dict[str, Any],
        topic: str,
        text: Optional[str] = None,
        platform: str = DEFAULT_PLATFORM,
        industry: Optional[str] = None,
        extra_hashtags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Generate hashtag set for a topic/platform."""
        valid, task_context, error = self._validate_task_context(context)
        if not valid or task_context is None:
            return self._error_result("Invalid Creator Agent context.", error)

        try:
            platform_name = self._normalize_platform(platform)
            topic_text = clean_text(topic)
            if not topic_text:
                raise ValueError("topic is required")

            hashtags = self._build_hashtags(
                text=clean_text(text),
                topic=topic_text,
                platform=platform_name,
                industry=industry,
                extra_hashtags=extra_hashtags,
            )

            data = {
                "topic": topic_text,
                "platform": platform_name,
                "hashtags": hashtags,
                "count": len(hashtags),
                "limit": self._platform_hashtag_limit(platform_name),
            }

            metadata = self._after_success(
                "generate_hashtags",
                task_context,
                data,
                {
                    "topic": topic_text,
                    "platform": platform_name,
                    "hashtags": hashtags,
                },
            )

            return self._safe_result(True, "Hashtags generated successfully.", data, metadata=metadata)
        except Exception as exc:
            self._log_audit_event("generate_hashtags", task_context, {"topic": topic}, success=False)
            return self._error_result("Failed to generate hashtags.", exc)

    def generate_social_caption(
        self,
        context: Dict[str, Any],
        topic: str,
        transcript: Optional[str] = None,
        platform: str = DEFAULT_PLATFORM,
        tone: str = DEFAULT_TONE,
        brand_name: Optional[str] = None,
        hook_style: Optional[str] = None,
        cta_style: Optional[str] = None,
        industry: Optional[str] = None,
        include_emojis: bool = True,
        include_hashtags: bool = True,
        extra_hashtags: Optional[List[str]] = None,
        variant_count: int = 3,
        language: str = DEFAULT_LANGUAGE,
        max_length: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Generate a complete social caption package.

        This method is suitable for Instagram, Facebook, LinkedIn, TikTok,
        YouTube, YouTube Shorts, X/Twitter, Threads, Pinterest, or general use.
        """
        valid, task_context, error = self._validate_task_context(context)
        if not valid or task_context is None:
            return self._error_result("Invalid Creator Agent context.", error)

        try:
            topic_text = clean_text(topic)
            if not topic_text:
                raise ValueError("topic is required")

            platform_name = self._normalize_platform(platform)
            tone_name = self._normalize_tone(tone)
            brand = self._get_brand_name(brand_name)
            transcript_text = clean_text(transcript)
            hook = self._choose_hook(topic_text, hook_style)
            cta = self._select_cta(cta_style, tone_name, platform_name)

            hashtags = self._build_hashtags(
                text=transcript_text,
                topic=topic_text,
                platform=platform_name,
                industry=industry,
                extra_hashtags=extra_hashtags,
            )

            caption = self._compose_caption(
                topic=topic_text,
                transcript=transcript_text,
                hook=hook,
                tone=tone_name,
                platform=platform_name,
                brand_name=brand,
                cta=cta,
                hashtags=hashtags,
                include_emojis=bool(include_emojis),
                include_hashtags=bool(include_hashtags),
                max_length=max_length,
            )

            variants = self._generate_variants(
                base_caption=caption,
                topic=topic_text,
                hook=hook,
                cta=cta,
                tone=tone_name,
                platform=platform_name,
                count=variant_count,
            )

            package = CaptionPackage(
                id=new_id("caption"),
                user_id=task_context.user_id,
                workspace_id=task_context.workspace_id,
                platform=platform_name,
                language=clean_text(language) or DEFAULT_LANGUAGE,
                tone=tone_name,
                topic=topic_text,
                hook=hook,
                caption=caption,
                hashtags=hashtags,
                cta=cta,
                variants=variants,
                metadata={
                    "brand_name": brand,
                    "hook_style": hook_style or "auto",
                    "cta_style": cta_style or "auto",
                    "include_emojis": bool(include_emojis),
                    "include_hashtags": bool(include_hashtags),
                    "caption_length": len(caption),
                    "platform_max_length": self._platform_max_length(platform_name),
                    "source": "deterministic_caption_generator",
                },
            )

            data = package.to_dict()
            metadata = self._after_success(
                "generate_social_caption",
                task_context,
                data,
                {
                    "topic": topic_text,
                    "platform": platform_name,
                    "tone": tone_name,
                    "brand_name": brand,
                    "caption_preview": caption[:180],
                    "hashtags": hashtags,
                },
            )

            return self._safe_result(True, "Social caption generated successfully.", data, metadata=metadata)
        except Exception as exc:
            self._log_audit_event("generate_social_caption", task_context, {"topic": topic}, success=False)
            return self._error_result("Failed to generate social caption.", exc)

    def generate_subtitles(
        self,
        context: Dict[str, Any],
        transcript: str,
        start_seconds: float = 0.0,
        words_per_minute: int = 155,
        max_chars_per_segment: int = 84,
        min_duration: float = 1.2,
        max_duration: float = 6.0,
        language: str = DEFAULT_LANGUAGE,
        include_srt: bool = True,
        include_vtt: bool = True,
    ) -> Dict[str, Any]:
        """
        Generate subtitle segments from transcript text.

        Timing is estimated locally. Later, this can be replaced by true
        timestamped ASR output while keeping the same method signature.
        """
        valid, task_context, error = self._validate_task_context(context)
        if not valid or task_context is None:
            return self._error_result("Invalid Creator Agent context.", error)

        try:
            transcript_text = clean_text(transcript)
            if not transcript_text:
                raise ValueError("transcript is required")

            chunks: List[str] = []
            for sentence in split_sentences(transcript_text):
                chunks.extend(smart_wrap_chunks(sentence, max_chars=max_chars_per_segment))

            current = max(0.0, float(start_seconds))
            segments: List[SubtitleSegment] = []

            for index, chunk in enumerate(chunks, start=1):
                duration = self._estimate_segment_duration(
                    text=chunk,
                    words_per_minute=words_per_minute,
                    min_duration=min_duration,
                    max_duration=max_duration,
                )
                segment = SubtitleSegment(
                    index=index,
                    start_seconds=round(current, 3),
                    end_seconds=round(current + duration, 3),
                    text=chunk,
                )
                segments.append(segment)
                current += duration

            srt = self._segments_to_srt(segments) if include_srt else None
            vtt = self._segments_to_vtt(segments) if include_vtt else None

            data = {
                "language": clean_text(language) or DEFAULT_LANGUAGE,
                "segments": [segment.to_dict() for segment in segments],
                "segment_count": len(segments),
                "duration_estimate_seconds": round(current - float(start_seconds), 3),
                "srt": srt,
                "vtt": vtt,
                "settings": {
                    "start_seconds": start_seconds,
                    "words_per_minute": words_per_minute,
                    "max_chars_per_segment": max_chars_per_segment,
                    "min_duration": min_duration,
                    "max_duration": max_duration,
                },
            }

            metadata = self._after_success(
                "generate_subtitles",
                task_context,
                data,
                {
                    "language": clean_text(language) or DEFAULT_LANGUAGE,
                    "segment_count": len(segments),
                    "duration_estimate_seconds": data["duration_estimate_seconds"],
                },
            )

            return self._safe_result(True, "Subtitles generated successfully.", data, metadata=metadata)
        except Exception as exc:
            self._log_audit_event("generate_subtitles", task_context, {"transcript_preview": clean_text(transcript)[:160]}, success=False)
            return self._error_result("Failed to generate subtitles.", exc)

    def export_subtitles(
        self,
        context: Dict[str, Any],
        segments: List[Dict[str, Any]],
        export_format: str = CaptionFormat.SRT.value,
    ) -> Dict[str, Any]:
        """
        Export provided subtitle segments to SRT or WebVTT.

        This action requires security approval because it prepares exportable
        creative data. It does not write files directly.
        """
        valid, task_context, error = self._validate_task_context(context)
        if not valid or task_context is None:
            return self._error_result("Invalid Creator Agent context.", error)

        approval = self._request_security_approval(
            SecuritySensitiveAction.EXPORT_CAPTIONS.value,
            task_context,
            {"export_format": export_format, "segment_count": len(segments or [])},
        )
        if not approval["approved"]:
            return self._safe_result(
                False,
                "Security approval denied for subtitle export.",
                data=None,
                error=approval["reason"],
                metadata={"security": approval},
            )

        try:
            parsed_segments: List[SubtitleSegment] = []
            for fallback_index, raw in enumerate(segments, start=1):
                if not isinstance(raw, dict):
                    raise ValueError("each segment must be a dictionary")
                parsed_segments.append(
                    SubtitleSegment(
                        index=int(raw.get("index", fallback_index)),
                        start_seconds=float(raw.get("start_seconds", 0.0)),
                        end_seconds=float(raw.get("end_seconds", 0.0)),
                        text=clean_text(raw.get("text")),
                    )
                )

            if not parsed_segments:
                raise ValueError("segments are required")

            fmt = clean_text(export_format).lower()
            if fmt == CaptionFormat.SRT.value:
                content = self._segments_to_srt(parsed_segments)
                mime_type = "application/x-subrip"
                extension = "srt"
            elif fmt in {CaptionFormat.VTT.value, "webvtt"}:
                content = self._segments_to_vtt(parsed_segments)
                mime_type = "text/vtt"
                extension = "vtt"
            else:
                raise ValueError("export_format must be 'srt' or 'vtt'")

            data = {
                "format": fmt,
                "extension": extension,
                "mime_type": mime_type,
                "content": content,
                "segment_count": len(parsed_segments),
                "generated_at": utc_now_iso(),
            }

            metadata = self._after_success(
                "export_subtitles",
                task_context,
                {
                    "format": fmt,
                    "extension": extension,
                    "segment_count": len(parsed_segments),
                },
                {
                    "export_format": fmt,
                    "segment_count": len(parsed_segments),
                },
            )

            return self._safe_result(
                True,
                "Subtitles exported successfully.",
                data,
                metadata={**metadata, "security": approval},
            )
        except Exception as exc:
            self._log_audit_event("export_subtitles", task_context, {"export_format": export_format}, success=False)
            return self._error_result("Failed to export subtitles.", exc, {"security": approval})

    def generate_caption_package(
        self,
        context: Dict[str, Any],
        topic: str,
        transcript: Optional[str] = None,
        platform: str = DEFAULT_PLATFORM,
        tone: str = DEFAULT_TONE,
        brand_name: Optional[str] = None,
        hook_style: Optional[str] = None,
        cta_style: Optional[str] = None,
        industry: Optional[str] = None,
        include_subtitles: bool = True,
        include_srt: bool = True,
        include_vtt: bool = True,
        include_emojis: bool = True,
        include_hashtags: bool = True,
        extra_hashtags: Optional[List[str]] = None,
        variant_count: int = 3,
        language: str = DEFAULT_LANGUAGE,
    ) -> Dict[str, Any]:
        """
        Generate a complete package:
            - hook
            - social caption
            - hashtags
            - CTA
            - variants
            - optional subtitles
            - optional SRT
            - optional VTT
        """
        valid, task_context, error = self._validate_task_context(context)
        if not valid or task_context is None:
            return self._error_result("Invalid Creator Agent context.", error)

        try:
            caption_result = self.generate_social_caption(
                context=context,
                topic=topic,
                transcript=transcript,
                platform=platform,
                tone=tone,
                brand_name=brand_name,
                hook_style=hook_style,
                cta_style=cta_style,
                industry=industry,
                include_emojis=include_emojis,
                include_hashtags=include_hashtags,
                extra_hashtags=extra_hashtags,
                variant_count=variant_count,
                language=language,
            )
            if not caption_result["success"]:
                return caption_result

            caption_data = caption_result["data"]
            subtitles: List[Dict[str, Any]] = []
            srt: Optional[str] = None
            vtt: Optional[str] = None

            if include_subtitles and clean_text(transcript):
                subtitle_result = self.generate_subtitles(
                    context=context,
                    transcript=clean_text(transcript),
                    language=language,
                    include_srt=include_srt,
                    include_vtt=include_vtt,
                )
                if subtitle_result["success"]:
                    subtitles = subtitle_result["data"]["segments"]
                    srt = subtitle_result["data"].get("srt")
                    vtt = subtitle_result["data"].get("vtt")

            caption_data["subtitles"] = subtitles
            caption_data["srt"] = srt
            caption_data["vtt"] = vtt
            caption_data["metadata"]["package_type"] = "complete_caption_package"
            caption_data["metadata"]["has_subtitles"] = bool(subtitles)

            metadata = self._after_success(
                "generate_caption_package",
                task_context,
                caption_data,
                {
                    "topic": clean_text(topic),
                    "platform": self._normalize_platform(platform),
                    "tone": self._normalize_tone(tone),
                    "has_subtitles": bool(subtitles),
                    "caption_preview": caption_data.get("caption", "")[:180],
                },
            )

            return self._safe_result(
                True,
                "Caption package generated successfully.",
                caption_data,
                metadata=metadata,
            )
        except Exception as exc:
            self._log_audit_event("generate_caption_package", task_context, {"topic": topic}, success=False)
            return self._error_result("Failed to generate caption package.", exc)

    def generate_platform_caption_set(
        self,
        context: Dict[str, Any],
        topic: str,
        transcript: Optional[str] = None,
        platforms: Optional[List[str]] = None,
        tone: str = DEFAULT_TONE,
        brand_name: Optional[str] = None,
        industry: Optional[str] = None,
        language: str = DEFAULT_LANGUAGE,
    ) -> Dict[str, Any]:
        """
        Generate captions for multiple platforms.

        This uses local generation only. For very large lists, it is treated as
        a bulk action and requires permission.
        """
        valid, task_context, error = self._validate_task_context(context)
        if not valid or task_context is None:
            return self._error_result("Invalid Creator Agent context.", error)

        try:
            selected_platforms = platforms or ["instagram", "linkedin", "tiktok", "youtube_shorts", "facebook"]
            selected_platforms = [self._normalize_platform(item) for item in selected_platforms if clean_text(item)]
            selected_platforms = dedupe_preserve_order(selected_platforms)

            if len(selected_platforms) > 5:
                approval = self._request_security_approval(
                    SecuritySensitiveAction.BULK_GENERATE.value,
                    task_context,
                    {"platform_count": len(selected_platforms), "topic": topic},
                )
                if not approval["approved"]:
                    return self._safe_result(
                        False,
                        "Security approval denied for bulk caption generation.",
                        data=None,
                        error=approval["reason"],
                        metadata={"security": approval},
                    )

            outputs: Dict[str, Any] = {}
            for platform in selected_platforms:
                result = self.generate_social_caption(
                    context=context,
                    topic=topic,
                    transcript=transcript,
                    platform=platform,
                    tone=tone,
                    brand_name=brand_name,
                    industry=industry,
                    language=language,
                )
                outputs[platform] = result["data"] if result["success"] else {
                    "success": False,
                    "error": result["error"],
                }

            data = {
                "topic": clean_text(topic),
                "tone": self._normalize_tone(tone),
                "language": clean_text(language) or DEFAULT_LANGUAGE,
                "platforms": selected_platforms,
                "outputs": outputs,
                "generated_at": utc_now_iso(),
            }

            metadata = self._after_success(
                "generate_platform_caption_set",
                task_context,
                {
                    "topic": data["topic"],
                    "platforms": selected_platforms,
                    "output_count": len(outputs),
                },
                {
                    "topic": data["topic"],
                    "platforms": selected_platforms,
                    "output_count": len(outputs),
                },
            )

            return self._safe_result(True, "Platform caption set generated successfully.", data, metadata=metadata)
        except Exception as exc:
            self._log_audit_event("generate_platform_caption_set", task_context, {"topic": topic}, success=False)
            return self._error_result("Failed to generate platform caption set.", exc)

    def improve_caption(
        self,
        context: Dict[str, Any],
        caption: str,
        goal: str = "make it clearer and more engaging",
        platform: str = DEFAULT_PLATFORM,
        tone: str = DEFAULT_TONE,
        include_hashtags: bool = True,
    ) -> Dict[str, Any]:
        """
        Improve an existing caption using deterministic rewriting rules.

        This avoids external model dependency while still providing useful
        production behavior.
        """
        valid, task_context, error = self._validate_task_context(context)
        if not valid or task_context is None:
            return self._error_result("Invalid Creator Agent context.", error)

        try:
            original = clean_text(caption)
            if not original:
                raise ValueError("caption is required")

            platform_name = self._normalize_platform(platform)
            tone_name = self._normalize_tone(tone)
            goal_text = clean_text(goal)

            first_sentence = split_sentences(original)[0] if split_sentences(original) else original
            topic_keywords = self._extract_keywords(original, max_keywords=5)
            topic = " ".join(topic_keywords[:3]) or "your content"
            hook = self._choose_hook(topic, "bold" if tone_name in {"bold", "urgent"} else "question")
            cta = self._select_cta(None, tone_name, platform_name)
            hashtags = self._build_hashtags(original, topic, platform_name) if include_hashtags else []

            improved = self._compose_caption(
                topic=topic,
                transcript=original,
                hook=hook,
                tone=tone_name,
                platform=platform_name,
                brand_name=self._get_brand_name(),
                cta=cta,
                hashtags=hashtags,
                include_emojis=True,
                include_hashtags=include_hashtags,
            )

            data = {
                "original_caption": original,
                "improved_caption": improved,
                "goal": goal_text,
                "platform": platform_name,
                "tone": tone_name,
                "hook": hook,
                "cta": cta,
                "hashtags": hashtags,
                "original_length": len(original),
                "improved_length": len(improved),
                "first_sentence_detected": first_sentence,
            }

            metadata = self._after_success(
                "improve_caption",
                task_context,
                data,
                {
                    "platform": platform_name,
                    "tone": tone_name,
                    "goal": goal_text,
                    "improved_preview": improved[:180],
                },
            )

            return self._safe_result(True, "Caption improved successfully.", data, metadata=metadata)
        except Exception as exc:
            self._log_audit_event("improve_caption", task_context, {"caption_preview": clean_text(caption)[:160]}, success=False)
            return self._error_result("Failed to improve caption.", exc)

    # -------------------------------------------------------------------------
    # Master Agent router compatibility
    # -------------------------------------------------------------------------

    def handle_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Master Agent / Agent Router compatible task entrypoint.

        Expected task format:
            {
                "action": "generate_social_caption",
                "context": {
                    "user_id": "...",
                    "workspace_id": "...",
                    "permissions": []
                },
                "payload": {
                    "topic": "...",
                    "platform": "instagram"
                }
            }

        Supported actions:
            - generate_hook
            - generate_hashtags
            - generate_social_caption
            - generate_subtitles
            - export_subtitles
            - generate_caption_package
            - generate_platform_caption_set
            - improve_caption
            - get_agent_manifest
        """
        if not isinstance(task, dict):
            return self._error_result("Invalid task.", "task must be a dictionary")

        action = clean_text(task.get("action"))
        context = task.get("context") or {}
        payload = task.get("payload") or {}

        if not action:
            return self._error_result("Invalid task.", "action is required")
        if not isinstance(payload, dict):
            return self._error_result("Invalid task.", "payload must be a dictionary")

        route_map = {
            "generate_hook": self.generate_hook,
            "generate_hashtags": self.generate_hashtags,
            "generate_social_caption": self.generate_social_caption,
            "generate_subtitles": self.generate_subtitles,
            "export_subtitles": self.export_subtitles,
            "generate_caption_package": self.generate_caption_package,
            "generate_platform_caption_set": self.generate_platform_caption_set,
            "improve_caption": self.improve_caption,
        }

        if action == "get_agent_manifest":
            return self._safe_result(
                True,
                "CaptionGenerator manifest retrieved successfully.",
                self.get_agent_manifest(),
            )

        handler = route_map.get(action)
        if not handler:
            return self._error_result(
                "Unsupported CaptionGenerator task action.",
                f"unsupported action: {action}",
                metadata={"supported_actions": sorted(list(route_map.keys()) + ["get_agent_manifest"])},
            )

        try:
            return handler(context=context, **payload)
        except TypeError as exc:
            return self._error_result(
                "CaptionGenerator task payload does not match action signature.",
                exc,
                metadata={"action": action},
            )
        except Exception as exc:
            return self._error_result(
                "CaptionGenerator task failed unexpectedly.",
                exc,
                metadata={"action": action},
            )

    # -------------------------------------------------------------------------
    # Registry / loader manifest
    # -------------------------------------------------------------------------

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Return Agent Registry / Agent Loader metadata.

        This makes the file discoverable by registry systems and helps the
        Master Agent understand capabilities without importing future modules.
        """
        return {
            "agent": "creator_agent.caption_generator",
            "class_name": "CaptionGenerator",
            "version": CAPTION_GENERATOR_VERSION,
            "module": "agents.super_agents.creator_agent.caption_generator",
            "purpose": "Captions, subtitles, social post captions, hooks.",
            "capabilities": [
                "generate_hook",
                "generate_hashtags",
                "generate_social_caption",
                "generate_subtitles",
                "export_subtitles",
                "generate_caption_package",
                "generate_platform_caption_set",
                "improve_caption",
            ],
            "supported_platforms": sorted(MAX_CAPTION_LENGTHS.keys()),
            "supported_tones": [item.value for item in CaptionTone],
            "supported_formats": [item.value for item in CaptionFormat],
            "requires_context": ["user_id", "workspace_id"],
            "security_sensitive_actions": [item.value for item in SecuritySensitiveAction],
            "structured_result": True,
            "import_safe": True,
            "master_agent_routable": True,
            "memory_agent_compatible": True,
            "verification_agent_compatible": True,
            "dashboard_api_ready": True,
            "external_side_effects": False,
        }


__all__ = [
    "CaptionGenerator",
    "CaptionFormat",
    "CaptionTone",
    "SecuritySensitiveAction",
    "CreatorTaskContext",
    "SubtitleSegment",
    "CaptionPackage",
]