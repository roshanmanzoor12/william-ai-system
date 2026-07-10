"""
William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

File: agents/super_agents/creator_agent/script_writer.py
Agent/Module: Creator Agent
Class: ScriptWriter

Purpose:
    Ad scripts, shorts scripts, dialogue, hooks, CTAs, and voiceover generation.

This module is designed to be:
    - Import-safe even when the full William/Jarvis framework is not available yet.
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router, and Master Agent routing.
    - SaaS-safe with user_id/workspace_id validation.
    - Ready for Dashboard/API/FastAPI integration.
    - Structured-result compatible: success, message, data, error, metadata.
    - Memory Agent compatible through prepared memory payloads.
    - Verification Agent compatible through prepared verification payloads.
    - Security Agent compatible through permission/security approval hooks.

Important Safety Notes:
    This file only prepares creative scripts and related content.
    It does not execute real messages, calls, ads, browser actions, financial actions,
    destructive actions, or publishing actions.
"""

from __future__ import annotations

import copy
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallbacks
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for isolated import/testing
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This allows the file to be imported and tested before the complete
        William/Jarvis framework exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent run() called.",
                "data": {},
                "error": None,
                "metadata": {},
            }


try:
    from agents.super_agents.creator_agent.config import CREATOR_AGENT_CONFIG  # type: ignore
except Exception:  # pragma: no cover
    CREATOR_AGENT_CONFIG = {
        "default_language": "en",
        "default_tone": "clear",
        "max_script_seconds": 300,
        "max_variations": 10,
        "blocked_claim_patterns": [
            r"\bguaranteed\s+sales\b",
            r"\bguaranteed\s+profit\b",
            r"\b100%\s+guaranteed\b",
            r"\bget\s+rich\s+quick\b",
        ],
        "default_cta_styles": ["soft", "direct", "urgent", "premium"],
        "safe_claim_mode": True,
    }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Enums and Data Structures
# ---------------------------------------------------------------------------

class ScriptFormat(str, Enum):
    """Supported script formats."""

    AD = "ad"
    SHORT = "short"
    DIALOGUE = "dialogue"
    VOICEOVER = "voiceover"
    HOOKS = "hooks"
    CTAS = "ctas"
    UGC = "ugc"
    EXPLAINER = "explainer"
    TESTIMONIAL_STYLE = "testimonial_style"


class Platform(str, Enum):
    """Supported content platforms."""

    GENERAL = "general"
    FACEBOOK = "facebook"
    INSTAGRAM = "instagram"
    TIKTOK = "tiktok"
    YOUTUBE = "youtube"
    YOUTUBE_SHORTS = "youtube_shorts"
    LINKEDIN = "linkedin"
    GOOGLE_ADS = "google_ads"
    SNAPCHAT = "snapchat"
    X = "x"
    WEBSITE = "website"
    LANDING_PAGE = "landing_page"


class ScriptTone(str, Enum):
    """Supported tones."""

    CLEAR = "clear"
    FRIENDLY = "friendly"
    PREMIUM = "premium"
    BOLD = "bold"
    EMOTIONAL = "emotional"
    PROFESSIONAL = "professional"
    CONVERSATIONAL = "conversational"
    URGENT = "urgent"
    EDUCATIONAL = "educational"
    LUXURY = "luxury"
    FUNNY = "funny"
    DRAMATIC = "dramatic"


class CTAStyle(str, Enum):
    """CTA styles."""

    SOFT = "soft"
    DIRECT = "direct"
    URGENT = "urgent"
    PREMIUM = "premium"
    CONSULTATIVE = "consultative"
    WHATSAPP = "whatsapp"
    CALL = "call"
    BOOKING = "booking"
    LEAD_FORM = "lead_form"


@dataclass
class ScriptContext:
    """
    SaaS execution context.

    Master Agent / Router should pass user_id and workspace_id whenever this
    file is used for user-specific execution.
    """

    user_id: str
    workspace_id: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    role: Optional[str] = None
    subscription_plan: Optional[str] = None
    permissions: Dict[str, Any] = field(default_factory=dict)
    source: str = "creator_agent"
    locale: str = "en"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScriptRequest:
    """Normalized creative script request."""

    topic: str
    offer: Optional[str] = None
    product_or_service: Optional[str] = None
    audience: Optional[str] = None
    platform: Union[str, Platform] = Platform.GENERAL
    script_format: Union[str, ScriptFormat] = ScriptFormat.AD
    tone: Union[str, ScriptTone] = ScriptTone.CLEAR
    language: str = "en"
    duration_seconds: int = 30
    brand_name: Optional[str] = None
    pain_points: List[str] = field(default_factory=list)
    benefits: List[str] = field(default_factory=list)
    proof_points: List[str] = field(default_factory=list)
    objections: List[str] = field(default_factory=list)
    cta: Optional[str] = None
    cta_style: Union[str, CTAStyle] = CTAStyle.DIRECT
    keywords: List[str] = field(default_factory=list)
    required_phrases: List[str] = field(default_factory=list)
    banned_phrases: List[str] = field(default_factory=list)
    hook_style: Optional[str] = None
    scene_count: Optional[int] = None
    variations: int = 1
    include_shot_notes: bool = True
    include_captions: bool = True
    include_timestamps: bool = True
    include_voice_direction: bool = True
    safe_claim_mode: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScriptLine:
    """A script line/beat."""

    timestamp: Optional[str]
    section: str
    visual: Optional[str]
    voiceover: Optional[str]
    dialogue: Optional[str]
    on_screen_text: Optional[str]
    notes: Optional[str]


@dataclass
class GeneratedScript:
    """Generated script result."""

    title: str
    format: str
    platform: str
    tone: str
    duration_seconds: int
    hook: str
    body: List[ScriptLine]
    cta: str
    captions: List[str]
    hashtags: List[str]
    alternates: List[Dict[str, Any]]
    safety_notes: List[str]
    production_notes: List[str]


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def _safe_strip(value: Any) -> str:
    """Safely convert value to stripped string."""
    if value is None:
        return ""
    return str(value).strip()


def _as_list(value: Any) -> List[str]:
    """Normalize arbitrary input into a clean string list."""
    if value is None:
        return []
    if isinstance(value, list):
        return [_safe_strip(item) for item in value if _safe_strip(item)]
    if isinstance(value, tuple):
        return [_safe_strip(item) for item in value if _safe_strip(item)]
    if isinstance(value, set):
        return [_safe_strip(item) for item in value if _safe_strip(item)]
    text = _safe_strip(value)
    if not text:
        return []
    return [item.strip() for item in re.split(r",|\n|;", text) if item.strip()]


def _normalize_enum(value: Any, enum_cls: Any, default: Any) -> str:
    """Normalize a string/enum value against an Enum."""
    if isinstance(value, enum_cls):
        return value.value
    raw = _safe_strip(value).lower()
    if not raw:
        return default.value if isinstance(default, enum_cls) else str(default)
    for member in enum_cls:
        if raw == member.value:
            return member.value
    return default.value if isinstance(default, enum_cls) else str(default)


def _word_count(text: str) -> int:
    """Count words in text."""
    return len(re.findall(r"\b[\w'-]+\b", text or ""))


def _estimate_voiceover_seconds(text: str, words_per_minute: int = 145) -> int:
    """Estimate spoken seconds from text."""
    words = _word_count(text)
    if words <= 0:
        return 0
    return max(1, round((words / max(words_per_minute, 1)) * 60))


def _chunk_time_range(index: int, total: int, duration: int) -> str:
    """Create approximate timestamp range for script beats."""
    total = max(total, 1)
    duration = max(duration, total)
    start = round((index / total) * duration)
    end = round(((index + 1) / total) * duration)
    return f"0:{start:02d}-0:{end:02d}" if duration < 60 else f"{start}s-{end}s"


# ---------------------------------------------------------------------------
# Main Class
# ---------------------------------------------------------------------------

class ScriptWriter(BaseAgent):
    """
    Creator Agent helper for ad scripts, shorts scripts, dialogue, hooks, CTAs,
    and voiceover.

    Master Agent / Router:
        Can route script-related tasks to this class using run(), handle_task(),
        or direct public methods.

    Security Agent:
        No real-world action is executed here. The security hook is still present
        for future cases where restricted claims, regulated categories, or
        publishing integrations may require approval.

    Memory Agent:
        This class prepares memory payloads only. It does not store memory by
        itself. The Master Agent or Memory Agent can consume the payload.

    Verification Agent:
        Every generated script can produce a verification payload for factual,
        brand, policy, and claim review.

    Dashboard/API:
        All public methods return structured dictionaries suitable for FastAPI
        responses or dashboard rendering.
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        agent_name: str = "ScriptWriter",
        agent_id: str = "creator_script_writer",
        config: Optional[Dict[str, Any]] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(agent_name=agent_name, agent_id=agent_id, **kwargs)
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.agent_id = agent_id
        self.config = copy.deepcopy(CREATOR_AGENT_CONFIG)
        if config:
            self.config.update(config)

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.audit_logger = audit_logger
        self.event_bus = event_bus

        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    # -----------------------------------------------------------------------
    # Required compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(self, context: Union[ScriptContext, Dict[str, Any]]) -> Tuple[bool, Optional[str], ScriptContext]:
        """
        Validate SaaS user/workspace context.

        Every user-specific task must include user_id and workspace_id to prevent
        cross-user or cross-workspace data mixing.
        """
        if isinstance(context, ScriptContext):
            ctx = context
        elif isinstance(context, dict):
            ctx = ScriptContext(
                user_id=_safe_strip(context.get("user_id")),
                workspace_id=_safe_strip(context.get("workspace_id")),
                request_id=_safe_strip(context.get("request_id")) or str(uuid.uuid4()),
                role=context.get("role"),
                subscription_plan=context.get("subscription_plan"),
                permissions=context.get("permissions") or {},
                source=context.get("source") or "creator_agent",
                locale=context.get("locale") or "en",
                metadata=context.get("metadata") or {},
            )
        else:
            ctx = ScriptContext(user_id="", workspace_id="")

        if not ctx.user_id:
            return False, "Missing required user_id for SaaS-safe execution.", ctx
        if not ctx.workspace_id:
            return False, "Missing required workspace_id for SaaS-safe execution.", ctx

        return True, None, ctx

    def _requires_security_check(self, action: str, request: Optional[ScriptRequest] = None) -> bool:
        """
        Decide whether a task requires Security Agent approval.

        Current script generation is normally non-destructive and does not
        publish or message anyone. Security checks are required for:
            - Restricted/regulated categories.
            - Unsafe claims.
            - Requests that imply impersonation, deception, or direct publishing.
        """
        restricted_keywords = [
            "financial guarantee",
            "medical cure",
            "legal advice",
            "investment return",
            "casino",
            "gambling",
            "adult",
            "weapon",
            "political persuasion",
            "impersonate",
            "fake testimonial",
            "guaranteed profit",
            "guaranteed sales",
        ]

        action_l = _safe_strip(action).lower()
        if "publish" in action_l or "send" in action_l or "call" in action_l:
            return True

        if request:
            combined = " ".join(
                [
                    request.topic or "",
                    request.offer or "",
                    request.product_or_service or "",
                    " ".join(request.benefits or []),
                    " ".join(request.proof_points or []),
                    " ".join(request.required_phrases or []),
                ]
            ).lower()
            if any(keyword in combined for keyword in restricted_keywords):
                return True

            blocked_patterns = self.config.get("blocked_claim_patterns", [])
            for pattern in blocked_patterns:
                try:
                    if re.search(pattern, combined, flags=re.IGNORECASE):
                        return True
                except re.error:
                    continue

        return False

    def _request_security_approval(
        self,
        context: ScriptContext,
        action: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval if available.

        Fallback behavior is conservative: mark as requiring manual review.
        """
        approval_payload = {
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "payload": payload,
            "created_at": _utc_now_iso(),
        }

        if self.security_agent and hasattr(self.security_agent, "approve_action"):
            try:
                result = self.security_agent.approve_action(approval_payload)
                if isinstance(result, dict):
                    return result
            except Exception as exc:
                self.logger.exception("Security approval failed: %s", exc)
                return {
                    "approved": False,
                    "requires_manual_review": True,
                    "reason": str(exc),
                    "payload": approval_payload,
                }

        return {
            "approved": False,
            "requires_manual_review": True,
            "reason": "Security Agent unavailable. Manual review required for this action.",
            "payload": approval_payload,
        }

    def _prepare_verification_payload(
        self,
        context: ScriptContext,
        request: ScriptRequest,
        script: Optional[GeneratedScript] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        The Verification Agent can use this to check:
            - Claims and factual accuracy.
            - Brand alignment.
            - Platform suitability.
            - Policy-sensitive wording.
            - CTA compliance.
        """
        return {
            "type": "creator_script_verification",
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "script_request": asdict(request),
            "script": asdict(script) if script else None,
            "checks": [
                "claim_safety",
                "factual_accuracy",
                "brand_alignment",
                "platform_fit",
                "cta_safety",
                "no_cross_workspace_data",
            ],
            "extra": extra or {},
            "created_at": _utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        context: ScriptContext,
        request: ScriptRequest,
        script: Optional[GeneratedScript] = None,
        memory_type: str = "creator_script_preference",
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        This file does not store memory directly. It only prepares a payload
        that Memory Agent can store if approved by the wider system.
        """
        reusable_preferences = {
            "brand_name": request.brand_name,
            "tone": _normalize_enum(request.tone, ScriptTone, ScriptTone.CLEAR),
            "platform": _normalize_enum(request.platform, Platform, Platform.GENERAL),
            "language": request.language,
            "cta_style": _normalize_enum(request.cta_style, CTAStyle, CTAStyle.DIRECT),
            "audience": request.audience,
            "keywords": request.keywords,
            "banned_phrases": request.banned_phrases,
        }

        return {
            "type": memory_type,
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "safe_to_store": True,
            "recommended_ttl": "long_term_if_user_approved",
            "data": {
                "preferences": reusable_preferences,
                "last_script_title": script.title if script else None,
                "last_script_format": script.format if script else None,
            },
            "created_at": _utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        context: ScriptContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit agent event for dashboard analytics or event bus.

        Safe fallback logs the event only.
        """
        event = {
            "event_name": event_name,
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "payload": payload or {},
            "created_at": _utc_now_iso(),
        }

        if self.event_bus and hasattr(self.event_bus, "emit"):
            try:
                self.event_bus.emit(event_name, event)
                return
            except Exception as exc:
                self.logger.warning("Event bus emit failed: %s", exc)

        self.logger.info("Agent event: %s", event)

    def _log_audit_event(
        self,
        context: ScriptContext,
        action: str,
        status: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event.

        This avoids mixing audit data by always including user_id/workspace_id.
        """
        audit_event = {
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "action": action,
            "status": status,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "details": details or {},
            "created_at": _utc_now_iso(),
        }

        if self.audit_logger and hasattr(self.audit_logger, "log"):
            try:
                self.audit_logger.log(audit_event)
                return
            except Exception as exc:
                self.logger.warning("Audit logger failed: %s", exc)

        self.logger.info("Audit event: %s", audit_event)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return successful structured result."""
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "version": self.VERSION,
                "created_at": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Dict[str, Any], Exception]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return error structured result."""
        if isinstance(error, Exception):
            error_value: Union[str, Dict[str, Any], None] = {
                "type": error.__class__.__name__,
                "message": str(error),
            }
        else:
            error_value = error

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": error_value,
            "metadata": {
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "version": self.VERSION,
                "created_at": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    # -----------------------------------------------------------------------
    # Public routing interfaces
    # -----------------------------------------------------------------------

    def run(self, task: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
        """
        BaseAgent-compatible entry point.

        Example task:
            {
                "action": "write_ad_script",
                "user_id": "user_123",
                "workspace_id": "workspace_123",
                "topic": "AI automation for real estate agencies",
                "offer": "Free strategy call",
                "platform": "facebook",
                "duration_seconds": 30
            }
        """
        payload = task or kwargs
        return self.handle_task(payload)

    def handle_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Master Agent / Router-compatible task handler.

        Supported actions:
            - write_ad_script
            - write_short_script
            - write_dialogue
            - write_voiceover
            - generate_hooks
            - generate_ctas
            - rewrite_script
            - analyze_script
        """
        if not isinstance(task, dict):
            return self._error_result("Task must be a dictionary.", "invalid_task_type")

        action = _safe_strip(task.get("action") or task.get("type") or "write_ad_script").lower()

        context_data = {
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "request_id": task.get("request_id"),
            "role": task.get("role"),
            "subscription_plan": task.get("subscription_plan"),
            "permissions": task.get("permissions") or {},
            "source": task.get("source") or "master_agent",
            "locale": task.get("locale") or task.get("language") or "en",
            "metadata": task.get("context_metadata") or {},
        }

        if action == "write_ad_script":
            return self.write_ad_script(context_data, task)
        if action == "write_short_script":
            return self.write_short_script(context_data, task)
        if action == "write_dialogue":
            return self.write_dialogue(context_data, task)
        if action == "write_voiceover":
            return self.write_voiceover(context_data, task)
        if action == "generate_hooks":
            return self.generate_hooks(context_data, task)
        if action == "generate_ctas":
            return self.generate_ctas(context_data, task)
        if action == "rewrite_script":
            return self.rewrite_script(context_data, task)
        if action == "analyze_script":
            return self.analyze_script(context_data, task)

        return self._error_result(
            message=f"Unsupported ScriptWriter action: {action}",
            error="unsupported_action",
            metadata={"supported_actions": self.supported_actions()},
        )

    def supported_actions(self) -> List[str]:
        """Return supported public actions for Agent Registry."""
        return [
            "write_ad_script",
            "write_short_script",
            "write_dialogue",
            "write_voiceover",
            "generate_hooks",
            "generate_ctas",
            "rewrite_script",
            "analyze_script",
        ]

    def registry_manifest(self) -> Dict[str, Any]:
        """
        Return manifest for Agent Registry / Agent Loader.

        This keeps the file discoverable by the William/Jarvis plugin-style
        future agent system.
        """
        return {
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "class_name": self.__class__.__name__,
            "module": "agents.super_agents.creator_agent.script_writer",
            "version": self.VERSION,
            "category": "creator_agent",
            "description": "Ad scripts, shorts scripts, dialogue, hooks, CTAs, and voiceover.",
            "actions": self.supported_actions(),
            "requires_user_context": True,
            "requires_workspace_context": True,
            "executes_external_actions": False,
            "security_sensitive": False,
            "memory_compatible": True,
            "verification_compatible": True,
            "dashboard_ready": True,
        }

    # -----------------------------------------------------------------------
    # Public creative methods
    # -----------------------------------------------------------------------

    def write_ad_script(
        self,
        context: Union[ScriptContext, Dict[str, Any]],
        request_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate an ad script with hook, body, CTA, captions, and production notes."""
        request = self._build_request(request_data, script_format=ScriptFormat.AD, default_duration=30)
        return self._generate_script_response(context, request, action="write_ad_script")

    def write_short_script(
        self,
        context: Union[ScriptContext, Dict[str, Any]],
        request_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate short-form video script for Reels, TikTok, YouTube Shorts, etc."""
        request = self._build_request(request_data, script_format=ScriptFormat.SHORT, default_duration=45)
        if request.platform == Platform.GENERAL.value:
            request.platform = Platform.YOUTUBE_SHORTS.value
        return self._generate_script_response(context, request, action="write_short_script")

    def write_dialogue(
        self,
        context: Union[ScriptContext, Dict[str, Any]],
        request_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate dialogue-based script between two or more speakers."""
        request = self._build_request(request_data, script_format=ScriptFormat.DIALOGUE, default_duration=60)
        return self._generate_script_response(context, request, action="write_dialogue")

    def write_voiceover(
        self,
        context: Union[ScriptContext, Dict[str, Any]],
        request_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate a voiceover-first script."""
        request = self._build_request(request_data, script_format=ScriptFormat.VOICEOVER, default_duration=30)
        return self._generate_script_response(context, request, action="write_voiceover")

    def generate_hooks(
        self,
        context: Union[ScriptContext, Dict[str, Any]],
        request_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate multiple hook options for ads or short-form videos."""
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error)

        request = self._build_request(request_data, script_format=ScriptFormat.HOOKS, default_duration=15)
        variations = max(1, min(int(request_data.get("variations", request.variations or 5)), self._max_variations()))

        if self._requires_security_check("generate_hooks", request):
            approval = self._request_security_approval(ctx, "generate_hooks", {"request": asdict(request)})
            if not approval.get("approved"):
                return self._error_result(
                    "Security approval required before generating these hooks.",
                    approval,
                    metadata={"request_id": ctx.request_id},
                )

        hooks = self._make_hooks(request, variations=variations)

        self._emit_agent_event("creator.script_writer.hooks_generated", ctx, {"count": len(hooks)})
        self._log_audit_event(ctx, "generate_hooks", "success", {"count": len(hooks)})

        verification_payload = self._prepare_verification_payload(
            ctx,
            request,
            None,
            extra={"generated_hooks": hooks},
        )
        memory_payload = self._prepare_memory_payload(ctx, request, None)

        return self._safe_result(
            "Hooks generated successfully.",
            data={
                "hooks": hooks,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def generate_ctas(
        self,
        context: Union[ScriptContext, Dict[str, Any]],
        request_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate CTA options."""
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error)

        request = self._build_request(request_data, script_format=ScriptFormat.CTAS, default_duration=15)
        variations = max(1, min(int(request_data.get("variations", request.variations or 5)), self._max_variations()))

        if self._requires_security_check("generate_ctas", request):
            approval = self._request_security_approval(ctx, "generate_ctas", {"request": asdict(request)})
            if not approval.get("approved"):
                return self._error_result(
                    "Security approval required before generating these CTAs.",
                    approval,
                    metadata={"request_id": ctx.request_id},
                )

        ctas = self._make_ctas(request, variations=variations)

        self._emit_agent_event("creator.script_writer.ctas_generated", ctx, {"count": len(ctas)})
        self._log_audit_event(ctx, "generate_ctas", "success", {"count": len(ctas)})

        verification_payload = self._prepare_verification_payload(
            ctx,
            request,
            None,
            extra={"generated_ctas": ctas},
        )
        memory_payload = self._prepare_memory_payload(ctx, request, None)

        return self._safe_result(
            "CTAs generated successfully.",
            data={
                "ctas": ctas,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def rewrite_script(
        self,
        context: Union[ScriptContext, Dict[str, Any]],
        request_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Rewrite an existing script for tone, clarity, duration, or platform fit.
        """
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error)

        original_script = _safe_strip(request_data.get("script") or request_data.get("original_script"))
        if not original_script:
            return self._error_result("Missing script to rewrite.", "missing_script")

        request = self._build_request(request_data, script_format=ScriptFormat.AD, default_duration=30)
        target_tone = _normalize_enum(request.tone, ScriptTone, ScriptTone.CLEAR)
        target_platform = _normalize_enum(request.platform, Platform, Platform.GENERAL)
        target_duration = request.duration_seconds

        if self._requires_security_check("rewrite_script", request):
            approval = self._request_security_approval(
                ctx,
                "rewrite_script",
                {"request": asdict(request), "original_script": original_script[:2000]},
            )
            if not approval.get("approved"):
                return self._error_result(
                    "Security approval required before rewriting this script.",
                    approval,
                    metadata={"request_id": ctx.request_id},
                )

        cleaned = self._remove_banned_phrases(original_script, request.banned_phrases)
        cleaned = self._soften_unsafe_claims(cleaned) if request.safe_claim_mode else cleaned

        rewritten = self._rewrite_text(
            cleaned,
            tone=target_tone,
            platform=target_platform,
            duration_seconds=target_duration,
            cta=request.cta,
        )

        analysis = self._analyze_script_text(rewritten, request)

        self._emit_agent_event("creator.script_writer.script_rewritten", ctx, {"platform": target_platform})
        self._log_audit_event(ctx, "rewrite_script", "success", {"analysis": analysis})

        verification_payload = self._prepare_verification_payload(
            ctx,
            request,
            None,
            extra={
                "original_script_excerpt": original_script[:500],
                "rewritten_script": rewritten,
                "analysis": analysis,
            },
        )
        memory_payload = self._prepare_memory_payload(ctx, request, None)

        return self._safe_result(
            "Script rewritten successfully.",
            data={
                "original_script": original_script,
                "rewritten_script": rewritten,
                "analysis": analysis,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def analyze_script(
        self,
        context: Union[ScriptContext, Dict[str, Any]],
        request_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Analyze an existing script for structure, hook strength, CTA clarity,
        estimated duration, safety notes, and improvement suggestions.
        """
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error)

        script_text = _safe_strip(request_data.get("script") or request_data.get("text"))
        if not script_text:
            return self._error_result("Missing script text to analyze.", "missing_script")

        request = self._build_request(request_data, script_format=ScriptFormat.AD, default_duration=30)
        analysis = self._analyze_script_text(script_text, request)

        self._emit_agent_event("creator.script_writer.script_analyzed", ctx, {"score": analysis.get("score")})
        self._log_audit_event(ctx, "analyze_script", "success", {"score": analysis.get("score")})

        verification_payload = self._prepare_verification_payload(
            ctx,
            request,
            None,
            extra={"script_text": script_text[:2000], "analysis": analysis},
        )

        return self._safe_result(
            "Script analyzed successfully.",
            data={
                "analysis": analysis,
                "verification_payload": verification_payload,
            },
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    # -----------------------------------------------------------------------
    # Core generation
    # -----------------------------------------------------------------------

    def _generate_script_response(
        self,
        context: Union[ScriptContext, Dict[str, Any]],
        request: ScriptRequest,
        action: str,
    ) -> Dict[str, Any]:
        """Validate context, apply security, generate script, and return structured result."""
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error)

        if self._requires_security_check(action, request):
            approval = self._request_security_approval(ctx, action, {"request": asdict(request)})
            if not approval.get("approved"):
                return self._error_result(
                    "Security approval required before generating this script.",
                    approval,
                    metadata={"request_id": ctx.request_id},
                )

        try:
            script = self._generate_script(request)
            verification_payload = self._prepare_verification_payload(ctx, request, script)
            memory_payload = self._prepare_memory_payload(ctx, request, script)

            self._emit_agent_event(
                "creator.script_writer.script_generated",
                ctx,
                {
                    "action": action,
                    "format": script.format,
                    "platform": script.platform,
                    "duration_seconds": script.duration_seconds,
                },
            )
            self._log_audit_event(
                ctx,
                action,
                "success",
                {
                    "format": script.format,
                    "platform": script.platform,
                    "title": script.title,
                },
            )

            return self._safe_result(
                "Script generated successfully.",
                data={
                    "script": self._generated_script_to_dict(script),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "request_id": ctx.request_id,
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                    "action": action,
                },
            )
        except Exception as exc:
            self.logger.exception("Script generation failed: %s", exc)
            self._log_audit_event(ctx, action, "error", {"error": str(exc)})
            return self._error_result(
                "Script generation failed.",
                exc,
                metadata={
                    "request_id": ctx.request_id,
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                    "action": action,
                },
            )

    def _generate_script(self, request: ScriptRequest) -> GeneratedScript:
        """Generate script according to requested format."""
        script_format = _normalize_enum(request.script_format, ScriptFormat, ScriptFormat.AD)
        platform = _normalize_enum(request.platform, Platform, Platform.GENERAL)
        tone = _normalize_enum(request.tone, ScriptTone, ScriptTone.CLEAR)

        if script_format == ScriptFormat.DIALOGUE.value:
            body = self._build_dialogue_body(request)
        elif script_format == ScriptFormat.VOICEOVER.value:
            body = self._build_voiceover_body(request)
        elif script_format == ScriptFormat.SHORT.value:
            body = self._build_short_body(request)
        else:
            body = self._build_ad_body(request)

        hook = self._select_hook(request)
        cta = request.cta or self._make_ctas(request, variations=1)[0]
        captions = self._make_captions(request, hook, cta) if request.include_captions else []
        hashtags = self._make_hashtags(request)
        alternates = self._make_alternates(request)
        safety_notes = self._make_safety_notes(request)
        production_notes = self._make_production_notes(request, body)

        title = self._make_title(request)

        return GeneratedScript(
            title=title,
            format=script_format,
            platform=platform,
            tone=tone,
            duration_seconds=request.duration_seconds,
            hook=hook,
            body=body,
            cta=cta,
            captions=captions,
            hashtags=hashtags,
            alternates=alternates,
            safety_notes=safety_notes,
            production_notes=production_notes,
        )

    def _build_ad_body(self, request: ScriptRequest) -> List[ScriptLine]:
        """Build ad script body."""
        beats = [
            (
                "Hook",
                self._visual_for_hook(request),
                self._select_hook(request),
                None,
                self._short_onscreen_text(self._select_hook(request)),
                "Open with a clear pattern break in the first 1-3 seconds.",
            ),
            (
                "Problem",
                self._visual_for_problem(request),
                self._problem_line(request),
                None,
                self._short_onscreen_text(self._main_pain(request)),
                "Make the audience feel understood without exaggerating claims.",
            ),
            (
                "Solution",
                self._visual_for_solution(request),
                self._solution_line(request),
                None,
                self._short_onscreen_text(request.product_or_service or request.offer or request.topic),
                "Show the product/service as the bridge from pain to outcome.",
            ),
            (
                "Benefits",
                self._visual_for_benefits(request),
                self._benefit_line(request),
                None,
                self._short_onscreen_text(self._first_benefit(request)),
                "Keep benefits concrete and easy to remember.",
            ),
            (
                "Proof",
                self._visual_for_proof(request),
                self._proof_line(request),
                None,
                self._short_onscreen_text(self._first_proof(request)),
                "Use proof carefully. Avoid unsupported guarantees.",
            ),
            (
                "CTA",
                self._visual_for_cta(request),
                request.cta or self._make_ctas(request, variations=1)[0],
                None,
                self._short_onscreen_text("Take the next step"),
                "End with one simple action.",
            ),
        ]
        return self._beats_to_lines(beats, request)

    def _build_short_body(self, request: ScriptRequest) -> List[ScriptLine]:
        """Build short-form video body."""
        beats = [
            (
                "Scroll Stopper",
                "Fast close-up, bold text overlay, quick motion or contrast shot.",
                self._select_hook(request),
                None,
                self._short_onscreen_text(self._select_hook(request)),
                "Use a fast first frame and remove any slow intro.",
            ),
            (
                "Relatable Moment",
                self._visual_for_problem(request),
                self._problem_line(request),
                None,
                self._short_onscreen_text("This is the real problem"),
                "Make it feel native to short-form platforms.",
            ),
            (
                "Simple Insight",
                "Show before/after, screen recording, result preview, or quick demo.",
                self._solution_line(request),
                None,
                self._short_onscreen_text("Here is the fix"),
                "Deliver the main idea quickly.",
            ),
            (
                "Value Stack",
                self._visual_for_benefits(request),
                self._benefit_line(request),
                None,
                self._short_onscreen_text(self._first_benefit(request)),
                "Use quick cuts every 2-4 seconds.",
            ),
            (
                "Close",
                self._visual_for_cta(request),
                request.cta or self._make_ctas(request, variations=1)[0],
                None,
                self._short_onscreen_text("Message us today"),
                "Keep CTA short enough to fit on screen.",
            ),
        ]
        return self._beats_to_lines(beats, request)

    def _build_dialogue_body(self, request: ScriptRequest) -> List[ScriptLine]:
        """Build dialogue script body."""
        speaker_a = _safe_strip(request.metadata.get("speaker_a")) or "Person A"
        speaker_b = _safe_strip(request.metadata.get("speaker_b")) or "Person B"

        hook = self._select_hook(request)
        cta = request.cta or self._make_ctas(request, variations=1)[0]

        dialogue_beats = [
            (
                "Hook",
                "Two-person scene. Start mid-conversation.",
                None,
                f"{speaker_a}: {hook}",
                self._short_onscreen_text(hook),
                "Start with curiosity or tension.",
            ),
            (
                "Problem",
                "Person B reacts with a common frustration.",
                None,
                f"{speaker_b}: {self._problem_line(request)}",
                self._short_onscreen_text(self._main_pain(request)),
                "Keep the problem specific.",
            ),
            (
                "Discovery",
                "Person A points to the solution or demo.",
                None,
                f"{speaker_a}: {self._solution_line(request)}",
                self._short_onscreen_text("Better way"),
                "Make the solution easy to understand.",
            ),
            (
                "Benefit",
                "Cut to result, dashboard, product, service, or happy customer moment.",
                None,
                f"{speaker_b}: {self._benefit_line(request)}",
                self._short_onscreen_text(self._first_benefit(request)),
                "Use natural spoken language.",
            ),
            (
                "CTA",
                "Both characters face camera or show final branded frame.",
                None,
                f"{speaker_a}: {cta}",
                self._short_onscreen_text("Get started"),
                "End with one clear next step.",
            ),
        ]

        return self._beats_to_lines(dialogue_beats, request)

    def _build_voiceover_body(self, request: ScriptRequest) -> List[ScriptLine]:
        """Build voiceover-first script body."""
        voiceover = [
            self._select_hook(request),
            self._problem_line(request),
            self._solution_line(request),
            self._benefit_line(request),
            self._proof_line(request),
            request.cta or self._make_ctas(request, variations=1)[0],
        ]

        visuals = [
            self._visual_for_hook(request),
            self._visual_for_problem(request),
            self._visual_for_solution(request),
            self._visual_for_benefits(request),
            self._visual_for_proof(request),
            self._visual_for_cta(request),
        ]

        beats = []
        for index, line in enumerate(voiceover):
            section = ["Hook", "Problem", "Solution", "Benefits", "Proof", "CTA"][index]
            beats.append(
                (
                    section,
                    visuals[index],
                    line,
                    None,
                    self._short_onscreen_text(line),
                    "Voiceover-first beat. Match visuals tightly to spoken line.",
                )
            )

        return self._beats_to_lines(beats, request)

    # -----------------------------------------------------------------------
    # Request normalization
    # -----------------------------------------------------------------------

    def _build_request(
        self,
        data: Dict[str, Any],
        script_format: ScriptFormat,
        default_duration: int,
    ) -> ScriptRequest:
        """Build normalized ScriptRequest from loose task dictionary."""
        duration = data.get("duration_seconds", data.get("duration", default_duration))
        try:
            duration_int = int(duration)
        except Exception:
            duration_int = default_duration

        max_seconds = int(self.config.get("max_script_seconds", 300))
        duration_int = max(5, min(duration_int, max_seconds))

        variations = data.get("variations", 1)
        try:
            variations_int = int(variations)
        except Exception:
            variations_int = 1
        variations_int = max(1, min(variations_int, self._max_variations()))

        topic = _safe_strip(data.get("topic") or data.get("brief") or data.get("idea"))
        product_or_service = _safe_strip(
            data.get("product_or_service")
            or data.get("service")
            or data.get("product")
            or data.get("business_type")
        )
        offer = _safe_strip(data.get("offer") or data.get("promotion") or data.get("deal"))
        audience = _safe_strip(data.get("audience") or data.get("target_audience") or data.get("avatar"))

        if not topic:
            topic = product_or_service or offer or "the offer"

        platform = _normalize_enum(data.get("platform"), Platform, Platform.GENERAL)
        tone = _normalize_enum(data.get("tone"), ScriptTone, ScriptTone.CLEAR)
        cta_style = _normalize_enum(data.get("cta_style"), CTAStyle, CTAStyle.DIRECT)

        safe_claim_mode = data.get("safe_claim_mode", self.config.get("safe_claim_mode", True))
        safe_claim_mode = bool(safe_claim_mode)

        return ScriptRequest(
            topic=topic,
            offer=offer or None,
            product_or_service=product_or_service or None,
            audience=audience or None,
            platform=platform,
            script_format=script_format.value,
            tone=tone,
            language=_safe_strip(data.get("language")) or self.config.get("default_language", "en"),
            duration_seconds=duration_int,
            brand_name=_safe_strip(data.get("brand_name") or data.get("brand")) or None,
            pain_points=_as_list(data.get("pain_points") or data.get("problems")),
            benefits=_as_list(data.get("benefits") or data.get("outcomes")),
            proof_points=_as_list(data.get("proof_points") or data.get("proof")),
            objections=_as_list(data.get("objections")),
            cta=_safe_strip(data.get("cta") or data.get("call_to_action")) or None,
            cta_style=cta_style,
            keywords=_as_list(data.get("keywords")),
            required_phrases=_as_list(data.get("required_phrases")),
            banned_phrases=_as_list(data.get("banned_phrases")),
            hook_style=_safe_strip(data.get("hook_style")) or None,
            scene_count=data.get("scene_count"),
            variations=variations_int,
            include_shot_notes=bool(data.get("include_shot_notes", True)),
            include_captions=bool(data.get("include_captions", True)),
            include_timestamps=bool(data.get("include_timestamps", True)),
            include_voice_direction=bool(data.get("include_voice_direction", True)),
            safe_claim_mode=safe_claim_mode,
            metadata=data.get("metadata") or {},
        )

    def _max_variations(self) -> int:
        """Configured max variations."""
        try:
            return max(1, int(self.config.get("max_variations", 10)))
        except Exception:
            return 10

    # -----------------------------------------------------------------------
    # Creative building blocks
    # -----------------------------------------------------------------------

    def _make_title(self, request: ScriptRequest) -> str:
        """Create script title."""
        brand = f"{request.brand_name} - " if request.brand_name else ""
        platform = _normalize_enum(request.platform, Platform, Platform.GENERAL).replace("_", " ").title()
        fmt = _normalize_enum(request.script_format, ScriptFormat, ScriptFormat.AD).replace("_", " ").title()
        return f"{brand}{platform} {fmt}: {request.topic}"

    def _select_hook(self, request: ScriptRequest) -> str:
        """Select the best hook for the request."""
        return self._make_hooks(request, variations=1)[0]

    def _make_hooks(self, request: ScriptRequest, variations: int = 5) -> List[str]:
        """Generate hook variations."""
        topic = request.topic
        audience = request.audience or "your audience"
        pain = self._main_pain(request)
        benefit = self._first_benefit(request)
        service = request.product_or_service or request.offer or topic

        templates = [
            f"Still struggling with {pain}? There is a better way.",
            f"What if {audience} could get {benefit} without making things complicated?",
            f"Most people miss this one thing about {topic}.",
            f"If {pain} is slowing you down, this is for you.",
            f"Before you spend more on {topic}, watch this.",
            f"Here is how {service} helps you move faster with less stress.",
            f"The problem is not effort. The problem is the wrong system for {topic}.",
            f"Your competitors may already be fixing {pain}. Are you?",
            f"This is the simple shift that can improve {topic}.",
            f"Stop guessing with {topic}. Start using a clearer process.",
        ]

        if request.hook_style:
            hook_style = request.hook_style.lower()
            if "question" in hook_style:
                templates.insert(0, f"Are you tired of dealing with {pain}?")
            elif "bold" in hook_style:
                templates.insert(0, f"{topic} is broken for most people. Here is the fix.")
            elif "premium" in hook_style:
                templates.insert(0, f"For serious brands, {topic} needs more than a basic approach.")
            elif "story" in hook_style:
                templates.insert(0, f"A few months ago, {pain} was the problem. Then the system changed.")

        hooks = self._apply_required_and_banned(templates, request)
        return hooks[: max(1, variations)]

    def _make_ctas(self, request: ScriptRequest, variations: int = 5) -> List[str]:
        """Generate CTA variations."""
        style = _normalize_enum(request.cta_style, CTAStyle, CTAStyle.DIRECT)
        brand = request.brand_name or "our team"
        offer = request.offer or "the next step"
        topic = request.topic

        if style == CTAStyle.SOFT.value:
            templates = [
                f"When you are ready, {brand} can help you explore {topic}.",
                f"Start with a simple conversation and see if {offer} is right for you.",
                "No pressure. Just take the next step when it makes sense.",
                f"Want to see how this could work for you? Reach out to {brand}.",
                "Save this and come back when you are ready to improve your process.",
            ]
        elif style == CTAStyle.URGENT.value:
            templates = [
                f"Message {brand} today before another week is lost to the same problem.",
                f"Book now and take action on {topic} today.",
                f"Do not wait until the problem gets bigger. Start with {offer}.",
                "Take the next step today and move with clarity.",
                f"Ready to fix this? Contact {brand} now.",
            ]
        elif style == CTAStyle.PREMIUM.value:
            templates = [
                f"Apply to work with {brand} and build a stronger system for {topic}.",
                f"Book a private consultation and see how {offer} fits your goals.",
                f"If you are serious about better results, speak with {brand}.",
                "Take the professional route. Start with a tailored strategy session.",
                f"Let {brand} help you build this properly from the start.",
            ]
        elif style == CTAStyle.WHATSAPP.value:
            templates = [
                "Send us a WhatsApp message to get started.",
                f"Message {brand} on WhatsApp and ask about {offer}.",
                "Tap WhatsApp now and tell us what you need.",
                f"Want help with {topic}? Send a WhatsApp message today.",
                "Start with one message. We will guide you from there.",
            ]
        elif style == CTAStyle.CALL.value:
            templates = [
                f"Call {brand} today and ask about {offer}.",
                "Speak with a specialist and get clear next steps.",
                f"Book a call and see how we can help with {topic}.",
                "A quick call can show you what to fix first.",
                "Call now and get a clearer plan.",
            ]
        elif style == CTAStyle.BOOKING.value:
            templates = [
                "Book your consultation today.",
                f"Schedule your session with {brand}.",
                f"Reserve your spot and start improving {topic}.",
                "Choose a time that works for you and we will guide the next step.",
                f"Book now to learn more about {offer}.",
            ]
        elif style == CTAStyle.LEAD_FORM.value:
            templates = [
                "Fill out the form and we will send the next steps.",
                f"Submit your details to learn more about {offer}.",
                "Complete the short form and our team will follow up.",
                f"Want help with {topic}? Fill out the form today.",
                "Start by sharing your details. We will take it from there.",
            ]
        else:
            templates = [
                f"Contact {brand} today and ask about {offer}.",
                f"Ready to improve {topic}? Get started now.",
                "Send a message today and get clear next steps.",
                "Click the button and take the next step.",
                f"Talk to {brand} and see what is possible.",
            ]

        ctas = self._apply_required_and_banned(templates, request)
        return ctas[: max(1, variations)]

    def _problem_line(self, request: ScriptRequest) -> str:
        """Create problem line."""
        pain = self._main_pain(request)
        audience = request.audience or "business owners"
        return f"For many {audience}, {pain} creates delays, confusion, and missed opportunities."

    def _solution_line(self, request: ScriptRequest) -> str:
        """Create solution line."""
        service = request.product_or_service or request.offer or request.topic
        brand = request.brand_name or "this solution"
        return f"{brand} helps simplify {service} with a clearer, more practical process."

    def _benefit_line(self, request: ScriptRequest) -> str:
        """Create benefits line."""
        benefits = request.benefits[:3] if request.benefits else [
            "save time",
            "reduce guesswork",
            "move with more confidence",
        ]
        if len(benefits) == 1:
            benefit_text = benefits[0]
        elif len(benefits) == 2:
            benefit_text = f"{benefits[0]} and {benefits[1]}"
        else:
            benefit_text = f"{benefits[0]}, {benefits[1]}, and {benefits[2]}"
        return f"The goal is simple: {benefit_text}."

    def _proof_line(self, request: ScriptRequest) -> str:
        """Create proof line."""
        if request.proof_points:
            proof = request.proof_points[0]
            return f"With {proof}, you can make a more confident decision."
        return "The process is built to be clear, practical, and easy to understand before you commit."

    def _main_pain(self, request: ScriptRequest) -> str:
        """Get main pain point."""
        if request.pain_points:
            return request.pain_points[0]
        if request.objections:
            return request.objections[0]
        return f"not getting enough clarity around {request.topic}"

    def _first_benefit(self, request: ScriptRequest) -> str:
        """Get first benefit."""
        if request.benefits:
            return request.benefits[0]
        return "a clearer path forward"

    def _first_proof(self, request: ScriptRequest) -> str:
        """Get first proof point."""
        if request.proof_points:
            return request.proof_points[0]
        return "clear process"

    # -----------------------------------------------------------------------
    # Visual and production helpers
    # -----------------------------------------------------------------------

    def _visual_for_hook(self, request: ScriptRequest) -> str:
        """Visual suggestion for hook."""
        return "Fast pattern-break opening with bold text overlay and a clear subject in frame."

    def _visual_for_problem(self, request: ScriptRequest) -> str:
        """Visual suggestion for problem."""
        return "Show the audience experiencing the pain point, messy workflow, slow process, or missed opportunity."

    def _visual_for_solution(self, request: ScriptRequest) -> str:
        """Visual suggestion for solution."""
        service = request.product_or_service or request.offer or request.topic
        return f"Show {service} in action with clean interface, product demo, service moment, or before/after transition."

    def _visual_for_benefits(self, request: ScriptRequest) -> str:
        """Visual suggestion for benefits."""
        return "Use quick cuts, icons, checkmarks, dashboard shots, client result scenes, or transformation visuals."

    def _visual_for_proof(self, request: ScriptRequest) -> str:
        """Visual suggestion for proof."""
        return "Show proof carefully: reviews, process screenshots, portfolio, case-study style visuals, or credibility markers."

    def _visual_for_cta(self, request: ScriptRequest) -> str:
        """Visual suggestion for CTA."""
        return "Final branded frame with one clear CTA button, phone/message cue, website, or booking instruction."

    def _beats_to_lines(
        self,
        beats: List[Tuple[str, Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]],
        request: ScriptRequest,
    ) -> List[ScriptLine]:
        """Convert beats into ScriptLine list with timestamps."""
        lines: List[ScriptLine] = []
        total = len(beats)
        for index, beat in enumerate(beats):
            section, visual, voiceover, dialogue, on_screen_text, notes = beat
            timestamp = _chunk_time_range(index, total, request.duration_seconds) if request.include_timestamps else None

            if not request.include_shot_notes:
                visual = None
                notes = None

            if not request.include_voice_direction:
                notes = None

            if request.safe_claim_mode:
                voiceover = self._soften_unsafe_claims(voiceover or "") if voiceover else voiceover
                dialogue = self._soften_unsafe_claims(dialogue or "") if dialogue else dialogue

            lines.append(
                ScriptLine(
                    timestamp=timestamp,
                    section=section,
                    visual=visual,
                    voiceover=voiceover,
                    dialogue=dialogue,
                    on_screen_text=on_screen_text,
                    notes=notes,
                )
            )

        return lines

    def _make_captions(self, request: ScriptRequest, hook: str, cta: str) -> List[str]:
        """Generate social caption options."""
        service = request.product_or_service or request.offer or request.topic
        benefit = self._first_benefit(request)
        brand = request.brand_name or "we"

        captions = [
            f"{hook} {brand} can help with {service} so you can move toward {benefit}. {cta}",
            f"If {self._main_pain(request)} has been slowing things down, this is your sign to look at {service} differently. {cta}",
            f"Better {request.topic} starts with a clearer process. {cta}",
        ]

        return self._apply_required_and_banned(captions, request)[:3]

    def _make_hashtags(self, request: ScriptRequest) -> List[str]:
        """Generate safe hashtags."""
        raw_terms = [
            request.brand_name,
            request.product_or_service,
            request.topic,
            request.platform if isinstance(request.platform, str) else request.platform.value,
            "business",
            "marketing",
            "growth",
        ]
        hashtags: List[str] = []
        for term in raw_terms:
            clean = re.sub(r"[^a-zA-Z0-9]+", "", _safe_strip(term).title())
            if clean and len(clean) <= 32:
                tag = f"#{clean}"
                if tag not in hashtags:
                    hashtags.append(tag)
        return hashtags[:8]

    def _make_alternates(self, request: ScriptRequest) -> List[Dict[str, Any]]:
        """Generate alternate hooks and CTAs."""
        return [
            {
                "type": "hooks",
                "items": self._make_hooks(request, variations=min(5, self._max_variations())),
            },
            {
                "type": "ctas",
                "items": self._make_ctas(request, variations=min(5, self._max_variations())),
            },
        ]

    def _make_safety_notes(self, request: ScriptRequest) -> List[str]:
        """Return safety notes for creative review."""
        notes = [
            "Script is prepared as creative draft only and does not publish, send, call, or run ads.",
            "Review all claims, prices, guarantees, testimonials, and regulated-category statements before publishing.",
            "Keep user_id and workspace_id attached when saving, editing, or routing this script.",
        ]

        combined = " ".join(
            [
                request.topic,
                request.offer or "",
                request.product_or_service or "",
                " ".join(request.proof_points),
            ]
        )
        if self._contains_blocked_claim(combined):
            notes.append("Potentially risky claim language detected. Verification/Security review is recommended.")

        return notes

    def _make_production_notes(self, request: ScriptRequest, body: List[ScriptLine]) -> List[str]:
        """Generate production notes."""
        voiceover_text = " ".join([line.voiceover or line.dialogue or "" for line in body])
        estimated_seconds = _estimate_voiceover_seconds(voiceover_text)

        notes = [
            f"Target duration: {request.duration_seconds} seconds.",
            f"Estimated voiceover duration: approximately {estimated_seconds} seconds.",
            "Keep first frame visually clear and avoid slow intros.",
            "Use subtitles for short-form and mobile-first placements.",
            "Keep CTA visible in the final 2-4 seconds.",
        ]

        platform = _normalize_enum(request.platform, Platform, Platform.GENERAL)
        if platform in {Platform.TIKTOK.value, Platform.INSTAGRAM.value, Platform.YOUTUBE_SHORTS.value}:
            notes.append("Use quick cuts every 2-4 seconds and keep on-screen text short.")
        if platform == Platform.LINKEDIN.value:
            notes.append("Keep wording professional, specific, and value-driven.")
        if platform in {Platform.FACEBOOK.value, Platform.GOOGLE_ADS.value}:
            notes.append("Avoid unsupported before/after promises and review ad policy before launch.")

        return notes

    # -----------------------------------------------------------------------
    # Text safety and cleanup
    # -----------------------------------------------------------------------

    def _contains_blocked_claim(self, text: str) -> bool:
        """Check configured blocked claim patterns."""
        blocked_patterns = self.config.get("blocked_claim_patterns", [])
        for pattern in blocked_patterns:
            try:
                if re.search(pattern, text or "", flags=re.IGNORECASE):
                    return True
            except re.error:
                continue
        return False

    def _soften_unsafe_claims(self, text: str) -> str:
        """Soften risky marketing claims without deleting the message."""
        if not text:
            return text

        replacements = {
            r"\bguaranteed sales\b": "a stronger opportunity for sales",
            r"\bguaranteed profit\b": "a clearer path toward profitability",
            r"\b100%\s+guaranteed\b": "designed to be reliable",
            r"\bget rich quick\b": "build a more sustainable path",
            r"\binstant results\b": "faster early progress",
            r"\bno risk\b": "lower-friction",
            r"\bwill make you\b": "can help you",
            r"\bwill get you\b": "can help you get",
        }

        updated = text
        for pattern, replacement in replacements.items():
            updated = re.sub(pattern, replacement, updated, flags=re.IGNORECASE)
        return updated

    def _remove_banned_phrases(self, text: str, banned_phrases: List[str]) -> str:
        """Remove user-specified banned phrases."""
        updated = text
        for phrase in banned_phrases:
            if phrase:
                updated = re.sub(re.escape(phrase), "", updated, flags=re.IGNORECASE)
        return re.sub(r"\s{2,}", " ", updated).strip()

    def _apply_required_and_banned(self, texts: List[str], request: ScriptRequest) -> List[str]:
        """Apply banned phrase filtering and lightly include required phrases."""
        output: List[str] = []
        for text in texts:
            cleaned = self._remove_banned_phrases(text, request.banned_phrases)
            if request.safe_claim_mode:
                cleaned = self._soften_unsafe_claims(cleaned)

            if request.required_phrases:
                required = request.required_phrases[0]
                if required.lower() not in cleaned.lower():
                    cleaned = f"{cleaned} {required}"

            cleaned = re.sub(r"\s{2,}", " ", cleaned).strip()
            if cleaned and cleaned not in output:
                output.append(cleaned)

        return output

    def _short_onscreen_text(self, text: Optional[str], max_chars: int = 42) -> str:
        """Create short on-screen text."""
        clean = _safe_strip(text)
        if len(clean) <= max_chars:
            return clean
        truncated = clean[: max_chars - 3].rstrip()
        return f"{truncated}..."

    # -----------------------------------------------------------------------
    # Rewrite and analysis
    # -----------------------------------------------------------------------

    def _rewrite_text(
        self,
        text: str,
        tone: str,
        platform: str,
        duration_seconds: int,
        cta: Optional[str] = None,
    ) -> str:
        """
        Deterministic rewrite helper.

        This avoids external model dependency while creating a clean structured
        rewrite that can be further improved by an LLM layer later.
        """
        sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]

        if not sentences:
            return text

        hook = sentences[0]
        body_sentences = sentences[1:4]
        ending = cta or (sentences[-1] if len(sentences) > 1 else "Take the next step today.")

        tone_prefix = {
            ScriptTone.PREMIUM.value: "For brands that want a more professional path:",
            ScriptTone.BOLD.value: "Here is the truth:",
            ScriptTone.FRIENDLY.value: "Here is a simple way to look at it:",
            ScriptTone.PROFESSIONAL.value: "For teams focused on better execution:",
            ScriptTone.EMOTIONAL.value: "It is frustrating when the same problem keeps holding you back.",
            ScriptTone.EDUCATIONAL.value: "The key lesson is simple:",
            ScriptTone.URGENT.value: "This is worth fixing now:",
            ScriptTone.LUXURY.value: "A better experience starts with a more refined process.",
            ScriptTone.FUNNY.value: "Nobody wakes up excited to deal with this problem.",
            ScriptTone.DRAMATIC.value: "The cost of ignoring this can be bigger than it looks.",
        }.get(tone, "Here is the simple version:")

        platform_note = ""
        if platform in {Platform.TIKTOK.value, Platform.INSTAGRAM.value, Platform.YOUTUBE_SHORTS.value}:
            platform_note = " Keep it quick, clear, and easy to follow."
        elif platform == Platform.LINKEDIN.value:
            platform_note = " Keep the message practical, credible, and business-focused."

        rewritten_parts = [f"{tone_prefix} {hook}"]
        rewritten_parts.extend(body_sentences)
        rewritten_parts.append(f"{ending}{platform_note}")

        rewritten = " ".join(rewritten_parts)
        estimated_seconds = _estimate_voiceover_seconds(rewritten)

        if estimated_seconds > duration_seconds:
            words = rewritten.split()
            target_words = max(20, int(duration_seconds * 2.35))
            rewritten = " ".join(words[:target_words]).rstrip(" ,") + ". " + (cta or "Take the next step today.")

        return rewritten.strip()

    def _analyze_script_text(self, script_text: str, request: ScriptRequest) -> Dict[str, Any]:
        """Analyze script quality and structure."""
        words = _word_count(script_text)
        estimated_seconds = _estimate_voiceover_seconds(script_text)
        has_cta = self._detect_cta(script_text)
        has_hook = self._detect_hook(script_text)
        blocked_claim = self._contains_blocked_claim(script_text)

        score = 50
        if has_hook:
            score += 15
        if has_cta:
            score += 15
        if estimated_seconds <= request.duration_seconds + 5:
            score += 10
        if words >= 20:
            score += 5
        if not blocked_claim:
            score += 5

        score = max(0, min(score, 100))

        suggestions: List[str] = []
        if not has_hook:
            suggestions.append("Add a stronger first-line hook that creates curiosity or calls out the audience pain.")
        if not has_cta:
            suggestions.append("Add one clear CTA at the end.")
        if estimated_seconds > request.duration_seconds + 5:
            suggestions.append("Shorten the script or increase the target duration.")
        if blocked_claim:
            suggestions.append("Review and soften risky claims such as guarantees or unsupported outcomes.")
        if request.platform in {Platform.TIKTOK.value, Platform.INSTAGRAM.value, Platform.YOUTUBE_SHORTS.value} and words > 120:
            suggestions.append("For short-form video, tighten the script and use faster visual beats.")

        if not suggestions:
            suggestions.append("Script structure looks usable. Review brand details and factual claims before publishing.")

        return {
            "score": score,
            "word_count": words,
            "estimated_voiceover_seconds": estimated_seconds,
            "target_duration_seconds": request.duration_seconds,
            "has_hook": has_hook,
            "has_cta": has_cta,
            "blocked_claim_detected": blocked_claim,
            "platform": _normalize_enum(request.platform, Platform, Platform.GENERAL),
            "tone": _normalize_enum(request.tone, ScriptTone, ScriptTone.CLEAR),
            "suggestions": suggestions,
        }

    def _detect_cta(self, text: str) -> bool:
        """Detect likely CTA."""
        patterns = [
            r"\bcontact\b",
            r"\bcall\b",
            r"\bmessage\b",
            r"\bbook\b",
            r"\bschedule\b",
            r"\bstart\b",
            r"\bget started\b",
            r"\bclick\b",
            r"\btap\b",
            r"\bvisit\b",
            r"\bfill out\b",
            r"\bapply\b",
        ]
        return any(re.search(pattern, text or "", flags=re.IGNORECASE) for pattern in patterns)

    def _detect_hook(self, text: str) -> bool:
        """Detect likely hook."""
        first_line = (text or "").strip().split("\n")[0][:200]
        if "?" in first_line:
            return True
        hook_words = [
            "stop",
            "still",
            "what if",
            "before",
            "most people",
            "here is",
            "truth",
            "mistake",
            "struggling",
            "tired",
        ]
        first_l = first_line.lower()
        return any(word in first_l for word in hook_words)

    # -----------------------------------------------------------------------
    # Serialization
    # -----------------------------------------------------------------------

    def _generated_script_to_dict(self, script: GeneratedScript) -> Dict[str, Any]:
        """Serialize GeneratedScript to dict."""
        return {
            "title": script.title,
            "format": script.format,
            "platform": script.platform,
            "tone": script.tone,
            "duration_seconds": script.duration_seconds,
            "hook": script.hook,
            "body": [asdict(line) for line in script.body],
            "cta": script.cta,
            "captions": script.captions,
            "hashtags": script.hashtags,
            "alternates": script.alternates,
            "safety_notes": script.safety_notes,
            "production_notes": script.production_notes,
        }


# ---------------------------------------------------------------------------
# Module-level helpers for Agent Loader / Registry
# ---------------------------------------------------------------------------

def get_agent_manifest() -> Dict[str, Any]:
    """Return registry manifest without requiring full framework boot."""
    return ScriptWriter().registry_manifest()


def build_agent(**kwargs: Any) -> ScriptWriter:
    """Factory for Agent Loader."""
    return ScriptWriter(**kwargs)


__all__ = [
    "ScriptWriter",
    "ScriptContext",
    "ScriptRequest",
    "ScriptLine",
    "GeneratedScript",
    "ScriptFormat",
    "Platform",
    "ScriptTone",
    "CTAStyle",
    "get_agent_manifest",
    "build_agent",
]