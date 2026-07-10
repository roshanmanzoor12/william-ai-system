"""
William / Jarvis Multi-Agent AI SaaS System
Creator Agent - Brand Style

File:
    agents/super_agents/creator_agent/brand_style.py

Purpose:
    Manages brand tone, style rules, colors, format rules, and reusable creative
    guidelines for Creator Agent workflows.

Architecture Compatibility:
    - BaseAgent compatible
    - Agent Registry compatible
    - Agent Loader compatible
    - Agent Router compatible
    - Master Agent routing compatible
    - Security Agent approval hook compatible
    - Verification Agent payload compatible
    - Memory Agent payload compatible
    - Dashboard/FastAPI integration ready

Safety Principles:
    - Every brand profile is scoped by user_id and workspace_id.
    - No client/workspace data is mixed.
    - Sensitive export/archive operations can go through Security Agent approval.
    - All public methods return structured dict/JSON-style results.
    - Import-safe even if future William/Jarvis modules are not created yet.
    - No hardcoded secrets.
"""

from __future__ import annotations

import copy
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


# =============================================================================
# Safe optional imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe if the real William/Jarvis BaseAgent is not
        available yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s | %s", event_name, payload)


try:
    from agents.super_agents.creator_agent.config import CREATOR_AGENT_CONFIG  # type: ignore
except Exception:  # pragma: no cover
    CREATOR_AGENT_CONFIG: Dict[str, Any] = {
        "agent_name": "Creator Agent",
        "module": "creator_agent",
        "brand_style": {
            "default_brand_status": "active",
            "max_rules_per_brand": 300,
            "max_guidelines_per_brand": 200,
            "max_palette_colors": 30,
            "audit_enabled": True,
            "memory_enabled": True,
            "verification_enabled": True,
        },
    }


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# =============================================================================
# Enums
# =============================================================================

class BrandStatus(str, Enum):
    """Supported brand profile lifecycle statuses."""

    ACTIVE = "active"
    DRAFT = "draft"
    PAUSED = "paused"
    ARCHIVED = "archived"


class ToneCategory(str, Enum):
    """Reusable brand tone categories."""

    PROFESSIONAL = "professional"
    FRIENDLY = "friendly"
    LUXURY = "luxury"
    PLAYFUL = "playful"
    BOLD = "bold"
    MINIMAL = "minimal"
    EDUCATIONAL = "educational"
    AUTHORITATIVE = "authoritative"
    CONVERSATIONAL = "conversational"
    EMOTIONAL = "emotional"


class RuleType(str, Enum):
    """Style rule categories."""

    TONE = "tone"
    COLOR = "color"
    TYPOGRAPHY = "typography"
    FORMAT = "format"
    COPYWRITING = "copywriting"
    VISUAL = "visual"
    PLATFORM = "platform"
    ACCESSIBILITY = "accessibility"
    COMPLIANCE = "compliance"


class GuidelineType(str, Enum):
    """Creative guideline types."""

    GENERAL = "general"
    SOCIAL_POST = "social_post"
    SHORT_VIDEO = "short_video"
    LONG_VIDEO = "long_video"
    THUMBNAIL = "thumbnail"
    AD_CREATIVE = "ad_creative"
    SCRIPT = "script"
    CAPTION = "caption"
    VOICEOVER = "voiceover"
    VEO_PROMPT = "veo_prompt"
    LANDING_PAGE = "landing_page"


class ContrastLevel(str, Enum):
    """Simple color contrast labels for creative guidance."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# =============================================================================
# Data models
# =============================================================================

@dataclass
class BrandColor:
    """A reusable brand color token."""

    name: str
    hex: str
    role: str = "general"
    usage: Optional[str] = None
    contrast_on_light: str = ContrastLevel.MEDIUM.value
    contrast_on_dark: str = ContrastLevel.MEDIUM.value
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TypographyRule:
    """Typography guidance for brand outputs."""

    heading_font: Optional[str] = None
    body_font: Optional[str] = None
    accent_font: Optional[str] = None
    heading_style: Optional[str] = None
    body_style: Optional[str] = None
    casing_rules: List[str] = field(default_factory=list)
    spacing_rules: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BrandRule:
    """Reusable style rule."""

    rule_id: str
    brand_id: str
    user_id: str
    workspace_id: str
    rule_type: str
    title: str
    description: str
    priority: int = 5
    enabled: bool = True
    platforms: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    avoid_examples: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: _utc_now())
    updated_at: str = field(default_factory=lambda: _utc_now())


@dataclass
class CreativeGuideline:
    """Reusable creative guideline for Creator Agent modules."""

    guideline_id: str
    brand_id: str
    user_id: str
    workspace_id: str
    guideline_type: str
    title: str
    instructions: List[str]
    format_rules: List[str] = field(default_factory=list)
    do_list: List[str] = field(default_factory=list)
    dont_list: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: _utc_now())
    updated_at: str = field(default_factory=lambda: _utc_now())


@dataclass
class BrandProfile:
    """Workspace-scoped brand style profile."""

    brand_id: str
    user_id: str
    workspace_id: str
    brand_name: str
    status: str = BrandStatus.ACTIVE.value
    tagline: Optional[str] = None
    description: Optional[str] = None
    audience: Optional[str] = None
    tone: List[str] = field(default_factory=list)
    voice_traits: List[str] = field(default_factory=list)
    banned_words: List[str] = field(default_factory=list)
    preferred_words: List[str] = field(default_factory=list)
    colors: List[Dict[str, Any]] = field(default_factory=list)
    typography: Dict[str, Any] = field(default_factory=dict)
    logo_rules: List[str] = field(default_factory=list)
    image_style: List[str] = field(default_factory=list)
    video_style: List[str] = field(default_factory=list)
    caption_style: List[str] = field(default_factory=list)
    formatting_rules: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: _utc_now())
    updated_at: str = field(default_factory=lambda: _utc_now())
    archived_at: Optional[str] = None


# =============================================================================
# Helper functions
# =============================================================================

def _utc_now() -> str:
    """Return current UTC datetime as ISO string."""

    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    """Generate readable unique IDs."""

    return f"{prefix}_{uuid.uuid4().hex[:18]}"


def _safe_text(value: Any, max_length: int = 5000) -> str:
    """Normalize text safely."""

    if value is None:
        return ""
    text = str(value).strip()
    if len(text) > max_length:
        text = text[:max_length]
    return text


def _normalize_list(values: Optional[Iterable[Any]], max_item_length: int = 300) -> List[str]:
    """Normalize list-like input into unique clean strings."""

    if not values:
        return []

    output: List[str] = []
    seen = set()

    for value in values:
        clean = _safe_text(value, max_item_length)
        if clean and clean.lower() not in seen:
            output.append(clean)
            seen.add(clean.lower())

    return output


def _normalize_platforms(platforms: Optional[Iterable[Any]]) -> List[str]:
    """Normalize platform names."""

    values = _normalize_list(platforms, 80)
    normalized: List[str] = []

    for value in values:
        clean = value.lower()
        clean = re.sub(r"\s+", "_", clean)
        clean = re.sub(r"[^a-z0-9_\-]", "", clean)
        if clean:
            normalized.append(clean)

    return sorted(set(normalized))


def _normalize_tone(values: Optional[Iterable[Any]]) -> List[str]:
    """Normalize tone values while allowing custom tone labels."""

    tones = []
    valid = {item.value for item in ToneCategory}

    for value in _normalize_list(values, 80):
        clean = value.lower().replace(" ", "_").replace("-", "_")
        clean = re.sub(r"[^a-z0-9_]", "", clean)
        if clean:
            tones.append(clean if clean in valid else value.lower())

    return sorted(set(tones))


def _validate_hex_color(value: str) -> str:
    """Validate and normalize HEX color."""

    clean = _safe_text(value, 20).upper()
    if not clean.startswith("#"):
        clean = f"#{clean}"

    if not re.match(r"^#[0-9A-F]{6}$", clean):
        raise ValueError(f"Invalid HEX color: {value}")

    return clean


def _validate_status(enum_cls: Any, value: Optional[str], default: str) -> str:
    """Validate enum-like status."""

    if not value:
        return default

    clean = _safe_text(value, 100).lower()
    valid = {item.value for item in enum_cls}

    if clean not in valid:
        raise ValueError(f"Invalid value '{value}'. Allowed values: {sorted(valid)}")

    return clean


def _copy_dict(value: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Safely deep-copy dictionary input."""

    if not value:
        return {}
    if not isinstance(value, dict):
        raise ValueError("Expected a dictionary.")
    return copy.deepcopy(value)


def _record_to_dict(record: Any) -> Dict[str, Any]:
    """Convert dataclass or dict to dictionary."""

    if hasattr(record, "__dataclass_fields__"):
        return asdict(record)
    if isinstance(record, dict):
        return copy.deepcopy(record)
    return {"value": record}


def _estimate_color_luminance(hex_color: str) -> float:
    """Estimate relative luminance for simple contrast guidance."""

    color = _validate_hex_color(hex_color).lstrip("#")
    r = int(color[0:2], 16) / 255.0
    g = int(color[2:4], 16) / 255.0
    b = int(color[4:6], 16) / 255.0
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contrast_label(hex_color: str, background: str) -> str:
    """Simple contrast label against light or dark background."""

    lum = _estimate_color_luminance(hex_color)
    if background == "light":
        if lum < 0.25:
            return ContrastLevel.HIGH.value
        if lum < 0.55:
            return ContrastLevel.MEDIUM.value
        return ContrastLevel.LOW.value

    if lum > 0.75:
        return ContrastLevel.HIGH.value
    if lum > 0.45:
        return ContrastLevel.MEDIUM.value
    return ContrastLevel.LOW.value


def _normalize_colors(colors: Optional[List[Dict[str, Any]]], max_colors: int = 30) -> List[Dict[str, Any]]:
    """Normalize brand color definitions."""

    if not colors:
        return []

    if not isinstance(colors, list):
        raise ValueError("colors must be a list of dictionaries.")

    normalized: List[Dict[str, Any]] = []
    seen = set()

    for item in colors[:max_colors]:
        if not isinstance(item, dict):
            raise ValueError("Each color must be a dictionary.")

        hex_value = _validate_hex_color(str(item.get("hex", "")))
        name = _safe_text(item.get("name") or item.get("role") or hex_value, 80)
        role = _safe_text(item.get("role") or "general", 80).lower()

        key = (name.lower(), hex_value)
        if key in seen:
            continue
        seen.add(key)

        color = BrandColor(
            name=name,
            hex=hex_value,
            role=role,
            usage=_safe_text(item.get("usage"), 500) if item.get("usage") else None,
            contrast_on_light=_contrast_label(hex_value, "light"),
            contrast_on_dark=_contrast_label(hex_value, "dark"),
            metadata=_copy_dict(item.get("metadata") or {}),
        )
        normalized.append(_record_to_dict(color))

    return normalized


# =============================================================================
# BrandStyle
# =============================================================================

class BrandStyle(BaseAgent):
    """
    Creator Agent helper for brand style systems.

    Responsibilities:
        - Create and manage brand profiles.
        - Manage tone, color, typography, format, and creative style rules.
        - Generate reusable creative guidelines for scripts, captions, thumbnails,
          VEO prompts, videos, social content, ads, and landing pages.
        - Validate generated creative content against stored brand rules.
        - Prepare Memory Agent and Verification Agent compatible payloads.
        - Stay import-safe and SaaS tenant-safe.

    Master Agent:
        Routes brand-style and creative-guideline tasks here.

    Security Agent:
        Sensitive actions such as exporting a full brand profile or archiving a
        brand can be approval-gated.

    Memory Agent:
        Useful brand preferences are prepared as memory payloads so Creator Agent
        modules can reuse consistent brand tone and visual rules.

    Verification Agent:
        Every completed mutation prepares verification payloads for safe review.

    Dashboard/API:
        Every method returns a structured result compatible with FastAPI and
        dashboard integrations.
    """

    agent_type = "creator_agent"
    module_name = "creator_agent"
    file_name = "brand_style.py"
    registry_name = "creator_agent.brand_style"
    public_name = "Brand Style"

    def __init__(
        self,
        *,
        storage: Optional[Dict[str, Dict[str, Any]]] = None,
        security_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        memory_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        verification_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        config: Optional[Dict[str, Any]] = None,
        logger_instance: Optional[logging.Logger] = None,
    ) -> None:
        super().__init__(agent_name=self.public_name, agent_id=self.registry_name)

        self.config = config or CREATOR_AGENT_CONFIG
        self.brand_config = self.config.get("brand_style", {})
        self.logger = logger_instance or logging.getLogger(self.registry_name)

        self.security_callback = security_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.memory_callback = memory_callback
        self.verification_callback = verification_callback

        self._storage: Dict[str, Dict[str, Any]] = storage if storage is not None else {
            "brands": {},
            "rules": {},
            "guidelines": {},
            "audit_events": {},
        }

        for bucket in ("brands", "rules", "guidelines", "audit_events"):
            self._storage.setdefault(bucket, {})

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(self, user_id: str, workspace_id: str) -> Tuple[bool, Optional[str]]:
        """Validate SaaS user/workspace context."""

        if not user_id or not _safe_text(user_id, 200):
            return False, "Missing required user_id."

        if not workspace_id or not _safe_text(workspace_id, 200):
            return False, "Missing required workspace_id."

        return True, None

    def _requires_security_check(self, action: str, payload: Optional[Dict[str, Any]] = None) -> bool:
        """Decide whether a Creator Agent brand-style action needs approval."""

        sensitive_actions = {
            "archive_brand",
            "export_brand_profile",
            "bulk_import_rules",
        }

        if action in sensitive_actions:
            return True

        payload = payload or {}
        if payload.get("contains_private_client_branding"):
            return True

        return False

    def _request_security_approval(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Request approval from Security Agent or fallback local policy."""

        request_payload = {
            "agent": self.registry_name,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": payload or {},
            "requested_at": _utc_now(),
        }

        if self.security_callback:
            try:
                response = self.security_callback(request_payload)
                if not isinstance(response, dict):
                    return {
                        "approved": False,
                        "reason": "Security callback returned invalid response.",
                    }
                return {
                    "approved": bool(response.get("approved", False)),
                    "reason": response.get("reason"),
                    "raw": response,
                }
            except Exception as exc:
                self.logger.exception("Security approval failed: %s", exc)
                return {
                    "approved": False,
                    "reason": f"Security approval error: {exc}",
                }

        valid, error = self._validate_task_context(user_id, workspace_id)
        if not valid:
            return {"approved": False, "reason": error}

        return {
            "approved": True,
            "reason": "Approved by local fallback policy.",
        }

    def _prepare_verification_payload(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        entity_type: str,
        entity_id: str,
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare Verification Agent compatible payload."""

        return {
            "agent": self.registry_name,
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "before": before,
            "after": after,
            "metadata": metadata or {},
            "created_at": _utc_now(),
        }

    def _prepare_memory_payload(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        memory_type: str,
        content: Dict[str, Any],
        importance: str = "normal",
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Prepare Memory Agent compatible payload."""

        return {
            "agent": self.registry_name,
            "source": "creator_agent.brand_style",
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "memory_type": memory_type,
            "importance": importance,
            "tags": tags or [],
            "content": copy.deepcopy(content),
            "created_at": _utc_now(),
        }

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """Emit event for dashboard, registry, router, or event bus."""

        safe_payload = copy.deepcopy(payload)

        try:
            if self.event_callback:
                self.event_callback(event_name, safe_payload)
            elif hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_name, safe_payload)  # type: ignore[misc]
                except Exception:
                    self.logger.debug("Base emit_event unavailable for %s", event_name)
            else:
                self.logger.debug("Agent event: %s | %s", event_name, safe_payload)
        except Exception as exc:
            self.logger.warning("Failed to emit event %s: %s", event_name, exc)

    def _log_audit_event(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        entity_type: str,
        entity_id: Optional[str] = None,
        status: str = "success",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Write audit event in a dashboard/API-ready format."""

        if not self.brand_config.get("audit_enabled", True):
            return

        audit_id = _new_id("audit")
        payload = {
            "audit_id": audit_id,
            "agent": self.registry_name,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "status": status,
            "details": details or {},
            "created_at": _utc_now(),
        }

        self._storage["audit_events"][audit_id] = payload

        try:
            if self.audit_callback:
                self.audit_callback(copy.deepcopy(payload))
        except Exception as exc:
            self.logger.warning("Audit callback failed: %s", exc)

    def _safe_result(
        self,
        *,
        success: bool = True,
        message: str = "OK",
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
            "metadata": metadata or {
                "agent": self.registry_name,
                "timestamp": _utc_now(),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Optional[str] = None,
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William/Jarvis standard structured error result."""

        return self._safe_result(
            success=False,
            message=message,
            data=data,
            error=error or message,
            metadata=metadata or {
                "agent": self.registry_name,
                "timestamp": _utc_now(),
            },
        )

    # -------------------------------------------------------------------------
    # Internal guards
    # -------------------------------------------------------------------------

    def _ensure_context_or_error(self, user_id: str, workspace_id: str) -> Optional[Dict[str, Any]]:
        valid, error = self._validate_task_context(user_id, workspace_id)
        if not valid:
            return self._error_result(message="Invalid task context.", error=error)
        return None

    def _check_security_or_error(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        if not self._requires_security_check(action, payload):
            return None

        approval = self._request_security_approval(
            action=action,
            user_id=user_id,
            workspace_id=workspace_id,
            payload=payload,
        )

        if not approval.get("approved"):
            return self._error_result(
                message="Security approval denied.",
                error=approval.get("reason", "Security Agent denied this action."),
                metadata={
                    "agent": self.registry_name,
                    "action": action,
                    "security": approval,
                    "timestamp": _utc_now(),
                },
            )

        return None

    def _belongs_to_context(self, record: Dict[str, Any], user_id: str, workspace_id: str) -> bool:
        """Ensure record belongs to exact SaaS user/workspace context."""

        return record.get("user_id") == user_id and record.get("workspace_id") == workspace_id

    def _get_brand_or_error(
        self,
        *,
        brand_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """Load one brand safely."""

        brand = self._storage["brands"].get(brand_id)

        if not brand:
            return None, self._error_result(
                message="Brand profile not found.",
                error=f"No brand exists with brand_id={brand_id}.",
            )

        if not self._belongs_to_context(brand, user_id, workspace_id):
            return None, self._error_result(
                message="Access denied.",
                error="Brand profile does not belong to this user_id/workspace_id.",
            )

        return copy.deepcopy(brand), None

    def _dispatch_post_action_payloads(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        entity_type: str,
        entity_id: str,
        before: Optional[Dict[str, Any]],
        after: Optional[Dict[str, Any]],
        memory_type: Optional[str] = None,
        memory_content: Optional[Dict[str, Any]] = None,
        memory_tags: Optional[List[str]] = None,
        event_extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare and optionally dispatch verification, memory, event, and audit payloads."""

        verification_payload = self._prepare_verification_payload(
            action=action,
            user_id=user_id,
            workspace_id=workspace_id,
            entity_type=entity_type,
            entity_id=entity_id,
            before=before,
            after=after,
            metadata=event_extra or {},
        )

        if self.verification_callback and self.brand_config.get("verification_enabled", True):
            try:
                self.verification_callback(copy.deepcopy(verification_payload))
            except Exception as exc:
                self.logger.warning("Verification callback failed: %s", exc)

        memory_payload = None
        if memory_type and memory_content and self.brand_config.get("memory_enabled", True):
            memory_payload = self._prepare_memory_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                memory_type=memory_type,
                content=memory_content,
                tags=memory_tags or [],
            )

            if self.memory_callback:
                try:
                    self.memory_callback(copy.deepcopy(memory_payload))
                except Exception as exc:
                    self.logger.warning("Memory callback failed: %s", exc)

        event_payload = {
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "timestamp": _utc_now(),
            "extra": event_extra or {},
        }

        self._emit_agent_event(f"{self.registry_name}.{action}", event_payload)

        self._log_audit_event(
            action=action,
            user_id=user_id,
            workspace_id=workspace_id,
            entity_type=entity_type,
            entity_id=entity_id,
            status="success",
            details=event_extra or {},
        )

        return {
            "verification_payload": verification_payload,
            "memory_payload": memory_payload,
            "event_payload": event_payload,
        }

    # -------------------------------------------------------------------------
    # Brand profile methods
    # -------------------------------------------------------------------------

    def create_brand_profile(
        self,
        *,
        user_id: str,
        workspace_id: str,
        brand_name: str,
        tagline: Optional[str] = None,
        description: Optional[str] = None,
        audience: Optional[str] = None,
        tone: Optional[List[str]] = None,
        voice_traits: Optional[List[str]] = None,
        banned_words: Optional[List[str]] = None,
        preferred_words: Optional[List[str]] = None,
        colors: Optional[List[Dict[str, Any]]] = None,
        typography: Optional[Dict[str, Any]] = None,
        logo_rules: Optional[List[str]] = None,
        image_style: Optional[List[str]] = None,
        video_style: Optional[List[str]] = None,
        caption_style: Optional[List[str]] = None,
        formatting_rules: Optional[List[str]] = None,
        platforms: Optional[List[str]] = None,
        status: Optional[str] = None,
        custom_fields: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a workspace-scoped brand profile."""

        context_error = self._ensure_context_or_error(user_id, workspace_id)
        if context_error:
            return context_error

        try:
            clean_name = _safe_text(brand_name, 250)
            if not clean_name:
                return self._error_result(message="Brand name is required.")

            brand_id = _new_id("brand")
            record = BrandProfile(
                brand_id=brand_id,
                user_id=_safe_text(user_id, 200),
                workspace_id=_safe_text(workspace_id, 200),
                brand_name=clean_name,
                status=_validate_status(
                    BrandStatus,
                    status,
                    self.brand_config.get("default_brand_status", BrandStatus.ACTIVE.value),
                ),
                tagline=_safe_text(tagline, 300) if tagline else None,
                description=_safe_text(description, 2500) if description else None,
                audience=_safe_text(audience, 1000) if audience else None,
                tone=_normalize_tone(tone),
                voice_traits=_normalize_list(voice_traits, 150),
                banned_words=_normalize_list(banned_words, 100),
                preferred_words=_normalize_list(preferred_words, 100),
                colors=_normalize_colors(
                    colors,
                    max_colors=int(self.brand_config.get("max_palette_colors", 30)),
                ),
                typography=_copy_dict(typography),
                logo_rules=_normalize_list(logo_rules, 500),
                image_style=_normalize_list(image_style, 500),
                video_style=_normalize_list(video_style, 500),
                caption_style=_normalize_list(caption_style, 500),
                formatting_rules=_normalize_list(formatting_rules, 500),
                platforms=_normalize_platforms(platforms),
                custom_fields=_copy_dict(custom_fields),
                metadata=_copy_dict(metadata),
            )

            record_dict = _record_to_dict(record)
            self._storage["brands"][brand_id] = record_dict

            hooks = self._dispatch_post_action_payloads(
                action="create_brand_profile",
                user_id=user_id,
                workspace_id=workspace_id,
                entity_type="brand",
                entity_id=brand_id,
                before=None,
                after=record_dict,
                memory_type="brand_profile",
                memory_content={
                    "brand_id": brand_id,
                    "brand_name": record.brand_name,
                    "tagline": record.tagline,
                    "audience": record.audience,
                    "tone": record.tone,
                    "voice_traits": record.voice_traits,
                    "colors": record.colors,
                    "platforms": record.platforms,
                },
                memory_tags=["brand", "style", "creator", *record.platforms],
            )

            return self._safe_result(
                message="Brand profile created successfully.",
                data={"brand": record_dict},
                metadata={
                    "agent": self.registry_name,
                    "action": "create_brand_profile",
                    "hooks": hooks,
                    "timestamp": _utc_now(),
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to create brand profile: %s", exc)
            self._log_audit_event(
                action="create_brand_profile",
                user_id=user_id,
                workspace_id=workspace_id,
                entity_type="brand",
                status="failed",
                details={"error": str(exc)},
            )
            return self._error_result(message="Failed to create brand profile.", error=str(exc))

    def get_brand_profile(
        self,
        *,
        user_id: str,
        workspace_id: str,
        brand_id: str,
        include_rules: bool = True,
        include_guidelines: bool = True,
    ) -> Dict[str, Any]:
        """Get one brand profile with optional rules and guidelines."""

        context_error = self._ensure_context_or_error(user_id, workspace_id)
        if context_error:
            return context_error

        brand, error = self._get_brand_or_error(
            brand_id=brand_id,
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if error:
            return error

        data: Dict[str, Any] = {"brand": brand}

        if include_rules:
            data["rules"] = self._find_rules(
                user_id=user_id,
                workspace_id=workspace_id,
                brand_id=brand_id,
            )

        if include_guidelines:
            data["guidelines"] = self._find_guidelines(
                user_id=user_id,
                workspace_id=workspace_id,
                brand_id=brand_id,
            )

        return self._safe_result(
            message="Brand profile retrieved successfully.",
            data=data,
            metadata={
                "agent": self.registry_name,
                "action": "get_brand_profile",
                "timestamp": _utc_now(),
            },
        )

    def update_brand_profile(
        self,
        *,
        user_id: str,
        workspace_id: str,
        brand_id: str,
        updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update brand profile fields safely."""

        context_error = self._ensure_context_or_error(user_id, workspace_id)
        if context_error:
            return context_error

        if not isinstance(updates, dict) or not updates:
            return self._error_result(message="Updates dictionary is required.")

        brand, error = self._get_brand_or_error(
            brand_id=brand_id,
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if error:
            return error

        assert brand is not None
        before = copy.deepcopy(brand)

        allowed_fields = {
            "brand_name",
            "status",
            "tagline",
            "description",
            "audience",
            "tone",
            "voice_traits",
            "banned_words",
            "preferred_words",
            "colors",
            "typography",
            "logo_rules",
            "image_style",
            "video_style",
            "caption_style",
            "formatting_rules",
            "platforms",
            "custom_fields",
            "metadata",
        }

        try:
            for key, value in updates.items():
                if key not in allowed_fields:
                    continue

                if key == "brand_name":
                    clean = _safe_text(value, 250)
                    if not clean:
                        raise ValueError("Brand name cannot be empty.")
                    brand[key] = clean
                elif key == "status":
                    brand[key] = _validate_status(BrandStatus, value, brand.get("status", BrandStatus.ACTIVE.value))
                elif key == "tone":
                    brand[key] = _normalize_tone(value)
                elif key in {
                    "voice_traits",
                    "banned_words",
                    "preferred_words",
                    "logo_rules",
                    "image_style",
                    "video_style",
                    "caption_style",
                    "formatting_rules",
                }:
                    brand[key] = _normalize_list(value, 500)
                elif key == "colors":
                    brand[key] = _normalize_colors(
                        value,
                        max_colors=int(self.brand_config.get("max_palette_colors", 30)),
                    )
                elif key == "platforms":
                    brand[key] = _normalize_platforms(value)
                elif key in {"typography", "custom_fields", "metadata"}:
                    brand[key] = _copy_dict(value)
                else:
                    brand[key] = _safe_text(value, 2500) if value is not None else None

            brand["updated_at"] = _utc_now()
            self._storage["brands"][brand_id] = copy.deepcopy(brand)

            hooks = self._dispatch_post_action_payloads(
                action="update_brand_profile",
                user_id=user_id,
                workspace_id=workspace_id,
                entity_type="brand",
                entity_id=brand_id,
                before=before,
                after=brand,
                memory_type="brand_profile_update",
                memory_content={
                    "brand_id": brand_id,
                    "brand_name": brand.get("brand_name"),
                    "updated_fields": sorted([key for key in updates if key in allowed_fields]),
                    "tone": brand.get("tone", []),
                    "colors": brand.get("colors", []),
                },
                memory_tags=["brand", "style", "update", *brand.get("platforms", [])],
            )

            return self._safe_result(
                message="Brand profile updated successfully.",
                data={"brand": copy.deepcopy(brand)},
                metadata={
                    "agent": self.registry_name,
                    "action": "update_brand_profile",
                    "hooks": hooks,
                    "timestamp": _utc_now(),
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to update brand profile: %s", exc)
            self._log_audit_event(
                action="update_brand_profile",
                user_id=user_id,
                workspace_id=workspace_id,
                entity_type="brand",
                entity_id=brand_id,
                status="failed",
                details={"error": str(exc)},
            )
            return self._error_result(message="Failed to update brand profile.", error=str(exc))

    def list_brand_profiles(
        self,
        *,
        user_id: str,
        workspace_id: str,
        status: Optional[str] = None,
        platform: Optional[str] = None,
        search: Optional[str] = None,
        include_archived: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List brand profiles for one user/workspace."""

        context_error = self._ensure_context_or_error(user_id, workspace_id)
        if context_error:
            return context_error

        try:
            limit = max(1, min(int(limit), 500))
            offset = max(0, int(offset))

            status_filter = _validate_status(BrandStatus, status, "") if status else None
            platform_filter = _normalize_platforms([platform])[0] if platform else None
            search_filter = _safe_text(search, 150).lower() if search else None

            brands: List[Dict[str, Any]] = []

            for brand in self._storage["brands"].values():
                if not self._belongs_to_context(brand, user_id, workspace_id):
                    continue
                if not include_archived and brand.get("status") == BrandStatus.ARCHIVED.value:
                    continue
                if status_filter and brand.get("status") != status_filter:
                    continue
                if platform_filter and platform_filter not in brand.get("platforms", []):
                    continue
                if search_filter:
                    haystack = " ".join(
                        str(brand.get(field) or "")
                        for field in ("brand_name", "tagline", "description", "audience")
                    ).lower()
                    if search_filter not in haystack:
                        continue
                brands.append(copy.deepcopy(brand))

            brands.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
            total = len(brands)
            paginated = brands[offset:offset + limit]

            return self._safe_result(
                message="Brand profiles listed successfully.",
                data={"brands": paginated},
                metadata={
                    "agent": self.registry_name,
                    "action": "list_brand_profiles",
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                    "timestamp": _utc_now(),
                },
            )

        except Exception as exc:
            return self._error_result(message="Failed to list brand profiles.", error=str(exc))

    def archive_brand(
        self,
        *,
        user_id: str,
        workspace_id: str,
        brand_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Archive a brand profile. This does not delete data."""

        context_error = self._ensure_context_or_error(user_id, workspace_id)
        if context_error:
            return context_error

        security_error = self._check_security_or_error(
            action="archive_brand",
            user_id=user_id,
            workspace_id=workspace_id,
            payload={"brand_id": brand_id, "reason": reason},
        )
        if security_error:
            return security_error

        brand, error = self._get_brand_or_error(
            brand_id=brand_id,
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if error:
            return error

        assert brand is not None
        before = copy.deepcopy(brand)

        brand["status"] = BrandStatus.ARCHIVED.value
        brand["archived_at"] = _utc_now()
        brand["updated_at"] = _utc_now()
        brand.setdefault("metadata", {})
        brand["metadata"]["archive_reason"] = _safe_text(reason, 1000) if reason else None

        self._storage["brands"][brand_id] = copy.deepcopy(brand)

        hooks = self._dispatch_post_action_payloads(
            action="archive_brand",
            user_id=user_id,
            workspace_id=workspace_id,
            entity_type="brand",
            entity_id=brand_id,
            before=before,
            after=brand,
            memory_type="brand_archive",
            memory_content={
                "brand_id": brand_id,
                "brand_name": brand.get("brand_name"),
                "archived_at": brand.get("archived_at"),
                "reason": reason,
            },
            memory_tags=["brand", "archive"],
        )

        return self._safe_result(
            message="Brand profile archived successfully.",
            data={"brand": brand},
            metadata={
                "agent": self.registry_name,
                "action": "archive_brand",
                "hooks": hooks,
                "timestamp": _utc_now(),
            },
        )

    # -------------------------------------------------------------------------
    # Rule methods
    # -------------------------------------------------------------------------

    def add_style_rule(
        self,
        *,
        user_id: str,
        workspace_id: str,
        brand_id: str,
        rule_type: str,
        title: str,
        description: str,
        priority: int = 5,
        enabled: bool = True,
        platforms: Optional[List[str]] = None,
        examples: Optional[List[str]] = None,
        avoid_examples: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Add a reusable brand style rule."""

        context_error = self._ensure_context_or_error(user_id, workspace_id)
        if context_error:
            return context_error

        brand, error = self._get_brand_or_error(
            brand_id=brand_id,
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if error:
            return error

        try:
            rules_count = len(self._find_rules(user_id=user_id, workspace_id=workspace_id, brand_id=brand_id))
            max_rules = int(self.brand_config.get("max_rules_per_brand", 300))
            if rules_count >= max_rules:
                return self._error_result(
                    message="Brand style rule limit reached.",
                    error=f"Maximum rules per brand is {max_rules}.",
                )

            clean_title = _safe_text(title, 250)
            clean_description = _safe_text(description, 2000)

            if not clean_title:
                return self._error_result(message="Rule title is required.")
            if not clean_description:
                return self._error_result(message="Rule description is required.")

            rule_id = _new_id("rule")
            record = BrandRule(
                rule_id=rule_id,
                brand_id=brand_id,
                user_id=_safe_text(user_id, 200),
                workspace_id=_safe_text(workspace_id, 200),
                rule_type=_validate_status(RuleType, rule_type, RuleType.GENERAL.value if hasattr(RuleType, "GENERAL") else RuleType.TONE.value),
                title=clean_title,
                description=clean_description,
                priority=max(1, min(int(priority), 10)),
                enabled=bool(enabled),
                platforms=_normalize_platforms(platforms),
                examples=_normalize_list(examples, 1000),
                avoid_examples=_normalize_list(avoid_examples, 1000),
                metadata=_copy_dict(metadata),
            )

            record_dict = _record_to_dict(record)
            self._storage["rules"][rule_id] = record_dict

            hooks = self._dispatch_post_action_payloads(
                action="add_style_rule",
                user_id=user_id,
                workspace_id=workspace_id,
                entity_type="brand_rule",
                entity_id=rule_id,
                before=None,
                after=record_dict,
                memory_type="brand_style_rule",
                memory_content={
                    "brand_id": brand_id,
                    "brand_name": brand.get("brand_name") if brand else None,
                    "rule_id": rule_id,
                    "rule_type": record.rule_type,
                    "title": record.title,
                    "description": record.description,
                    "platforms": record.platforms,
                },
                memory_tags=["brand", "style_rule", record.rule_type, *record.platforms],
            )

            return self._safe_result(
                message="Brand style rule added successfully.",
                data={"rule": record_dict},
                metadata={
                    "agent": self.registry_name,
                    "action": "add_style_rule",
                    "hooks": hooks,
                    "timestamp": _utc_now(),
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to add style rule: %s", exc)
            return self._error_result(message="Failed to add style rule.", error=str(exc))

    def update_style_rule(
        self,
        *,
        user_id: str,
        workspace_id: str,
        rule_id: str,
        updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update a brand style rule."""

        context_error = self._ensure_context_or_error(user_id, workspace_id)
        if context_error:
            return context_error

        rule = self._storage["rules"].get(rule_id)
        if not rule:
            return self._error_result(message="Style rule not found.")

        if not self._belongs_to_context(rule, user_id, workspace_id):
            return self._error_result(
                message="Access denied.",
                error="Style rule does not belong to this user_id/workspace_id.",
            )

        before = copy.deepcopy(rule)
        allowed_fields = {
            "rule_type",
            "title",
            "description",
            "priority",
            "enabled",
            "platforms",
            "examples",
            "avoid_examples",
            "metadata",
        }

        try:
            for key, value in updates.items():
                if key not in allowed_fields:
                    continue

                if key == "rule_type":
                    rule[key] = _validate_status(RuleType, value, rule.get("rule_type", RuleType.TONE.value))
                elif key == "title":
                    clean = _safe_text(value, 250)
                    if not clean:
                        raise ValueError("Rule title cannot be empty.")
                    rule[key] = clean
                elif key == "description":
                    clean = _safe_text(value, 2000)
                    if not clean:
                        raise ValueError("Rule description cannot be empty.")
                    rule[key] = clean
                elif key == "priority":
                    rule[key] = max(1, min(int(value), 10))
                elif key == "enabled":
                    rule[key] = bool(value)
                elif key == "platforms":
                    rule[key] = _normalize_platforms(value)
                elif key in {"examples", "avoid_examples"}:
                    rule[key] = _normalize_list(value, 1000)
                elif key == "metadata":
                    rule[key] = _copy_dict(value)

            rule["updated_at"] = _utc_now()
            self._storage["rules"][rule_id] = copy.deepcopy(rule)

            hooks = self._dispatch_post_action_payloads(
                action="update_style_rule",
                user_id=user_id,
                workspace_id=workspace_id,
                entity_type="brand_rule",
                entity_id=rule_id,
                before=before,
                after=rule,
                memory_type="brand_style_rule_update",
                memory_content={
                    "rule_id": rule_id,
                    "brand_id": rule.get("brand_id"),
                    "title": rule.get("title"),
                    "rule_type": rule.get("rule_type"),
                    "enabled": rule.get("enabled"),
                },
                memory_tags=["brand", "style_rule", "update"],
            )

            return self._safe_result(
                message="Brand style rule updated successfully.",
                data={"rule": copy.deepcopy(rule)},
                metadata={
                    "agent": self.registry_name,
                    "action": "update_style_rule",
                    "hooks": hooks,
                    "timestamp": _utc_now(),
                },
            )

        except Exception as exc:
            return self._error_result(message="Failed to update style rule.", error=str(exc))

    def list_style_rules(
        self,
        *,
        user_id: str,
        workspace_id: str,
        brand_id: str,
        rule_type: Optional[str] = None,
        platform: Optional[str] = None,
        enabled_only: bool = False,
    ) -> Dict[str, Any]:
        """List style rules for a brand."""

        context_error = self._ensure_context_or_error(user_id, workspace_id)
        if context_error:
            return context_error

        _, error = self._get_brand_or_error(
            brand_id=brand_id,
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if error:
            return error

        try:
            rule_type_filter = _validate_status(RuleType, rule_type, "") if rule_type else None
            platform_filter = _normalize_platforms([platform])[0] if platform else None

            rules = self._find_rules(
                user_id=user_id,
                workspace_id=workspace_id,
                brand_id=brand_id,
                rule_type=rule_type_filter,
                platform=platform_filter,
                enabled_only=enabled_only,
            )

            rules.sort(key=lambda item: (int(item.get("priority", 5)), item.get("created_at", "")))

            return self._safe_result(
                message="Brand style rules listed successfully.",
                data={"rules": rules},
                metadata={
                    "agent": self.registry_name,
                    "action": "list_style_rules",
                    "total": len(rules),
                    "timestamp": _utc_now(),
                },
            )

        except Exception as exc:
            return self._error_result(message="Failed to list style rules.", error=str(exc))

    # -------------------------------------------------------------------------
    # Guideline methods
    # -------------------------------------------------------------------------

    def create_creative_guideline(
        self,
        *,
        user_id: str,
        workspace_id: str,
        brand_id: str,
        guideline_type: str,
        title: str,
        instructions: List[str],
        format_rules: Optional[List[str]] = None,
        do_list: Optional[List[str]] = None,
        dont_list: Optional[List[str]] = None,
        platforms: Optional[List[str]] = None,
        examples: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create reusable creative guideline for creator workflows."""

        context_error = self._ensure_context_or_error(user_id, workspace_id)
        if context_error:
            return context_error

        brand, error = self._get_brand_or_error(
            brand_id=brand_id,
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if error:
            return error

        try:
            guideline_count = len(self._find_guidelines(user_id=user_id, workspace_id=workspace_id, brand_id=brand_id))
            max_guidelines = int(self.brand_config.get("max_guidelines_per_brand", 200))
            if guideline_count >= max_guidelines:
                return self._error_result(
                    message="Creative guideline limit reached.",
                    error=f"Maximum guidelines per brand is {max_guidelines}.",
                )

            clean_title = _safe_text(title, 250)
            clean_instructions = _normalize_list(instructions, 1000)

            if not clean_title:
                return self._error_result(message="Guideline title is required.")
            if not clean_instructions:
                return self._error_result(message="At least one instruction is required.")

            guideline_id = _new_id("guideline")
            record = CreativeGuideline(
                guideline_id=guideline_id,
                brand_id=brand_id,
                user_id=_safe_text(user_id, 200),
                workspace_id=_safe_text(workspace_id, 200),
                guideline_type=_validate_status(GuidelineType, guideline_type, GuidelineType.GENERAL.value),
                title=clean_title,
                instructions=clean_instructions,
                format_rules=_normalize_list(format_rules, 1000),
                do_list=_normalize_list(do_list, 1000),
                dont_list=_normalize_list(dont_list, 1000),
                platforms=_normalize_platforms(platforms),
                examples=_normalize_list(examples, 1500),
                metadata=_copy_dict(metadata),
            )

            record_dict = _record_to_dict(record)
            self._storage["guidelines"][guideline_id] = record_dict

            hooks = self._dispatch_post_action_payloads(
                action="create_creative_guideline",
                user_id=user_id,
                workspace_id=workspace_id,
                entity_type="creative_guideline",
                entity_id=guideline_id,
                before=None,
                after=record_dict,
                memory_type="creative_guideline",
                memory_content={
                    "brand_id": brand_id,
                    "brand_name": brand.get("brand_name") if brand else None,
                    "guideline_id": guideline_id,
                    "guideline_type": record.guideline_type,
                    "title": record.title,
                    "instructions": record.instructions,
                    "platforms": record.platforms,
                },
                memory_tags=["brand", "creative_guideline", record.guideline_type, *record.platforms],
            )

            return self._safe_result(
                message="Creative guideline created successfully.",
                data={"guideline": record_dict},
                metadata={
                    "agent": self.registry_name,
                    "action": "create_creative_guideline",
                    "hooks": hooks,
                    "timestamp": _utc_now(),
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to create creative guideline: %s", exc)
            return self._error_result(message="Failed to create creative guideline.", error=str(exc))

    def update_creative_guideline(
        self,
        *,
        user_id: str,
        workspace_id: str,
        guideline_id: str,
        updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update a creative guideline."""

        context_error = self._ensure_context_or_error(user_id, workspace_id)
        if context_error:
            return context_error

        guideline = self._storage["guidelines"].get(guideline_id)
        if not guideline:
            return self._error_result(message="Creative guideline not found.")

        if not self._belongs_to_context(guideline, user_id, workspace_id):
            return self._error_result(
                message="Access denied.",
                error="Creative guideline does not belong to this user_id/workspace_id.",
            )

        before = copy.deepcopy(guideline)
        allowed_fields = {
            "guideline_type",
            "title",
            "instructions",
            "format_rules",
            "do_list",
            "dont_list",
            "platforms",
            "examples",
            "metadata",
        }

        try:
            for key, value in updates.items():
                if key not in allowed_fields:
                    continue

                if key == "guideline_type":
                    guideline[key] = _validate_status(GuidelineType, value, guideline.get("guideline_type", GuidelineType.GENERAL.value))
                elif key == "title":
                    clean = _safe_text(value, 250)
                    if not clean:
                        raise ValueError("Guideline title cannot be empty.")
                    guideline[key] = clean
                elif key in {"instructions", "format_rules", "do_list", "dont_list"}:
                    guideline[key] = _normalize_list(value, 1000)
                    if key == "instructions" and not guideline[key]:
                        raise ValueError("Guideline instructions cannot be empty.")
                elif key == "platforms":
                    guideline[key] = _normalize_platforms(value)
                elif key == "examples":
                    guideline[key] = _normalize_list(value, 1500)
                elif key == "metadata":
                    guideline[key] = _copy_dict(value)

            guideline["updated_at"] = _utc_now()
            self._storage["guidelines"][guideline_id] = copy.deepcopy(guideline)

            hooks = self._dispatch_post_action_payloads(
                action="update_creative_guideline",
                user_id=user_id,
                workspace_id=workspace_id,
                entity_type="creative_guideline",
                entity_id=guideline_id,
                before=before,
                after=guideline,
                memory_type="creative_guideline_update",
                memory_content={
                    "guideline_id": guideline_id,
                    "brand_id": guideline.get("brand_id"),
                    "guideline_type": guideline.get("guideline_type"),
                    "title": guideline.get("title"),
                },
                memory_tags=["brand", "creative_guideline", "update"],
            )

            return self._safe_result(
                message="Creative guideline updated successfully.",
                data={"guideline": copy.deepcopy(guideline)},
                metadata={
                    "agent": self.registry_name,
                    "action": "update_creative_guideline",
                    "hooks": hooks,
                    "timestamp": _utc_now(),
                },
            )

        except Exception as exc:
            return self._error_result(message="Failed to update creative guideline.", error=str(exc))

    def list_creative_guidelines(
        self,
        *,
        user_id: str,
        workspace_id: str,
        brand_id: str,
        guideline_type: Optional[str] = None,
        platform: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List creative guidelines for a brand."""

        context_error = self._ensure_context_or_error(user_id, workspace_id)
        if context_error:
            return context_error

        _, error = self._get_brand_or_error(
            brand_id=brand_id,
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if error:
            return error

        try:
            guideline_type_filter = _validate_status(GuidelineType, guideline_type, "") if guideline_type else None
            platform_filter = _normalize_platforms([platform])[0] if platform else None

            guidelines = self._find_guidelines(
                user_id=user_id,
                workspace_id=workspace_id,
                brand_id=brand_id,
                guideline_type=guideline_type_filter,
                platform=platform_filter,
            )

            guidelines.sort(key=lambda item: item.get("created_at", ""), reverse=True)

            return self._safe_result(
                message="Creative guidelines listed successfully.",
                data={"guidelines": guidelines},
                metadata={
                    "agent": self.registry_name,
                    "action": "list_creative_guidelines",
                    "total": len(guidelines),
                    "timestamp": _utc_now(),
                },
            )

        except Exception as exc:
            return self._error_result(message="Failed to list creative guidelines.", error=str(exc))

    # -------------------------------------------------------------------------
    # Brand system generation and validation
    # -------------------------------------------------------------------------

    def generate_brand_brief(
        self,
        *,
        user_id: str,
        workspace_id: str,
        brand_id: str,
        platform: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate a reusable Creator Agent brand brief.

        Other Creator modules can consume this for scripts, VEO prompts, thumbnails,
        captions, voiceovers, and content calendars.
        """

        result = self.get_brand_profile(
            user_id=user_id,
            workspace_id=workspace_id,
            brand_id=brand_id,
            include_rules=True,
            include_guidelines=True,
        )
        if not result.get("success"):
            return result

        brand = result["data"]["brand"]
        rules = result["data"].get("rules", [])
        guidelines = result["data"].get("guidelines", [])

        platform_filter = _normalize_platforms([platform])[0] if platform else None
        content_type_filter = _validate_status(GuidelineType, content_type, "") if content_type else None

        filtered_rules = []
        for rule in rules:
            if not rule.get("enabled", True):
                continue
            if platform_filter and rule.get("platforms") and platform_filter not in rule.get("platforms", []):
                continue
            filtered_rules.append(rule)

        filtered_guidelines = []
        for guideline in guidelines:
            if platform_filter and guideline.get("platforms") and platform_filter not in guideline.get("platforms", []):
                continue
            if content_type_filter and guideline.get("guideline_type") != content_type_filter:
                continue
            filtered_guidelines.append(guideline)

        brief = {
            "brand_id": brand_id,
            "brand_name": brand.get("brand_name"),
            "tagline": brand.get("tagline"),
            "audience": brand.get("audience"),
            "tone": brand.get("tone", []),
            "voice_traits": brand.get("voice_traits", []),
            "preferred_words": brand.get("preferred_words", []),
            "banned_words": brand.get("banned_words", []),
            "colors": brand.get("colors", []),
            "typography": brand.get("typography", {}),
            "logo_rules": brand.get("logo_rules", []),
            "image_style": brand.get("image_style", []),
            "video_style": brand.get("video_style", []),
            "caption_style": brand.get("caption_style", []),
            "formatting_rules": brand.get("formatting_rules", []),
            "rules": filtered_rules,
            "guidelines": filtered_guidelines,
            "creative_summary": self._build_creative_summary(brand, filtered_rules, filtered_guidelines),
            "filters": {
                "platform": platform_filter,
                "content_type": content_type_filter,
            },
            "generated_at": _utc_now(),
        }

        return self._safe_result(
            message="Brand brief generated successfully.",
            data={"brief": brief},
            metadata={
                "agent": self.registry_name,
                "action": "generate_brand_brief",
                "timestamp": _utc_now(),
            },
        )

    def validate_content_against_brand(
        self,
        *,
        user_id: str,
        workspace_id: str,
        brand_id: str,
        content: str,
        platform: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate a piece of creative content against brand style rules.

        This is a safe deterministic check, not an external AI call.
        """

        brief_result = self.generate_brand_brief(
            user_id=user_id,
            workspace_id=workspace_id,
            brand_id=brand_id,
            platform=platform,
            content_type=content_type,
        )
        if not brief_result.get("success"):
            return brief_result

        brief = brief_result["data"]["brief"]
        clean_content = _safe_text(content, 50000)
        lower_content = clean_content.lower()

        issues: List[Dict[str, Any]] = []
        passes: List[Dict[str, Any]] = []

        for banned in brief.get("banned_words", []):
            if banned.lower() in lower_content:
                issues.append({
                    "type": "banned_word",
                    "severity": "high",
                    "message": f"Banned word or phrase found: {banned}",
                })

        for preferred in brief.get("preferred_words", []):
            if preferred.lower() in lower_content:
                passes.append({
                    "type": "preferred_word",
                    "message": f"Preferred word or phrase used: {preferred}",
                })

        for rule in brief.get("rules", []):
            description = str(rule.get("description", ""))
            avoid_examples = rule.get("avoid_examples", []) or []
            examples = rule.get("examples", []) or []

            for avoid in avoid_examples:
                if str(avoid).lower() and str(avoid).lower() in lower_content:
                    issues.append({
                        "type": "avoid_example",
                        "severity": "medium",
                        "rule_id": rule.get("rule_id"),
                        "message": f"Content matches avoid example from rule: {rule.get('title')}",
                    })

            for example in examples:
                if str(example).lower() and str(example).lower() in lower_content:
                    passes.append({
                        "type": "rule_example",
                        "rule_id": rule.get("rule_id"),
                        "message": f"Content aligns with example from rule: {rule.get('title')}",
                    })

            if rule.get("rule_type") == RuleType.FORMAT.value and "emoji" in description.lower():
                if "no emoji" in description.lower() and re.search(r"[\U0001F300-\U0001FAFF]", clean_content):
                    issues.append({
                        "type": "format",
                        "severity": "medium",
                        "rule_id": rule.get("rule_id"),
                        "message": "Emoji usage may violate a no-emoji formatting rule.",
                    })

        score = max(0, 100 - (len([i for i in issues if i.get("severity") == "high"]) * 25) - (len([i for i in issues if i.get("severity") == "medium"]) * 10))
        status = "pass" if score >= 80 and not any(i.get("severity") == "high" for i in issues) else "review"

        validation = {
            "brand_id": brand_id,
            "platform": platform,
            "content_type": content_type,
            "score": score,
            "status": status,
            "issues": issues,
            "passes": passes,
            "checked_at": _utc_now(),
        }

        return self._safe_result(
            message="Content validation completed.",
            data={"validation": validation},
            metadata={
                "agent": self.registry_name,
                "action": "validate_content_against_brand",
                "timestamp": _utc_now(),
            },
        )

    def export_brand_profile(
        self,
        *,
        user_id: str,
        workspace_id: str,
        brand_id: str,
    ) -> Dict[str, Any]:
        """Export full brand profile with rules and guidelines. Requires security approval."""

        context_error = self._ensure_context_or_error(user_id, workspace_id)
        if context_error:
            return context_error

        security_error = self._check_security_or_error(
            action="export_brand_profile",
            user_id=user_id,
            workspace_id=workspace_id,
            payload={"brand_id": brand_id},
        )
        if security_error:
            return security_error

        result = self.get_brand_profile(
            user_id=user_id,
            workspace_id=workspace_id,
            brand_id=brand_id,
            include_rules=True,
            include_guidelines=True,
        )
        if not result.get("success"):
            return result

        export_data = copy.deepcopy(result["data"])
        export_data["exported_at"] = _utc_now()
        export_data["exported_by_agent"] = self.registry_name

        self._log_audit_event(
            action="export_brand_profile",
            user_id=user_id,
            workspace_id=workspace_id,
            entity_type="brand",
            entity_id=brand_id,
            details={"includes_rules": True, "includes_guidelines": True},
        )

        return self._safe_result(
            message="Brand profile exported successfully.",
            data={"export": export_data},
            metadata={
                "agent": self.registry_name,
                "action": "export_brand_profile",
                "timestamp": _utc_now(),
            },
        )

    # -------------------------------------------------------------------------
    # Internal find/build helpers
    # -------------------------------------------------------------------------

    def _find_rules(
        self,
        *,
        user_id: str,
        workspace_id: str,
        brand_id: str,
        rule_type: Optional[str] = None,
        platform: Optional[str] = None,
        enabled_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """Find rules scoped to one brand and tenant."""

        records: List[Dict[str, Any]] = []

        for rule in self._storage["rules"].values():
            if not self._belongs_to_context(rule, user_id, workspace_id):
                continue
            if rule.get("brand_id") != brand_id:
                continue
            if rule_type and rule.get("rule_type") != rule_type:
                continue
            if platform and rule.get("platforms") and platform not in rule.get("platforms", []):
                continue
            if enabled_only and not rule.get("enabled", True):
                continue
            records.append(copy.deepcopy(rule))

        return records

    def _find_guidelines(
        self,
        *,
        user_id: str,
        workspace_id: str,
        brand_id: str,
        guideline_type: Optional[str] = None,
        platform: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Find guidelines scoped to one brand and tenant."""

        records: List[Dict[str, Any]] = []

        for guideline in self._storage["guidelines"].values():
            if not self._belongs_to_context(guideline, user_id, workspace_id):
                continue
            if guideline.get("brand_id") != brand_id:
                continue
            if guideline_type and guideline.get("guideline_type") != guideline_type:
                continue
            if platform and guideline.get("platforms") and platform not in guideline.get("platforms", []):
                continue
            records.append(copy.deepcopy(guideline))

        return records

    def _build_creative_summary(
        self,
        brand: Dict[str, Any],
        rules: List[Dict[str, Any]],
        guidelines: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Build concise creative summary for other Creator Agent modules."""

        primary_colors = [
            color for color in brand.get("colors", [])
            if str(color.get("role", "")).lower() in {"primary", "main", "brand"}
        ]

        accent_colors = [
            color for color in brand.get("colors", [])
            if str(color.get("role", "")).lower() in {"accent", "secondary", "highlight"}
        ]

        return {
            "brand_name": brand.get("brand_name"),
            "one_line_style": self._compose_one_line_style(brand),
            "tone": brand.get("tone", []),
            "must_use": brand.get("preferred_words", [])[:20],
            "must_avoid": brand.get("banned_words", [])[:20],
            "primary_colors": primary_colors or brand.get("colors", [])[:3],
            "accent_colors": accent_colors[:3],
            "top_rules": [
                {
                    "title": rule.get("title"),
                    "description": rule.get("description"),
                    "rule_type": rule.get("rule_type"),
                }
                for rule in sorted(rules, key=lambda item: int(item.get("priority", 5)))[:10]
            ],
            "top_guidelines": [
                {
                    "title": guideline.get("title"),
                    "guideline_type": guideline.get("guideline_type"),
                    "instructions": guideline.get("instructions", [])[:5],
                }
                for guideline in guidelines[:10]
            ],
        }

    def _compose_one_line_style(self, brand: Dict[str, Any]) -> str:
        """Compose a simple one-line style summary."""

        name = brand.get("brand_name") or "Brand"
        tone = ", ".join(brand.get("tone", [])[:3]) or "consistent"
        audience = brand.get("audience") or "target audience"
        return f"{name} should sound {tone} and create clear, reusable content for {audience}."

    # -------------------------------------------------------------------------
    # Registry/router compatibility
    # -------------------------------------------------------------------------

    def get_agent_manifest(self) -> Dict[str, Any]:
        """Return Agent Registry / Agent Loader compatible manifest."""

        return {
            "agent": self.registry_name,
            "class_name": self.__class__.__name__,
            "module": self.module_name,
            "file": self.file_name,
            "version": "1.0.0",
            "status": "ready",
            "capabilities": [
                "create_brand_profile",
                "get_brand_profile",
                "update_brand_profile",
                "list_brand_profiles",
                "archive_brand",
                "add_style_rule",
                "update_style_rule",
                "list_style_rules",
                "create_creative_guideline",
                "update_creative_guideline",
                "list_creative_guidelines",
                "generate_brand_brief",
                "validate_content_against_brand",
                "export_brand_profile",
            ],
            "requires_user_id": True,
            "requires_workspace_id": True,
            "security_hooks": [
                "_requires_security_check",
                "_request_security_approval",
            ],
            "verification_hooks": [
                "_prepare_verification_payload",
            ],
            "memory_hooks": [
                "_prepare_memory_payload",
            ],
            "audit_hooks": [
                "_log_audit_event",
            ],
            "created_at": _utc_now(),
        }

    def route_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generic Master Agent routing entry point.

        Expected task:
            {
                "action": "create_brand_profile",
                "user_id": "...",
                "workspace_id": "...",
                "payload": {...}
            }
        """

        if not isinstance(task, dict):
            return self._error_result(message="Task must be a dictionary.")

        action = _safe_text(task.get("action"), 120)
        user_id = _safe_text(task.get("user_id"), 200)
        workspace_id = _safe_text(task.get("workspace_id"), 200)
        payload = task.get("payload") or {}

        if not isinstance(payload, dict):
            return self._error_result(message="Task payload must be a dictionary.")

        context_error = self._ensure_context_or_error(user_id, workspace_id)
        if context_error:
            return context_error

        route_map: Dict[str, Callable[..., Dict[str, Any]]] = {
            "create_brand_profile": self.create_brand_profile,
            "get_brand_profile": self.get_brand_profile,
            "update_brand_profile": self.update_brand_profile,
            "list_brand_profiles": self.list_brand_profiles,
            "archive_brand": self.archive_brand,
            "add_style_rule": self.add_style_rule,
            "update_style_rule": self.update_style_rule,
            "list_style_rules": self.list_style_rules,
            "create_creative_guideline": self.create_creative_guideline,
            "update_creative_guideline": self.update_creative_guideline,
            "list_creative_guidelines": self.list_creative_guidelines,
            "generate_brand_brief": self.generate_brand_brief,
            "validate_content_against_brand": self.validate_content_against_brand,
            "export_brand_profile": self.export_brand_profile,
        }

        handler = route_map.get(action)
        if not handler:
            return self._error_result(
                message="Unsupported brand style action.",
                error=f"Action '{action}' is not supported by {self.registry_name}.",
                metadata={
                    "agent": self.registry_name,
                    "supported_actions": sorted(route_map.keys()),
                    "timestamp": _utc_now(),
                },
            )

        try:
            return handler(user_id=user_id, workspace_id=workspace_id, **payload)
        except TypeError as exc:
            return self._error_result(
                message="Invalid task payload for action.",
                error=str(exc),
                metadata={
                    "agent": self.registry_name,
                    "action": action,
                    "timestamp": _utc_now(),
                },
            )
        except Exception as exc:
            self.logger.exception("route_task failed for %s: %s", action, exc)
            return self._error_result(
                message="Brand style task failed.",
                error=str(exc),
                metadata={
                    "agent": self.registry_name,
                    "action": action,
                    "timestamp": _utc_now(),
                },
            )

    def health_check(self) -> Dict[str, Any]:
        """Return runtime health for dashboard and monitoring."""

        return self._safe_result(
            message="BrandStyle is healthy.",
            data={
                "agent": self.registry_name,
                "storage_buckets": {
                    bucket: len(records)
                    for bucket, records in self._storage.items()
                },
                "config_loaded": bool(self.config),
                "callbacks": {
                    "security": bool(self.security_callback),
                    "event": bool(self.event_callback),
                    "audit": bool(self.audit_callback),
                    "memory": bool(self.memory_callback),
                    "verification": bool(self.verification_callback),
                },
            },
            metadata={
                "agent": self.registry_name,
                "action": "health_check",
                "timestamp": _utc_now(),
            },
        )


# =============================================================================
# Local smoke test
# =============================================================================

def _smoke_test() -> Dict[str, Any]:
    """
    Simple local smoke test.

    Does not call external services. Uses in-memory storage only.
    """

    manager = BrandStyle()

    created = manager.create_brand_profile(
        user_id="user_test",
        workspace_id="workspace_test",
        brand_name="Digital Promotix",
        tagline="Growth-focused digital marketing and AI automation.",
        audience="Mature business owners who need premium digital growth systems.",
        tone=["professional", "friendly", "authoritative"],
        voice_traits=["clear", "confident", "helpful", "conversion-focused"],
        preferred_words=["growth", "automation", "premium", "results"],
        banned_words=["cheap", "guaranteed overnight success"],
        colors=[
            {
                "name": "Digital Promotix Purple",
                "hex": "#6400B3",
                "role": "primary",
                "usage": "Main buttons, highlights, creative accents.",
            },
            {
                "name": "Dark Background",
                "hex": "#101010",
                "role": "background",
                "usage": "Premium dark layouts.",
            },
            {
                "name": "Light Gray",
                "hex": "#D9D9D9",
                "role": "neutral",
                "usage": "Secondary surfaces and subtle dividers.",
            },
        ],
        typography={
            "heading_font": "Inter",
            "body_font": "Inter",
            "heading_style": "bold, clean, modern",
        },
        formatting_rules=[
            "Use clear headings.",
            "Keep CTAs direct.",
            "Avoid overcomplicated sentences.",
        ],
        platforms=["youtube", "facebook", "instagram", "linkedin"],
    )

    if not created["success"]:
        return created

    brand_id = created["data"]["brand"]["brand_id"]

    rule = manager.add_style_rule(
        user_id="user_test",
        workspace_id="workspace_test",
        brand_id=brand_id,
        rule_type="copywriting",
        title="Use premium positioning",
        description="Frame the offer around business growth, automation, and mature client value.",
        priority=1,
        examples=["Scale your business with smarter automation."],
        avoid_examples=["Cheap website for everyone."],
    )

    if not rule["success"]:
        return rule

    guideline = manager.create_creative_guideline(
        user_id="user_test",
        workspace_id="workspace_test",
        brand_id=brand_id,
        guideline_type="ad_creative",
        title="Premium ad creative style",
        instructions=[
            "Lead with a clear business pain point.",
            "Show the transformation clearly.",
            "Use one direct CTA.",
        ],
        do_list=[
            "Use premium visual spacing.",
            "Use purple as the main accent.",
        ],
        dont_list=[
            "Do not make unrealistic guarantees.",
            "Do not overuse emojis.",
        ],
        platforms=["facebook", "instagram"],
    )

    if not guideline["success"]:
        return guideline

    return manager.generate_brand_brief(
        user_id="user_test",
        workspace_id="workspace_test",
        brand_id=brand_id,
        platform="facebook",
        content_type="ad_creative",
    )


if __name__ == "__main__":  # pragma: no cover
    print(_smoke_test())


__all__ = [
    "BrandStyle",
    "BrandProfile",
    "BrandColor",
    "TypographyRule",
    "BrandRule",
    "CreativeGuideline",
    "BrandStatus",
    "ToneCategory",
    "RuleType",
    "GuidelineType",
    "ContrastLevel",
]