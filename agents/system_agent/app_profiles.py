"""
agents/system_agent/app_profiles.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    App-specific profiles for Chrome, VS Code, Photoshop, WhatsApp,
    banking apps, and future desktop/mobile/web applications.

This file is part of the System Agent module.

It provides:
    - App profile registry
    - App-specific risk rules
    - Allowed/blocked action checks
    - Sensitive app classification
    - Security Agent approval payloads
    - Verification Agent payloads
    - Memory Agent payloads
    - Audit/event hooks
    - SaaS user/workspace isolation support

Important:
    This file does NOT launch, control, click, message, call, browse,
    automate, or execute actions directly.

    It only describes and validates app profiles so other System Agent
    files such as app_controller.py, automation.py, gesture_control.py,
    desktop_vision.py, and device_controls.py can make safer decisions
    before execution.

Architecture Compatibility:
    - Master Agent routing
    - BaseAgent compatibility
    - Agent Registry / Agent Loader safe import
    - Security Agent approval flow
    - Verification Agent payload preparation
    - Memory Agent payload compatibility
    - Dashboard/API audit logging
    - SaaS user/workspace isolation
"""

from __future__ import annotations

import enum
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union


# -------------------------------------------------------------------------
# Safe optional imports for William/Jarvis architecture compatibility
# -------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe if the real William BaseAgent has not
        been generated yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)


try:
    from core.context import AgentContext  # type: ignore
except Exception:  # pragma: no cover
    class AgentContext:
        """
        Fallback AgentContext stub.

        The real AgentContext should provide user_id, workspace_id,
        task_id, role, permissions, and metadata.
        """

        def __init__(self, **kwargs: Any) -> None:
            self.__dict__.update(kwargs)


try:
    from core.config import settings  # type: ignore
except Exception:  # pragma: no cover
    class _FallbackSettings:
        SYSTEM_AGENT_APP_PROFILES_STRICT_MODE = True
        SYSTEM_AGENT_APP_PROFILES_AUDIT_ENABLED = True
        SYSTEM_AGENT_APP_PROFILES_MEMORY_ENABLED = True
        SYSTEM_AGENT_APP_PROFILES_VERIFICATION_ENABLED = True
        SYSTEM_AGENT_APP_PROFILES_ALLOW_UNKNOWN_APPS = False
        SYSTEM_AGENT_APP_PROFILES_REQUIRE_SECURITY_FOR_SENSITIVE = True

    settings = _FallbackSettings()


# -------------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------------

logger = logging.getLogger("william.system_agent.app_profiles")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# -------------------------------------------------------------------------
# Enums
# -------------------------------------------------------------------------

class AppRiskLevel(str, enum.Enum):
    """
    App profile risk levels.
    """

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"


class AppCategory(str, enum.Enum):
    """
    Supported app categories.
    """

    BROWSER = "browser"
    CODE_EDITOR = "code_editor"
    DESIGN = "design"
    MESSAGING = "messaging"
    BANKING = "banking"
    FINANCE = "finance"
    SYSTEM = "system"
    OFFICE = "office"
    MEDIA = "media"
    TERMINAL = "terminal"
    SECURITY = "security"
    CLOUD_STORAGE = "cloud_storage"
    SOCIAL_MEDIA = "social_media"
    ECOMMERCE = "ecommerce"
    CRM = "crm"
    UNKNOWN = "unknown"


class AppActionType(str, enum.Enum):
    """
    Normalized action types other System Agent files can check.
    """

    OPEN_APP = "open_app"
    CLOSE_APP = "close_app"
    FOCUS_APP = "focus_app"
    READ_WINDOW_TITLE = "read_window_title"
    READ_SCREEN = "read_screen"
    SCREENSHOT = "screenshot"
    CLICK = "click"
    TYPE_TEXT = "type_text"
    HOTKEY = "hotkey"
    PASTE = "paste"
    COPY = "copy"
    OPEN_URL = "open_url"
    DOWNLOAD = "download"
    UPLOAD = "upload"
    SEND_MESSAGE = "send_message"
    MAKE_CALL = "make_call"
    PAYMENT = "payment"
    TRANSFER_FUNDS = "transfer_funds"
    DELETE_DATA = "delete_data"
    CHANGE_SETTINGS = "change_settings"
    RUN_COMMAND = "run_command"
    INSTALL_EXTENSION = "install_extension"
    ACCESS_SECRETS = "access_secrets"
    UNKNOWN = "unknown"


class ProfileDecision(str, enum.Enum):
    """
    Decision returned by app profile checks.
    """

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_SECURITY_APPROVAL = "require_security_approval"
    REQUIRE_USER_CONFIRMATION = "require_user_confirmation"
    REQUIRE_ADMIN_APPROVAL = "require_admin_approval"
    UNKNOWN = "unknown"


class AppSensitivity(str, enum.Enum):
    """
    Privacy/security sensitivity of an app.
    """

    PUBLIC = "public"
    WORKSPACE = "workspace"
    PERSONAL = "personal"
    CONFIDENTIAL = "confidential"
    FINANCIAL = "financial"
    SECURITY_CRITICAL = "security_critical"
    UNKNOWN = "unknown"


# -------------------------------------------------------------------------
# Data structures
# -------------------------------------------------------------------------

@dataclass
class AppProfile:
    """
    One app-specific profile.

    Attributes:
        app_id:
            Stable internal app identifier.
        display_name:
            Human-friendly app name.
        category:
            App category.
        aliases:
            Names/process names/package names/user-facing names.
        risk_level:
            Default app risk level.
        sensitivity:
            Privacy/security sensitivity.
        allowed_actions:
            Actions allowed locally when context is valid.
        blocked_actions:
            Actions blocked by profile.
        security_required_actions:
            Actions requiring Security Agent approval.
        confirmation_required_actions:
            Actions requiring user confirmation.
        admin_required_actions:
            Actions requiring admin/workspace-owner role.
        process_names:
            Desktop process names.
        package_names:
            Mobile package names.
        url_patterns:
            Known URLs/domains for browser/web apps.
        notes:
            Human-readable profile notes for dashboard/API.
        metadata:
            Future extension data.
    """

    app_id: str
    display_name: str
    category: AppCategory
    aliases: Set[str] = field(default_factory=set)
    risk_level: AppRiskLevel = AppRiskLevel.UNKNOWN
    sensitivity: AppSensitivity = AppSensitivity.UNKNOWN
    allowed_actions: Set[AppActionType] = field(default_factory=set)
    blocked_actions: Set[AppActionType] = field(default_factory=set)
    security_required_actions: Set[AppActionType] = field(default_factory=set)
    confirmation_required_actions: Set[AppActionType] = field(default_factory=set)
    admin_required_actions: Set[AppActionType] = field(default_factory=set)
    process_names: Set[str] = field(default_factory=set)
    package_names: Set[str] = field(default_factory=set)
    url_patterns: Set[str] = field(default_factory=set)
    notes: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AppProfileRequest:
    """
    Normalized request for checking an app action.
    """

    app_name: str
    action: AppActionType
    user_id: Optional[Union[str, int]] = None
    workspace_id: Optional[Union[str, int]] = None
    role: Optional[str] = None
    task_id: Optional[str] = None
    app_id: Optional[str] = None
    resource: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    requested_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class AppProfileEvaluation:
    """
    Internal evaluation result before final structured response.
    """

    request_id: str
    decision: ProfileDecision
    allowed: bool
    app_found: bool
    app_id: Optional[str]
    app_name: str
    action: AppActionType
    risk_level: AppRiskLevel
    sensitivity: AppSensitivity
    message: str
    requires_security: bool = False
    requires_user_confirmation: bool = False
    requires_admin: bool = False
    reasons: List[str] = field(default_factory=list)
    violations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    security_payload: Optional[Dict[str, Any]] = None
    verification_payload: Optional[Dict[str, Any]] = None
    memory_payload: Optional[Dict[str, Any]] = None
    audit_event: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# -------------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------------

DEFAULT_ADMIN_ROLES: Set[str] = {
    "owner",
    "admin",
    "workspace_owner",
    "super_admin",
}

DEFAULT_SAFE_ACTIONS: Set[AppActionType] = {
    AppActionType.OPEN_APP,
    AppActionType.CLOSE_APP,
    AppActionType.FOCUS_APP,
    AppActionType.READ_WINDOW_TITLE,
}

DEFAULT_VIEW_ACTIONS: Set[AppActionType] = {
    AppActionType.READ_SCREEN,
    AppActionType.SCREENSHOT,
    AppActionType.COPY,
}

DEFAULT_INTERACTION_ACTIONS: Set[AppActionType] = {
    AppActionType.CLICK,
    AppActionType.TYPE_TEXT,
    AppActionType.HOTKEY,
    AppActionType.PASTE,
    AppActionType.OPEN_URL,
}

DEFAULT_RISKY_ACTIONS: Set[AppActionType] = {
    AppActionType.DOWNLOAD,
    AppActionType.UPLOAD,
    AppActionType.SEND_MESSAGE,
    AppActionType.MAKE_CALL,
    AppActionType.DELETE_DATA,
    AppActionType.CHANGE_SETTINGS,
    AppActionType.RUN_COMMAND,
    AppActionType.INSTALL_EXTENSION,
    AppActionType.ACCESS_SECRETS,
}

DEFAULT_BLOCKED_FINANCIAL_ACTIONS: Set[AppActionType] = {
    AppActionType.PAYMENT,
    AppActionType.TRANSFER_FUNDS,
    AppActionType.ACCESS_SECRETS,
}

DEFAULT_SECRET_KEYS: Set[str] = {
    "password",
    "secret",
    "token",
    "api_key",
    "private_key",
    "credential",
    "authorization",
    "cookie",
    "session",
}


# -------------------------------------------------------------------------
# AppProfiles
# -------------------------------------------------------------------------

class AppProfiles(BaseAgent):
    """
    App-specific profile manager for System Agent.

    This class gives app_controller.py, desktop_vision.py, gesture_control.py,
    automation.py, and device_controls.py a safe way to understand app-specific
    risks before taking action.

    It does not execute actions directly.
    """

    agent_name = "AppProfiles"
    agent_module = "System Agent"
    version = "1.0.0"

    def __init__(
        self,
        *,
        strict_mode: Optional[bool] = None,
        allow_unknown_apps: Optional[bool] = None,
        profiles: Optional[List[AppProfile]] = None,
        audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        security_requester: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> None:
        """
        Initialize AppProfiles.

        Args:
            strict_mode:
                If True, missing user/workspace context blocks checks.
            allow_unknown_apps:
                If True, unknown apps are allowed only with Security Agent review.
            profiles:
                Optional custom app profiles.
            audit_sink:
                Optional audit sink for dashboard/API.
            event_sink:
                Optional event sink for Agent events.
            security_requester:
                Optional callable for Security Agent approval requests.
        """

        super().__init__(agent_name=self.agent_name)

        self.strict_mode = (
            bool(strict_mode)
            if strict_mode is not None
            else bool(getattr(settings, "SYSTEM_AGENT_APP_PROFILES_STRICT_MODE", True))
        )

        self.allow_unknown_apps = (
            bool(allow_unknown_apps)
            if allow_unknown_apps is not None
            else bool(getattr(settings, "SYSTEM_AGENT_APP_PROFILES_ALLOW_UNKNOWN_APPS", False))
        )

        self.audit_enabled = bool(
            getattr(settings, "SYSTEM_AGENT_APP_PROFILES_AUDIT_ENABLED", True)
        )
        self.memory_enabled = bool(
            getattr(settings, "SYSTEM_AGENT_APP_PROFILES_MEMORY_ENABLED", True)
        )
        self.verification_enabled = bool(
            getattr(settings, "SYSTEM_AGENT_APP_PROFILES_VERIFICATION_ENABLED", True)
        )

        self.require_security_for_sensitive = bool(
            getattr(settings, "SYSTEM_AGENT_APP_PROFILES_REQUIRE_SECURITY_FOR_SENSITIVE", True)
        )

        self.audit_sink = audit_sink
        self.event_sink = event_sink
        self.security_requester = security_requester

        self._profiles_by_id: Dict[str, AppProfile] = {}
        self._alias_index: Dict[str, str] = {}

        for profile in profiles or self._default_profiles():
            self.register_profile(profile, emit_event=False)

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def check_app_action(
        self,
        app_name: str,
        action: Union[str, AppActionType],
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        task_id: Optional[str] = None,
        app_id: Optional[str] = None,
        resource: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        context: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Check whether a specific action is allowed for an app profile.

        Returns:
            William/Jarvis structured dict with:
                success, message, data, error, metadata
        """

        started = time.time()
        request_id = self._new_id("app_profile")

        try:
            request = self._build_request(
                app_name=app_name,
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                role=role,
                task_id=task_id,
                app_id=app_id,
                resource=resource,
                payload=payload or {},
                metadata=metadata or {},
                context=context,
            )

            validation = self._validate_task_context(request)
            if not validation["success"]:
                evaluation = AppProfileEvaluation(
                    request_id=request_id,
                    decision=ProfileDecision.DENY,
                    allowed=False,
                    app_found=False,
                    app_id=request.app_id,
                    app_name=request.app_name,
                    action=request.action,
                    risk_level=AppRiskLevel.UNKNOWN,
                    sensitivity=AppSensitivity.UNKNOWN,
                    message=validation["message"],
                    violations=validation.get("data", {}).get("violations", []),
                    metadata={
                        "stage": "context_validation",
                        "duration_ms": self._duration_ms(started),
                    },
                )
                return self._finalize_evaluation(request, evaluation)

            profile = self.get_profile(
                request.app_name,
                app_id=request.app_id,
            ).get("data", {}).get("profile_object")

            evaluation = self._evaluate_app_action(
                request=request,
                profile=profile,
                request_id=request_id,
            )
            evaluation.metadata["duration_ms"] = self._duration_ms(started)

            return self._finalize_evaluation(request, evaluation)

        except Exception as exc:
            logger.exception("App profile action check failed.")
            return self._error_result(
                message="App profile check failed unexpectedly.",
                error=str(exc),
                metadata={
                    "request_id": request_id,
                    "app_name": app_name,
                    "action": str(action),
                    "duration_ms": self._duration_ms(started),
                },
            )

    def is_action_allowed(
        self,
        app_name: str,
        action: Union[str, AppActionType],
        **kwargs: Any,
    ) -> bool:
        """
        Convenience boolean check.

        Returns True only when action is locally allowed without additional
        Security Agent approval.
        """

        result = self.check_app_action(app_name, action, **kwargs)
        data = result.get("data", {})
        return bool(
            result.get("success")
            and data.get("allowed") is True
            and data.get("decision") == ProfileDecision.ALLOW.value
        )

    def get_profile(
        self,
        app_name: Optional[str] = None,
        *,
        app_id: Optional[str] = None,
        include_object: bool = True,
    ) -> Dict[str, Any]:
        """
        Fetch an app profile by app_id, display name, alias, process, or package.
        """

        profile: Optional[AppProfile] = None

        if app_id:
            profile = self._profiles_by_id.get(self._normalize_key(app_id))

        if profile is None and app_name:
            normalized = self._normalize_key(app_name)
            resolved_id = self._alias_index.get(normalized)
            if resolved_id:
                profile = self._profiles_by_id.get(resolved_id)

        if profile is None:
            return self._safe_result(
                success=False,
                message="App profile not found.",
                data={
                    "profile": None,
                    "profile_object": None,
                    "app_name": app_name,
                    "app_id": app_id,
                },
            )

        data = {
            "profile": self._serialize_profile(profile),
            "app_name": app_name,
            "app_id": profile.app_id,
        }

        if include_object:
            data["profile_object"] = profile

        return self._safe_result(
            message="App profile found.",
            data=data,
        )

    def list_profiles(
        self,
        *,
        category: Optional[Union[str, AppCategory]] = None,
        sensitivity: Optional[Union[str, AppSensitivity]] = None,
        include_sensitive: bool = True,
    ) -> Dict[str, Any]:
        """
        List registered app profiles for dashboard/API use.
        """

        category_filter = self._normalize_category(category) if category else None
        sensitivity_filter = self._normalize_sensitivity(sensitivity) if sensitivity else None

        profiles: List[Dict[str, Any]] = []

        for profile in self._profiles_by_id.values():
            if category_filter and profile.category != category_filter:
                continue

            if sensitivity_filter and profile.sensitivity != sensitivity_filter:
                continue

            if not include_sensitive and profile.sensitivity in {
                AppSensitivity.FINANCIAL,
                AppSensitivity.SECURITY_CRITICAL,
                AppSensitivity.CONFIDENTIAL,
            }:
                continue

            profiles.append(self._serialize_profile(profile))

        return self._safe_result(
            message="App profiles loaded.",
            data={
                "profiles": sorted(profiles, key=lambda item: item["display_name"].lower()),
                "total": len(profiles),
            },
        )

    def register_profile(
        self,
        profile: AppProfile,
        *,
        emit_event: bool = True,
    ) -> Dict[str, Any]:
        """
        Register or replace an app profile.

        This supports plugin-style future apps and dashboard-managed profiles.
        """

        if not isinstance(profile, AppProfile):
            return self._error_result(
                message="Invalid app profile.",
                error="profile must be an AppProfile instance.",
            )

        if not profile.app_id:
            return self._error_result(
                message="Invalid app profile.",
                error="app_id is required.",
            )

        normalized_id = self._normalize_key(profile.app_id)
        profile.app_id = normalized_id

        self._profiles_by_id[normalized_id] = profile
        self._index_profile_aliases(profile)

        if emit_event:
            self._emit_agent_event(
                "app_profile_registered",
                {
                    "app_id": profile.app_id,
                    "display_name": profile.display_name,
                    "category": profile.category.value,
                    "risk_level": profile.risk_level.value,
                    "sensitivity": profile.sensitivity.value,
                },
            )

        return self._safe_result(
            message="App profile registered successfully.",
            data={
                "profile": self._serialize_profile(profile),
                "total_profiles": len(self._profiles_by_id),
            },
        )

    def remove_profile(
        self,
        app_id: str,
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Remove a custom app profile.

        Admin-only because it changes System Agent profile configuration.
        """

        if not self._is_admin_role(role):
            return self._error_result(
                message="Admin role is required to remove an app profile.",
                error="admin_required",
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "role": role,
                },
            )

        normalized_id = self._normalize_key(app_id)
        profile = self._profiles_by_id.pop(normalized_id, None)

        if not profile:
            return self._error_result(
                message="App profile not found.",
                error="profile_not_found",
                metadata={
                    "app_id": app_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        self._rebuild_alias_index()

        self._emit_agent_event(
            "app_profile_removed",
            {
                "app_id": normalized_id,
                "display_name": profile.display_name,
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

        return self._safe_result(
            message="App profile removed successfully.",
            data={
                "removed_profile": self._serialize_profile(profile),
                "total_profiles": len(self._profiles_by_id),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def classify_app(
        self,
        app_name: str,
        *,
        app_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Classify an app by known profile.
        """

        profile_result = self.get_profile(app_name, app_id=app_id)
        if not profile_result["success"]:
            return self._safe_result(
                success=False,
                message="App could not be classified.",
                data={
                    "app_name": app_name,
                    "app_id": app_id,
                    "category": AppCategory.UNKNOWN.value,
                    "risk_level": AppRiskLevel.UNKNOWN.value,
                    "sensitivity": AppSensitivity.UNKNOWN.value,
                },
            )

        profile = profile_result["data"]["profile"]

        return self._safe_result(
            message="App classified successfully.",
            data={
                "app_name": app_name,
                "app_id": profile["app_id"],
                "display_name": profile["display_name"],
                "category": profile["category"],
                "risk_level": profile["risk_level"],
                "sensitivity": profile["sensitivity"],
            },
        )

    def export_profiles(self) -> Dict[str, Any]:
        """
        Export profiles in JSON-safe format for dashboard/API/config backup.
        """

        return self._safe_result(
            message="App profiles exported successfully.",
            data={
                "profiles": [
                    self._serialize_profile(profile)
                    for profile in self._profiles_by_id.values()
                ],
                "total": len(self._profiles_by_id),
                "exported_at": datetime.now(timezone.utc).isoformat(),
            },
        )

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------

    def _build_request(
        self,
        *,
        app_name: str,
        action: Union[str, AppActionType],
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        role: Optional[str],
        task_id: Optional[str],
        app_id: Optional[str],
        resource: Optional[str],
        payload: Dict[str, Any],
        metadata: Dict[str, Any],
        context: Optional[Any],
    ) -> AppProfileRequest:
        """
        Build normalized request from explicit params and optional context.
        """

        context_values = self._extract_context(context)

        resolved_user_id = user_id if user_id is not None else context_values.get("user_id")
        resolved_workspace_id = (
            workspace_id
            if workspace_id is not None
            else context_values.get("workspace_id")
        )
        resolved_role = role if role is not None else context_values.get("role")
        resolved_task_id = task_id if task_id is not None else context_values.get("task_id")

        merged_metadata = {
            **context_values.get("metadata", {}),
            **metadata,
        }

        return AppProfileRequest(
            app_name=str(app_name or "").strip(),
            app_id=str(app_id).strip() if app_id else None,
            action=self._normalize_action(action),
            user_id=resolved_user_id,
            workspace_id=resolved_workspace_id,
            role=str(resolved_role or "member").strip().lower(),
            task_id=str(resolved_task_id) if resolved_task_id else None,
            resource=resource or payload.get("resource"),
            payload=payload,
            metadata=merged_metadata,
        )

    def _evaluate_app_action(
        self,
        *,
        request: AppProfileRequest,
        profile: Optional[AppProfile],
        request_id: str,
    ) -> AppProfileEvaluation:
        """
        Evaluate app action against a profile.
        """

        if profile is None:
            if not self.allow_unknown_apps:
                return AppProfileEvaluation(
                    request_id=request_id,
                    decision=ProfileDecision.DENY,
                    allowed=False,
                    app_found=False,
                    app_id=request.app_id,
                    app_name=request.app_name,
                    action=request.action,
                    risk_level=AppRiskLevel.UNKNOWN,
                    sensitivity=AppSensitivity.UNKNOWN,
                    message="Unknown app is denied by local app profile policy.",
                    violations=["Unknown app profile."],
                    metadata={
                        "allow_unknown_apps": self.allow_unknown_apps,
                    },
                )

            security_payload = self._request_security_approval(
                request=request,
                profile=None,
                reasons=["Unknown app requires Security Agent approval."],
            )

            return AppProfileEvaluation(
                request_id=request_id,
                decision=ProfileDecision.REQUIRE_SECURITY_APPROVAL,
                allowed=False,
                app_found=False,
                app_id=request.app_id,
                app_name=request.app_name,
                action=request.action,
                risk_level=AppRiskLevel.UNKNOWN,
                sensitivity=AppSensitivity.UNKNOWN,
                message="Unknown app requires Security Agent approval.",
                requires_security=True,
                reasons=["Unknown app profile but unknown apps are allowed with approval."],
                warnings=["Unknown app may have unclassified risks."],
                security_payload=security_payload,
                metadata={
                    "allow_unknown_apps": self.allow_unknown_apps,
                },
            )

        reasons: List[str] = [
            f"Matched app profile: {profile.display_name}",
            f"Category: {profile.category.value}",
            f"Risk level: {profile.risk_level.value}",
            f"Sensitivity: {profile.sensitivity.value}",
        ]
        violations: List[str] = []
        warnings: List[str] = []

        requires_security = False
        requires_user_confirmation = False
        requires_admin = False

        if request.action == AppActionType.UNKNOWN:
            violations.append("Unknown action type.")
            return AppProfileEvaluation(
                request_id=request_id,
                decision=ProfileDecision.DENY,
                allowed=False,
                app_found=True,
                app_id=profile.app_id,
                app_name=profile.display_name,
                action=request.action,
                risk_level=profile.risk_level,
                sensitivity=profile.sensitivity,
                message="Unknown action type denied.",
                violations=violations,
                reasons=reasons,
            )

        if request.action in profile.blocked_actions:
            violations.append(f"Action '{request.action.value}' is blocked for {profile.display_name}.")
            return AppProfileEvaluation(
                request_id=request_id,
                decision=ProfileDecision.DENY,
                allowed=False,
                app_found=True,
                app_id=profile.app_id,
                app_name=profile.display_name,
                action=request.action,
                risk_level=profile.risk_level,
                sensitivity=profile.sensitivity,
                message="Action denied by app profile.",
                violations=violations,
                reasons=reasons,
            )

        if request.action in profile.admin_required_actions:
            requires_admin = True
            reasons.append("Action requires admin/workspace-owner role.")

        if requires_admin and not self._is_admin_role(request.role):
            return AppProfileEvaluation(
                request_id=request_id,
                decision=ProfileDecision.REQUIRE_ADMIN_APPROVAL,
                allowed=False,
                app_found=True,
                app_id=profile.app_id,
                app_name=profile.display_name,
                action=request.action,
                risk_level=profile.risk_level,
                sensitivity=profile.sensitivity,
                message="Admin approval is required for this app action.",
                requires_admin=True,
                requires_security=True,
                reasons=reasons,
                warnings=warnings,
            )

        if request.action in profile.security_required_actions:
            requires_security = True
            reasons.append("Action requires Security Agent approval by profile.")

        if request.action in profile.confirmation_required_actions:
            requires_user_confirmation = True
            reasons.append("Action requires user confirmation by profile.")

        if profile.sensitivity in {
            AppSensitivity.FINANCIAL,
            AppSensitivity.SECURITY_CRITICAL,
            AppSensitivity.CONFIDENTIAL,
        } and self.require_security_for_sensitive:
            requires_security = True
            reasons.append("Sensitive app requires Security Agent approval.")

        if profile.risk_level in {
            AppRiskLevel.HIGH,
            AppRiskLevel.CRITICAL,
            AppRiskLevel.RESTRICTED,
            AppRiskLevel.UNKNOWN,
        }:
            requires_security = True
            reasons.append("High-risk app profile requires Security Agent approval.")

        if request.payload.get("contains_secret") is True:
            requires_security = True
            warnings.append("Payload indicates secrets may be present.")

        if request.payload.get("contains_financial_data") is True:
            requires_security = True
            requires_user_confirmation = True
            warnings.append("Payload indicates financial data may be present.")

        if request.payload.get("destructive") is True:
            requires_security = True
            requires_user_confirmation = True
            warnings.append("Payload indicates destructive action.")

        if (
            request.action not in profile.allowed_actions
            and request.action not in profile.security_required_actions
            and request.action not in profile.confirmation_required_actions
            and request.action not in profile.admin_required_actions
        ):
            requires_security = True
            warnings.append(
                f"Action '{request.action.value}' is not explicitly allowed for {profile.display_name}."
            )

        if requires_security:
            security_payload = self._request_security_approval(
                request=request,
                profile=profile,
                reasons=reasons,
            )

            return AppProfileEvaluation(
                request_id=request_id,
                decision=ProfileDecision.REQUIRE_SECURITY_APPROVAL,
                allowed=False,
                app_found=True,
                app_id=profile.app_id,
                app_name=profile.display_name,
                action=request.action,
                risk_level=profile.risk_level,
                sensitivity=profile.sensitivity,
                message="Security Agent approval is required for this app action.",
                requires_security=True,
                requires_user_confirmation=requires_user_confirmation,
                requires_admin=requires_admin,
                reasons=reasons,
                warnings=warnings,
                security_payload=security_payload,
            )

        if requires_user_confirmation:
            return AppProfileEvaluation(
                request_id=request_id,
                decision=ProfileDecision.REQUIRE_USER_CONFIRMATION,
                allowed=False,
                app_found=True,
                app_id=profile.app_id,
                app_name=profile.display_name,
                action=request.action,
                risk_level=profile.risk_level,
                sensitivity=profile.sensitivity,
                message="User confirmation is required for this app action.",
                requires_user_confirmation=True,
                reasons=reasons,
                warnings=warnings,
            )

        return AppProfileEvaluation(
            request_id=request_id,
            decision=ProfileDecision.ALLOW,
            allowed=True,
            app_found=True,
            app_id=profile.app_id,
            app_name=profile.display_name,
            action=request.action,
            risk_level=profile.risk_level,
            sensitivity=profile.sensitivity,
            message="App action allowed by local app profile.",
            reasons=reasons,
            warnings=warnings,
        )

    def _finalize_evaluation(
        self,
        request: AppProfileRequest,
        evaluation: AppProfileEvaluation,
    ) -> Dict[str, Any]:
        """
        Attach Security, Verification, Memory, audit, and event data.
        """

        if self.verification_enabled:
            evaluation.verification_payload = self._prepare_verification_payload(
                request,
                evaluation,
            )

        if self.memory_enabled:
            evaluation.memory_payload = self._prepare_memory_payload(
                request,
                evaluation,
            )

        if self.audit_enabled:
            evaluation.audit_event = self._log_audit_event(
                request,
                evaluation,
            )

        self._emit_agent_event(
            "app_profile_action_evaluated",
            {
                "request_id": evaluation.request_id,
                "app_id": evaluation.app_id,
                "app_name": evaluation.app_name,
                "action": evaluation.action.value,
                "decision": evaluation.decision.value,
                "allowed": evaluation.allowed,
                "risk_level": evaluation.risk_level.value,
                "sensitivity": evaluation.sensitivity.value,
                "user_id": request.user_id,
                "workspace_id": request.workspace_id,
                "task_id": request.task_id,
            },
        )

        data = {
            "request_id": evaluation.request_id,
            "decision": evaluation.decision.value,
            "allowed": evaluation.allowed,
            "app_found": evaluation.app_found,
            "app_id": evaluation.app_id,
            "app_name": evaluation.app_name,
            "action": evaluation.action.value,
            "risk_level": evaluation.risk_level.value,
            "sensitivity": evaluation.sensitivity.value,
            "requires_security": evaluation.requires_security,
            "requires_user_confirmation": evaluation.requires_user_confirmation,
            "requires_admin": evaluation.requires_admin,
            "reasons": evaluation.reasons,
            "violations": evaluation.violations,
            "warnings": evaluation.warnings,
            "security_payload": evaluation.security_payload,
            "verification_payload": evaluation.verification_payload,
            "memory_payload": evaluation.memory_payload,
            "audit_event": evaluation.audit_event,
        }

        metadata = {
            **evaluation.metadata,
            "agent_name": self.agent_name,
            "agent_module": self.agent_module,
            "version": self.version,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "task_id": request.task_id,
        }

        success = evaluation.decision != ProfileDecision.DENY

        return self._safe_result(
            success=success,
            message=evaluation.message,
            data=data,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        request: AppProfileRequest,
    ) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace context.

        Required by William/Jarvis architecture:
            - Every user-specific app action must include user_id.
            - Every workspace app action must include workspace_id.
            - Strict mode blocks missing context.
        """

        violations: List[str] = []

        if not request.app_name and not request.app_id:
            violations.append("Missing app_name or app_id.")

        if request.action == AppActionType.UNKNOWN:
            violations.append("Unknown app action.")

        if request.user_id in (None, "", "None"):
            violations.append("Missing user_id.")

        if request.workspace_id in (None, "", "None"):
            violations.append("Missing workspace_id.")

        if not request.role:
            violations.append("Missing role.")

        if violations and self.strict_mode:
            return self._safe_result(
                success=False,
                message="App profile task context validation failed.",
                data={"violations": violations},
            )

        return self._safe_result(
            success=True,
            message="App profile task context validated successfully.",
            data={"violations": violations},
        )

    def _requires_security_check(
        self,
        request: AppProfileRequest,
        profile: Optional[AppProfile] = None,
    ) -> bool:
        """
        Determine if app action should go through Security Agent.
        """

        if profile is None:
            return True

        if request.action in profile.security_required_actions:
            return True

        if profile.sensitivity in {
            AppSensitivity.FINANCIAL,
            AppSensitivity.CONFIDENTIAL,
            AppSensitivity.SECURITY_CRITICAL,
        }:
            return True

        if profile.risk_level in {
            AppRiskLevel.HIGH,
            AppRiskLevel.CRITICAL,
            AppRiskLevel.RESTRICTED,
            AppRiskLevel.UNKNOWN,
        }:
            return True

        if request.action in DEFAULT_RISKY_ACTIONS:
            return True

        return False

    def _request_security_approval(
        self,
        *,
        request: AppProfileRequest,
        profile: Optional[AppProfile],
        reasons: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare or dispatch Security Agent approval payload.
        """

        payload = {
            "approval_request_id": self._new_id("sec"),
            "source_agent": self.agent_name,
            "target_agent": "SecurityAgent",
            "approval_type": "app_profile_action",
            "app": {
                "app_id": profile.app_id if profile else request.app_id,
                "app_name": profile.display_name if profile else request.app_name,
                "category": profile.category.value if profile else AppCategory.UNKNOWN.value,
                "risk_level": profile.risk_level.value if profile else AppRiskLevel.UNKNOWN.value,
                "sensitivity": profile.sensitivity.value if profile else AppSensitivity.UNKNOWN.value,
            },
            "action": request.action.value,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "role": request.role,
            "task_id": request.task_id,
            "resource": self._redact_sensitive_value(request.resource),
            "payload_summary": self._safe_payload_summary(request.payload),
            "reasons": reasons or [],
            "metadata": {
                "requested_at": datetime.now(timezone.utc).isoformat(),
                "app_profiles_version": self.version,
                "strict_mode": self.strict_mode,
            },
        }

        if self.security_requester:
            try:
                response = self.security_requester(payload)
                payload["security_agent_response"] = response
            except Exception as exc:
                logger.warning("Security requester callable failed: %s", exc)
                payload["security_agent_response_error"] = str(exc)

        return payload

    def _prepare_verification_payload(
        self,
        request: AppProfileRequest,
        evaluation: AppProfileEvaluation,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        The Verification Agent can use this after an app action completes to
        verify the executed action matched the approved profile scope.
        """

        return {
            "verification_id": self._new_id("ver"),
            "source_agent": self.agent_name,
            "target_agent": "VerificationAgent",
            "verification_type": "app_profile_action",
            "app_id": evaluation.app_id,
            "app_name": evaluation.app_name,
            "action": evaluation.action.value,
            "decision": evaluation.decision.value,
            "allowed": evaluation.allowed,
            "risk_level": evaluation.risk_level.value,
            "sensitivity": evaluation.sensitivity.value,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "task_id": request.task_id,
            "expected_result_contract": {
                "must_return_structured_result": True,
                "must_include_success": True,
                "must_include_message": True,
                "must_include_data_or_error": True,
                "must_preserve_user_workspace_isolation": True,
                "must_not_exceed_approved_app_scope": True,
            },
            "metadata": {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "guard_request_id": evaluation.request_id,
            },
        }

    def _prepare_memory_payload(
        self,
        request: AppProfileRequest,
        evaluation: AppProfileEvaluation,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        Stores useful non-secret profile decision context.
        """

        return {
            "memory_id": self._new_id("mem"),
            "source_agent": self.agent_name,
            "target_agent": "MemoryAgent",
            "memory_type": "app_profile_decision",
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "task_id": request.task_id,
            "content": {
                "app_id": evaluation.app_id,
                "app_name": evaluation.app_name,
                "action": evaluation.action.value,
                "decision": evaluation.decision.value,
                "risk_level": evaluation.risk_level.value,
                "sensitivity": evaluation.sensitivity.value,
                "reasons": evaluation.reasons[:10],
                "warnings": evaluation.warnings[:10],
            },
            "metadata": {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "safe_to_store": True,
                "contains_secret": False,
                "guard_request_id": evaluation.request_id,
            },
        }

    def _emit_agent_event(
        self,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Emit event for Master Agent, dashboard, task history, or registry.
        """

        event = {
            "event_id": self._new_id("evt"),
            "event_type": event_type,
            "source_agent": self.agent_name,
            "agent_module": self.agent_module,
            "payload": payload or {},
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        if self.event_sink:
            try:
                self.event_sink(event)
            except Exception as exc:
                logger.warning("Event sink failed: %s", exc)

        logger.debug("App profile event emitted: %s", event)
        return event

    def _log_audit_event(
        self,
        request: AppProfileRequest,
        evaluation: AppProfileEvaluation,
    ) -> Dict[str, Any]:
        """
        Create dashboard/API audit event.

        Always includes user_id and workspace_id to preserve SaaS isolation.
        """

        audit_event = {
            "audit_id": self._new_id("aud"),
            "source_agent": self.agent_name,
            "agent_module": self.agent_module,
            "event_type": "app_profile_action_check",
            "app_id": evaluation.app_id,
            "app_name": evaluation.app_name,
            "action": evaluation.action.value,
            "decision": evaluation.decision.value,
            "allowed": evaluation.allowed,
            "risk_level": evaluation.risk_level.value,
            "sensitivity": evaluation.sensitivity.value,
            "requires_security": evaluation.requires_security,
            "requires_user_confirmation": evaluation.requires_user_confirmation,
            "requires_admin": evaluation.requires_admin,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "role": request.role,
            "task_id": request.task_id,
            "resource": self._redact_sensitive_value(request.resource),
            "violations": evaluation.violations,
            "warnings": evaluation.warnings,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "metadata": {
                "guard_request_id": evaluation.request_id,
                "strict_mode": self.strict_mode,
                "version": self.version,
            },
        }

        if self.audit_sink:
            try:
                self.audit_sink(audit_event)
            except Exception as exc:
                logger.warning("Audit sink failed: %s", exc)

        logger.info(
            "App profile audit: app=%s action=%s decision=%s user=%s workspace=%s",
            evaluation.app_name,
            evaluation.action.value,
            evaluation.decision.value,
            request.user_id,
            request.workspace_id,
        )

        return audit_event

    def _safe_result(
        self,
        *,
        success: bool = True,
        message: str = "Success.",
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis structured result.
        """

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
        error: Optional[Any] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis structured error result.
        """

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    # ------------------------------------------------------------------
    # Profile indexing and serialization
    # ------------------------------------------------------------------

    def _index_profile_aliases(self, profile: AppProfile) -> None:
        """
        Index app aliases, process names, package names, display name, and app_id.
        """

        profile_id = self._normalize_key(profile.app_id)

        values = {
            profile.app_id,
            profile.display_name,
            *profile.aliases,
            *profile.process_names,
            *profile.package_names,
            *profile.url_patterns,
        }

        for value in values:
            if value:
                self._alias_index[self._normalize_key(value)] = profile_id

    def _rebuild_alias_index(self) -> None:
        """
        Rebuild alias index after profile removal.
        """

        self._alias_index = {}
        for profile in self._profiles_by_id.values():
            self._index_profile_aliases(profile)

    def _serialize_profile(self, profile: AppProfile) -> Dict[str, Any]:
        """
        Convert AppProfile to JSON-safe dict.
        """

        return {
            "app_id": profile.app_id,
            "display_name": profile.display_name,
            "category": profile.category.value,
            "aliases": sorted(profile.aliases),
            "risk_level": profile.risk_level.value,
            "sensitivity": profile.sensitivity.value,
            "allowed_actions": sorted(action.value for action in profile.allowed_actions),
            "blocked_actions": sorted(action.value for action in profile.blocked_actions),
            "security_required_actions": sorted(
                action.value for action in profile.security_required_actions
            ),
            "confirmation_required_actions": sorted(
                action.value for action in profile.confirmation_required_actions
            ),
            "admin_required_actions": sorted(
                action.value for action in profile.admin_required_actions
            ),
            "process_names": sorted(profile.process_names),
            "package_names": sorted(profile.package_names),
            "url_patterns": sorted(profile.url_patterns),
            "notes": profile.notes,
            "metadata": profile.metadata,
        }

    # ------------------------------------------------------------------
    # Normalization helpers
    # ------------------------------------------------------------------

    def _normalize_key(self, value: Any) -> str:
        """
        Normalize strings for profile lookup.
        """

        return str(value or "").strip().lower().replace(" ", "_")

    def _normalize_action(
        self,
        action: Union[str, AppActionType],
    ) -> AppActionType:
        """
        Normalize action input.
        """

        if isinstance(action, AppActionType):
            return action

        action_str = str(action or "").strip().lower()

        for item in AppActionType:
            if item.value == action_str or item.name.lower() == action_str:
                return item

        aliases = {
            "open": AppActionType.OPEN_APP,
            "close": AppActionType.CLOSE_APP,
            "focus": AppActionType.FOCUS_APP,
            "read": AppActionType.READ_SCREEN,
            "capture": AppActionType.SCREENSHOT,
            "screenshot": AppActionType.SCREENSHOT,
            "click": AppActionType.CLICK,
            "tap": AppActionType.CLICK,
            "type": AppActionType.TYPE_TEXT,
            "write": AppActionType.TYPE_TEXT,
            "send": AppActionType.SEND_MESSAGE,
            "message": AppActionType.SEND_MESSAGE,
            "call": AppActionType.MAKE_CALL,
            "pay": AppActionType.PAYMENT,
            "transfer": AppActionType.TRANSFER_FUNDS,
            "delete": AppActionType.DELETE_DATA,
            "settings": AppActionType.CHANGE_SETTINGS,
            "command": AppActionType.RUN_COMMAND,
            "install": AppActionType.INSTALL_EXTENSION,
            "secret": AppActionType.ACCESS_SECRETS,
        }

        return aliases.get(action_str, AppActionType.UNKNOWN)

    def _normalize_category(
        self,
        category: Union[str, AppCategory],
    ) -> AppCategory:
        """
        Normalize category input.
        """

        if isinstance(category, AppCategory):
            return category

        category_str = str(category or "").strip().lower()

        for item in AppCategory:
            if item.value == category_str or item.name.lower() == category_str:
                return item

        return AppCategory.UNKNOWN

    def _normalize_sensitivity(
        self,
        sensitivity: Union[str, AppSensitivity],
    ) -> AppSensitivity:
        """
        Normalize sensitivity input.
        """

        if isinstance(sensitivity, AppSensitivity):
            return sensitivity

        sensitivity_str = str(sensitivity or "").strip().lower()

        for item in AppSensitivity:
            if item.value == sensitivity_str or item.name.lower() == sensitivity_str:
                return item

        return AppSensitivity.UNKNOWN

    def _extract_context(self, context: Optional[Any]) -> Dict[str, Any]:
        """
        Extract values from dict-like or object-like AgentContext.
        """

        if context is None:
            return {}

        if isinstance(context, dict):
            return {
                "user_id": context.get("user_id"),
                "workspace_id": context.get("workspace_id"),
                "role": context.get("role"),
                "task_id": context.get("task_id"),
                "metadata": context.get("metadata", {}) or {},
            }

        return {
            "user_id": getattr(context, "user_id", None),
            "workspace_id": getattr(context, "workspace_id", None),
            "role": getattr(context, "role", None),
            "task_id": getattr(context, "task_id", None),
            "metadata": getattr(context, "metadata", {}) or {},
        }

    def _is_admin_role(self, role: Optional[str]) -> bool:
        """
        Check admin/workspace-owner role.
        """

        return str(role or "").strip().lower() in DEFAULT_ADMIN_ROLES

    def _safe_payload_summary(
        self,
        payload: Dict[str, Any],
        *,
        max_items: int = 30,
    ) -> Dict[str, Any]:
        """
        Return safe payload summary for audit/security.
        """

        summary: Dict[str, Any] = {}

        for index, (key, value) in enumerate(payload.items()):
            if index >= max_items:
                summary["_truncated"] = True
                break

            key_lower = str(key).lower()

            if any(secret_key in key_lower for secret_key in DEFAULT_SECRET_KEYS):
                summary[key] = "[REDACTED]"
            else:
                summary[key] = self._redact_sensitive_value(value)

        return summary

    def _redact_sensitive_value(self, value: Any) -> Any:
        """
        Redact secrets and truncate long values.
        """

        if value is None:
            return None

        text = str(value)
        lowered = text.lower()

        sensitive_markers = [
            "password=",
            "token=",
            "api_key=",
            "secret=",
            "authorization:",
            "bearer ",
            "private_key",
            "session=",
            "cookie=",
        ]

        if any(marker in lowered for marker in sensitive_markers):
            return "[REDACTED]"

        if len(text) > 300:
            return text[:300] + "...[TRUNCATED]"

        return value

    def _new_id(self, prefix: str) -> str:
        """
        Generate unique ID.
        """

        return f"{prefix}_{uuid.uuid4().hex}"

    def _duration_ms(self, started: float) -> int:
        """
        Duration helper.
        """

        return int((time.time() - started) * 1000)

    # ------------------------------------------------------------------
    # Default app profiles
    # ------------------------------------------------------------------

    def _default_profiles(self) -> List[AppProfile]:
        """
        Default app-specific profiles.

        These profiles are conservative by design. Sensitive apps such as
        banking, finance, password managers, and security tools require
        Security Agent approval before interaction.
        """

        browser_allowed = DEFAULT_SAFE_ACTIONS | {
            AppActionType.OPEN_URL,
            AppActionType.READ_SCREEN,
            AppActionType.SCREENSHOT,
            AppActionType.COPY,
        }

        browser_security = {
            AppActionType.TYPE_TEXT,
            AppActionType.PASTE,
            AppActionType.DOWNLOAD,
            AppActionType.UPLOAD,
            AppActionType.INSTALL_EXTENSION,
            AppActionType.ACCESS_SECRETS,
            AppActionType.CHANGE_SETTINGS,
        }

        code_allowed = DEFAULT_SAFE_ACTIONS | {
            AppActionType.READ_SCREEN,
            AppActionType.SCREENSHOT,
            AppActionType.COPY,
            AppActionType.TYPE_TEXT,
            AppActionType.HOTKEY,
        }

        code_security = {
            AppActionType.RUN_COMMAND,
            AppActionType.DELETE_DATA,
            AppActionType.INSTALL_EXTENSION,
            AppActionType.ACCESS_SECRETS,
            AppActionType.CHANGE_SETTINGS,
        }

        design_allowed = DEFAULT_SAFE_ACTIONS | {
            AppActionType.READ_SCREEN,
            AppActionType.SCREENSHOT,
            AppActionType.CLICK,
            AppActionType.HOTKEY,
            AppActionType.COPY,
        }

        messaging_allowed = DEFAULT_SAFE_ACTIONS | {
            AppActionType.READ_WINDOW_TITLE,
            AppActionType.READ_SCREEN,
        }

        messaging_security = {
            AppActionType.TYPE_TEXT,
            AppActionType.PASTE,
            AppActionType.SEND_MESSAGE,
            AppActionType.MAKE_CALL,
            AppActionType.UPLOAD,
            AppActionType.DOWNLOAD,
            AppActionType.ACCESS_SECRETS,
        }

        finance_allowed = {
            AppActionType.OPEN_APP,
            AppActionType.CLOSE_APP,
            AppActionType.FOCUS_APP,
            AppActionType.READ_WINDOW_TITLE,
        }

        finance_blocked = DEFAULT_BLOCKED_FINANCIAL_ACTIONS

        return [
            AppProfile(
                app_id="chrome",
                display_name="Google Chrome",
                category=AppCategory.BROWSER,
                aliases={
                    "chrome",
                    "google chrome",
                    "chromium",
                    "browser",
                    "com.android.chrome",
                },
                risk_level=AppRiskLevel.MEDIUM,
                sensitivity=AppSensitivity.WORKSPACE,
                allowed_actions=browser_allowed,
                security_required_actions=browser_security,
                confirmation_required_actions={
                    AppActionType.DOWNLOAD,
                    AppActionType.UPLOAD,
                    AppActionType.INSTALL_EXTENSION,
                },
                process_names={"chrome", "chrome.exe", "chromium", "chromium-browser"},
                package_names={"com.android.chrome"},
                url_patterns={"chrome://", "https://", "http://"},
                notes="Browser profile. Safe viewing is allowed. Typing, uploads, downloads, extensions, and settings require approval.",
            ),
            AppProfile(
                app_id="edge",
                display_name="Microsoft Edge",
                category=AppCategory.BROWSER,
                aliases={"edge", "microsoft edge", "msedge", "com.microsoft.emmx"},
                risk_level=AppRiskLevel.MEDIUM,
                sensitivity=AppSensitivity.WORKSPACE,
                allowed_actions=browser_allowed,
                security_required_actions=browser_security,
                confirmation_required_actions={
                    AppActionType.DOWNLOAD,
                    AppActionType.UPLOAD,
                    AppActionType.INSTALL_EXTENSION,
                },
                process_names={"msedge", "msedge.exe"},
                package_names={"com.microsoft.emmx"},
                url_patterns={"edge://", "https://", "http://"},
                notes="Microsoft Edge browser profile.",
            ),
            AppProfile(
                app_id="firefox",
                display_name="Mozilla Firefox",
                category=AppCategory.BROWSER,
                aliases={"firefox", "mozilla firefox", "org.mozilla.firefox"},
                risk_level=AppRiskLevel.MEDIUM,
                sensitivity=AppSensitivity.WORKSPACE,
                allowed_actions=browser_allowed,
                security_required_actions=browser_security,
                confirmation_required_actions={
                    AppActionType.DOWNLOAD,
                    AppActionType.UPLOAD,
                    AppActionType.INSTALL_EXTENSION,
                },
                process_names={"firefox", "firefox.exe"},
                package_names={"org.mozilla.firefox"},
                url_patterns={"about:", "https://", "http://"},
                notes="Firefox browser profile.",
            ),
            AppProfile(
                app_id="vscode",
                display_name="Visual Studio Code",
                category=AppCategory.CODE_EDITOR,
                aliases={
                    "vscode",
                    "vs code",
                    "visual studio code",
                    "code",
                    "com.visualstudio.code",
                },
                risk_level=AppRiskLevel.MEDIUM,
                sensitivity=AppSensitivity.WORKSPACE,
                allowed_actions=code_allowed,
                security_required_actions=code_security,
                confirmation_required_actions={
                    AppActionType.RUN_COMMAND,
                    AppActionType.DELETE_DATA,
                    AppActionType.INSTALL_EXTENSION,
                },
                admin_required_actions={
                    AppActionType.CHANGE_SETTINGS,
                },
                process_names={"code", "code.exe"},
                package_names={"com.visualstudio.code"},
                notes="Code editor profile. Editing is allowed, but commands, deletes, extensions, secrets, and settings require approval.",
            ),
            AppProfile(
                app_id="photoshop",
                display_name="Adobe Photoshop",
                category=AppCategory.DESIGN,
                aliases={
                    "photoshop",
                    "adobe photoshop",
                    "ps",
                },
                risk_level=AppRiskLevel.LOW,
                sensitivity=AppSensitivity.WORKSPACE,
                allowed_actions=design_allowed,
                security_required_actions={
                    AppActionType.DELETE_DATA,
                    AppActionType.UPLOAD,
                    AppActionType.DOWNLOAD,
                    AppActionType.ACCESS_SECRETS,
                    AppActionType.CHANGE_SETTINGS,
                },
                confirmation_required_actions={
                    AppActionType.DELETE_DATA,
                    AppActionType.UPLOAD,
                },
                process_names={"photoshop", "photoshop.exe"},
                notes="Design app profile. Visual actions are mostly low risk, but upload/delete/settings require approval.",
            ),
            AppProfile(
                app_id="whatsapp",
                display_name="WhatsApp",
                category=AppCategory.MESSAGING,
                aliases={
                    "whatsapp",
                    "whatsapp desktop",
                    "com.whatsapp",
                    "com.whatsapp.w4b",
                },
                risk_level=AppRiskLevel.HIGH,
                sensitivity=AppSensitivity.PERSONAL,
                allowed_actions=messaging_allowed,
                security_required_actions=messaging_security,
                confirmation_required_actions={
                    AppActionType.SEND_MESSAGE,
                    AppActionType.MAKE_CALL,
                    AppActionType.UPLOAD,
                },
                process_names={"whatsapp", "whatsapp.exe"},
                package_names={"com.whatsapp", "com.whatsapp.w4b"},
                notes="Messaging app profile. Reading screen/window may be allowed with context, but sending messages/calls/uploads require approval.",
            ),
            AppProfile(
                app_id="telegram",
                display_name="Telegram",
                category=AppCategory.MESSAGING,
                aliases={"telegram", "telegram desktop", "org.telegram.messenger"},
                risk_level=AppRiskLevel.HIGH,
                sensitivity=AppSensitivity.PERSONAL,
                allowed_actions=messaging_allowed,
                security_required_actions=messaging_security,
                confirmation_required_actions={
                    AppActionType.SEND_MESSAGE,
                    AppActionType.MAKE_CALL,
                    AppActionType.UPLOAD,
                },
                process_names={"telegram", "telegram.exe"},
                package_names={"org.telegram.messenger"},
                notes="Telegram messaging profile.",
            ),
            AppProfile(
                app_id="slack",
                display_name="Slack",
                category=AppCategory.MESSAGING,
                aliases={"slack", "com.slack"},
                risk_level=AppRiskLevel.MEDIUM,
                sensitivity=AppSensitivity.WORKSPACE,
                allowed_actions=messaging_allowed,
                security_required_actions=messaging_security,
                confirmation_required_actions={
                    AppActionType.SEND_MESSAGE,
                    AppActionType.UPLOAD,
                },
                process_names={"slack", "slack.exe"},
                package_names={"com.slack"},
                notes="Workspace messaging profile.",
            ),
            AppProfile(
                app_id="banking_app",
                display_name="Banking App",
                category=AppCategory.BANKING,
                aliases={
                    "bank",
                    "banking",
                    "banking app",
                    "mobile banking",
                    "online banking",
                },
                risk_level=AppRiskLevel.RESTRICTED,
                sensitivity=AppSensitivity.FINANCIAL,
                allowed_actions=finance_allowed,
                blocked_actions=finance_blocked,
                security_required_actions={
                    AppActionType.READ_SCREEN,
                    AppActionType.SCREENSHOT,
                    AppActionType.CLICK,
                    AppActionType.TYPE_TEXT,
                    AppActionType.PASTE,
                    AppActionType.PAYMENT,
                    AppActionType.TRANSFER_FUNDS,
                    AppActionType.ACCESS_SECRETS,
                    AppActionType.CHANGE_SETTINGS,
                },
                confirmation_required_actions={
                    AppActionType.READ_SCREEN,
                    AppActionType.SCREENSHOT,
                    AppActionType.CLICK,
                    AppActionType.TYPE_TEXT,
                    AppActionType.PASTE,
                },
                admin_required_actions={
                    AppActionType.CHANGE_SETTINGS,
                },
                notes="Generic banking profile. Payments, fund transfers, and secret access are blocked locally.",
            ),
            AppProfile(
                app_id="paypal",
                display_name="PayPal",
                category=AppCategory.FINANCE,
                aliases={"paypal", "com.paypal.android.p2pmobile"},
                risk_level=AppRiskLevel.RESTRICTED,
                sensitivity=AppSensitivity.FINANCIAL,
                allowed_actions=finance_allowed,
                blocked_actions=finance_blocked,
                security_required_actions={
                    AppActionType.READ_SCREEN,
                    AppActionType.SCREENSHOT,
                    AppActionType.CLICK,
                    AppActionType.TYPE_TEXT,
                    AppActionType.PASTE,
                    AppActionType.PAYMENT,
                    AppActionType.TRANSFER_FUNDS,
                    AppActionType.ACCESS_SECRETS,
                },
                confirmation_required_actions={
                    AppActionType.READ_SCREEN,
                    AppActionType.SCREENSHOT,
                    AppActionType.CLICK,
                    AppActionType.TYPE_TEXT,
                },
                package_names={"com.paypal.android.p2pmobile"},
                url_patterns={"paypal.com"},
                notes="Financial payment app. Payment and transfer actions are blocked locally.",
            ),
            AppProfile(
                app_id="password_manager",
                display_name="Password Manager",
                category=AppCategory.SECURITY,
                aliases={
                    "password manager",
                    "1password",
                    "bitwarden",
                    "lastpass",
                    "dashlane",
                    "keeper",
                },
                risk_level=AppRiskLevel.RESTRICTED,
                sensitivity=AppSensitivity.SECURITY_CRITICAL,
                allowed_actions={
                    AppActionType.OPEN_APP,
                    AppActionType.CLOSE_APP,
                    AppActionType.FOCUS_APP,
                },
                blocked_actions={
                    AppActionType.ACCESS_SECRETS,
                    AppActionType.COPY,
                    AppActionType.PASTE,
                    AppActionType.TYPE_TEXT,
                    AppActionType.SCREENSHOT,
                    AppActionType.READ_SCREEN,
                },
                security_required_actions={
                    AppActionType.CHANGE_SETTINGS,
                },
                confirmation_required_actions={
                    AppActionType.CHANGE_SETTINGS,
                },
                notes="Security-critical app. Secret access, copying, reading, and screenshots are blocked locally.",
            ),
            AppProfile(
                app_id="terminal",
                display_name="Terminal",
                category=AppCategory.TERMINAL,
                aliases={
                    "terminal",
                    "cmd",
                    "command prompt",
                    "powershell",
                    "bash",
                    "zsh",
                    "shell",
                    "windows terminal",
                },
                risk_level=AppRiskLevel.HIGH,
                sensitivity=AppSensitivity.CONFIDENTIAL,
                allowed_actions={
                    AppActionType.OPEN_APP,
                    AppActionType.CLOSE_APP,
                    AppActionType.FOCUS_APP,
                    AppActionType.READ_WINDOW_TITLE,
                },
                security_required_actions={
                    AppActionType.TYPE_TEXT,
                    AppActionType.PASTE,
                    AppActionType.RUN_COMMAND,
                    AppActionType.ACCESS_SECRETS,
                    AppActionType.CHANGE_SETTINGS,
                },
                confirmation_required_actions={
                    AppActionType.TYPE_TEXT,
                    AppActionType.PASTE,
                    AppActionType.RUN_COMMAND,
                },
                admin_required_actions={
                    AppActionType.CHANGE_SETTINGS,
                },
                process_names={
                    "cmd.exe",
                    "powershell.exe",
                    "pwsh.exe",
                    "terminal",
                    "bash",
                    "zsh",
                },
                notes="Terminal profile. Commands and typing require Security Agent approval.",
            ),
        ]


# -------------------------------------------------------------------------
# Module-level convenience instance and functions
# -------------------------------------------------------------------------

_default_app_profiles: Optional[AppProfiles] = None


def get_app_profiles() -> AppProfiles:
    """
    Return shared AppProfiles instance.

    Useful for Agent Loader, Registry, Router, FastAPI dependency injection,
    and other System Agent files.
    """

    global _default_app_profiles

    if _default_app_profiles is None:
        _default_app_profiles = AppProfiles()

    return _default_app_profiles


def check_app_action(
    app_name: str,
    action: Union[str, AppActionType],
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Module-level helper for quick app action checks.
    """

    profiles = get_app_profiles()
    return profiles.check_app_action(app_name, action, **kwargs)


__all__ = [
    "AppProfiles",
    "AppProfile",
    "AppProfileRequest",
    "AppProfileEvaluation",
    "AppRiskLevel",
    "AppCategory",
    "AppActionType",
    "ProfileDecision",
    "AppSensitivity",
    "get_app_profiles",
    "check_app_action",
]


# -------------------------------------------------------------------------
# Safe manual test
# -------------------------------------------------------------------------

if __name__ == "__main__":
    app_profiles = AppProfiles()

    demo = app_profiles.check_app_action(
        app_name="Chrome",
        action="open_url",
        user_id="demo_user",
        workspace_id="demo_workspace",
        role="member",
        resource="https://example.com",
        payload={
            "resource": "https://example.com",
            "contains_secret": False,
        },
        metadata={
            "source": "manual_test",
        },
    )

    print(demo)