"""
agents/system_agent/config.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    System Agent permissions, safe mode, protected actions, and platform settings.

Main Class:
    SystemConfig

This file is designed to be:
    - Production-level
    - Import-safe even if future William modules are not created yet
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router,
      Master Agent routing, Security Agent, Memory Agent, Verification Agent,
      Dashboard/API, and future FastAPI integration
    - SaaS-safe with user_id/workspace_id isolation
    - Safe by default for protected system actions

Important:
    This config file does NOT execute OS/device/browser/message/call/financial actions.
    It only manages policy/configuration and permission decisions.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import platform
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Optional BaseAgent compatibility
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    try:
        from agents.base_agent.base_agent import BaseAgent  # type: ignore
    except Exception:

        class BaseAgent:  # type: ignore
            """
            Fallback BaseAgent stub.

            This makes the file import-safe before the full William/Jarvis
            agent framework is generated.
            """

            def __init__(
                self,
                agent_name: str = "system_config",
                agent_type: str = "system_agent",
                **kwargs: Any,
            ) -> None:
                self.agent_name = agent_name
                self.agent_type = agent_type
                self.agent_id = kwargs.get("agent_id", f"{agent_type}:{agent_name}")

            def emit_event(self, event_type: str, payload: Dict[str, Any]) -> None:
                return None

            def log(self, level: str, message: str, **kwargs: Any) -> None:
                return None


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_AGENT_NAME = "system_config"
DEFAULT_AGENT_TYPE = "system_agent"

DEFAULT_STORAGE_DIR = os.environ.get(
    "WILLIAM_SYSTEM_CONFIG_DIR",
    os.path.join(".william_data", "system_config"),
)

CONFIG_SCHEMA = "william.system_agent.config.v1"

SAFE_MODE_STRICT = "strict"
SAFE_MODE_BALANCED = "balanced"
SAFE_MODE_ASSISTED = "assisted"
SAFE_MODE_OFF = "off"

SUPPORTED_SAFE_MODES = {
    SAFE_MODE_STRICT,
    SAFE_MODE_BALANCED,
    SAFE_MODE_ASSISTED,
    SAFE_MODE_OFF,
}

SUPPORTED_PLATFORMS = {
    "windows",
    "macos",
    "linux",
    "android",
    "ios",
    "web",
    "unknown",
}

SUPPORTED_RISK_LEVELS = {
    "low",
    "medium",
    "high",
    "critical",
}

DEFAULT_ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "owner": ["*"],
    "admin": [
        "system.read_config",
        "system.update_config",
        "system.manage_permissions",
        "system.manage_platform_settings",
        "system.view_audit",
        "system.request_protected_action",
    ],
    "manager": [
        "system.read_config",
        "system.update_preferences",
        "system.request_protected_action",
    ],
    "member": [
        "system.read_config",
        "system.update_preferences",
    ],
    "viewer": [
        "system.read_config",
    ],
}

DEFAULT_PROTECTED_ACTIONS: Dict[str, Dict[str, Any]] = {
    "os.execute_command": {
        "risk_level": "critical",
        "requires_security": True,
        "requires_human_approval": True,
        "description": "Execute a command on the operating system.",
    },
    "os.delete_file": {
        "risk_level": "critical",
        "requires_security": True,
        "requires_human_approval": True,
        "description": "Delete a file or folder.",
    },
    "os.modify_file": {
        "risk_level": "high",
        "requires_security": True,
        "requires_human_approval": True,
        "description": "Modify file contents or metadata.",
    },
    "os.install_app": {
        "risk_level": "critical",
        "requires_security": True,
        "requires_human_approval": True,
        "description": "Install software or packages.",
    },
    "os.uninstall_app": {
        "risk_level": "critical",
        "requires_security": True,
        "requires_human_approval": True,
        "description": "Uninstall software or packages.",
    },
    "device.change_settings": {
        "risk_level": "high",
        "requires_security": True,
        "requires_human_approval": True,
        "description": "Change device settings.",
    },
    "device.access_camera": {
        "risk_level": "high",
        "requires_security": True,
        "requires_human_approval": True,
        "description": "Access camera.",
    },
    "device.access_microphone": {
        "risk_level": "high",
        "requires_security": True,
        "requires_human_approval": True,
        "description": "Access microphone.",
    },
    "browser.open_url": {
        "risk_level": "medium",
        "requires_security": True,
        "requires_human_approval": False,
        "description": "Open a URL in browser.",
    },
    "browser.submit_form": {
        "risk_level": "high",
        "requires_security": True,
        "requires_human_approval": True,
        "description": "Submit a browser form.",
    },
    "message.send": {
        "risk_level": "critical",
        "requires_security": True,
        "requires_human_approval": True,
        "description": "Send email, SMS, chat, or app message.",
    },
    "call.start": {
        "risk_level": "critical",
        "requires_security": True,
        "requires_human_approval": True,
        "description": "Start a phone or voice call.",
    },
    "finance.transaction": {
        "risk_level": "critical",
        "requires_security": True,
        "requires_human_approval": True,
        "description": "Perform financial transaction.",
    },
    "automation.run_workflow": {
        "risk_level": "high",
        "requires_security": True,
        "requires_human_approval": True,
        "description": "Run system workflow automation.",
    },
    "memory.export": {
        "risk_level": "high",
        "requires_security": True,
        "requires_human_approval": True,
        "description": "Export user/workspace memory.",
    },
    "security.change_policy": {
        "risk_level": "critical",
        "requires_security": True,
        "requires_human_approval": True,
        "description": "Change security policy.",
    },
}

DEFAULT_PLATFORM_SETTINGS: Dict[str, Dict[str, Any]] = {
    "windows": {
        "enabled": True,
        "allow_shell": False,
        "allow_file_write": False,
        "allow_app_control": False,
        "allowed_roots": [],
        "blocked_roots": ["C:/Windows", "C:/Program Files", "C:/Program Files (x86)"],
    },
    "macos": {
        "enabled": True,
        "allow_shell": False,
        "allow_file_write": False,
        "allow_app_control": False,
        "allowed_roots": [],
        "blocked_roots": ["/System", "/Library", "/Applications"],
    },
    "linux": {
        "enabled": True,
        "allow_shell": False,
        "allow_file_write": False,
        "allow_app_control": False,
        "allowed_roots": [],
        "blocked_roots": ["/bin", "/sbin", "/usr", "/etc", "/root"],
    },
    "android": {
        "enabled": True,
        "allow_shell": False,
        "allow_file_write": False,
        "allow_app_control": False,
        "allowed_roots": [],
        "blocked_roots": ["/system", "/vendor", "/data"],
    },
    "ios": {
        "enabled": False,
        "allow_shell": False,
        "allow_file_write": False,
        "allow_app_control": False,
        "allowed_roots": [],
        "blocked_roots": [],
    },
    "web": {
        "enabled": True,
        "allow_shell": False,
        "allow_file_write": False,
        "allow_app_control": False,
        "allowed_roots": [],
        "blocked_roots": [],
    },
    "unknown": {
        "enabled": False,
        "allow_shell": False,
        "allow_file_write": False,
        "allow_app_control": False,
        "allowed_roots": [],
        "blocked_roots": [],
    },
}


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def generate_id(prefix: str = "id") -> str:
    """Generate a unique readable ID."""
    return f"{prefix}_{uuid.uuid4().hex}"


def deep_copy(value: Any) -> Any:
    """Safe deep copy helper."""
    try:
        return copy.deepcopy(value)
    except Exception:
        return value


def safe_json_dumps(value: Any) -> str:
    """Safely serialize any value to JSON string."""
    try:
        return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        return json.dumps(str(value), ensure_ascii=False)


def normalize_text(value: Any) -> str:
    """Normalize string values for config keys."""
    return str(value or "").strip().lower()


def normalize_permission(value: Any) -> str:
    """Normalize permission name."""
    return str(value or "").strip().lower()


def normalize_action(value: Any) -> str:
    """Normalize protected action name."""
    return str(value or "").strip().lower()


def sanitize_list(values: Optional[Iterable[Any]], max_items: int = 200) -> List[str]:
    """Sanitize list values into unique strings."""
    if not values:
        return []

    output: List[str] = []
    for item in values:
        text = str(item or "").strip()
        if text and text not in output:
            output.append(text[:300])

        if len(output) >= max_items:
            break

    return output


def detect_current_platform() -> str:
    """Detect current runtime platform as a safe string."""
    raw = platform.system().lower()

    if "windows" in raw:
        return "windows"
    if "darwin" in raw:
        return "macos"
    if "linux" in raw:
        return "linux"

    return "unknown"


def is_safe_mode(value: Any) -> bool:
    """Check if safe mode is supported."""
    return normalize_text(value) in SUPPORTED_SAFE_MODES


def is_risk_level(value: Any) -> bool:
    """Check if risk level is supported."""
    return normalize_text(value) in SUPPORTED_RISK_LEVELS


def is_platform(value: Any) -> bool:
    """Check if platform is supported."""
    return normalize_text(value) in SUPPORTED_PLATFORMS


def redact_sensitive_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """Redact sensitive-looking keys from logs/events."""
    redacted: Dict[str, Any] = {}

    sensitive_tokens = {
        "password",
        "secret",
        "token",
        "api_key",
        "private_key",
        "credential",
        "cookie",
        "session",
        "bearer",
        "oauth",
    }

    for key, value in (data or {}).items():
        key_text = str(key).lower()
        if any(token in key_text for token in sensitive_tokens):
            redacted[key] = "[REDACTED]"
        elif isinstance(value, dict):
            redacted[key] = redact_sensitive_dict(value)
        elif isinstance(value, list):
            redacted[key] = [
                redact_sensitive_dict(item) if isinstance(item, dict) else item
                for item in value[:50]
            ]
        else:
            redacted[key] = value

    return redacted


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SystemConfigContext:
    """
    SaaS context for SystemConfig operations.

    user_id and workspace_id are required for user/workspace-specific config.
    """

    user_id: str
    workspace_id: str
    request_id: str = field(default_factory=lambda: generate_id("req"))
    actor_id: Optional[str] = None
    role: Optional[str] = None
    session_id: Optional[str] = None
    source: str = "system_config"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProtectedActionPolicy:
    """Policy for one protected system action."""

    action: str
    risk_level: str = "high"
    requires_security: bool = True
    requires_human_approval: bool = True
    enabled: bool = True
    description: str = ""
    allowed_roles: List[str] = field(default_factory=list)
    blocked_roles: List[str] = field(default_factory=list)
    allowed_platforms: List[str] = field(default_factory=list)
    blocked_platforms: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    updated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProtectedActionPolicy":
        raw = dict(data or {})
        raw.setdefault("action", "")
        raw.setdefault("risk_level", "high")
        raw.setdefault("requires_security", True)
        raw.setdefault("requires_human_approval", True)
        raw.setdefault("enabled", True)
        raw.setdefault("description", "")
        raw.setdefault("allowed_roles", [])
        raw.setdefault("blocked_roles", [])
        raw.setdefault("allowed_platforms", [])
        raw.setdefault("blocked_platforms", [])
        raw.setdefault("metadata", {})
        raw.setdefault("updated_at", utc_now_iso())
        return cls(**raw)


@dataclass
class PlatformSettings:
    """Settings for one platform."""

    platform_name: str
    enabled: bool = True
    allow_shell: bool = False
    allow_file_write: bool = False
    allow_app_control: bool = False
    allowed_roots: List[str] = field(default_factory=list)
    blocked_roots: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    updated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PlatformSettings":
        raw = dict(data or {})
        raw.setdefault("platform_name", "unknown")
        raw.setdefault("enabled", False)
        raw.setdefault("allow_shell", False)
        raw.setdefault("allow_file_write", False)
        raw.setdefault("allow_app_control", False)
        raw.setdefault("allowed_roots", [])
        raw.setdefault("blocked_roots", [])
        raw.setdefault("metadata", {})
        raw.setdefault("updated_at", utc_now_iso())
        return cls(**raw)


@dataclass
class WorkspaceSystemConfig:
    """Complete System Agent config for one user/workspace."""

    user_id: str
    workspace_id: str
    safe_mode: str = SAFE_MODE_STRICT
    system_agent_enabled: bool = True
    protected_actions: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    role_permissions: Dict[str, List[str]] = field(default_factory=dict)
    platform_settings: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    default_platform: str = "unknown"
    audit_enabled: bool = True
    verification_required: bool = True
    memory_payload_enabled: bool = True
    dashboard_events_enabled: bool = True
    max_actions_per_minute: int = 30
    max_high_risk_actions_per_hour: int = 10
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def default(cls, user_id: str, workspace_id: str) -> "WorkspaceSystemConfig":
        detected_platform = detect_current_platform()

        protected_actions = {
            action: ProtectedActionPolicy(
                action=action,
                risk_level=str(settings.get("risk_level", "high")),
                requires_security=bool(settings.get("requires_security", True)),
                requires_human_approval=bool(settings.get("requires_human_approval", True)),
                enabled=True,
                description=str(settings.get("description", "")),
                allowed_roles=[],
                blocked_roles=[],
                allowed_platforms=[],
                blocked_platforms=[],
                metadata={},
            ).to_dict()
            for action, settings in DEFAULT_PROTECTED_ACTIONS.items()
        }

        platform_settings = {
            name: PlatformSettings(
                platform_name=name,
                enabled=bool(settings.get("enabled", False)),
                allow_shell=bool(settings.get("allow_shell", False)),
                allow_file_write=bool(settings.get("allow_file_write", False)),
                allow_app_control=bool(settings.get("allow_app_control", False)),
                allowed_roots=sanitize_list(settings.get("allowed_roots", [])),
                blocked_roots=sanitize_list(settings.get("blocked_roots", [])),
                metadata={},
            ).to_dict()
            for name, settings in DEFAULT_PLATFORM_SETTINGS.items()
        }

        return cls(
            user_id=str(user_id),
            workspace_id=str(workspace_id),
            safe_mode=SAFE_MODE_STRICT,
            system_agent_enabled=True,
            protected_actions=protected_actions,
            role_permissions=deep_copy(DEFAULT_ROLE_PERMISSIONS),
            platform_settings=platform_settings,
            default_platform=detected_platform,
            audit_enabled=True,
            verification_required=True,
            memory_payload_enabled=True,
            dashboard_events_enabled=True,
            max_actions_per_minute=30,
            max_high_risk_actions_per_hour=10,
            metadata={
                "schema": CONFIG_SCHEMA,
                "created_by": DEFAULT_AGENT_NAME,
                "default_platform_detected": detected_platform,
            },
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WorkspaceSystemConfig":
        raw = dict(data or {})

        raw.setdefault("user_id", "")
        raw.setdefault("workspace_id", "")
        raw.setdefault("safe_mode", SAFE_MODE_STRICT)
        raw.setdefault("system_agent_enabled", True)
        raw.setdefault("protected_actions", {})
        raw.setdefault("role_permissions", deep_copy(DEFAULT_ROLE_PERMISSIONS))
        raw.setdefault("platform_settings", {})
        raw.setdefault("default_platform", detect_current_platform())
        raw.setdefault("audit_enabled", True)
        raw.setdefault("verification_required", True)
        raw.setdefault("memory_payload_enabled", True)
        raw.setdefault("dashboard_events_enabled", True)
        raw.setdefault("max_actions_per_minute", 30)
        raw.setdefault("max_high_risk_actions_per_hour", 10)
        raw.setdefault("metadata", {})
        raw.setdefault("created_at", utc_now_iso())
        raw.setdefault("updated_at", utc_now_iso())

        return cls(**raw)


# ---------------------------------------------------------------------------
# Storage adapter
# ---------------------------------------------------------------------------

class JsonSystemConfigStore:
    """
    JSON storage adapter for System Agent config.

    In production SaaS this can be replaced with PostgreSQL, Redis, encrypted
    storage, or a workspace config microservice.

    File layout:
        .william_data/system_config/
            user_<user_id>/
                workspace_<workspace_id>.json
    """

    def __init__(self, storage_dir: Union[str, Path] = DEFAULT_STORAGE_DIR) -> None:
        self.storage_dir = Path(storage_dir)
        self._lock = threading.RLock()

    def _safe_segment(self, value: Any) -> str:
        text = str(value or "").strip() or "unknown"
        output = []

        for char in text:
            if char.isalnum() or char in {"-", "_", "."}:
                output.append(char)
            else:
                output.append("_")

        return "".join(output)[:120]

    def _config_file(self, user_id: str, workspace_id: str) -> Path:
        safe_user = self._safe_segment(user_id)
        safe_workspace = self._safe_segment(workspace_id)
        return self.storage_dir / f"user_{safe_user}" / f"workspace_{safe_workspace}.json"

    def load_config(self, user_id: str, workspace_id: str) -> Optional[WorkspaceSystemConfig]:
        """Load isolated user/workspace config."""
        with self._lock:
            path = self._config_file(user_id, workspace_id)

            if not path.exists():
                return None

            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                config_data = raw.get("config", raw)

                config = WorkspaceSystemConfig.from_dict(config_data)

                if str(config.user_id) != str(user_id):
                    logger.warning("System config user_id mismatch blocked.")
                    return None

                if str(config.workspace_id) != str(workspace_id):
                    logger.warning("System config workspace_id mismatch blocked.")
                    return None

                return config

            except Exception as exc:
                logger.exception("Failed to load system config: %s", exc)
                return None

    def save_config(self, config: WorkspaceSystemConfig) -> None:
        """Save isolated user/workspace config."""
        with self._lock:
            path = self._config_file(config.user_id, config.workspace_id)
            path.parent.mkdir(parents=True, exist_ok=True)

            payload = {
                "schema": CONFIG_SCHEMA,
                "saved_at": utc_now_iso(),
                "user_id": config.user_id,
                "workspace_id": config.workspace_id,
                "config": config.to_dict(),
            }

            tmp_path = path.with_suffix(".json.tmp")
            tmp_path.write_text(safe_json_dumps(payload), encoding="utf-8")
            tmp_path.replace(path)


# ---------------------------------------------------------------------------
# SystemConfig
# ---------------------------------------------------------------------------

class SystemConfig(BaseAgent):
    """
    System Agent configuration manager.

    This class manages:
        - safe mode
        - protected action policies
        - platform settings
        - user/workspace role permissions
        - permission checks
        - Security Agent approval hooks
        - Verification Agent payloads
        - Memory Agent payloads
        - audit/event hooks for Dashboard/API

    It does not execute protected actions directly.
    """

    def __init__(
        self,
        storage_dir: Union[str, Path] = DEFAULT_STORAGE_DIR,
        storage: Optional[JsonSystemConfigStore] = None,
        security_checker: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=kwargs.pop("agent_name", DEFAULT_AGENT_NAME),
            agent_type=kwargs.pop("agent_type", DEFAULT_AGENT_TYPE),
            **kwargs,
        )

        self.storage = storage or JsonSystemConfigStore(storage_dir=storage_dir)
        self.security_checker = security_checker
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter
        self._cache: Dict[Tuple[str, str], WorkspaceSystemConfig] = {}
        self._lock = threading.RLock()

    # -----------------------------------------------------------------------
    # Required compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[SystemConfigContext, Dict[str, Any], None],
    ) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        Every user/workspace-specific config operation must include user_id and
        workspace_id to prevent cross-tenant config mixing.
        """
        if isinstance(context, SystemConfigContext):
            ctx = context.to_dict()
        elif isinstance(context, dict):
            ctx = dict(context)
        else:
            ctx = {}

        user_id = str(ctx.get("user_id") or "").strip()
        workspace_id = str(ctx.get("workspace_id") or "").strip()

        if not user_id:
            return self._error_result(
                message="Missing required user_id in task context.",
                error_code="MISSING_USER_ID",
                metadata={"hook": "_validate_task_context"},
            )

        if not workspace_id:
            return self._error_result(
                message="Missing required workspace_id in task context.",
                error_code="MISSING_WORKSPACE_ID",
                metadata={"hook": "_validate_task_context"},
            )

        ctx["user_id"] = user_id
        ctx["workspace_id"] = workspace_id
        ctx.setdefault("request_id", generate_id("req"))
        ctx.setdefault("source", "system_config")
        ctx.setdefault("metadata", {})

        return self._safe_result(
            message="Task context validated.",
            data=ctx,
            metadata={"hook": "_validate_task_context"},
        )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Decide whether config operation must go through Security Agent.
        """
        action_name = normalize_action(action)
        payload = payload or {}

        high_security_actions = {
            "set_safe_mode",
            "update_protected_action",
            "remove_protected_action",
            "set_role_permissions",
            "grant_permission",
            "revoke_permission",
            "update_platform_settings",
            "reset_config",
            "import_config",
            "export_config",
            "evaluate_action_request",
        }

        if action_name in high_security_actions:
            return True

        if action_name.startswith("security."):
            return True

        risk_level = normalize_text(payload.get("risk_level"))
        if risk_level in {"high", "critical"}:
            return True

        if bool(payload.get("requires_security")):
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        context: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Ask Security Agent for approval when needed.

        If no Security Agent checker is configured, sensitive config changes are
        denied by default.
        """
        payload = payload or {}
        requires_check = self._requires_security_check(action, payload)

        security_payload = {
            "agent": DEFAULT_AGENT_NAME,
            "action": action,
            "requires_security_check": requires_check,
            "context": self._public_context(context),
            "payload_summary": self._summarize_payload(payload),
            "created_at": utc_now_iso(),
        }

        if not requires_check:
            return self._safe_result(
                message="Security approval not required.",
                data={
                    "approved": True,
                    "security_payload": security_payload,
                },
                metadata={"hook": "_request_security_approval"},
            )

        if self.security_checker is None:
            return self._error_result(
                message=(
                    "Security approval is required for this SystemConfig action, "
                    "but no Security Agent checker is configured."
                ),
                error_code="SECURITY_CHECKER_NOT_CONFIGURED",
                data={
                    "approved": False,
                    "security_payload": security_payload,
                },
                metadata={"hook": "_request_security_approval"},
            )

        try:
            approval = self.security_checker(security_payload)
            approved = bool(approval.get("approved") or approval.get("success"))

            if not approved:
                return self._error_result(
                    message="Security Agent denied this SystemConfig action.",
                    error_code="SECURITY_DENIED",
                    data={
                        "approved": False,
                        "approval": approval,
                        "security_payload": security_payload,
                    },
                    metadata={"hook": "_request_security_approval"},
                )

            return self._safe_result(
                message="Security Agent approved this SystemConfig action.",
                data={
                    "approved": True,
                    "approval": approval,
                    "security_payload": security_payload,
                },
                metadata={"hook": "_request_security_approval"},
            )

        except Exception as exc:
            logger.exception("Security approval failed: %s", exc)
            return self._error_result(
                message="Security approval failed.",
                error_code="SECURITY_APPROVAL_EXCEPTION",
                error=str(exc),
                data={
                    "approved": False,
                    "security_payload": security_payload,
                },
                metadata={"hook": "_request_security_approval"},
            )

    def _prepare_verification_payload(
        self,
        action: str,
        context: Dict[str, Any],
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent.

        Verification Agent can confirm:
            - correct tenant isolation
            - expected config changes
            - policy validity
            - structured result format
        """
        return {
            "verification_type": "system_config_action",
            "agent": DEFAULT_AGENT_NAME,
            "action": action,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "request_id": context.get("request_id"),
            "result_metadata": result.get("metadata", {}),
            "created_at": utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: Dict[str, Any],
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        Useful for remembering user/workspace safety preferences and platform
        preferences without mixing tenants.
        """
        return {
            "memory_scope": "system_agent",
            "memory_component": "system_config",
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "request_id": context.get("request_id"),
            "created_at": utc_now_iso(),
            "data": data or {},
        }

    def _emit_agent_event(
        self,
        event_type: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Emit Dashboard/API/Agent event if configured.
        """
        event_payload = deep_copy(payload)
        event_payload.setdefault("event_id", generate_id("evt"))
        event_payload.setdefault("agent", DEFAULT_AGENT_NAME)
        event_payload.setdefault("created_at", utc_now_iso())

        try:
            if self.event_emitter:
                self.event_emitter(event_type, event_payload)
                return

            if hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_type, event_payload)  # type: ignore
                    return
                except Exception:
                    pass

            logger.debug("SystemConfig event: %s %s", event_type, event_payload)

        except Exception as exc:
            logger.warning("Failed to emit SystemConfig event: %s", exc)

    def _log_audit_event(
        self,
        action: str,
        context: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
        success: bool = True,
        error: Optional[str] = None,
    ) -> None:
        """
        Write audit event for Dashboard/API compliance.

        Payload is summarized and sensitive values are redacted.
        """
        audit_payload = {
            "audit_id": generate_id("audit"),
            "agent": DEFAULT_AGENT_NAME,
            "action": action,
            "success": success,
            "error": error,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "actor_id": context.get("actor_id"),
            "role": context.get("role"),
            "request_id": context.get("request_id"),
            "payload_summary": self._summarize_payload(payload or {}),
            "created_at": utc_now_iso(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit_payload)
            else:
                logger.info("SystemConfig audit: %s", safe_json_dumps(audit_payload))
        except Exception as exc:
            logger.warning("Failed to write SystemConfig audit: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success result."""
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
        error_code: str = "SYSTEM_CONFIG_ERROR",
        error: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error result."""
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": {
                "code": error_code,
                "detail": error or message,
            },
            "metadata": metadata or {},
        }

    # -----------------------------------------------------------------------
    # Public config methods
    # -----------------------------------------------------------------------

    def get_config(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Return full config for one user/workspace."""
        action = "get_config"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]
        config = self._load_config(ctx)

        result = self._safe_result(
            message="System Agent config retrieved.",
            data={
                "config": config.to_dict(),
                "memory_payload": self._prepare_memory_payload(
                    action,
                    ctx,
                    data={
                        "safe_mode": config.safe_mode,
                        "default_platform": config.default_platform,
                    },
                ),
            },
            metadata={
                "safe_mode": config.safe_mode,
                "default_platform": config.default_platform,
            },
        )

        result["data"]["verification_payload"] = self._prepare_verification_payload(
            action,
            ctx,
            result,
        )

        self._log_audit_event(action, ctx, {}, True)
        return result

    def get_public_config(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Return dashboard-safe config summary.

        This avoids exposing all low-level internal policy details.
        """
        action = "get_public_config"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]
        config = self._load_config(ctx)

        public_config = {
            "user_id": config.user_id,
            "workspace_id": config.workspace_id,
            "safe_mode": config.safe_mode,
            "system_agent_enabled": config.system_agent_enabled,
            "default_platform": config.default_platform,
            "audit_enabled": config.audit_enabled,
            "verification_required": config.verification_required,
            "memory_payload_enabled": config.memory_payload_enabled,
            "dashboard_events_enabled": config.dashboard_events_enabled,
            "max_actions_per_minute": config.max_actions_per_minute,
            "max_high_risk_actions_per_hour": config.max_high_risk_actions_per_hour,
            "protected_action_count": len(config.protected_actions),
            "platform_count": len(config.platform_settings),
            "updated_at": config.updated_at,
        }

        result = self._safe_result(
            message="Public System Agent config retrieved.",
            data={
                "config": public_config,
            },
            metadata={
                "safe_mode": config.safe_mode,
                "default_platform": config.default_platform,
            },
        )

        self._log_audit_event(action, ctx, {}, True)
        return result

    def set_safe_mode(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
        safe_mode: str,
    ) -> Dict[str, Any]:
        """Set safe mode for one user/workspace."""
        action = "set_safe_mode"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]
        safe_mode_value = normalize_text(safe_mode)

        if safe_mode_value not in SUPPORTED_SAFE_MODES:
            return self._error_result(
                message="Unsupported safe mode.",
                error_code="INVALID_SAFE_MODE",
                metadata={
                    "safe_mode": safe_mode,
                    "supported_safe_modes": sorted(SUPPORTED_SAFE_MODES),
                },
            )

        security_result = self._request_security_approval(
            action=action,
            context=ctx,
            payload={"safe_mode": safe_mode_value},
        )
        if not security_result["success"]:
            self._log_audit_event(action, ctx, {"safe_mode": safe_mode_value}, False)
            return security_result

        config = self._load_config(ctx)
        old_safe_mode = config.safe_mode
        config.safe_mode = safe_mode_value
        config.updated_at = utc_now_iso()
        self._save_config(config)

        result = self._safe_result(
            message="System Agent safe mode updated.",
            data={
                "old_safe_mode": old_safe_mode,
                "new_safe_mode": config.safe_mode,
                "config": config.to_dict(),
                "memory_payload": self._prepare_memory_payload(
                    action,
                    ctx,
                    data={
                        "old_safe_mode": old_safe_mode,
                        "new_safe_mode": config.safe_mode,
                    },
                ),
            },
            metadata={
                "old_safe_mode": old_safe_mode,
                "new_safe_mode": config.safe_mode,
            },
        )

        result["data"]["verification_payload"] = self._prepare_verification_payload(
            action,
            ctx,
            result,
        )

        self._emit_agent_event(
            "system_config.safe_mode_updated",
            {
                "context": self._public_context(ctx),
                "old_safe_mode": old_safe_mode,
                "new_safe_mode": config.safe_mode,
            },
        )
        self._log_audit_event(action, ctx, {"safe_mode": safe_mode_value}, True)

        return result

    def set_system_agent_enabled(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
        enabled: bool,
    ) -> Dict[str, Any]:
        """Enable or disable System Agent for a workspace."""
        action = "set_system_agent_enabled"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]

        security_result = self._request_security_approval(
            action=action,
            context=ctx,
            payload={"enabled": bool(enabled), "requires_security": True},
        )
        if not security_result["success"]:
            self._log_audit_event(action, ctx, {"enabled": enabled}, False)
            return security_result

        config = self._load_config(ctx)
        old_value = config.system_agent_enabled
        config.system_agent_enabled = bool(enabled)
        config.updated_at = utc_now_iso()
        self._save_config(config)

        result = self._safe_result(
            message="System Agent enabled status updated.",
            data={
                "old_value": old_value,
                "new_value": config.system_agent_enabled,
                "config": config.to_dict(),
            },
            metadata={
                "old_value": old_value,
                "new_value": config.system_agent_enabled,
            },
        )

        result["data"]["verification_payload"] = self._prepare_verification_payload(
            action,
            ctx,
            result,
        )

        self._emit_agent_event(
            "system_config.enabled_updated",
            {
                "context": self._public_context(ctx),
                "old_value": old_value,
                "new_value": config.system_agent_enabled,
            },
        )
        self._log_audit_event(action, ctx, {"enabled": enabled}, True)

        return result

    # -----------------------------------------------------------------------
    # Protected action policy methods
    # -----------------------------------------------------------------------

    def list_protected_actions(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """List protected actions for one workspace."""
        action = "list_protected_actions"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]
        config = self._load_config(ctx)

        actions = dict(sorted(config.protected_actions.items()))

        result = self._safe_result(
            message="Protected actions listed.",
            data={
                "protected_actions": actions,
                "count": len(actions),
            },
            metadata={"count": len(actions)},
        )

        self._log_audit_event(action, ctx, {}, True)
        return result

    def get_protected_action(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
        protected_action: str,
    ) -> Dict[str, Any]:
        """Get one protected action policy."""
        action = "get_protected_action"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]
        config = self._load_config(ctx)
        action_key = normalize_action(protected_action)

        policy = config.protected_actions.get(action_key)
        if not policy:
            return self._error_result(
                message="Protected action policy not found.",
                error_code="PROTECTED_ACTION_NOT_FOUND",
                metadata={"protected_action": action_key},
            )

        result = self._safe_result(
            message="Protected action policy retrieved.",
            data={
                "protected_action": action_key,
                "policy": policy,
            },
            metadata={"protected_action": action_key},
        )

        self._log_audit_event(action, ctx, {"protected_action": action_key}, True)
        return result

    def update_protected_action(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
        protected_action: str,
        risk_level: str = "high",
        requires_security: bool = True,
        requires_human_approval: bool = True,
        enabled: bool = True,
        description: str = "",
        allowed_roles: Optional[Iterable[Any]] = None,
        blocked_roles: Optional[Iterable[Any]] = None,
        allowed_platforms: Optional[Iterable[Any]] = None,
        blocked_platforms: Optional[Iterable[Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create or update a protected action policy."""
        action = "update_protected_action"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]
        action_key = normalize_action(protected_action)
        risk = normalize_text(risk_level)

        if not action_key:
            return self._error_result(
                message="Missing protected action name.",
                error_code="MISSING_PROTECTED_ACTION",
            )

        if risk not in SUPPORTED_RISK_LEVELS:
            return self._error_result(
                message="Invalid risk level.",
                error_code="INVALID_RISK_LEVEL",
                metadata={"supported_risk_levels": sorted(SUPPORTED_RISK_LEVELS)},
            )

        cleaned_allowed_platforms = [
            item for item in sanitize_list(allowed_platforms)
            if normalize_text(item) in SUPPORTED_PLATFORMS
        ]
        cleaned_blocked_platforms = [
            item for item in sanitize_list(blocked_platforms)
            if normalize_text(item) in SUPPORTED_PLATFORMS
        ]

        payload = {
            "protected_action": action_key,
            "risk_level": risk,
            "requires_security": bool(requires_security),
            "requires_human_approval": bool(requires_human_approval),
            "enabled": bool(enabled),
            "description": description,
            "allowed_roles": sanitize_list(allowed_roles),
            "blocked_roles": sanitize_list(blocked_roles),
            "allowed_platforms": cleaned_allowed_platforms,
            "blocked_platforms": cleaned_blocked_platforms,
            "metadata": metadata or {},
        }

        security_result = self._request_security_approval(
            action=action,
            context=ctx,
            payload=payload,
        )
        if not security_result["success"]:
            self._log_audit_event(action, ctx, payload, False)
            return security_result

        config = self._load_config(ctx)
        old_policy = deep_copy(config.protected_actions.get(action_key))

        policy = ProtectedActionPolicy(
            action=action_key,
            risk_level=risk,
            requires_security=bool(requires_security),
            requires_human_approval=bool(requires_human_approval),
            enabled=bool(enabled),
            description=str(description or ""),
            allowed_roles=sanitize_list(allowed_roles),
            blocked_roles=sanitize_list(blocked_roles),
            allowed_platforms=cleaned_allowed_platforms,
            blocked_platforms=cleaned_blocked_platforms,
            metadata=metadata or {},
            updated_at=utc_now_iso(),
        )

        config.protected_actions[action_key] = policy.to_dict()
        config.updated_at = utc_now_iso()
        self._save_config(config)

        result = self._safe_result(
            message="Protected action policy updated.",
            data={
                "protected_action": action_key,
                "old_policy": old_policy,
                "new_policy": policy.to_dict(),
                "config": config.to_dict(),
            },
            metadata={
                "protected_action": action_key,
                "risk_level": risk,
            },
        )

        result["data"]["verification_payload"] = self._prepare_verification_payload(
            action,
            ctx,
            result,
        )

        self._emit_agent_event(
            "system_config.protected_action_updated",
            {
                "context": self._public_context(ctx),
                "protected_action": action_key,
                "risk_level": risk,
            },
        )
        self._log_audit_event(action, ctx, payload, True)

        return result

    def remove_protected_action(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
        protected_action: str,
    ) -> Dict[str, Any]:
        """Remove a custom protected action policy."""
        action = "remove_protected_action"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]
        action_key = normalize_action(protected_action)

        security_result = self._request_security_approval(
            action=action,
            context=ctx,
            payload={
                "protected_action": action_key,
                "requires_security": True,
            },
        )
        if not security_result["success"]:
            self._log_audit_event(action, ctx, {"protected_action": action_key}, False)
            return security_result

        config = self._load_config(ctx)

        if action_key not in config.protected_actions:
            return self._error_result(
                message="Protected action policy not found.",
                error_code="PROTECTED_ACTION_NOT_FOUND",
                metadata={"protected_action": action_key},
            )

        removed_policy = config.protected_actions.pop(action_key)
        config.updated_at = utc_now_iso()
        self._save_config(config)

        result = self._safe_result(
            message="Protected action policy removed.",
            data={
                "protected_action": action_key,
                "removed_policy": removed_policy,
            },
            metadata={"protected_action": action_key},
        )

        result["data"]["verification_payload"] = self._prepare_verification_payload(
            action,
            ctx,
            result,
        )

        self._emit_agent_event(
            "system_config.protected_action_removed",
            {
                "context": self._public_context(ctx),
                "protected_action": action_key,
            },
        )
        self._log_audit_event(action, ctx, {"protected_action": action_key}, True)

        return result

    # -----------------------------------------------------------------------
    # Role permission methods
    # -----------------------------------------------------------------------

    def list_role_permissions(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """List role permissions."""
        action = "list_role_permissions"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]
        config = self._load_config(ctx)

        result = self._safe_result(
            message="Role permissions listed.",
            data={
                "role_permissions": deep_copy(config.role_permissions),
            },
            metadata={"role_count": len(config.role_permissions)},
        )

        self._log_audit_event(action, ctx, {}, True)
        return result

    def set_role_permissions(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
        role: str,
        permissions: Iterable[Any],
    ) -> Dict[str, Any]:
        """Replace permissions for one role."""
        action = "set_role_permissions"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]
        role_key = normalize_text(role)
        cleaned_permissions = [
            normalize_permission(permission)
            for permission in permissions or []
            if normalize_permission(permission)
        ]

        if not role_key:
            return self._error_result(
                message="Missing role.",
                error_code="MISSING_ROLE",
            )

        payload = {
            "role": role_key,
            "permissions": cleaned_permissions,
            "requires_security": True,
        }

        security_result = self._request_security_approval(action, ctx, payload)
        if not security_result["success"]:
            self._log_audit_event(action, ctx, payload, False)
            return security_result

        config = self._load_config(ctx)
        old_permissions = deep_copy(config.role_permissions.get(role_key, []))
        config.role_permissions[role_key] = cleaned_permissions
        config.updated_at = utc_now_iso()
        self._save_config(config)

        result = self._safe_result(
            message="Role permissions updated.",
            data={
                "role": role_key,
                "old_permissions": old_permissions,
                "new_permissions": cleaned_permissions,
                "config": config.to_dict(),
            },
            metadata={"role": role_key},
        )

        result["data"]["verification_payload"] = self._prepare_verification_payload(
            action,
            ctx,
            result,
        )

        self._emit_agent_event(
            "system_config.role_permissions_updated",
            {
                "context": self._public_context(ctx),
                "role": role_key,
            },
        )
        self._log_audit_event(action, ctx, payload, True)

        return result

    def grant_permission(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
        role: str,
        permission: str,
    ) -> Dict[str, Any]:
        """Grant one permission to a role."""
        action = "grant_permission"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]
        role_key = normalize_text(role)
        permission_key = normalize_permission(permission)

        if not role_key or not permission_key:
            return self._error_result(
                message="Missing role or permission.",
                error_code="MISSING_ROLE_OR_PERMISSION",
            )

        payload = {
            "role": role_key,
            "permission": permission_key,
            "requires_security": True,
        }

        security_result = self._request_security_approval(action, ctx, payload)
        if not security_result["success"]:
            self._log_audit_event(action, ctx, payload, False)
            return security_result

        config = self._load_config(ctx)
        permissions = config.role_permissions.setdefault(role_key, [])

        if permission_key not in permissions:
            permissions.append(permission_key)

        config.role_permissions[role_key] = sorted(permissions)
        config.updated_at = utc_now_iso()
        self._save_config(config)

        result = self._safe_result(
            message="Permission granted.",
            data={
                "role": role_key,
                "permission": permission_key,
                "permissions": config.role_permissions[role_key],
            },
            metadata={
                "role": role_key,
                "permission": permission_key,
            },
        )

        result["data"]["verification_payload"] = self._prepare_verification_payload(
            action,
            ctx,
            result,
        )

        self._emit_agent_event(
            "system_config.permission_granted",
            {
                "context": self._public_context(ctx),
                "role": role_key,
                "permission": permission_key,
            },
        )
        self._log_audit_event(action, ctx, payload, True)

        return result

    def revoke_permission(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
        role: str,
        permission: str,
    ) -> Dict[str, Any]:
        """Revoke one permission from a role."""
        action = "revoke_permission"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]
        role_key = normalize_text(role)
        permission_key = normalize_permission(permission)

        if not role_key or not permission_key:
            return self._error_result(
                message="Missing role or permission.",
                error_code="MISSING_ROLE_OR_PERMISSION",
            )

        payload = {
            "role": role_key,
            "permission": permission_key,
            "requires_security": True,
        }

        security_result = self._request_security_approval(action, ctx, payload)
        if not security_result["success"]:
            self._log_audit_event(action, ctx, payload, False)
            return security_result

        config = self._load_config(ctx)
        permissions = config.role_permissions.setdefault(role_key, [])

        if permission_key in permissions:
            permissions.remove(permission_key)

        config.role_permissions[role_key] = sorted(permissions)
        config.updated_at = utc_now_iso()
        self._save_config(config)

        result = self._safe_result(
            message="Permission revoked.",
            data={
                "role": role_key,
                "permission": permission_key,
                "permissions": config.role_permissions[role_key],
            },
            metadata={
                "role": role_key,
                "permission": permission_key,
            },
        )

        result["data"]["verification_payload"] = self._prepare_verification_payload(
            action,
            ctx,
            result,
        )

        self._emit_agent_event(
            "system_config.permission_revoked",
            {
                "context": self._public_context(ctx),
                "role": role_key,
                "permission": permission_key,
            },
        )
        self._log_audit_event(action, ctx, payload, True)

        return result

    def has_permission(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
        permission: str,
        role: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Check whether a role has a permission."""
        action = "has_permission"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]
        config = self._load_config(ctx)
        role_key = normalize_text(role or ctx.get("role") or "viewer")
        permission_key = normalize_permission(permission)

        permissions = config.role_permissions.get(role_key, [])
        owner_permissions = config.role_permissions.get("owner", [])

        allowed = (
            "*" in permissions
            or permission_key in permissions
            or f"{permission_key.split('.')[0]}.*" in permissions
            or (role_key == "owner" and "*" in owner_permissions)
        )

        result = self._safe_result(
            message="Permission check completed.",
            data={
                "allowed": allowed,
                "role": role_key,
                "permission": permission_key,
                "permissions": permissions,
            },
            metadata={
                "allowed": allowed,
                "role": role_key,
                "permission": permission_key,
            },
        )

        self._log_audit_event(action, ctx, {"role": role_key, "permission": permission_key}, True)
        return result

    # -----------------------------------------------------------------------
    # Platform settings methods
    # -----------------------------------------------------------------------

    def list_platform_settings(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """List all platform settings."""
        action = "list_platform_settings"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]
        config = self._load_config(ctx)

        result = self._safe_result(
            message="Platform settings listed.",
            data={
                "platform_settings": deep_copy(config.platform_settings),
                "default_platform": config.default_platform,
            },
            metadata={"platform_count": len(config.platform_settings)},
        )

        self._log_audit_event(action, ctx, {}, True)
        return result

    def get_platform_settings(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
        platform_name: str,
    ) -> Dict[str, Any]:
        """Get one platform settings object."""
        action = "get_platform_settings"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]
        config = self._load_config(ctx)
        platform_key = normalize_text(platform_name)

        settings = config.platform_settings.get(platform_key)
        if not settings:
            return self._error_result(
                message="Platform settings not found.",
                error_code="PLATFORM_SETTINGS_NOT_FOUND",
                metadata={"platform_name": platform_key},
            )

        result = self._safe_result(
            message="Platform settings retrieved.",
            data={
                "platform_name": platform_key,
                "settings": settings,
            },
            metadata={"platform_name": platform_key},
        )

        self._log_audit_event(action, ctx, {"platform_name": platform_key}, True)
        return result

    def update_platform_settings(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
        platform_name: str,
        enabled: Optional[bool] = None,
        allow_shell: Optional[bool] = None,
        allow_file_write: Optional[bool] = None,
        allow_app_control: Optional[bool] = None,
        allowed_roots: Optional[Iterable[Any]] = None,
        blocked_roots: Optional[Iterable[Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update platform settings."""
        action = "update_platform_settings"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]
        platform_key = normalize_text(platform_name)

        if platform_key not in SUPPORTED_PLATFORMS:
            return self._error_result(
                message="Unsupported platform.",
                error_code="INVALID_PLATFORM",
                metadata={"supported_platforms": sorted(SUPPORTED_PLATFORMS)},
            )

        payload = {
            "platform_name": platform_key,
            "enabled": enabled,
            "allow_shell": allow_shell,
            "allow_file_write": allow_file_write,
            "allow_app_control": allow_app_control,
            "allowed_roots": sanitize_list(allowed_roots),
            "blocked_roots": sanitize_list(blocked_roots),
            "metadata": metadata or {},
            "requires_security": True,
        }

        security_result = self._request_security_approval(action, ctx, payload)
        if not security_result["success"]:
            self._log_audit_event(action, ctx, payload, False)
            return security_result

        config = self._load_config(ctx)

        current = PlatformSettings.from_dict(
            config.platform_settings.get(
                platform_key,
                PlatformSettings(platform_name=platform_key).to_dict(),
            )
        )

        old_settings = current.to_dict()

        if enabled is not None:
            current.enabled = bool(enabled)
        if allow_shell is not None:
            current.allow_shell = bool(allow_shell)
        if allow_file_write is not None:
            current.allow_file_write = bool(allow_file_write)
        if allow_app_control is not None:
            current.allow_app_control = bool(allow_app_control)
        if allowed_roots is not None:
            current.allowed_roots = sanitize_list(allowed_roots)
        if blocked_roots is not None:
            current.blocked_roots = sanitize_list(blocked_roots)
        if metadata is not None:
            current.metadata = {
                **(current.metadata or {}),
                **metadata,
            }

        current.updated_at = utc_now_iso()
        config.platform_settings[platform_key] = current.to_dict()
        config.updated_at = utc_now_iso()
        self._save_config(config)

        result = self._safe_result(
            message="Platform settings updated.",
            data={
                "platform_name": platform_key,
                "old_settings": old_settings,
                "new_settings": current.to_dict(),
                "config": config.to_dict(),
            },
            metadata={"platform_name": platform_key},
        )

        result["data"]["verification_payload"] = self._prepare_verification_payload(
            action,
            ctx,
            result,
        )

        self._emit_agent_event(
            "system_config.platform_settings_updated",
            {
                "context": self._public_context(ctx),
                "platform_name": platform_key,
            },
        )
        self._log_audit_event(action, ctx, payload, True)

        return result

    def set_default_platform(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
        platform_name: str,
    ) -> Dict[str, Any]:
        """Set default platform for System Agent operations."""
        action = "set_default_platform"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]
        platform_key = normalize_text(platform_name)

        if platform_key not in SUPPORTED_PLATFORMS:
            return self._error_result(
                message="Unsupported platform.",
                error_code="INVALID_PLATFORM",
                metadata={"supported_platforms": sorted(SUPPORTED_PLATFORMS)},
            )

        config = self._load_config(ctx)
        old_platform = config.default_platform
        config.default_platform = platform_key
        config.updated_at = utc_now_iso()
        self._save_config(config)

        result = self._safe_result(
            message="Default platform updated.",
            data={
                "old_platform": old_platform,
                "new_platform": platform_key,
                "config": config.to_dict(),
                "memory_payload": self._prepare_memory_payload(
                    action,
                    ctx,
                    data={
                        "old_platform": old_platform,
                        "new_platform": platform_key,
                    },
                ),
            },
            metadata={
                "old_platform": old_platform,
                "new_platform": platform_key,
            },
        )

        result["data"]["verification_payload"] = self._prepare_verification_payload(
            action,
            ctx,
            result,
        )

        self._emit_agent_event(
            "system_config.default_platform_updated",
            {
                "context": self._public_context(ctx),
                "old_platform": old_platform,
                "new_platform": platform_key,
            },
        )
        self._log_audit_event(action, ctx, {"platform_name": platform_key}, True)

        return result

    # -----------------------------------------------------------------------
    # Action evaluation
    # -----------------------------------------------------------------------

    def evaluate_action_request(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
        requested_action: str,
        platform_name: Optional[str] = None,
        role: Optional[str] = None,
        permission: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate whether a requested action can proceed.

        This method does not execute the action. It only produces a decision
        that Master Agent / Router / Security Agent can use.
        """
        action = "evaluate_action_request"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]
        config = self._load_config(ctx)

        request_action = normalize_action(requested_action)
        platform_key = normalize_text(platform_name or config.default_platform or "unknown")
        role_key = normalize_text(role or ctx.get("role") or "viewer")
        permission_key = normalize_permission(permission or f"system.request_protected_action")

        if not request_action:
            return self._error_result(
                message="Missing requested action.",
                error_code="MISSING_REQUESTED_ACTION",
            )

        decision = {
            "allowed": False,
            "requires_security": True,
            "requires_human_approval": True,
            "risk_level": "high",
            "reasons": [],
            "requested_action": request_action,
            "platform_name": platform_key,
            "role": role_key,
            "permission": permission_key,
        }

        if not config.system_agent_enabled:
            decision["reasons"].append("System Agent is disabled for this workspace.")
            return self._decision_result(ctx, action, config, decision, metadata)

        if config.safe_mode == SAFE_MODE_STRICT:
            decision["reasons"].append("Strict safe mode is active.")

        platform_settings_raw = config.platform_settings.get(platform_key)
        if not platform_settings_raw:
            decision["reasons"].append("Platform settings not found.")
            return self._decision_result(ctx, action, config, decision, metadata)

        platform_settings = PlatformSettings.from_dict(platform_settings_raw)

        if not platform_settings.enabled:
            decision["reasons"].append("Platform is disabled.")
            return self._decision_result(ctx, action, config, decision, metadata)

        policy_raw = config.protected_actions.get(request_action)
        if policy_raw:
            policy = ProtectedActionPolicy.from_dict(policy_raw)
        else:
            policy = ProtectedActionPolicy(
                action=request_action,
                risk_level="medium",
                requires_security=True,
                requires_human_approval=True,
                enabled=True,
                description="Unregistered action uses safe default policy.",
            )

        decision["risk_level"] = policy.risk_level
        decision["requires_security"] = bool(policy.requires_security)
        decision["requires_human_approval"] = bool(policy.requires_human_approval)

        if not policy.enabled:
            decision["reasons"].append("Protected action policy is disabled.")
            return self._decision_result(ctx, action, config, decision, metadata)

        if policy.allowed_roles and role_key not in policy.allowed_roles:
            decision["reasons"].append("Role is not in allowed_roles for this action.")
            return self._decision_result(ctx, action, config, decision, metadata)

        if policy.blocked_roles and role_key in policy.blocked_roles:
            decision["reasons"].append("Role is blocked for this action.")
            return self._decision_result(ctx, action, config, decision, metadata)

        if policy.allowed_platforms and platform_key not in policy.allowed_platforms:
            decision["reasons"].append("Platform is not in allowed_platforms for this action.")
            return self._decision_result(ctx, action, config, decision, metadata)

        if policy.blocked_platforms and platform_key in policy.blocked_platforms:
            decision["reasons"].append("Platform is blocked for this action.")
            return self._decision_result(ctx, action, config, decision, metadata)

        permission_result = self.has_permission(ctx, permission_key, role=role_key)
        if not permission_result.get("data", {}).get("allowed", False):
            decision["reasons"].append("Role does not have required permission.")
            return self._decision_result(ctx, action, config, decision, metadata)

        if config.safe_mode == SAFE_MODE_STRICT:
            if policy.risk_level in {"high", "critical"}:
                decision["requires_security"] = True
                decision["requires_human_approval"] = True

        elif config.safe_mode == SAFE_MODE_BALANCED:
            if policy.risk_level == "critical":
                decision["requires_security"] = True
                decision["requires_human_approval"] = True

        elif config.safe_mode == SAFE_MODE_ASSISTED:
            if policy.risk_level in {"high", "critical"}:
                decision["requires_security"] = True

        elif config.safe_mode == SAFE_MODE_OFF:
            decision["requires_security"] = bool(policy.requires_security)
            decision["requires_human_approval"] = bool(policy.requires_human_approval)

        decision["allowed"] = True
        decision["reasons"].append("Action request passed config policy evaluation.")

        security_result = self._request_security_approval(
            action=action,
            context=ctx,
            payload={
                "requested_action": request_action,
                "platform_name": platform_key,
                "role": role_key,
                "permission": permission_key,
                "risk_level": policy.risk_level,
                "requires_security": decision["requires_security"],
            },
        )

        if not security_result["success"]:
            decision["allowed"] = False
            decision["reasons"].append("Security Agent approval failed or was denied.")
            return self._decision_result(ctx, action, config, decision, metadata, security_result)

        decision["security_approval"] = security_result.get("data", {})

        return self._decision_result(ctx, action, config, decision, metadata)

    def _decision_result(
        self,
        context: Dict[str, Any],
        action: str,
        config: WorkspaceSystemConfig,
        decision: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
        security_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build structured decision result."""
        result = self._safe_result(
            message="System action request evaluated.",
            data={
                "decision": decision,
                "security_result": security_result,
                "memory_payload": self._prepare_memory_payload(
                    action,
                    context,
                    data={
                        "requested_action": decision.get("requested_action"),
                        "allowed": decision.get("allowed"),
                        "risk_level": decision.get("risk_level"),
                        "safe_mode": config.safe_mode,
                    },
                ),
            },
            metadata={
                "allowed": decision.get("allowed"),
                "risk_level": decision.get("risk_level"),
                "safe_mode": config.safe_mode,
                **(metadata or {}),
            },
        )

        result["data"]["verification_payload"] = self._prepare_verification_payload(
            action,
            context,
            result,
        )

        self._emit_agent_event(
            "system_config.action_evaluated",
            {
                "context": self._public_context(context),
                "decision": decision,
            },
        )
        self._log_audit_event(
            action,
            context,
            {
                "decision": decision,
                "metadata": metadata or {},
            },
            bool(decision.get("allowed", False)),
        )

        return result

    # -----------------------------------------------------------------------
    # Import / Export / Reset
    # -----------------------------------------------------------------------

    def export_config(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Export isolated config for this user/workspace."""
        action = "export_config"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]

        security_result = self._request_security_approval(
            action=action,
            context=ctx,
            payload={"requires_security": True},
        )
        if not security_result["success"]:
            self._log_audit_event(action, ctx, {}, False)
            return security_result

        config = self._load_config(ctx)

        export_payload = {
            "schema": CONFIG_SCHEMA,
            "export_id": generate_id("syscfg_export"),
            "created_at": utc_now_iso(),
            "user_id": ctx["user_id"],
            "workspace_id": ctx["workspace_id"],
            "config": config.to_dict(),
        }

        result = self._safe_result(
            message="System Agent config exported.",
            data={
                "export": export_payload,
            },
            metadata={
                "safe_mode": config.safe_mode,
                "default_platform": config.default_platform,
            },
        )

        result["data"]["verification_payload"] = self._prepare_verification_payload(
            action,
            ctx,
            result,
        )

        self._log_audit_event(action, ctx, {}, True)
        return result

    def import_config(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
        import_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Import config into current user/workspace.

        Important:
            Imported config is forced into current user_id/workspace_id to
            prevent cross-tenant leakage.
        """
        action = "import_config"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]

        if not isinstance(import_payload, dict):
            return self._error_result(
                message="Import payload must be a dictionary.",
                error_code="INVALID_IMPORT_PAYLOAD",
            )

        security_result = self._request_security_approval(
            action=action,
            context=ctx,
            payload={
                "requires_security": True,
                "payload_keys": list(import_payload.keys()),
            },
        )
        if not security_result["success"]:
            self._log_audit_event(action, ctx, {}, False)
            return security_result

        raw_config = import_payload.get("config", import_payload)

        if not isinstance(raw_config, dict):
            return self._error_result(
                message="Imported config must be a dictionary.",
                error_code="INVALID_IMPORTED_CONFIG",
            )

        config = WorkspaceSystemConfig.from_dict(raw_config)
        config.user_id = ctx["user_id"]
        config.workspace_id = ctx["workspace_id"]
        config.safe_mode = (
            config.safe_mode
            if config.safe_mode in SUPPORTED_SAFE_MODES
            else SAFE_MODE_STRICT
        )
        config.default_platform = (
            config.default_platform
            if config.default_platform in SUPPORTED_PLATFORMS
            else detect_current_platform()
        )
        config.updated_at = utc_now_iso()

        self._save_config(config)

        result = self._safe_result(
            message="System Agent config imported.",
            data={
                "config": config.to_dict(),
            },
            metadata={
                "safe_mode": config.safe_mode,
                "default_platform": config.default_platform,
            },
        )

        result["data"]["verification_payload"] = self._prepare_verification_payload(
            action,
            ctx,
            result,
        )

        self._emit_agent_event(
            "system_config.imported",
            {
                "context": self._public_context(ctx),
                "safe_mode": config.safe_mode,
            },
        )
        self._log_audit_event(action, ctx, {}, True)

        return result

    def reset_config(
        self,
        context: Union[SystemConfigContext, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Reset config to safe defaults for this user/workspace."""
        action = "reset_config"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]

        security_result = self._request_security_approval(
            action=action,
            context=ctx,
            payload={"requires_security": True},
        )
        if not security_result["success"]:
            self._log_audit_event(action, ctx, {}, False)
            return security_result

        old_config = self._load_config(ctx)
        new_config = WorkspaceSystemConfig.default(
            user_id=ctx["user_id"],
            workspace_id=ctx["workspace_id"],
        )

        self._save_config(new_config)

        result = self._safe_result(
            message="System Agent config reset to safe defaults.",
            data={
                "old_config": old_config.to_dict(),
                "new_config": new_config.to_dict(),
            },
            metadata={
                "safe_mode": new_config.safe_mode,
                "default_platform": new_config.default_platform,
            },
        )

        result["data"]["verification_payload"] = self._prepare_verification_payload(
            action,
            ctx,
            result,
        )

        self._emit_agent_event(
            "system_config.reset",
            {
                "context": self._public_context(ctx),
            },
        )
        self._log_audit_event(action, ctx, {}, True)

        return result

    # -----------------------------------------------------------------------
    # Router / Master Agent entry point
    # -----------------------------------------------------------------------

    def handle_task(
        self,
        task: Dict[str, Any],
        context: Optional[Union[SystemConfigContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Router-compatible task handler.

        Example task:
            {
                "action": "set_safe_mode",
                "payload": {"safe_mode": "balanced"},
                "context": {"user_id": "1", "workspace_id": "main"}
            }
        """
        if not isinstance(task, dict):
            return self._error_result(
                message="Task must be a dictionary.",
                error_code="INVALID_TASK",
            )

        action = normalize_action(task.get("action"))
        payload = task.get("payload") if isinstance(task.get("payload"), dict) else {}

        merged_context: Dict[str, Any] = {}

        if isinstance(context, SystemConfigContext):
            merged_context.update(context.to_dict())
        elif isinstance(context, dict):
            merged_context.update(context)

        if isinstance(task.get("context"), dict):
            merged_context.update(task["context"])

        if not action:
            return self._error_result(
                message="Missing task action.",
                error_code="MISSING_TASK_ACTION",
            )

        try:
            if action == "get_config":
                return self.get_config(merged_context)

            if action == "get_public_config":
                return self.get_public_config(merged_context)

            if action == "set_safe_mode":
                return self.set_safe_mode(
                    merged_context,
                    safe_mode=payload.get("safe_mode"),
                )

            if action == "set_system_agent_enabled":
                return self.set_system_agent_enabled(
                    merged_context,
                    enabled=bool(payload.get("enabled")),
                )

            if action == "list_protected_actions":
                return self.list_protected_actions(merged_context)

            if action == "get_protected_action":
                return self.get_protected_action(
                    merged_context,
                    protected_action=payload.get("protected_action") or payload.get("action_name"),
                )

            if action == "update_protected_action":
                return self.update_protected_action(
                    merged_context,
                    protected_action=payload.get("protected_action") or payload.get("action_name"),
                    risk_level=payload.get("risk_level", "high"),
                    requires_security=bool(payload.get("requires_security", True)),
                    requires_human_approval=bool(payload.get("requires_human_approval", True)),
                    enabled=bool(payload.get("enabled", True)),
                    description=str(payload.get("description") or ""),
                    allowed_roles=payload.get("allowed_roles"),
                    blocked_roles=payload.get("blocked_roles"),
                    allowed_platforms=payload.get("allowed_platforms"),
                    blocked_platforms=payload.get("blocked_platforms"),
                    metadata=payload.get("metadata"),
                )

            if action == "remove_protected_action":
                return self.remove_protected_action(
                    merged_context,
                    protected_action=payload.get("protected_action") or payload.get("action_name"),
                )

            if action == "list_role_permissions":
                return self.list_role_permissions(merged_context)

            if action == "set_role_permissions":
                return self.set_role_permissions(
                    merged_context,
                    role=payload.get("role"),
                    permissions=payload.get("permissions", []),
                )

            if action == "grant_permission":
                return self.grant_permission(
                    merged_context,
                    role=payload.get("role"),
                    permission=payload.get("permission"),
                )

            if action == "revoke_permission":
                return self.revoke_permission(
                    merged_context,
                    role=payload.get("role"),
                    permission=payload.get("permission"),
                )

            if action == "has_permission":
                return self.has_permission(
                    merged_context,
                    permission=payload.get("permission"),
                    role=payload.get("role"),
                )

            if action == "list_platform_settings":
                return self.list_platform_settings(merged_context)

            if action == "get_platform_settings":
                return self.get_platform_settings(
                    merged_context,
                    platform_name=payload.get("platform_name") or payload.get("platform"),
                )

            if action == "update_platform_settings":
                return self.update_platform_settings(
                    merged_context,
                    platform_name=payload.get("platform_name") or payload.get("platform"),
                    enabled=payload.get("enabled"),
                    allow_shell=payload.get("allow_shell"),
                    allow_file_write=payload.get("allow_file_write"),
                    allow_app_control=payload.get("allow_app_control"),
                    allowed_roots=payload.get("allowed_roots"),
                    blocked_roots=payload.get("blocked_roots"),
                    metadata=payload.get("metadata"),
                )

            if action == "set_default_platform":
                return self.set_default_platform(
                    merged_context,
                    platform_name=payload.get("platform_name") or payload.get("platform"),
                )

            if action == "evaluate_action_request":
                return self.evaluate_action_request(
                    merged_context,
                    requested_action=payload.get("requested_action") or payload.get("action_name"),
                    platform_name=payload.get("platform_name") or payload.get("platform"),
                    role=payload.get("role"),
                    permission=payload.get("permission"),
                    metadata=payload.get("metadata"),
                )

            if action == "export_config":
                return self.export_config(merged_context)

            if action == "import_config":
                return self.import_config(
                    merged_context,
                    import_payload=payload.get("import_payload") or payload.get("config") or {},
                )

            if action == "reset_config":
                return self.reset_config(merged_context)

            return self._error_result(
                message=f"Unsupported SystemConfig action: {action}",
                error_code="UNSUPPORTED_ACTION",
                metadata={
                    "supported_actions": [
                        "get_config",
                        "get_public_config",
                        "set_safe_mode",
                        "set_system_agent_enabled",
                        "list_protected_actions",
                        "get_protected_action",
                        "update_protected_action",
                        "remove_protected_action",
                        "list_role_permissions",
                        "set_role_permissions",
                        "grant_permission",
                        "revoke_permission",
                        "has_permission",
                        "list_platform_settings",
                        "get_platform_settings",
                        "update_platform_settings",
                        "set_default_platform",
                        "evaluate_action_request",
                        "export_config",
                        "import_config",
                        "reset_config",
                    ],
                },
            )

        except TypeError as exc:
            logger.exception("SystemConfig task parameter error: %s", exc)
            return self._error_result(
                message="Invalid parameters for SystemConfig task.",
                error_code="INVALID_TASK_PARAMETERS",
                error=str(exc),
                metadata={
                    "action": action,
                    "payload_keys": sorted(payload.keys()),
                },
            )
        except Exception as exc:
            logger.exception("SystemConfig task failed: %s", exc)
            return self._error_result(
                message="SystemConfig task failed.",
                error_code="TASK_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    # -----------------------------------------------------------------------
    # Internal config helpers
    # -----------------------------------------------------------------------

    def _load_config(self, context: Dict[str, Any]) -> WorkspaceSystemConfig:
        """Load config from cache/storage or create safe default."""
        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])
        cache_key = (user_id, workspace_id)

        with self._lock:
            if cache_key in self._cache:
                return WorkspaceSystemConfig.from_dict(self._cache[cache_key].to_dict())

            config = self.storage.load_config(user_id, workspace_id)

            if config is None:
                config = WorkspaceSystemConfig.default(user_id=user_id, workspace_id=workspace_id)
                self.storage.save_config(config)

            self._cache[cache_key] = WorkspaceSystemConfig.from_dict(config.to_dict())
            return WorkspaceSystemConfig.from_dict(config.to_dict())

    def _save_config(self, config: WorkspaceSystemConfig) -> None:
        """Save config to cache/storage."""
        with self._lock:
            config.updated_at = utc_now_iso()
            cache_key = (str(config.user_id), str(config.workspace_id))
            self._cache[cache_key] = WorkspaceSystemConfig.from_dict(config.to_dict())
            self.storage.save_config(config)

    def _public_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Return safe public context for events/audit payloads."""
        return {
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "request_id": context.get("request_id"),
            "actor_id": context.get("actor_id"),
            "role": context.get("role"),
            "source": context.get("source"),
        }

    def _summarize_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Return safe payload summary for logs/audits."""
        if not isinstance(payload, dict):
            return {"type": type(payload).__name__}

        redacted = redact_sensitive_dict(payload)
        summary: Dict[str, Any] = {}

        for key, value in redacted.items():
            if isinstance(value, dict):
                summary[key] = {
                    "type": "dict",
                    "keys": sorted([str(item) for item in value.keys()])[:40],
                }
            elif isinstance(value, list):
                summary[key] = {
                    "type": "list",
                    "count": len(value),
                    "sample": value[:10],
                }
            else:
                text = str(value)
                summary[key] = text[:200] + ("..." if len(text) > 200 else "")

        return summary


# ---------------------------------------------------------------------------
# Factory for Agent Registry / Agent Loader
# ---------------------------------------------------------------------------

def create_system_config(**kwargs: Any) -> SystemConfig:
    """
    Factory used by William Agent Loader / Agent Registry.

    Example:
        registry.register("system_config", create_system_config())
    """
    return SystemConfig(**kwargs)


# ---------------------------------------------------------------------------
# Manual test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    def demo_security_checker(payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Demo checker for local testing only.

        In production, this should be replaced by Security Agent.
        """
        return {
            "success": True,
            "approved": True,
            "reason": "Demo local approval.",
            "payload_received": payload,
        }

    config = SystemConfig(
        storage_dir=os.path.join(".william_data_test", "system_config"),
        security_checker=demo_security_checker,
    )

    ctx = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "actor_id": "demo_actor",
        "role": "owner",
    }

    print(safe_json_dumps(config.get_config(ctx)))

    print(safe_json_dumps(config.set_safe_mode(ctx, "balanced")))

    print(
        safe_json_dumps(
            config.update_platform_settings(
                ctx,
                platform_name=detect_current_platform(),
                enabled=True,
                allow_shell=False,
                allow_file_write=False,
                allow_app_control=False,
                allowed_roots=[],
                blocked_roots=[],
            )
        )
    )

    print(
        safe_json_dumps(
            config.evaluate_action_request(
                ctx,
                requested_action="os.execute_command",
                platform_name=detect_current_platform(),
                role="owner",
            )
        )
    )

    print(safe_json_dumps(config.get_public_config(ctx)))