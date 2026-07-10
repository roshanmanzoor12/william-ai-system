"""
core/config.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Core configuration defaults for Master Agent, routing, timeouts, safe mode,
    logging, environment loading, SaaS isolation, agent registry compatibility,
    Security Agent bridge compatibility, Memory Agent compatibility, Verification
    Agent compatibility, and dashboard/API readiness.

This file is intentionally import-safe:
    - No real system/browser/financial/call/message/destructive actions are executed.
    - No secrets are hardcoded.
    - Environment variables are loaded safely.
    - Optional .env loading works if python-dotenv is installed, but does not crash
      if it is missing.
    - All returned results use structured dict format:
      success, message, data, error, metadata.

Main Class:
    CoreConfig
"""

from __future__ import annotations

import os
import json
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timezone


# =============================================================================
# Optional dotenv support
# =============================================================================

try:
    from dotenv import load_dotenv  # type: ignore
except Exception:  # pragma: no cover
    load_dotenv = None


# =============================================================================
# Constants
# =============================================================================

DEFAULT_AGENT_NAMES: List[str] = [
    "master",
    "voice",
    "system",
    "browser",
    "code",
    "memory",
    "security",
    "verification",
    "visual",
    "workflow",
    "hologram",
    "call",
    "business",
    "finance",
    "creator",
]

SENSITIVE_AGENT_NAMES: List[str] = [
    "system",
    "browser",
    "code",
    "call",
    "finance",
    "security",
]

HIGH_RISK_ACTIONS: List[str] = [
    "delete",
    "destroy",
    "send_email",
    "send_message",
    "make_call",
    "transfer_money",
    "purchase",
    "execute_code",
    "run_terminal",
    "browser_submit",
    "modify_file",
    "upload_file",
    "download_file",
    "external_api_write",
    "change_permissions",
    "change_subscription",
]

DEFAULT_ALLOWED_ENVIRONMENTS: List[str] = [
    "development",
    "staging",
    "production",
    "testing",
]

DEFAULT_LOG_FORMAT = (
    "%(asctime)s | %(levelname)s | %(name)s | "
    "%(filename)s:%(lineno)d | %(message)s"
)


# =============================================================================
# Helper functions
# =============================================================================

def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def _safe_bool(value: Any, default: bool = False) -> bool:
    """Safely convert environment/string values into boolean."""
    if value is None:
        return default

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        return value != 0

    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on", "enabled"}:
            return True
        if normalized in {"0", "false", "no", "n", "off", "disabled"}:
            return False

    return default


def _safe_int(value: Any, default: int, minimum: Optional[int] = None, maximum: Optional[int] = None) -> int:
    """Safely convert value into integer with optional boundaries."""
    try:
        parsed = int(value)
    except Exception:
        parsed = default

    if minimum is not None:
        parsed = max(minimum, parsed)

    if maximum is not None:
        parsed = min(maximum, parsed)

    return parsed


def _safe_float(value: Any, default: float, minimum: Optional[float] = None, maximum: Optional[float] = None) -> float:
    """Safely convert value into float with optional boundaries."""
    try:
        parsed = float(value)
    except Exception:
        parsed = default

    if minimum is not None:
        parsed = max(minimum, parsed)

    if maximum is not None:
        parsed = min(maximum, parsed)

    return parsed


def _safe_json_dict(value: Any, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Safely parse JSON dictionary from env/string/dict."""
    if default is None:
        default = {}

    if value is None:
        return default

    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return default

    return default


def _safe_json_list(value: Any, default: Optional[List[Any]] = None) -> List[Any]:
    """Safely parse JSON list from env/string/list."""
    if default is None:
        default = []

    if value is None:
        return default

    if isinstance(value, list):
        return value

    if isinstance(value, str):
        raw = value.strip()

        if not raw:
            return default

        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            pass

        if "," in raw:
            return [item.strip() for item in raw.split(",") if item.strip()]

        return [raw]

    return default


def _normalize_environment(value: Optional[str]) -> str:
    """Normalize environment name."""
    if not value:
        return "development"

    normalized = str(value).strip().lower()

    aliases = {
        "dev": "development",
        "prod": "production",
        "test": "testing",
    }

    normalized = aliases.get(normalized, normalized)

    if normalized not in DEFAULT_ALLOWED_ENVIRONMENTS:
        return "development"

    return normalized


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class LoggingConfig:
    """Logging configuration used by CoreConfig and future dashboard/API layers."""

    level: str = "INFO"
    logger_name: str = "william.core"
    log_to_file: bool = False
    log_file_path: str = "logs/william_core.log"
    log_format: str = DEFAULT_LOG_FORMAT
    enable_audit_logs: bool = True
    enable_agent_events: bool = True
    redact_sensitive_values: bool = True


@dataclass
class TimeoutConfig:
    """Default timeout configuration for Master Agent and agent routing."""

    default_task_timeout_seconds: int = 60
    short_task_timeout_seconds: int = 15
    long_task_timeout_seconds: int = 300
    security_approval_timeout_seconds: int = 120
    verification_timeout_seconds: int = 60
    memory_write_timeout_seconds: int = 30
    agent_heartbeat_timeout_seconds: int = 30
    dashboard_request_timeout_seconds: int = 30
    external_api_timeout_seconds: int = 30


@dataclass
class RoutingConfig:
    """Routing defaults for Master Agent, Agent Router, Registry, and Loader."""

    default_agent: str = "master"
    fallback_agent: str = "master"
    enable_agent_registry: bool = True
    enable_plugin_agents: bool = True
    enable_agent_loader: bool = True
    enable_router_confidence_scoring: bool = True
    minimum_router_confidence: float = 0.55
    max_routing_attempts: int = 3
    allow_multi_agent_tasks: bool = True
    allow_parallel_agent_execution: bool = False
    registered_agents: List[str] = field(default_factory=lambda: list(DEFAULT_AGENT_NAMES))
    sensitive_agents: List[str] = field(default_factory=lambda: list(SENSITIVE_AGENT_NAMES))


@dataclass
class SafetyConfig:
    """Safety and Security Agent bridge defaults."""

    safe_mode: bool = True
    strict_mode: bool = True
    require_security_for_sensitive_agents: bool = True
    require_security_for_high_risk_actions: bool = True
    require_user_confirmation_for_sensitive_actions: bool = True
    block_destructive_actions_by_default: bool = True
    allow_real_browser_actions: bool = False
    allow_real_system_actions: bool = False
    allow_real_calls: bool = False
    allow_real_financial_actions: bool = False
    allow_real_messages: bool = False
    allow_code_execution: bool = False
    high_risk_actions: List[str] = field(default_factory=lambda: list(HIGH_RISK_ACTIONS))


@dataclass
class SaaSConfig:
    """SaaS isolation, workspace, dashboard, analytics, and subscription defaults."""

    require_user_id: bool = True
    require_workspace_id: bool = True
    enforce_workspace_isolation: bool = True
    enforce_user_memory_isolation: bool = True
    enforce_user_file_isolation: bool = True
    enforce_user_log_isolation: bool = True
    enforce_user_task_isolation: bool = True
    enable_roles: bool = True
    enable_subscriptions: bool = True
    enable_agent_permissions: bool = True
    enable_dashboard_analytics: bool = True
    enable_task_history: bool = True
    enable_audit_trail: bool = True
    default_workspace_role: str = "member"
    default_subscription_plan: str = "free"


@dataclass
class MemoryConfig:
    """Memory Agent compatibility defaults."""

    enable_memory_agent: bool = True
    auto_prepare_memory_payload: bool = True
    write_completed_tasks_to_memory: bool = True
    memory_scope: str = "workspace"
    redact_sensitive_memory_values: bool = True
    max_memory_context_items: int = 20


@dataclass
class VerificationConfig:
    """Verification Agent compatibility defaults."""

    enable_verification_agent: bool = True
    auto_prepare_verification_payload: bool = True
    verify_completed_actions: bool = True
    verify_sensitive_actions: bool = True
    verification_level: str = "standard"


@dataclass
class DashboardConfig:
    """Dashboard/API integration defaults."""

    enable_dashboard_api: bool = True
    enable_health_endpoint: bool = True
    enable_config_endpoint: bool = False
    expose_safe_config_only: bool = True
    enable_agent_status_stream: bool = True
    enable_task_progress_stream: bool = True


@dataclass
class StorageConfig:
    """Storage path defaults. These are safe local paths, not secrets."""

    base_dir: str = "."
    data_dir: str = "data"
    logs_dir: str = "logs"
    temp_dir: str = "tmp"
    uploads_dir: str = "uploads"
    workspace_data_dir: str = "data/workspaces"
    user_data_dir: str = "data/users"


@dataclass
class CoreConfigSnapshot:
    """Serializable snapshot of full config state."""

    app_name: str
    app_version: str
    environment: str
    debug: bool
    logging: Dict[str, Any]
    timeouts: Dict[str, Any]
    routing: Dict[str, Any]
    safety: Dict[str, Any]
    saas: Dict[str, Any]
    memory: Dict[str, Any]
    verification: Dict[str, Any]
    dashboard: Dict[str, Any]
    storage: Dict[str, Any]
    metadata: Dict[str, Any]


# =============================================================================
# Main config class
# =============================================================================

class CoreConfig:
    """
    Core configuration controller for William/Jarvis.

    Responsibilities:
        - Load safe defaults.
        - Load environment values.
        - Provide routing/timeouts/safe-mode/logging config.
        - Maintain SaaS user/workspace isolation rules.
        - Provide compatibility hooks for Master Agent, Security Agent,
          Memory Agent, Verification Agent, Dashboard/API, Agent Registry,
          Agent Loader, and Agent Router.
        - Return structured result dictionaries.
    """

    def __init__(
        self,
        env_file: Optional[Union[str, Path]] = None,
        auto_load_env: bool = True,
        overrides: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.created_at: str = _utc_now_iso()
        self.env_file = Path(env_file) if env_file else None
        self.overrides = overrides or {}

        if auto_load_env:
            self.load_environment_file(self.env_file)

        self.app_name: str = os.getenv("WILLIAM_APP_NAME", "William / Jarvis AI SaaS")
        self.app_version: str = os.getenv("WILLIAM_APP_VERSION", "1.0.0")
        self.environment: str = _normalize_environment(os.getenv("WILLIAM_ENV", "development"))
        self.debug: bool = _safe_bool(os.getenv("WILLIAM_DEBUG"), default=self.environment != "production")

        self.logging_config = self._build_logging_config()
        self.timeout_config = self._build_timeout_config()
        self.routing_config = self._build_routing_config()
        self.safety_config = self._build_safety_config()
        self.saas_config = self._build_saas_config()
        self.memory_config = self._build_memory_config()
        self.verification_config = self._build_verification_config()
        self.dashboard_config = self._build_dashboard_config()
        self.storage_config = self._build_storage_config()

        self._apply_overrides(self.overrides)
        self.logger = self.configure_logging()

        self._emit_agent_event(
            event_type="core_config_initialized",
            data={
                "app_name": self.app_name,
                "app_version": self.app_version,
                "environment": self.environment,
                "safe_mode": self.safety_config.safe_mode,
            },
        )

    # -------------------------------------------------------------------------
    # Environment loading
    # -------------------------------------------------------------------------

    def load_environment_file(self, env_file: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
        """
        Safely load .env file if python-dotenv is installed.

        This method does not crash if:
            - dotenv is missing
            - env file does not exist
            - env loading fails
        """
        try:
            selected_env_file = Path(env_file) if env_file else Path(".env")

            if load_dotenv is None:
                return self._safe_result(
                    message="python-dotenv is not installed; skipped .env loading.",
                    data={"loaded": False, "env_file": str(selected_env_file)},
                    metadata={"optional_dependency_missing": "python-dotenv"},
                )

            if selected_env_file.exists():
                load_dotenv(dotenv_path=selected_env_file)
                return self._safe_result(
                    message="Environment file loaded successfully.",
                    data={"loaded": True, "env_file": str(selected_env_file)},
                )

            load_dotenv()
            return self._safe_result(
                message="Default environment loading attempted.",
                data={"loaded": True, "env_file": "default"},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to load environment file safely.",
                error=exc,
                metadata={"env_file": str(env_file) if env_file else ".env"},
            )

    # -------------------------------------------------------------------------
    # Config builders
    # -------------------------------------------------------------------------

    def _build_logging_config(self) -> LoggingConfig:
        return LoggingConfig(
            level=os.getenv("WILLIAM_LOG_LEVEL", "INFO").upper(),
            logger_name=os.getenv("WILLIAM_LOGGER_NAME", "william.core"),
            log_to_file=_safe_bool(os.getenv("WILLIAM_LOG_TO_FILE"), False),
            log_file_path=os.getenv("WILLIAM_LOG_FILE_PATH", "logs/william_core.log"),
            enable_audit_logs=_safe_bool(os.getenv("WILLIAM_ENABLE_AUDIT_LOGS"), True),
            enable_agent_events=_safe_bool(os.getenv("WILLIAM_ENABLE_AGENT_EVENTS"), True),
            redact_sensitive_values=_safe_bool(os.getenv("WILLIAM_REDACT_SENSITIVE_VALUES"), True),
        )

    def _build_timeout_config(self) -> TimeoutConfig:
        return TimeoutConfig(
            default_task_timeout_seconds=_safe_int(
                os.getenv("WILLIAM_DEFAULT_TASK_TIMEOUT_SECONDS"), 60, minimum=5, maximum=3600
            ),
            short_task_timeout_seconds=_safe_int(
                os.getenv("WILLIAM_SHORT_TASK_TIMEOUT_SECONDS"), 15, minimum=3, maximum=300
            ),
            long_task_timeout_seconds=_safe_int(
                os.getenv("WILLIAM_LONG_TASK_TIMEOUT_SECONDS"), 300, minimum=30, maximum=7200
            ),
            security_approval_timeout_seconds=_safe_int(
                os.getenv("WILLIAM_SECURITY_APPROVAL_TIMEOUT_SECONDS"), 120, minimum=10, maximum=3600
            ),
            verification_timeout_seconds=_safe_int(
                os.getenv("WILLIAM_VERIFICATION_TIMEOUT_SECONDS"), 60, minimum=5, maximum=600
            ),
            memory_write_timeout_seconds=_safe_int(
                os.getenv("WILLIAM_MEMORY_WRITE_TIMEOUT_SECONDS"), 30, minimum=5, maximum=300
            ),
            agent_heartbeat_timeout_seconds=_safe_int(
                os.getenv("WILLIAM_AGENT_HEARTBEAT_TIMEOUT_SECONDS"), 30, minimum=5, maximum=300
            ),
            dashboard_request_timeout_seconds=_safe_int(
                os.getenv("WILLIAM_DASHBOARD_REQUEST_TIMEOUT_SECONDS"), 30, minimum=5, maximum=300
            ),
            external_api_timeout_seconds=_safe_int(
                os.getenv("WILLIAM_EXTERNAL_API_TIMEOUT_SECONDS"), 30, minimum=5, maximum=300
            ),
        )

    def _build_routing_config(self) -> RoutingConfig:
        registered_agents = _safe_json_list(
            os.getenv("WILLIAM_REGISTERED_AGENTS"),
            default=list(DEFAULT_AGENT_NAMES),
        )

        sensitive_agents = _safe_json_list(
            os.getenv("WILLIAM_SENSITIVE_AGENTS"),
            default=list(SENSITIVE_AGENT_NAMES),
        )

        return RoutingConfig(
            default_agent=os.getenv("WILLIAM_DEFAULT_AGENT", "master"),
            fallback_agent=os.getenv("WILLIAM_FALLBACK_AGENT", "master"),
            enable_agent_registry=_safe_bool(os.getenv("WILLIAM_ENABLE_AGENT_REGISTRY"), True),
            enable_plugin_agents=_safe_bool(os.getenv("WILLIAM_ENABLE_PLUGIN_AGENTS"), True),
            enable_agent_loader=_safe_bool(os.getenv("WILLIAM_ENABLE_AGENT_LOADER"), True),
            enable_router_confidence_scoring=_safe_bool(
                os.getenv("WILLIAM_ENABLE_ROUTER_CONFIDENCE_SCORING"), True
            ),
            minimum_router_confidence=_safe_float(
                os.getenv("WILLIAM_MINIMUM_ROUTER_CONFIDENCE"), 0.55, minimum=0.0, maximum=1.0
            ),
            max_routing_attempts=_safe_int(
                os.getenv("WILLIAM_MAX_ROUTING_ATTEMPTS"), 3, minimum=1, maximum=10
            ),
            allow_multi_agent_tasks=_safe_bool(os.getenv("WILLIAM_ALLOW_MULTI_AGENT_TASKS"), True),
            allow_parallel_agent_execution=_safe_bool(
                os.getenv("WILLIAM_ALLOW_PARALLEL_AGENT_EXECUTION"), False
            ),
            registered_agents=[str(agent).strip().lower() for agent in registered_agents if str(agent).strip()],
            sensitive_agents=[str(agent).strip().lower() for agent in sensitive_agents if str(agent).strip()],
        )

    def _build_safety_config(self) -> SafetyConfig:
        high_risk_actions = _safe_json_list(
            os.getenv("WILLIAM_HIGH_RISK_ACTIONS"),
            default=list(HIGH_RISK_ACTIONS),
        )

        return SafetyConfig(
            safe_mode=_safe_bool(os.getenv("WILLIAM_SAFE_MODE"), True),
            strict_mode=_safe_bool(os.getenv("WILLIAM_STRICT_MODE"), True),
            require_security_for_sensitive_agents=_safe_bool(
                os.getenv("WILLIAM_REQUIRE_SECURITY_FOR_SENSITIVE_AGENTS"), True
            ),
            require_security_for_high_risk_actions=_safe_bool(
                os.getenv("WILLIAM_REQUIRE_SECURITY_FOR_HIGH_RISK_ACTIONS"), True
            ),
            require_user_confirmation_for_sensitive_actions=_safe_bool(
                os.getenv("WILLIAM_REQUIRE_USER_CONFIRMATION_FOR_SENSITIVE_ACTIONS"), True
            ),
            block_destructive_actions_by_default=_safe_bool(
                os.getenv("WILLIAM_BLOCK_DESTRUCTIVE_ACTIONS_BY_DEFAULT"), True
            ),
            allow_real_browser_actions=_safe_bool(os.getenv("WILLIAM_ALLOW_REAL_BROWSER_ACTIONS"), False),
            allow_real_system_actions=_safe_bool(os.getenv("WILLIAM_ALLOW_REAL_SYSTEM_ACTIONS"), False),
            allow_real_calls=_safe_bool(os.getenv("WILLIAM_ALLOW_REAL_CALLS"), False),
            allow_real_financial_actions=_safe_bool(os.getenv("WILLIAM_ALLOW_REAL_FINANCIAL_ACTIONS"), False),
            allow_real_messages=_safe_bool(os.getenv("WILLIAM_ALLOW_REAL_MESSAGES"), False),
            allow_code_execution=_safe_bool(os.getenv("WILLIAM_ALLOW_CODE_EXECUTION"), False),
            high_risk_actions=[
                str(action).strip().lower()
                for action in high_risk_actions
                if str(action).strip()
            ],
        )

    def _build_saas_config(self) -> SaaSConfig:
        return SaaSConfig(
            require_user_id=_safe_bool(os.getenv("WILLIAM_REQUIRE_USER_ID"), True),
            require_workspace_id=_safe_bool(os.getenv("WILLIAM_REQUIRE_WORKSPACE_ID"), True),
            enforce_workspace_isolation=_safe_bool(os.getenv("WILLIAM_ENFORCE_WORKSPACE_ISOLATION"), True),
            enforce_user_memory_isolation=_safe_bool(os.getenv("WILLIAM_ENFORCE_USER_MEMORY_ISOLATION"), True),
            enforce_user_file_isolation=_safe_bool(os.getenv("WILLIAM_ENFORCE_USER_FILE_ISOLATION"), True),
            enforce_user_log_isolation=_safe_bool(os.getenv("WILLIAM_ENFORCE_USER_LOG_ISOLATION"), True),
            enforce_user_task_isolation=_safe_bool(os.getenv("WILLIAM_ENFORCE_USER_TASK_ISOLATION"), True),
            enable_roles=_safe_bool(os.getenv("WILLIAM_ENABLE_ROLES"), True),
            enable_subscriptions=_safe_bool(os.getenv("WILLIAM_ENABLE_SUBSCRIPTIONS"), True),
            enable_agent_permissions=_safe_bool(os.getenv("WILLIAM_ENABLE_AGENT_PERMISSIONS"), True),
            enable_dashboard_analytics=_safe_bool(os.getenv("WILLIAM_ENABLE_DASHBOARD_ANALYTICS"), True),
            enable_task_history=_safe_bool(os.getenv("WILLIAM_ENABLE_TASK_HISTORY"), True),
            enable_audit_trail=_safe_bool(os.getenv("WILLIAM_ENABLE_AUDIT_TRAIL"), True),
            default_workspace_role=os.getenv("WILLIAM_DEFAULT_WORKSPACE_ROLE", "member"),
            default_subscription_plan=os.getenv("WILLIAM_DEFAULT_SUBSCRIPTION_PLAN", "free"),
        )

    def _build_memory_config(self) -> MemoryConfig:
        return MemoryConfig(
            enable_memory_agent=_safe_bool(os.getenv("WILLIAM_ENABLE_MEMORY_AGENT"), True),
            auto_prepare_memory_payload=_safe_bool(os.getenv("WILLIAM_AUTO_PREPARE_MEMORY_PAYLOAD"), True),
            write_completed_tasks_to_memory=_safe_bool(os.getenv("WILLIAM_WRITE_COMPLETED_TASKS_TO_MEMORY"), True),
            memory_scope=os.getenv("WILLIAM_MEMORY_SCOPE", "workspace"),
            redact_sensitive_memory_values=_safe_bool(os.getenv("WILLIAM_REDACT_SENSITIVE_MEMORY_VALUES"), True),
            max_memory_context_items=_safe_int(
                os.getenv("WILLIAM_MAX_MEMORY_CONTEXT_ITEMS"), 20, minimum=1, maximum=200
            ),
        )

    def _build_verification_config(self) -> VerificationConfig:
        return VerificationConfig(
            enable_verification_agent=_safe_bool(os.getenv("WILLIAM_ENABLE_VERIFICATION_AGENT"), True),
            auto_prepare_verification_payload=_safe_bool(
                os.getenv("WILLIAM_AUTO_PREPARE_VERIFICATION_PAYLOAD"), True
            ),
            verify_completed_actions=_safe_bool(os.getenv("WILLIAM_VERIFY_COMPLETED_ACTIONS"), True),
            verify_sensitive_actions=_safe_bool(os.getenv("WILLIAM_VERIFY_SENSITIVE_ACTIONS"), True),
            verification_level=os.getenv("WILLIAM_VERIFICATION_LEVEL", "standard"),
        )

    def _build_dashboard_config(self) -> DashboardConfig:
        return DashboardConfig(
            enable_dashboard_api=_safe_bool(os.getenv("WILLIAM_ENABLE_DASHBOARD_API"), True),
            enable_health_endpoint=_safe_bool(os.getenv("WILLIAM_ENABLE_HEALTH_ENDPOINT"), True),
            enable_config_endpoint=_safe_bool(os.getenv("WILLIAM_ENABLE_CONFIG_ENDPOINT"), False),
            expose_safe_config_only=_safe_bool(os.getenv("WILLIAM_EXPOSE_SAFE_CONFIG_ONLY"), True),
            enable_agent_status_stream=_safe_bool(os.getenv("WILLIAM_ENABLE_AGENT_STATUS_STREAM"), True),
            enable_task_progress_stream=_safe_bool(os.getenv("WILLIAM_ENABLE_TASK_PROGRESS_STREAM"), True),
        )

    def _build_storage_config(self) -> StorageConfig:
        return StorageConfig(
            base_dir=os.getenv("WILLIAM_BASE_DIR", "."),
            data_dir=os.getenv("WILLIAM_DATA_DIR", "data"),
            logs_dir=os.getenv("WILLIAM_LOGS_DIR", "logs"),
            temp_dir=os.getenv("WILLIAM_TEMP_DIR", "tmp"),
            uploads_dir=os.getenv("WILLIAM_UPLOADS_DIR", "uploads"),
            workspace_data_dir=os.getenv("WILLIAM_WORKSPACE_DATA_DIR", "data/workspaces"),
            user_data_dir=os.getenv("WILLIAM_USER_DATA_DIR", "data/users"),
        )

    # -------------------------------------------------------------------------
    # Overrides
    # -------------------------------------------------------------------------

    def _apply_overrides(self, overrides: Dict[str, Any]) -> None:
        """
        Apply runtime overrides safely.

        Expected shape:
            {
                "debug": true,
                "logging": {"level": "DEBUG"},
                "safety": {"safe_mode": true},
                "routing": {"max_routing_attempts": 2}
            }
        """
        if not isinstance(overrides, dict):
            return

        simple_keys = {
            "app_name": "app_name",
            "app_version": "app_version",
            "environment": "environment",
            "debug": "debug",
        }

        for input_key, attr_name in simple_keys.items():
            if input_key in overrides:
                setattr(self, attr_name, overrides[input_key])

        section_map = {
            "logging": self.logging_config,
            "timeouts": self.timeout_config,
            "routing": self.routing_config,
            "safety": self.safety_config,
            "saas": self.saas_config,
            "memory": self.memory_config,
            "verification": self.verification_config,
            "dashboard": self.dashboard_config,
            "storage": self.storage_config,
        }

        for section_name, section_obj in section_map.items():
            section_overrides = overrides.get(section_name)
            if not isinstance(section_overrides, dict):
                continue

            for key, value in section_overrides.items():
                if hasattr(section_obj, key):
                    setattr(section_obj, key, value)

        self.environment = _normalize_environment(str(self.environment))

    # -------------------------------------------------------------------------
    # Logging
    # -------------------------------------------------------------------------

    def configure_logging(self) -> logging.Logger:
        """Configure and return a logger for William/Jarvis core."""
        logger = logging.getLogger(self.logging_config.logger_name)

        level = getattr(logging, self.logging_config.level.upper(), logging.INFO)
        logger.setLevel(level)
        logger.propagate = False

        formatter = logging.Formatter(self.logging_config.log_format)

        if not logger.handlers:
            stream_handler = logging.StreamHandler()
            stream_handler.setLevel(level)
            stream_handler.setFormatter(formatter)
            logger.addHandler(stream_handler)

            if self.logging_config.log_to_file:
                log_path = Path(self.logging_config.log_file_path)
                log_path.parent.mkdir(parents=True, exist_ok=True)

                file_handler = logging.FileHandler(log_path, encoding="utf-8")
                file_handler.setLevel(level)
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)

        return logger

    # -------------------------------------------------------------------------
    # Public config access methods
    # -------------------------------------------------------------------------

    def get_config_snapshot(self, safe_only: bool = True) -> Dict[str, Any]:
        """Return full serializable config snapshot."""
        try:
            snapshot = CoreConfigSnapshot(
                app_name=self.app_name,
                app_version=self.app_version,
                environment=self.environment,
                debug=self.debug,
                logging=asdict(self.logging_config),
                timeouts=asdict(self.timeout_config),
                routing=asdict(self.routing_config),
                safety=asdict(self.safety_config),
                saas=asdict(self.saas_config),
                memory=asdict(self.memory_config),
                verification=asdict(self.verification_config),
                dashboard=asdict(self.dashboard_config),
                storage=asdict(self.storage_config),
                metadata={
                    "created_at": self.created_at,
                    "generated_at": _utc_now_iso(),
                    "safe_only": safe_only,
                    "module": "core.config",
                },
            )

            data = asdict(snapshot)

            if safe_only:
                data = self._redact_sensitive_config(data)

            return self._safe_result(
                message="Core configuration snapshot generated.",
                data=data,
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to generate config snapshot.",
                error=exc,
            )

    def get_agent_registry_config(self) -> Dict[str, Any]:
        """Return config structure compatible with Agent Registry and Agent Loader."""
        return self._safe_result(
            message="Agent registry configuration generated.",
            data={
                "enable_agent_registry": self.routing_config.enable_agent_registry,
                "enable_agent_loader": self.routing_config.enable_agent_loader,
                "enable_plugin_agents": self.routing_config.enable_plugin_agents,
                "registered_agents": list(self.routing_config.registered_agents),
                "sensitive_agents": list(self.routing_config.sensitive_agents),
                "default_agent": self.routing_config.default_agent,
                "fallback_agent": self.routing_config.fallback_agent,
                "metadata": {
                    "module": "core.config",
                    "generated_at": _utc_now_iso(),
                },
            },
        )

    def get_router_config(self) -> Dict[str, Any]:
        """Return config structure compatible with Agent Router and Master Agent routing."""
        return self._safe_result(
            message="Router configuration generated.",
            data={
                "default_agent": self.routing_config.default_agent,
                "fallback_agent": self.routing_config.fallback_agent,
                "minimum_router_confidence": self.routing_config.minimum_router_confidence,
                "max_routing_attempts": self.routing_config.max_routing_attempts,
                "allow_multi_agent_tasks": self.routing_config.allow_multi_agent_tasks,
                "allow_parallel_agent_execution": self.routing_config.allow_parallel_agent_execution,
                "enable_router_confidence_scoring": self.routing_config.enable_router_confidence_scoring,
                "timeouts": asdict(self.timeout_config),
                "safety": {
                    "safe_mode": self.safety_config.safe_mode,
                    "strict_mode": self.safety_config.strict_mode,
                    "require_security_for_sensitive_agents": (
                        self.safety_config.require_security_for_sensitive_agents
                    ),
                },
            },
        )

    def get_saas_policy_config(self) -> Dict[str, Any]:
        """Return SaaS isolation and permission policy config."""
        return self._safe_result(
            message="SaaS policy configuration generated.",
            data=asdict(self.saas_config),
            metadata={
                "module": "core.config",
                "generated_at": _utc_now_iso(),
            },
        )

    def get_security_policy_config(self) -> Dict[str, Any]:
        """Return security/safety policy config for Security Agent bridge."""
        return self._safe_result(
            message="Security policy configuration generated.",
            data=asdict(self.safety_config),
            metadata={
                "module": "core.config",
                "generated_at": _utc_now_iso(),
            },
        )

    def get_timeout(self, timeout_type: str = "default") -> int:
        """Return timeout by type."""
        mapping = {
            "default": self.timeout_config.default_task_timeout_seconds,
            "short": self.timeout_config.short_task_timeout_seconds,
            "long": self.timeout_config.long_task_timeout_seconds,
            "security": self.timeout_config.security_approval_timeout_seconds,
            "verification": self.timeout_config.verification_timeout_seconds,
            "memory": self.timeout_config.memory_write_timeout_seconds,
            "heartbeat": self.timeout_config.agent_heartbeat_timeout_seconds,
            "dashboard": self.timeout_config.dashboard_request_timeout_seconds,
            "external_api": self.timeout_config.external_api_timeout_seconds,
        }

        return mapping.get(str(timeout_type).strip().lower(), self.timeout_config.default_task_timeout_seconds)

    # -------------------------------------------------------------------------
    # SaaS context validation
    # -------------------------------------------------------------------------

    def _validate_task_context(self, context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate task context for SaaS user/workspace isolation.

        Required where user-specific execution is involved:
            - user_id
            - workspace_id
        """
        try:
            if context is None:
                context = {}

            if not isinstance(context, dict):
                return self._error_result(
                    message="Invalid task context. Context must be a dictionary.",
                    error="INVALID_CONTEXT_TYPE",
                    metadata={"expected": "dict", "received": type(context).__name__},
                )

            missing: List[str] = []

            if self.saas_config.require_user_id and not context.get("user_id"):
                missing.append("user_id")

            if self.saas_config.require_workspace_id and not context.get("workspace_id"):
                missing.append("workspace_id")

            if missing:
                return self._error_result(
                    message="Task context failed SaaS isolation validation.",
                    error="MISSING_REQUIRED_CONTEXT_FIELDS",
                    data={
                        "valid": False,
                        "missing": missing,
                        "context_keys": list(context.keys()),
                    },
                    metadata={
                        "require_user_id": self.saas_config.require_user_id,
                        "require_workspace_id": self.saas_config.require_workspace_id,
                    },
                )

            return self._safe_result(
                message="Task context validated successfully.",
                data={
                    "valid": True,
                    "user_id": context.get("user_id"),
                    "workspace_id": context.get("workspace_id"),
                    "role": context.get("role", self.saas_config.default_workspace_role),
                    "subscription_plan": context.get(
                        "subscription_plan",
                        self.saas_config.default_subscription_plan,
                    ),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to validate task context.",
                error=exc,
            )

    # -------------------------------------------------------------------------
    # Security Agent compatibility hooks
    # -------------------------------------------------------------------------

    def _requires_security_check(
        self,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Decide whether a task/action should be routed through Security Agent.

        This method only returns a decision payload.
        It does not execute any real sensitive action.
        """
        try:
            normalized_agent = str(agent_name or "").strip().lower()
            normalized_action = str(action or "").strip().lower()

            reasons: List[str] = []

            if self.safety_config.safe_mode:
                reasons.append("safe_mode_enabled")

            if (
                self.safety_config.require_security_for_sensitive_agents
                and normalized_agent in self.routing_config.sensitive_agents
            ):
                reasons.append("sensitive_agent")

            if (
                self.safety_config.require_security_for_high_risk_actions
                and normalized_action in self.safety_config.high_risk_actions
            ):
                reasons.append("high_risk_action")

            if self.safety_config.block_destructive_actions_by_default:
                destructive_keywords = ["delete", "destroy", "wipe", "remove_all", "drop_table"]
                if any(keyword in normalized_action for keyword in destructive_keywords):
                    reasons.append("destructive_action_blocked_by_default")

            context_validation = self._validate_task_context(context or {})
            if not context_validation.get("success"):
                reasons.append("invalid_or_missing_saas_context")

            requires_check = len(reasons) > 0

            return self._safe_result(
                message="Security check decision generated.",
                data={
                    "requires_security_check": requires_check,
                    "agent_name": normalized_agent,
                    "action": normalized_action,
                    "reasons": reasons,
                    "safe_mode": self.safety_config.safe_mode,
                    "strict_mode": self.safety_config.strict_mode,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to determine security check requirement.",
                error=exc,
            )

    def _request_security_approval(
        self,
        agent_name: Optional[str],
        action: Optional[str],
        context: Optional[Dict[str, Any]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Security Agent approval request payload.

        This method does not approve automatically.
        It prepares a structured payload for Security Agent.
        """
        try:
            context = context or {}
            payload = payload or {}

            decision = self._requires_security_check(agent_name, action, context)

            approval_payload = {
                "approval_required": decision.get("data", {}).get("requires_security_check", True),
                "agent_name": str(agent_name or "").strip().lower(),
                "action": str(action or "").strip().lower(),
                "context": {
                    "user_id": context.get("user_id"),
                    "workspace_id": context.get("workspace_id"),
                    "role": context.get("role"),
                    "subscription_plan": context.get("subscription_plan"),
                },
                "payload_summary": self._redact_sensitive_config(payload),
                "security_reasons": decision.get("data", {}).get("reasons", []),
                "timeout_seconds": self.timeout_config.security_approval_timeout_seconds,
                "created_at": _utc_now_iso(),
                "source_module": "core.config",
                "target_agent": "security",
            }

            self._log_audit_event(
                event_type="security_approval_payload_prepared",
                user_id=context.get("user_id"),
                workspace_id=context.get("workspace_id"),
                data={
                    "agent_name": approval_payload["agent_name"],
                    "action": approval_payload["action"],
                    "approval_required": approval_payload["approval_required"],
                    "security_reasons": approval_payload["security_reasons"],
                },
            )

            return self._safe_result(
                message="Security approval payload prepared.",
                data=approval_payload,
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to prepare security approval payload.",
                error=exc,
            )

    # -------------------------------------------------------------------------
    # Verification Agent compatibility hook
    # -------------------------------------------------------------------------

    def _prepare_verification_payload(
        self,
        task_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
        result: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare Verification Agent payload for completed actions."""
        try:
            context = context or {}
            result = result or {}

            payload = {
                "verification_required": self.verification_config.enable_verification_agent,
                "verification_level": self.verification_config.verification_level,
                "task_id": task_id,
                "agent_name": str(agent_name or "").strip().lower(),
                "action": str(action or "").strip().lower(),
                "result_summary": self._redact_sensitive_config(result),
                "context": {
                    "user_id": context.get("user_id"),
                    "workspace_id": context.get("workspace_id"),
                },
                "timeout_seconds": self.timeout_config.verification_timeout_seconds,
                "created_at": _utc_now_iso(),
                "source_module": "core.config",
                "target_agent": "verification",
            }

            return self._safe_result(
                message="Verification payload prepared.",
                data=payload,
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to prepare verification payload.",
                error=exc,
            )

    # -------------------------------------------------------------------------
    # Memory Agent compatibility hook
    # -------------------------------------------------------------------------

    def _prepare_memory_payload(
        self,
        task_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
        useful_context: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare Memory Agent payload while preserving SaaS isolation."""
        try:
            context = context or {}
            useful_context = useful_context or {}

            validation = self._validate_task_context(context)
            if not validation.get("success"):
                return validation

            payload = {
                "memory_enabled": self.memory_config.enable_memory_agent,
                "memory_scope": self.memory_config.memory_scope,
                "task_id": task_id,
                "agent_name": str(agent_name or "").strip().lower(),
                "action": str(action or "").strip().lower(),
                "user_id": context.get("user_id"),
                "workspace_id": context.get("workspace_id"),
                "useful_context": self._redact_sensitive_config(useful_context)
                if self.memory_config.redact_sensitive_memory_values
                else useful_context,
                "timeout_seconds": self.timeout_config.memory_write_timeout_seconds,
                "created_at": _utc_now_iso(),
                "source_module": "core.config",
                "target_agent": "memory",
            }

            return self._safe_result(
                message="Memory payload prepared.",
                data=payload,
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to prepare memory payload.",
                error=exc,
            )

    # -------------------------------------------------------------------------
    # Event and audit hooks
    # -------------------------------------------------------------------------

    def _emit_agent_event(
        self,
        event_type: str,
        data: Optional[Dict[str, Any]] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """
        Emit an agent event in a safe structured format.

        Current file logs locally only.
        Future dashboard/event bus can replace this implementation.
        """
        try:
            event = {
                "event_type": event_type,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "data": self._redact_sensitive_config(data or {}),
                "created_at": _utc_now_iso(),
                "source_module": "core.config",
            }

            if getattr(self, "logging_config", None) and self.logging_config.enable_agent_events:
                logger = getattr(self, "logger", None)
                if logger:
                    logger.info("AGENT_EVENT %s", json.dumps(event, default=str))

            return self._safe_result(
                message="Agent event emitted.",
                data=event,
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to emit agent event.",
                error=exc,
            )

    def _log_audit_event(
        self,
        event_type: str,
        data: Optional[Dict[str, Any]] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """
        Log audit event in structured format.

        Current file logs locally only.
        Future database/dashboard audit trail can consume the same structure.
        """
        try:
            audit_event = {
                "event_type": event_type,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "data": self._redact_sensitive_config(data or {}),
                "created_at": _utc_now_iso(),
                "source_module": "core.config",
            }

            if getattr(self, "logging_config", None) and self.logging_config.enable_audit_logs:
                logger = getattr(self, "logger", None)
                if logger:
                    logger.info("AUDIT_EVENT %s", json.dumps(audit_event, default=str))

            return self._safe_result(
                message="Audit event logged.",
                data=audit_event,
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to log audit event.",
                error=exc,
            )

    # -------------------------------------------------------------------------
    # Path helpers
    # -------------------------------------------------------------------------

    def ensure_runtime_directories(self) -> Dict[str, Any]:
        """Create safe runtime directories for logs/data/temp/uploads if needed."""
        try:
            paths = [
                self.storage_config.data_dir,
                self.storage_config.logs_dir,
                self.storage_config.temp_dir,
                self.storage_config.uploads_dir,
                self.storage_config.workspace_data_dir,
                self.storage_config.user_data_dir,
            ]

            created_or_verified: List[str] = []

            for path in paths:
                target = Path(path)
                target.mkdir(parents=True, exist_ok=True)
                created_or_verified.append(str(target))

            return self._safe_result(
                message="Runtime directories created or verified.",
                data={"paths": created_or_verified},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to create runtime directories.",
                error=exc,
            )

    def build_workspace_path(self, user_id: Union[str, int], workspace_id: Union[str, int]) -> Dict[str, Any]:
        """Build isolated workspace path without creating files."""
        try:
            if not user_id or not workspace_id:
                return self._error_result(
                    message="user_id and workspace_id are required to build workspace path.",
                    error="MISSING_USER_OR_WORKSPACE_ID",
                )

            safe_user_id = str(user_id).replace("/", "_").replace("\\", "_").strip()
            safe_workspace_id = str(workspace_id).replace("/", "_").replace("\\", "_").strip()

            path = Path(self.storage_config.workspace_data_dir) / safe_user_id / safe_workspace_id

            return self._safe_result(
                message="Workspace path generated.",
                data={
                    "path": str(path),
                    "user_id": safe_user_id,
                    "workspace_id": safe_workspace_id,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to build workspace path.",
                error=exc,
            )

    # -------------------------------------------------------------------------
    # Redaction
    # -------------------------------------------------------------------------

    def _redact_sensitive_config(self, value: Any) -> Any:
        """
        Redact sensitive values from config/payload dictionaries.

        This prevents accidental exposure in dashboard/API/logs/memory.
        """
        sensitive_keywords = [
            "secret",
            "token",
            "password",
            "api_key",
            "apikey",
            "private_key",
            "access_key",
            "refresh_token",
            "authorization",
            "cookie",
            "credential",
        ]

        if isinstance(value, dict):
            redacted: Dict[str, Any] = {}

            for key, item in value.items():
                key_str = str(key).lower()
                if any(keyword in key_str for keyword in sensitive_keywords):
                    redacted[key] = "***REDACTED***"
                else:
                    redacted[key] = self._redact_sensitive_config(item)

            return redacted

        if isinstance(value, list):
            return [self._redact_sensitive_config(item) for item in value]

        return value

    # -------------------------------------------------------------------------
    # Structured result helpers
    # -------------------------------------------------------------------------

    def _safe_result(
        self,
        message: str = "Success.",
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success result."""
        return {
            "success": True,
            "message": message,
            "data": data if data is not None else {},
            "error": None,
            "metadata": {
                "module": "core.config",
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str = "Error.",
        error: Optional[Any] = None,
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error result."""
        error_message = str(error) if error is not None else "UNKNOWN_ERROR"

        return {
            "success": False,
            "message": message,
            "data": data if data is not None else {},
            "error": error_message,
            "metadata": {
                "module": "core.config",
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    # -------------------------------------------------------------------------
    # Health and validation
    # -------------------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        """Return import-safe health check for config module."""
        try:
            issues: List[str] = []

            if self.environment not in DEFAULT_ALLOWED_ENVIRONMENTS:
                issues.append("invalid_environment")

            if self.routing_config.default_agent not in self.routing_config.registered_agents:
                issues.append("default_agent_not_registered")

            if self.routing_config.fallback_agent not in self.routing_config.registered_agents:
                issues.append("fallback_agent_not_registered")

            if self.timeout_config.default_task_timeout_seconds <= 0:
                issues.append("invalid_default_timeout")

            healthy = len(issues) == 0

            return self._safe_result(
                message="Core configuration health check completed.",
                data={
                    "healthy": healthy,
                    "issues": issues,
                    "app_name": self.app_name,
                    "app_version": self.app_version,
                    "environment": self.environment,
                    "safe_mode": self.safety_config.safe_mode,
                    "registered_agents_count": len(self.routing_config.registered_agents),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Core configuration health check failed.",
                error=exc,
            )

    def validate_runtime_config(self) -> Dict[str, Any]:
        """Validate important runtime configuration settings."""
        try:
            warnings: List[str] = []
            errors: List[str] = []

            if self.environment == "production" and self.debug:
                warnings.append("debug_enabled_in_production")

            if self.environment == "production" and not self.safety_config.safe_mode:
                errors.append("safe_mode_disabled_in_production")

            if not self.saas_config.enforce_workspace_isolation:
                errors.append("workspace_isolation_disabled")

            if not self.saas_config.enforce_user_memory_isolation:
                warnings.append("user_memory_isolation_disabled")

            if self.safety_config.allow_real_financial_actions:
                warnings.append("real_financial_actions_enabled")

            if self.safety_config.allow_real_calls:
                warnings.append("real_calls_enabled")

            if self.safety_config.allow_code_execution:
                warnings.append("code_execution_enabled")

            valid = len(errors) == 0

            return self._safe_result(
                message="Runtime configuration validation completed.",
                data={
                    "valid": valid,
                    "errors": errors,
                    "warnings": warnings,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Runtime configuration validation failed.",
                error=exc,
            )


# =============================================================================
# Module-level safe default instance and helper
# =============================================================================

_default_config: Optional[CoreConfig] = None


def get_core_config(
    env_file: Optional[Union[str, Path]] = None,
    reload_config: bool = False,
    overrides: Optional[Dict[str, Any]] = None,
) -> CoreConfig:
    """
    Return singleton-style CoreConfig instance.

    Safe for:
        - Master Agent
        - Agent Router
        - Registry
        - Loader
        - FastAPI dependency injection
        - Dashboard/API layer
    """
    global _default_config

    if _default_config is None or reload_config:
        _default_config = CoreConfig(
            env_file=env_file,
            auto_load_env=True,
            overrides=overrides,
        )

    return _default_config


def get_safe_config_snapshot() -> Dict[str, Any]:
    """Return safe config snapshot using module-level CoreConfig."""
    config = get_core_config()
    return config.get_config_snapshot(safe_only=True)


__all__ = [
    "CoreConfig",
    "CoreConfigSnapshot",
    "LoggingConfig",
    "TimeoutConfig",
    "RoutingConfig",
    "SafetyConfig",
    "SaaSConfig",
    "MemoryConfig",
    "VerificationConfig",
    "DashboardConfig",
    "StorageConfig",
    "get_core_config",
    "get_safe_config_snapshot",
]


if __name__ == "__main__":
    config = get_core_config()
    print(json.dumps(config.health_check(), indent=2))
    print(json.dumps(config.validate_runtime_config(), indent=2))


# =============================================================================
# Completion Tracking
# =============================================================================
# Agent/Module: Core Master Control Files
# File Completed: config.py
# Completion: 20.0%
# Completed Files: ['context.py', 'config.py']
# Remaining Files: ['master_agent.py', 'planner.py', 'router.py', 'task_manager.py', 'response_builder.py', 'safety_bridge.py', 'verification_bridge.py', 'memory_bridge.py']
# Next Recommended File: core/master_agent.py
# FILE COMPLETE