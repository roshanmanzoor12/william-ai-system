"""
agents/agent_config.py

Global Agent System Configuration for William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    This file provides centralized configuration for:
    - Safe mode
    - Agent execution timeouts
    - Dynamic agent loading
    - Enabled/disabled agents
    - Verification settings
    - Security defaults
    - Memory compatibility
    - SaaS user/workspace isolation defaults
    - Dashboard/API-ready configuration export
    - Registry/Loader/Router/MasterAgent compatibility

Architecture:
    William is a Jarvis-style multi-agent SaaS system with:
    - Master Agent
    - Voice Agent
    - System Agent
    - Browser Agent
    - Code Agent
    - Memory Agent
    - Security Agent
    - Verification Agent
    - Visual Agent
    - Workflow Agent
    - Hologram Agent
    - Call Agent
    - Business Agent
    - Finance Agent
    - Creator Agent

Important:
    This file is import-safe.
    It does not require other William modules to exist.
    If optional project modules are unavailable, local fallback behavior is used.

Author:
    Digital Promotix / William AI System
"""

from __future__ import annotations

import copy
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# =============================================================================
# Optional / Safe Imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This prevents import failures while the full William system is still
        being generated file-by-file.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)


try:
    from agents.agent_events import AgentEventEmitter  # type: ignore
except Exception:  # pragma: no cover
    class AgentEventEmitter:  # type: ignore
        """
        Fallback event emitter.

        Used only when the real agents.agent_events module is not available.
        """

        def emit(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback event emitted.",
                "data": {
                    "event_type": event_type,
                    "payload": payload,
                },
                "error": None,
                "metadata": {
                    "fallback": True,
                    "timestamp": time.time(),
                },
            }


# =============================================================================
# Constants
# =============================================================================

CONFIG_VERSION = "1.0.0"
CONFIG_FILE_NAME = "agent_config.json"

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
    "security",
    "call",
    "finance",
]

HIGH_RISK_ACTION_KEYWORDS: List[str] = [
    "delete",
    "remove",
    "destroy",
    "shutdown",
    "restart",
    "execute",
    "transfer",
    "payment",
    "withdraw",
    "send_money",
    "place_call",
    "send_sms",
    "send_email",
    "browser_login",
    "download",
    "upload",
    "modify_file",
    "system_command",
    "shell",
    "terminal",
    "financial",
    "credential",
    "secret",
    "token",
    "api_key",
]


# =============================================================================
# Enums
# =============================================================================

class ConfigEnvironment(str, Enum):
    """Supported runtime environments."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


class AgentExecutionMode(str, Enum):
    """Agent execution behavior."""

    SAFE = "safe"
    STANDARD = "standard"
    ADVANCED = "advanced"
    RESTRICTED = "restricted"


class VerificationMode(str, Enum):
    """Verification behavior after agent execution."""

    DISABLED = "disabled"
    BASIC = "basic"
    STRICT = "strict"
    ENTERPRISE = "enterprise"


class DynamicLoadingMode(str, Enum):
    """How agents are dynamically discovered and loaded."""

    DISABLED = "disabled"
    MANUAL_ONLY = "manual_only"
    REGISTRY_ONLY = "registry_only"
    AUTO_DISCOVERY = "auto_discovery"


class AuditLevel(str, Enum):
    """Audit logging detail level."""

    NONE = "none"
    BASIC = "basic"
    DETAILED = "detailed"
    STRICT = "strict"


class MemoryMode(str, Enum):
    """Memory compatibility behavior."""

    DISABLED = "disabled"
    SESSION_ONLY = "session_only"
    USER_SCOPED = "user_scoped"
    WORKSPACE_SCOPED = "workspace_scoped"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class TimeoutConfig:
    """
    Timeout configuration for agent execution.

    These values are consumed by Agent Router, Agent Loader, Master Agent,
    dashboard workers, background queues, and future API execution endpoints.
    """

    default_timeout_seconds: int = 60
    quick_task_timeout_seconds: int = 15
    long_task_timeout_seconds: int = 300
    critical_task_timeout_seconds: int = 30
    browser_task_timeout_seconds: int = 120
    code_task_timeout_seconds: int = 180
    call_task_timeout_seconds: int = 240
    finance_task_timeout_seconds: int = 45
    workflow_task_timeout_seconds: int = 600
    health_check_timeout_seconds: int = 10
    registry_load_timeout_seconds: int = 20
    dynamic_import_timeout_seconds: int = 20

    def validate(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        values = asdict(self)
        for key, value in values.items():
            if not isinstance(value, int):
                errors.append(f"{key} must be an integer.")
            elif value <= 0:
                errors.append(f"{key} must be greater than 0.")

        if self.quick_task_timeout_seconds > self.default_timeout_seconds:
            errors.append(
                "quick_task_timeout_seconds should not be greater than "
                "default_timeout_seconds."
            )

        if self.critical_task_timeout_seconds > self.default_timeout_seconds:
            errors.append(
                "critical_task_timeout_seconds should not be greater than "
                "default_timeout_seconds."
            )

        return len(errors) == 0, errors


@dataclass
class DynamicLoadingConfig:
    """
    Dynamic loading configuration.

    This controls whether future plugin-style agents can be discovered and
    loaded through Agent Loader / Registry.
    """

    enabled: bool = True
    mode: DynamicLoadingMode = DynamicLoadingMode.REGISTRY_ONLY
    allow_external_plugins: bool = False
    allow_runtime_imports: bool = True
    agent_package_root: str = "agents"
    plugin_package_root: str = "plugins"
    manifest_file_name: str = "agent_manifest.py"
    registry_file_name: str = "registry.py"
    strict_manifest_validation: bool = True
    require_agent_class: bool = True
    require_safe_import: bool = True
    cache_loaded_agents: bool = True
    reload_on_change: bool = False

    blocked_module_patterns: List[str] = field(
        default_factory=lambda: [
            "os.system",
            "subprocess.Popen",
            "eval",
            "exec",
            "__import__",
        ]
    )

    allowed_agent_file_suffixes: List[str] = field(
        default_factory=lambda: [".py"]
    )

    def validate(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if isinstance(self.mode, str):
            try:
                self.mode = DynamicLoadingMode(self.mode)
            except ValueError:
                errors.append(f"Invalid dynamic loading mode: {self.mode}")

        if not self.agent_package_root:
            errors.append("agent_package_root cannot be empty.")

        if self.allow_external_plugins and self.mode == DynamicLoadingMode.DISABLED:
            errors.append(
                "allow_external_plugins cannot be true when dynamic loading is disabled."
            )

        return len(errors) == 0, errors


@dataclass
class VerificationConfig:
    """
    Verification configuration.

    Verification Agent can use this payload after actions are completed.
    """

    enabled: bool = True
    mode: VerificationMode = VerificationMode.STRICT
    verify_all_completed_actions: bool = True
    verify_sensitive_actions: bool = True
    verify_financial_actions: bool = True
    verify_system_actions: bool = True
    verify_browser_actions: bool = True
    verify_call_actions: bool = True
    require_verification_payload: bool = True
    include_task_snapshot: bool = True
    include_agent_metadata: bool = True
    include_user_workspace_context: bool = True
    store_verification_history: bool = True
    max_verification_history_per_workspace: int = 5000

    def validate(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if isinstance(self.mode, str):
            try:
                self.mode = VerificationMode(self.mode)
            except ValueError:
                errors.append(f"Invalid verification mode: {self.mode}")

        if self.max_verification_history_per_workspace < 0:
            errors.append("max_verification_history_per_workspace cannot be negative.")

        return len(errors) == 0, errors


@dataclass
class SecurityConfig:
    """
    Global security configuration.

    Security Agent should be consulted for every sensitive action.
    """

    enabled: bool = True
    safe_mode: bool = True
    require_security_for_sensitive_agents: bool = True
    require_security_for_sensitive_actions: bool = True
    require_security_for_system_actions: bool = True
    require_security_for_browser_actions: bool = True
    require_security_for_code_execution: bool = True
    require_security_for_finance_actions: bool = True
    require_security_for_call_actions: bool = True
    block_destructive_actions_by_default: bool = True
    block_unknown_agents_by_default: bool = True
    allow_user_override_with_permission: bool = True
    require_workspace_permission: bool = True
    require_role_permission: bool = True
    require_subscription_permission: bool = True
    max_failed_security_checks: int = 3
    sensitive_agent_names: List[str] = field(
        default_factory=lambda: copy.deepcopy(SENSITIVE_AGENT_NAMES)
    )
    high_risk_action_keywords: List[str] = field(
        default_factory=lambda: copy.deepcopy(HIGH_RISK_ACTION_KEYWORDS)
    )

    def validate(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if self.max_failed_security_checks < 0:
            errors.append("max_failed_security_checks cannot be negative.")

        if not isinstance(self.sensitive_agent_names, list):
            errors.append("sensitive_agent_names must be a list.")

        if not isinstance(self.high_risk_action_keywords, list):
            errors.append("high_risk_action_keywords must be a list.")

        return len(errors) == 0, errors


@dataclass
class MemoryConfig:
    """
    Memory compatibility configuration.

    Memory Agent can use this to decide what context is eligible for storage.
    """

    enabled: bool = True
    mode: MemoryMode = MemoryMode.WORKSPACE_SCOPED
    allow_task_context_memory: bool = True
    allow_user_preference_memory: bool = True
    allow_agent_performance_memory: bool = True
    allow_security_memory: bool = False
    allow_sensitive_memory: bool = False
    require_user_scope: bool = True
    require_workspace_scope: bool = True
    redact_secrets_before_memory: bool = True
    max_memory_payload_chars: int = 12000
    memory_event_name: str = "agent_config.memory_payload_prepared"

    def validate(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if isinstance(self.mode, str):
            try:
                self.mode = MemoryMode(self.mode)
            except ValueError:
                errors.append(f"Invalid memory mode: {self.mode}")

        if self.max_memory_payload_chars <= 0:
            errors.append("max_memory_payload_chars must be greater than 0.")

        if self.allow_sensitive_memory:
            errors.append(
                "allow_sensitive_memory should remain False by default for safety."
            )

        return len(errors) == 0, errors


@dataclass
class AuditConfig:
    """
    Audit logging configuration.

    Dashboard/API can use audit settings for task history, compliance, and
    workspace-level visibility.
    """

    enabled: bool = True
    level: AuditLevel = AuditLevel.DETAILED
    log_config_reads: bool = False
    log_config_updates: bool = True
    log_security_checks: bool = True
    log_verification_payloads: bool = True
    log_memory_payloads: bool = False
    log_agent_enable_disable: bool = True
    log_dynamic_loading_changes: bool = True
    include_user_id: bool = True
    include_workspace_id: bool = True
    max_audit_events_per_workspace: int = 10000

    def validate(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if isinstance(self.level, str):
            try:
                self.level = AuditLevel(self.level)
            except ValueError:
                errors.append(f"Invalid audit level: {self.level}")

        if self.max_audit_events_per_workspace < 0:
            errors.append("max_audit_events_per_workspace cannot be negative.")

        return len(errors) == 0, errors


@dataclass
class SaaSIsolationConfig:
    """
    SaaS isolation defaults.

    These rules prevent memory, files, logs, tasks, analytics, and audit data
    from being mixed between users or workspaces.
    """

    enabled: bool = True
    require_user_id: bool = True
    require_workspace_id: bool = True
    isolate_memory: bool = True
    isolate_files: bool = True
    isolate_logs: bool = True
    isolate_tasks: bool = True
    isolate_analytics: bool = True
    isolate_audit_events: bool = True
    isolate_agent_permissions: bool = True
    isolate_registry_views: bool = True
    allow_cross_workspace_admin_view: bool = False
    allow_cross_workspace_agent_execution: bool = False
    default_workspace_role: str = "member"

    def validate(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if self.enabled:
            if not self.require_user_id:
                errors.append("require_user_id should be True when isolation is enabled.")
            if not self.require_workspace_id:
                errors.append(
                    "require_workspace_id should be True when isolation is enabled."
                )

        if self.allow_cross_workspace_agent_execution:
            errors.append(
                "allow_cross_workspace_agent_execution should remain False by default."
            )

        return len(errors) == 0, errors


@dataclass
class DashboardConfig:
    """
    Dashboard/API integration defaults.
    """

    enabled: bool = True
    expose_config_read_api: bool = True
    expose_config_update_api: bool = False
    expose_agent_status: bool = True
    expose_agent_health: bool = True
    expose_enabled_agents: bool = True
    expose_timeout_settings: bool = True
    expose_security_settings: bool = False
    expose_memory_settings: bool = False
    expose_verification_settings: bool = True
    require_admin_for_updates: bool = True
    require_workspace_admin_for_workspace_config: bool = True
    redact_sensitive_config_values: bool = True

    def validate(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if self.expose_config_update_api and not self.require_admin_for_updates:
            errors.append(
                "require_admin_for_updates should be True when config update API is exposed."
            )

        return len(errors) == 0, errors


@dataclass
class AgentDefaults:
    """
    Default per-agent settings used by Registry, Loader, Router, and Master Agent.
    """

    enabled_agents: List[str] = field(
        default_factory=lambda: copy.deepcopy(DEFAULT_AGENT_NAMES)
    )
    disabled_agents: List[str] = field(default_factory=list)
    default_agent: str = "master"
    fallback_agent: str = "master"
    required_agents: List[str] = field(
        default_factory=lambda: [
            "master",
            "security",
            "verification",
            "memory",
        ]
    )
    allow_unknown_agents: bool = False
    auto_enable_registered_agents: bool = False
    agent_execution_mode: AgentExecutionMode = AgentExecutionMode.SAFE
    per_agent_timeout_overrides: Dict[str, int] = field(
        default_factory=lambda: {
            "master": 90,
            "voice": 120,
            "system": 60,
            "browser": 120,
            "code": 180,
            "memory": 45,
            "security": 30,
            "verification": 30,
            "visual": 120,
            "workflow": 600,
            "hologram": 180,
            "call": 240,
            "business": 120,
            "finance": 45,
            "creator": 180,
        }
    )

    def validate(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if isinstance(self.agent_execution_mode, str):
            try:
                self.agent_execution_mode = AgentExecutionMode(
                    self.agent_execution_mode
                )
            except ValueError:
                errors.append(
                    f"Invalid agent execution mode: {self.agent_execution_mode}"
                )

        if not self.default_agent:
            errors.append("default_agent cannot be empty.")

        if not self.fallback_agent:
            errors.append("fallback_agent cannot be empty.")

        for agent in self.required_agents:
            if agent not in self.enabled_agents:
                errors.append(
                    f"Required agent '{agent}' must be present in enabled_agents."
                )

        for agent in self.disabled_agents:
            if agent in self.required_agents:
                errors.append(
                    f"Required agent '{agent}' cannot be listed in disabled_agents."
                )

        for agent_name, timeout in self.per_agent_timeout_overrides.items():
            if not isinstance(timeout, int) or timeout <= 0:
                errors.append(
                    f"Timeout override for agent '{agent_name}' must be a positive integer."
                )

        return len(errors) == 0, errors


# =============================================================================
# Main Config Class
# =============================================================================

class AgentSystemConfig(BaseAgent):
    """
    Global configuration controller for the William/Jarvis agent system.

    This class is intentionally safe to import even while other modules are
    still under development.

    Main consumers:
        - Master Agent
        - Agent Registry
        - Agent Loader
        - Agent Router
        - Security Agent
        - Verification Agent
        - Memory Agent
        - Dashboard/API
        - SaaS workspace runtime
    """

    def __init__(
        self,
        environment: Union[str, ConfigEnvironment] = ConfigEnvironment.DEVELOPMENT,
        config_path: Optional[Union[str, Path]] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        auto_load: bool = False,
    ) -> None:
        try:
            super().__init__(agent_name="agent_system_config")
        except TypeError:
            try:
                super().__init__()
            except Exception:
                pass

        self.config_id: str = str(uuid.uuid4())
        self.version: str = CONFIG_VERSION
        self.created_at: float = time.time()
        self.updated_at: float = self.created_at

        self.environment: ConfigEnvironment = self._normalize_environment(environment)
        self.config_path: Optional[Path] = Path(config_path) if config_path else None

        self.user_id: Optional[Union[str, int]] = user_id
        self.workspace_id: Optional[Union[str, int]] = workspace_id

        self.timeouts: TimeoutConfig = TimeoutConfig()
        self.dynamic_loading: DynamicLoadingConfig = DynamicLoadingConfig()
        self.verification: VerificationConfig = VerificationConfig()
        self.security: SecurityConfig = SecurityConfig()
        self.memory: MemoryConfig = MemoryConfig()
        self.audit: AuditConfig = AuditConfig()
        self.saas_isolation: SaaSIsolationConfig = SaaSIsolationConfig()
        self.dashboard: DashboardConfig = DashboardConfig()
        self.agent_defaults: AgentDefaults = AgentDefaults()

        self.metadata: Dict[str, Any] = {
            "system_name": "William / Jarvis Multi-Agent AI SaaS System",
            "brand": "Digital Promotix",
            "module": "Global Agent Infrastructure Files",
            "file": "agents/agent_config.py",
            "config_version": CONFIG_VERSION,
            "import_safe": True,
            "saas_ready": True,
            "dashboard_ready": True,
            "registry_ready": True,
            "loader_ready": True,
            "router_ready": True,
            "master_agent_ready": True,
        }

        self._event_emitter = AgentEventEmitter()
        self._audit_events: List[Dict[str, Any]] = []
        self._config_update_history: List[Dict[str, Any]] = []

        self._apply_environment_defaults()

        if auto_load and self.config_path:
            self.load_from_file(self.config_path)

    # =========================================================================
    # Normalization
    # =========================================================================

    def _normalize_environment(
        self,
        environment: Union[str, ConfigEnvironment],
    ) -> ConfigEnvironment:
        if isinstance(environment, ConfigEnvironment):
            return environment

        try:
            return ConfigEnvironment(str(environment).lower().strip())
        except ValueError:
            logger.warning(
                "Invalid environment '%s'. Falling back to development.",
                environment,
            )
            return ConfigEnvironment.DEVELOPMENT

    def _normalize_agent_name(self, agent_name: str) -> str:
        return str(agent_name).strip().lower().replace("_agent", "")

    def _now(self) -> float:
        return time.time()

    # =========================================================================
    # Environment Defaults
    # =========================================================================

    def _apply_environment_defaults(self) -> None:
        """
        Apply environment-specific safety defaults.

        Production keeps stricter security, verification, and audit settings.
        Development allows easier local testing but still keeps safe mode enabled.
        """

        if self.environment == ConfigEnvironment.PRODUCTION:
            self.security.safe_mode = True
            self.security.block_destructive_actions_by_default = True
            self.security.require_security_for_sensitive_actions = True
            self.verification.enabled = True
            self.verification.mode = VerificationMode.ENTERPRISE
            self.audit.enabled = True
            self.audit.level = AuditLevel.STRICT
            self.dynamic_loading.allow_external_plugins = False
            self.dynamic_loading.reload_on_change = False
            self.dashboard.expose_config_update_api = False

        elif self.environment == ConfigEnvironment.STAGING:
            self.security.safe_mode = True
            self.verification.enabled = True
            self.verification.mode = VerificationMode.STRICT
            self.audit.enabled = True
            self.audit.level = AuditLevel.DETAILED
            self.dynamic_loading.allow_external_plugins = False
            self.dashboard.expose_config_update_api = False

        elif self.environment == ConfigEnvironment.TESTING:
            self.security.safe_mode = True
            self.verification.enabled = True
            self.verification.mode = VerificationMode.BASIC
            self.audit.enabled = True
            self.audit.level = AuditLevel.BASIC
            self.timeouts.default_timeout_seconds = 20
            self.timeouts.long_task_timeout_seconds = 60
            self.timeouts.workflow_task_timeout_seconds = 120

        else:
            self.security.safe_mode = True
            self.verification.enabled = True
            self.verification.mode = VerificationMode.STRICT
            self.audit.enabled = True
            self.audit.level = AuditLevel.DETAILED
            self.dynamic_loading.reload_on_change = True

    # =========================================================================
    # Required Compatibility Hooks
    # =========================================================================

    def _validate_task_context(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        require_user_workspace: bool = True,
    ) -> Dict[str, Any]:
        """
        Validate task context for SaaS user/workspace isolation.

        Every user-specific task must carry user_id and workspace_id.
        """

        context = task_context or {}
        errors: List[str] = []

        user_id = context.get("user_id", self.user_id)
        workspace_id = context.get("workspace_id", self.workspace_id)

        if self.saas_isolation.enabled and require_user_workspace:
            if self.saas_isolation.require_user_id and not user_id:
                errors.append("Missing required user_id for SaaS-isolated task.")

            if self.saas_isolation.require_workspace_id and not workspace_id:
                errors.append("Missing required workspace_id for SaaS-isolated task.")

        validated_context = {
            **context,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "environment": self.environment.value,
            "config_id": self.config_id,
            "config_version": self.version,
            "saas_isolation_enabled": self.saas_isolation.enabled,
        }

        if errors:
            return self._error_result(
                message="Task context validation failed.",
                error={
                    "code": "TASK_CONTEXT_VALIDATION_FAILED",
                    "details": errors,
                },
                metadata={
                    "hook": "_validate_task_context",
                    "context": validated_context,
                },
            )

        return self._safe_result(
            message="Task context validated successfully.",
            data=validated_context,
            metadata={
                "hook": "_validate_task_context",
            },
        )

    def _requires_security_check(
        self,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Decide whether a task requires Security Agent approval.
        """

        if not self.security.enabled:
            return False

        if self.security.safe_mode:
            if not agent_name and not action:
                return True

        normalized_agent = self._normalize_agent_name(agent_name or "")
        normalized_action = str(action or "").lower().strip()

        if (
            self.security.require_security_for_sensitive_agents
            and normalized_agent in self.security.sensitive_agent_names
        ):
            return True

        if self.security.require_security_for_sensitive_actions:
            for keyword in self.security.high_risk_action_keywords:
                if keyword.lower() in normalized_action:
                    return True

        if normalized_agent == "system" and self.security.require_security_for_system_actions:
            return True

        if normalized_agent == "browser" and self.security.require_security_for_browser_actions:
            return True

        if normalized_agent == "code" and self.security.require_security_for_code_execution:
            return True

        if normalized_agent == "finance" and self.security.require_security_for_finance_actions:
            return True

        if normalized_agent == "call" and self.security.require_security_for_call_actions:
            return True

        if task_context:
            sensitivity = str(task_context.get("sensitivity", "")).lower()
            risk_level = str(task_context.get("risk_level", "")).lower()

            if sensitivity in {"high", "critical", "sensitive"}:
                return True

            if risk_level in {"high", "critical"}:
                return True

        return False

    def _request_security_approval(
        self,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Security Agent approval request payload.

        This method does not directly approve dangerous tasks.
        It only builds a structured payload that Security Agent can process.
        """

        context_result = self._validate_task_context(task_context or {})
        requires_security = self._requires_security_check(
            agent_name=agent_name,
            action=action,
            task_context=task_context,
        )

        payload = {
            "security_request_id": str(uuid.uuid4()),
            "requires_security_check": requires_security,
            "agent_name": agent_name,
            "action": action,
            "task_context": task_context or {},
            "safe_mode": self.security.safe_mode,
            "security_config": self.get_security_summary(redacted=True),
            "context_validation": context_result,
            "created_at": self._now(),
        }

        self._emit_agent_event(
            event_type="agent_config.security_approval_requested",
            payload=payload,
        )

        self._log_audit_event(
            event_type="security_approval_requested",
            details=payload,
        )

        return self._safe_result(
            message="Security approval payload prepared.",
            data=payload,
            metadata={
                "hook": "_request_security_approval",
                "requires_security_check": requires_security,
            },
        )

    def _prepare_verification_payload(
        self,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
        result: Optional[Dict[str, Any]] = None,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent-compatible payload after action completion.
        """

        if not self.verification.enabled:
            return self._safe_result(
                message="Verification is disabled.",
                data={
                    "verification_enabled": False,
                    "payload": None,
                },
                metadata={
                    "hook": "_prepare_verification_payload",
                },
            )

        context_result = self._validate_task_context(task_context or {})

        payload = {
            "verification_id": str(uuid.uuid4()),
            "verification_enabled": self.verification.enabled,
            "verification_mode": self.verification.mode.value,
            "agent_name": agent_name,
            "action": action,
            "result": result or {},
            "task_context": task_context or {},
            "context_validation": context_result,
            "requires_security_check": self._requires_security_check(
                agent_name=agent_name,
                action=action,
                task_context=task_context,
            ),
            "config": {
                "include_task_snapshot": self.verification.include_task_snapshot,
                "include_agent_metadata": self.verification.include_agent_metadata,
                "include_user_workspace_context": (
                    self.verification.include_user_workspace_context
                ),
            },
            "created_at": self._now(),
        }

        self._emit_agent_event(
            event_type="agent_config.verification_payload_prepared",
            payload=payload,
        )

        self._log_audit_event(
            event_type="verification_payload_prepared",
            details=payload,
        )

        return self._safe_result(
            message="Verification payload prepared.",
            data=payload,
            metadata={
                "hook": "_prepare_verification_payload",
            },
        )

    def _prepare_memory_payload(
        self,
        event_type: str,
        content: Dict[str, Any],
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        This respects SaaS isolation and redacts sensitive values.
        """

        if not self.memory.enabled:
            return self._safe_result(
                message="Memory is disabled.",
                data={
                    "memory_enabled": False,
                    "payload": None,
                },
                metadata={
                    "hook": "_prepare_memory_payload",
                },
            )

        context_result = self._validate_task_context(task_context or {})
        safe_content = self._redact_sensitive_values(content)

        serialized = json.dumps(safe_content, default=str)
        if len(serialized) > self.memory.max_memory_payload_chars:
            safe_content = {
                "truncated": True,
                "original_length": len(serialized),
                "preview": serialized[: self.memory.max_memory_payload_chars],
            }

        payload = {
            "memory_id": str(uuid.uuid4()),
            "event_type": event_type,
            "memory_mode": self.memory.mode.value,
            "content": safe_content,
            "task_context": task_context or {},
            "context_validation": context_result,
            "user_id": (task_context or {}).get("user_id", self.user_id),
            "workspace_id": (task_context or {}).get(
                "workspace_id",
                self.workspace_id,
            ),
            "created_at": self._now(),
        }

        self._emit_agent_event(
            event_type=self.memory.memory_event_name,
            payload=payload,
        )

        if self.audit.log_memory_payloads:
            self._log_audit_event(
                event_type="memory_payload_prepared",
                details=payload,
            )

        return self._safe_result(
            message="Memory payload prepared.",
            data=payload,
            metadata={
                "hook": "_prepare_memory_payload",
            },
        )

    def _emit_agent_event(
        self,
        event_type: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Emit an agent configuration event.

        Uses real AgentEventEmitter when available.
        Uses fallback emitter otherwise.
        """

        event_payload = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "payload": payload,
            "config_id": self.config_id,
            "version": self.version,
            "environment": self.environment.value,
            "created_at": self._now(),
        }

        try:
            if hasattr(self._event_emitter, "emit"):
                result = self._event_emitter.emit(event_type, event_payload)
            else:
                result = {
                    "success": True,
                    "message": "Event emitter unavailable; event captured locally.",
                    "data": event_payload,
                    "error": None,
                    "metadata": {
                        "fallback": True,
                    },
                }

            return result

        except Exception as exc:
            logger.exception("Failed to emit agent config event.")
            return self._error_result(
                message="Failed to emit agent config event.",
                error={
                    "code": "EVENT_EMIT_FAILED",
                    "details": str(exc),
                },
                metadata={
                    "hook": "_emit_agent_event",
                    "event_type": event_type,
                },
            )

    def _log_audit_event(
        self,
        event_type: str,
        details: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Store a local audit event.

        Future dashboard/API/database layers can replace this with persistent
        storage while keeping the same structure.
        """

        if not self.audit.enabled:
            return self._safe_result(
                message="Audit logging disabled.",
                data=None,
                metadata={
                    "hook": "_log_audit_event",
                },
            )

        event = {
            "audit_id": str(uuid.uuid4()),
            "event_type": event_type,
            "details": self._redact_sensitive_values(details),
            "config_id": self.config_id,
            "environment": self.environment.value,
            "user_id": self.user_id if self.audit.include_user_id else None,
            "workspace_id": (
                self.workspace_id if self.audit.include_workspace_id else None
            ),
            "created_at": self._now(),
        }

        self._audit_events.append(event)

        max_events = self.audit.max_audit_events_per_workspace
        if max_events and len(self._audit_events) > max_events:
            self._audit_events = self._audit_events[-max_events:]

        return self._safe_result(
            message="Audit event logged.",
            data=event,
            metadata={
                "hook": "_log_audit_event",
            },
        )

    def _safe_result(
        self,
        message: str = "Success.",
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success result.
        """

        return {
            "success": True,
            "message": message,
            "data": data,
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str = "Error.",
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result.
        """

        return {
            "success": False,
            "message": message,
            "data": None,
            "error": error or {
                "code": "UNKNOWN_ERROR",
                "details": message,
            },
            "metadata": metadata or {},
        }

    # =========================================================================
    # Agent Enable / Disable
    # =========================================================================

    def is_agent_enabled(self, agent_name: str) -> bool:
        normalized = self._normalize_agent_name(agent_name)

        if normalized in self.agent_defaults.disabled_agents:
            return False

        if normalized in self.agent_defaults.enabled_agents:
            return True

        return bool(
            self.agent_defaults.allow_unknown_agents
            and not self.security.block_unknown_agents_by_default
        )

    def enable_agent(
        self,
        agent_name: str,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        normalized = self._normalize_agent_name(agent_name)

        context_result = self._validate_task_context(task_context or {})
        if not context_result.get("success"):
            return context_result

        if normalized not in self.agent_defaults.enabled_agents:
            self.agent_defaults.enabled_agents.append(normalized)

        if normalized in self.agent_defaults.disabled_agents:
            self.agent_defaults.disabled_agents.remove(normalized)

        self._touch()

        payload = {
            "agent_name": normalized,
            "enabled": True,
            "task_context": task_context or {},
        }

        self._emit_agent_event(
            event_type="agent_config.agent_enabled",
            payload=payload,
        )

        if self.audit.log_agent_enable_disable:
            self._log_audit_event("agent_enabled", payload)

        return self._safe_result(
            message=f"Agent '{normalized}' enabled.",
            data=payload,
        )

    def disable_agent(
        self,
        agent_name: str,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        normalized = self._normalize_agent_name(agent_name)

        context_result = self._validate_task_context(task_context or {})
        if not context_result.get("success"):
            return context_result

        if normalized in self.agent_defaults.required_agents:
            return self._error_result(
                message=f"Cannot disable required agent '{normalized}'.",
                error={
                    "code": "REQUIRED_AGENT_DISABLE_BLOCKED",
                    "agent_name": normalized,
                },
            )

        if normalized not in self.agent_defaults.disabled_agents:
            self.agent_defaults.disabled_agents.append(normalized)

        if normalized in self.agent_defaults.enabled_agents:
            self.agent_defaults.enabled_agents.remove(normalized)

        self._touch()

        payload = {
            "agent_name": normalized,
            "enabled": False,
            "task_context": task_context or {},
        }

        self._emit_agent_event(
            event_type="agent_config.agent_disabled",
            payload=payload,
        )

        if self.audit.log_agent_enable_disable:
            self._log_audit_event("agent_disabled", payload)

        return self._safe_result(
            message=f"Agent '{normalized}' disabled.",
            data=payload,
        )

    def get_enabled_agents(self) -> Dict[str, Any]:
        enabled = [
            agent
            for agent in self.agent_defaults.enabled_agents
            if agent not in self.agent_defaults.disabled_agents
        ]

        return self._safe_result(
            message="Enabled agents loaded.",
            data={
                "enabled_agents": enabled,
                "disabled_agents": copy.deepcopy(
                    self.agent_defaults.disabled_agents
                ),
                "required_agents": copy.deepcopy(
                    self.agent_defaults.required_agents
                ),
            },
        )

    # =========================================================================
    # Timeout Helpers
    # =========================================================================

    def get_timeout_for_agent(
        self,
        agent_name: Optional[str] = None,
        task_type: Optional[str] = None,
    ) -> int:
        normalized = self._normalize_agent_name(agent_name or "")

        if normalized in self.agent_defaults.per_agent_timeout_overrides:
            return self.agent_defaults.per_agent_timeout_overrides[normalized]

        task_type_normalized = str(task_type or "").lower().strip()

        if task_type_normalized in {"quick", "small", "fast"}:
            return self.timeouts.quick_task_timeout_seconds

        if task_type_normalized in {"long", "heavy", "background"}:
            return self.timeouts.long_task_timeout_seconds

        if task_type_normalized in {"critical", "security", "approval"}:
            return self.timeouts.critical_task_timeout_seconds

        if task_type_normalized in {"workflow", "automation"}:
            return self.timeouts.workflow_task_timeout_seconds

        return self.timeouts.default_timeout_seconds

    def set_agent_timeout(
        self,
        agent_name: str,
        timeout_seconds: int,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if timeout_seconds <= 0:
            return self._error_result(
                message="Timeout must be greater than 0.",
                error={
                    "code": "INVALID_TIMEOUT",
                    "timeout_seconds": timeout_seconds,
                },
            )

        context_result = self._validate_task_context(task_context or {})
        if not context_result.get("success"):
            return context_result

        normalized = self._normalize_agent_name(agent_name)
        self.agent_defaults.per_agent_timeout_overrides[normalized] = timeout_seconds
        self._touch()

        payload = {
            "agent_name": normalized,
            "timeout_seconds": timeout_seconds,
            "task_context": task_context or {},
        }

        self._log_audit_event("agent_timeout_updated", payload)

        return self._safe_result(
            message=f"Timeout updated for agent '{normalized}'.",
            data=payload,
        )

    # =========================================================================
    # Dynamic Loading Helpers
    # =========================================================================

    def is_dynamic_loading_enabled(self) -> bool:
        return bool(
            self.dynamic_loading.enabled
            and self.dynamic_loading.mode != DynamicLoadingMode.DISABLED
        )

    def get_dynamic_loading_summary(self) -> Dict[str, Any]:
        return self._safe_result(
            message="Dynamic loading summary prepared.",
            data={
                "enabled": self.dynamic_loading.enabled,
                "mode": self.dynamic_loading.mode.value,
                "allow_external_plugins": self.dynamic_loading.allow_external_plugins,
                "allow_runtime_imports": self.dynamic_loading.allow_runtime_imports,
                "agent_package_root": self.dynamic_loading.agent_package_root,
                "plugin_package_root": self.dynamic_loading.plugin_package_root,
                "strict_manifest_validation": (
                    self.dynamic_loading.strict_manifest_validation
                ),
                "cache_loaded_agents": self.dynamic_loading.cache_loaded_agents,
                "reload_on_change": self.dynamic_loading.reload_on_change,
            },
        )

    def update_dynamic_loading(
        self,
        enabled: Optional[bool] = None,
        mode: Optional[Union[str, DynamicLoadingMode]] = None,
        allow_external_plugins: Optional[bool] = None,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        context_result = self._validate_task_context(task_context or {})
        if not context_result.get("success"):
            return context_result

        before = asdict(self.dynamic_loading)

        if enabled is not None:
            self.dynamic_loading.enabled = bool(enabled)

        if mode is not None:
            try:
                self.dynamic_loading.mode = (
                    mode
                    if isinstance(mode, DynamicLoadingMode)
                    else DynamicLoadingMode(str(mode))
                )
            except ValueError:
                return self._error_result(
                    message="Invalid dynamic loading mode.",
                    error={
                        "code": "INVALID_DYNAMIC_LOADING_MODE",
                        "mode": str(mode),
                    },
                )

        if allow_external_plugins is not None:
            if allow_external_plugins and self.environment == ConfigEnvironment.PRODUCTION:
                return self._error_result(
                    message="External plugins are blocked in production by default.",
                    error={
                        "code": "EXTERNAL_PLUGINS_BLOCKED_PRODUCTION",
                    },
                )

            self.dynamic_loading.allow_external_plugins = bool(
                allow_external_plugins
            )

        valid, errors = self.dynamic_loading.validate()
        if not valid:
            self.dynamic_loading = DynamicLoadingConfig(**before)
            return self._error_result(
                message="Dynamic loading update failed validation.",
                error={
                    "code": "DYNAMIC_LOADING_VALIDATION_FAILED",
                    "details": errors,
                },
            )

        self._touch()

        payload = {
            "before": before,
            "after": asdict(self.dynamic_loading),
            "task_context": task_context or {},
        }

        if self.audit.log_dynamic_loading_changes:
            self._log_audit_event("dynamic_loading_updated", payload)

        self._emit_agent_event(
            event_type="agent_config.dynamic_loading_updated",
            payload=payload,
        )

        return self._safe_result(
            message="Dynamic loading configuration updated.",
            data=payload,
        )

    # =========================================================================
    # Security / Verification / Memory Summaries
    # =========================================================================

    def get_security_summary(self, redacted: bool = True) -> Dict[str, Any]:
        data = asdict(self.security)

        if redacted:
            data["high_risk_action_keywords"] = [
                "***redacted***"
                for _ in data.get("high_risk_action_keywords", [])
            ]

        return {
            "enabled": data.get("enabled"),
            "safe_mode": data.get("safe_mode"),
            "require_security_for_sensitive_agents": data.get(
                "require_security_for_sensitive_agents"
            ),
            "require_security_for_sensitive_actions": data.get(
                "require_security_for_sensitive_actions"
            ),
            "block_destructive_actions_by_default": data.get(
                "block_destructive_actions_by_default"
            ),
            "block_unknown_agents_by_default": data.get(
                "block_unknown_agents_by_default"
            ),
            "sensitive_agent_names": data.get("sensitive_agent_names", []),
            "high_risk_action_keywords": data.get(
                "high_risk_action_keywords",
                [],
            ),
        }

    def get_verification_summary(self) -> Dict[str, Any]:
        return {
            "enabled": self.verification.enabled,
            "mode": self.verification.mode.value,
            "verify_all_completed_actions": (
                self.verification.verify_all_completed_actions
            ),
            "verify_sensitive_actions": self.verification.verify_sensitive_actions,
            "require_verification_payload": (
                self.verification.require_verification_payload
            ),
        }

    def get_memory_summary(self, redacted: bool = True) -> Dict[str, Any]:
        return {
            "enabled": self.memory.enabled,
            "mode": self.memory.mode.value,
            "allow_task_context_memory": self.memory.allow_task_context_memory,
            "allow_user_preference_memory": (
                self.memory.allow_user_preference_memory
            ),
            "allow_sensitive_memory": (
                False if redacted else self.memory.allow_sensitive_memory
            ),
            "require_user_scope": self.memory.require_user_scope,
            "require_workspace_scope": self.memory.require_workspace_scope,
            "redact_secrets_before_memory": (
                self.memory.redact_secrets_before_memory
            ),
        }

    # =========================================================================
    # Validation
    # =========================================================================

    def validate_config(self) -> Dict[str, Any]:
        """
        Validate the full configuration object.
        """

        validation_groups = {
            "timeouts": self.timeouts.validate(),
            "dynamic_loading": self.dynamic_loading.validate(),
            "verification": self.verification.validate(),
            "security": self.security.validate(),
            "memory": self.memory.validate(),
            "audit": self.audit.validate(),
            "saas_isolation": self.saas_isolation.validate(),
            "dashboard": self.dashboard.validate(),
            "agent_defaults": self.agent_defaults.validate(),
        }

        errors: Dict[str, List[str]] = {}

        for group_name, result in validation_groups.items():
            valid, group_errors = result
            if not valid:
                errors[group_name] = group_errors

        if errors:
            return self._error_result(
                message="Agent system configuration validation failed.",
                error={
                    "code": "CONFIG_VALIDATION_FAILED",
                    "details": errors,
                },
                metadata={
                    "config_id": self.config_id,
                    "version": self.version,
                },
            )

        return self._safe_result(
            message="Agent system configuration validated successfully.",
            data={
                "valid": True,
                "groups_checked": list(validation_groups.keys()),
            },
            metadata={
                "config_id": self.config_id,
                "version": self.version,
            },
        )

    # =========================================================================
    # Serialization / Export
    # =========================================================================

    def to_dict(
        self,
        redacted: bool = True,
        include_runtime_events: bool = False,
    ) -> Dict[str, Any]:
        """
        Export full configuration as a dictionary.
        """

        data = {
            "config_id": self.config_id,
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "environment": self.environment.value,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "timeouts": asdict(self.timeouts),
            "dynamic_loading": self._enum_safe_dict(asdict(self.dynamic_loading)),
            "verification": self._enum_safe_dict(asdict(self.verification)),
            "security": asdict(self.security),
            "memory": self._enum_safe_dict(asdict(self.memory)),
            "audit": self._enum_safe_dict(asdict(self.audit)),
            "saas_isolation": asdict(self.saas_isolation),
            "dashboard": asdict(self.dashboard),
            "agent_defaults": self._enum_safe_dict(asdict(self.agent_defaults)),
            "metadata": copy.deepcopy(self.metadata),
        }

        if redacted:
            data = self._redact_sensitive_values(data)

        if include_runtime_events:
            data["runtime"] = {
                "audit_events": copy.deepcopy(self._audit_events),
                "config_update_history": copy.deepcopy(
                    self._config_update_history
                ),
            }

        return data

    def to_json(
        self,
        redacted: bool = True,
        include_runtime_events: bool = False,
        indent: int = 2,
    ) -> str:
        return json.dumps(
            self.to_dict(
                redacted=redacted,
                include_runtime_events=include_runtime_events,
            ),
            indent=indent,
            default=str,
        )

    def public_dashboard_config(self) -> Dict[str, Any]:
        """
        Return dashboard-safe configuration.

        Sensitive config values are hidden by default.
        """

        data = {
            "config_id": self.config_id,
            "version": self.version,
            "environment": self.environment.value,
            "safe_mode": self.security.safe_mode,
            "enabled_agents": self.get_enabled_agents().get("data", {}),
            "timeouts": asdict(self.timeouts)
            if self.dashboard.expose_timeout_settings
            else None,
            "dynamic_loading": self.get_dynamic_loading_summary().get("data"),
            "verification": self.get_verification_summary()
            if self.dashboard.expose_verification_settings
            else None,
            "security": self.get_security_summary(redacted=True)
            if self.dashboard.expose_security_settings
            else {
                "enabled": self.security.enabled,
                "safe_mode": self.security.safe_mode,
            },
            "memory": self.get_memory_summary(redacted=True)
            if self.dashboard.expose_memory_settings
            else {
                "enabled": self.memory.enabled,
                "mode": self.memory.mode.value,
            },
            "saas_isolation": {
                "enabled": self.saas_isolation.enabled,
                "require_user_id": self.saas_isolation.require_user_id,
                "require_workspace_id": self.saas_isolation.require_workspace_id,
            },
            "metadata": {
                "system_name": self.metadata.get("system_name"),
                "brand": self.metadata.get("brand"),
                "dashboard_ready": self.metadata.get("dashboard_ready"),
                "registry_ready": self.metadata.get("registry_ready"),
                "loader_ready": self.metadata.get("loader_ready"),
                "router_ready": self.metadata.get("router_ready"),
                "master_agent_ready": self.metadata.get("master_agent_ready"),
            },
        }

        return self._safe_result(
            message="Dashboard-safe configuration prepared.",
            data=data,
        )

    # =========================================================================
    # Loading / Saving
    # =========================================================================

    def save_to_file(
        self,
        path: Optional[Union[str, Path]] = None,
        redacted: bool = False,
    ) -> Dict[str, Any]:
        """
        Save configuration to JSON file.

        By default redacted=False because this is intended for internal config
        storage. Never hardcode secrets in this config.
        """

        target_path = Path(path) if path else self.config_path

        if not target_path:
            return self._error_result(
                message="No config path provided.",
                error={
                    "code": "CONFIG_PATH_MISSING",
                },
            )

        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)

            with target_path.open("w", encoding="utf-8") as file:
                file.write(self.to_json(redacted=redacted, indent=2))

            self.config_path = target_path

            payload = {
                "path": str(target_path),
                "redacted": redacted,
            }

            self._log_audit_event("config_saved_to_file", payload)

            return self._safe_result(
                message="Configuration saved to file.",
                data=payload,
            )

        except Exception as exc:
            logger.exception("Failed to save agent system config.")
            return self._error_result(
                message="Failed to save configuration to file.",
                error={
                    "code": "CONFIG_SAVE_FAILED",
                    "details": str(exc),
                },
            )

    def load_from_file(
        self,
        path: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Load configuration from JSON file.
        """

        target_path = Path(path) if path else self.config_path

        if not target_path:
            return self._error_result(
                message="No config path provided.",
                error={
                    "code": "CONFIG_PATH_MISSING",
                },
            )

        if not target_path.exists():
            return self._error_result(
                message="Config file does not exist.",
                error={
                    "code": "CONFIG_FILE_NOT_FOUND",
                    "path": str(target_path),
                },
            )

        try:
            with target_path.open("r", encoding="utf-8") as file:
                raw_data = json.load(file)

            result = self.update_from_dict(raw_data, system_load=True)
            if not result.get("success"):
                return result

            self.config_path = target_path

            payload = {
                "path": str(target_path),
            }

            self._log_audit_event("config_loaded_from_file", payload)

            return self._safe_result(
                message="Configuration loaded from file.",
                data=payload,
            )

        except Exception as exc:
            logger.exception("Failed to load agent system config.")
            return self._error_result(
                message="Failed to load configuration from file.",
                error={
                    "code": "CONFIG_LOAD_FAILED",
                    "details": str(exc),
                },
            )

    def update_from_dict(
        self,
        data: Dict[str, Any],
        task_context: Optional[Dict[str, Any]] = None,
        system_load: bool = False,
    ) -> Dict[str, Any]:
        """
        Update configuration from dictionary.

        For runtime updates, task context is validated.
        For system load from disk, validation is skipped but config is still
        validated after assignment.
        """

        if not system_load:
            context_result = self._validate_task_context(task_context or {})
            if not context_result.get("success"):
                return context_result

        before = self.to_dict(redacted=False)

        try:
            if "environment" in data:
                self.environment = self._normalize_environment(data["environment"])

            if "user_id" in data:
                self.user_id = data["user_id"]

            if "workspace_id" in data:
                self.workspace_id = data["workspace_id"]

            if "timeouts" in data and isinstance(data["timeouts"], dict):
                self.timeouts = TimeoutConfig(**data["timeouts"])

            if "dynamic_loading" in data and isinstance(
                data["dynamic_loading"],
                dict,
            ):
                dynamic_data = data["dynamic_loading"]
                if "mode" in dynamic_data:
                    dynamic_data["mode"] = DynamicLoadingMode(dynamic_data["mode"])
                self.dynamic_loading = DynamicLoadingConfig(**dynamic_data)

            if "verification" in data and isinstance(data["verification"], dict):
                verification_data = data["verification"]
                if "mode" in verification_data:
                    verification_data["mode"] = VerificationMode(
                        verification_data["mode"]
                    )
                self.verification = VerificationConfig(**verification_data)

            if "security" in data and isinstance(data["security"], dict):
                self.security = SecurityConfig(**data["security"])

            if "memory" in data and isinstance(data["memory"], dict):
                memory_data = data["memory"]
                if "mode" in memory_data:
                    memory_data["mode"] = MemoryMode(memory_data["mode"])
                self.memory = MemoryConfig(**memory_data)

            if "audit" in data and isinstance(data["audit"], dict):
                audit_data = data["audit"]
                if "level" in audit_data:
                    audit_data["level"] = AuditLevel(audit_data["level"])
                self.audit = AuditConfig(**audit_data)

            if "saas_isolation" in data and isinstance(
                data["saas_isolation"],
                dict,
            ):
                self.saas_isolation = SaaSIsolationConfig(
                    **data["saas_isolation"]
                )

            if "dashboard" in data and isinstance(data["dashboard"], dict):
                self.dashboard = DashboardConfig(**data["dashboard"])

            if "agent_defaults" in data and isinstance(
                data["agent_defaults"],
                dict,
            ):
                defaults_data = data["agent_defaults"]
                if "agent_execution_mode" in defaults_data:
                    defaults_data["agent_execution_mode"] = AgentExecutionMode(
                        defaults_data["agent_execution_mode"]
                    )
                self.agent_defaults = AgentDefaults(**defaults_data)

            if "metadata" in data and isinstance(data["metadata"], dict):
                self.metadata.update(data["metadata"])

            validation = self.validate_config()
            if not validation.get("success"):
                self._restore_from_dict(before)
                return validation

            self._touch()

            payload = {
                "system_load": system_load,
                "task_context": task_context or {},
                "updated_keys": list(data.keys()),
            }

            self._config_update_history.append(
                {
                    "update_id": str(uuid.uuid4()),
                    "payload": payload,
                    "created_at": self._now(),
                }
            )

            if self.audit.log_config_updates:
                self._log_audit_event("config_updated_from_dict", payload)

            return self._safe_result(
                message="Configuration updated successfully.",
                data=payload,
            )

        except Exception as exc:
            self._restore_from_dict(before)
            logger.exception("Failed to update configuration from dictionary.")

            return self._error_result(
                message="Failed to update configuration from dictionary.",
                error={
                    "code": "CONFIG_UPDATE_FAILED",
                    "details": str(exc),
                },
            )

    def _restore_from_dict(self, data: Dict[str, Any]) -> None:
        """
        Best-effort internal restore helper.
        """

        try:
            self.update_from_dict(data, system_load=True)
        except Exception:
            logger.exception("Failed to restore previous configuration.")

    # =========================================================================
    # Redaction / Utility
    # =========================================================================

    def _touch(self) -> None:
        self.updated_at = self._now()

    def _enum_safe_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        safe: Dict[str, Any] = {}

        for key, value in data.items():
            if isinstance(value, Enum):
                safe[key] = value.value
            elif isinstance(value, dict):
                safe[key] = self._enum_safe_dict(value)
            elif isinstance(value, list):
                safe[key] = [
                    item.value if isinstance(item, Enum) else item
                    for item in value
                ]
            else:
                safe[key] = value

        return safe

    def _redact_sensitive_values(self, value: Any) -> Any:
        """
        Redact sensitive values from nested structures.
        """

        sensitive_keys = {
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "credential",
            "private_key",
            "access_key",
            "refresh_token",
            "client_secret",
        }

        if isinstance(value, dict):
            redacted: Dict[str, Any] = {}
            for key, item in value.items():
                key_lower = str(key).lower()
                if any(sensitive in key_lower for sensitive in sensitive_keys):
                    redacted[key] = "***redacted***"
                else:
                    redacted[key] = self._redact_sensitive_values(item)
            return redacted

        if isinstance(value, list):
            return [self._redact_sensitive_values(item) for item in value]

        if isinstance(value, tuple):
            return tuple(self._redact_sensitive_values(item) for item in value)

        return value

    # =========================================================================
    # Runtime Status
    # =========================================================================

    def get_runtime_status(self) -> Dict[str, Any]:
        """
        Return runtime status for dashboard/API.
        """

        validation = self.validate_config()

        data = {
            "config_id": self.config_id,
            "version": self.version,
            "environment": self.environment.value,
            "valid": validation.get("success", False),
            "safe_mode": self.security.safe_mode,
            "dynamic_loading_enabled": self.is_dynamic_loading_enabled(),
            "verification_enabled": self.verification.enabled,
            "memory_enabled": self.memory.enabled,
            "audit_enabled": self.audit.enabled,
            "saas_isolation_enabled": self.saas_isolation.enabled,
            "enabled_agents_count": len(
                self.get_enabled_agents().get("data", {}).get(
                    "enabled_agents",
                    [],
                )
            ),
            "disabled_agents_count": len(self.agent_defaults.disabled_agents),
            "audit_events_count": len(self._audit_events),
            "config_updates_count": len(self._config_update_history),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

        return self._safe_result(
            message="Runtime status prepared.",
            data=data,
        )

    def get_audit_events(
        self,
        limit: int = 100,
        redacted: bool = True,
    ) -> Dict[str, Any]:
        """
        Return recent local audit events.
        """

        events = self._audit_events[-limit:] if limit > 0 else self._audit_events

        if redacted:
            events = self._redact_sensitive_values(events)

        return self._safe_result(
            message="Audit events loaded.",
            data={
                "events": events,
                "count": len(events),
                "total_available": len(self._audit_events),
            },
        )

    # =========================================================================
    # Factory Methods
    # =========================================================================

    @classmethod
    def create_default(
        cls,
        environment: Union[str, ConfigEnvironment] = ConfigEnvironment.DEVELOPMENT,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> "AgentSystemConfig":
        """
        Create default config instance.
        """

        return cls(
            environment=environment,
            user_id=user_id,
            workspace_id=workspace_id,
            auto_load=False,
        )

    @classmethod
    def create_production(
        cls,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> "AgentSystemConfig":
        """
        Create production-safe config instance.
        """

        return cls(
            environment=ConfigEnvironment.PRODUCTION,
            user_id=user_id,
            workspace_id=workspace_id,
            auto_load=False,
        )

    @classmethod
    def from_file(
        cls,
        path: Union[str, Path],
        environment: Union[str, ConfigEnvironment] = ConfigEnvironment.DEVELOPMENT,
    ) -> "AgentSystemConfig":
        """
        Create config instance from file.
        """

        instance = cls(
            environment=environment,
            config_path=path,
            auto_load=True,
        )
        return instance


# =============================================================================
# Module-Level Singleton Helpers
# =============================================================================

_GLOBAL_AGENT_CONFIG: Optional[AgentSystemConfig] = None


def get_global_agent_config(
    environment: Union[str, ConfigEnvironment] = ConfigEnvironment.DEVELOPMENT,
    user_id: Optional[Union[str, int]] = None,
    workspace_id: Optional[Union[str, int]] = None,
) -> AgentSystemConfig:
    """
    Return global AgentSystemConfig singleton.

    Useful for Registry, Loader, Router, and Master Agent imports.
    """

    global _GLOBAL_AGENT_CONFIG

    if _GLOBAL_AGENT_CONFIG is None:
        _GLOBAL_AGENT_CONFIG = AgentSystemConfig(
            environment=environment,
            user_id=user_id,
            workspace_id=workspace_id,
        )

    return _GLOBAL_AGENT_CONFIG


def reset_global_agent_config() -> AgentSystemConfig:
    """
    Reset global config singleton.

    Mainly useful for tests.
    """

    global _GLOBAL_AGENT_CONFIG
    _GLOBAL_AGENT_CONFIG = AgentSystemConfig()
    return _GLOBAL_AGENT_CONFIG


def load_agent_config_from_env() -> AgentSystemConfig:
    """
    Load config using environment variables.

    Supported variables:
        WILLIAM_ENV
        WILLIAM_AGENT_CONFIG_PATH
    """

    environment = os.getenv("WILLIAM_ENV", ConfigEnvironment.DEVELOPMENT.value)
    config_path = os.getenv("WILLIAM_AGENT_CONFIG_PATH")

    if config_path:
        return AgentSystemConfig.from_file(
            path=config_path,
            environment=environment,
        )

    return AgentSystemConfig(environment=environment)


# =============================================================================
# Safe Module Test
# =============================================================================

if __name__ == "__main__":
    config = AgentSystemConfig.create_default(
        environment=ConfigEnvironment.DEVELOPMENT,
        user_id="demo_user",
        workspace_id="demo_workspace",
    )

    print(config.to_json(redacted=True))