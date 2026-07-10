"""
agents/verification_agent/config.py

VerificationConfig for William / Jarvis Verification Agent.

Purpose:
    Verification thresholds, screenshot rules, retry settings, and safe mode.

This module is intentionally import-safe and does not require the rest of the
William/Jarvis codebase to exist yet. It provides configuration structures and
helper methods used by Verification Agent components such as:

    - verification_agent.py
    - state_checker.py
    - screenshot_checker.py
    - result_validator.py
    - app_state_checker.py
    - file_state_checker.py
    - browser_state_checker.py
    - code_state_checker.py
    - device_state_checker.py
    - ui_element_checker.py
    - action_replay_checker.py
    - error_detector.py
    - proof_collector.py
    - retry_manager.py
    - report_generator.py
    - verification_memory.py

Architecture Integration Notes:
    - Master Agent / Router:
        Uses this config to understand Verification Agent capability defaults.

    - Security Agent:
        Sensitive configuration changes and risky verification modes can be
        routed through Security Agent by calling compatibility hooks.

    - Memory Agent:
        Stable verification preferences and successful verification patterns can
        be prepared as memory-compatible payloads.

    - Dashboard / API:
        Public methods return structured dict results:
            {
                "success": bool,
                "message": str,
                "data": dict,
                "error": Optional[dict],
                "metadata": dict
            }

    - SaaS Isolation:
        Every context-aware method validates user_id and workspace_id and avoids
        mixing configuration state across users/workspaces.

Safety:
    This file does not execute browser, system, financial, destructive, call,
    message, or device actions. It only defines safe configuration defaults and
    validation helpers.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Optional BaseAgent compatibility
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback is for import-safety

    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent stub.

        This allows agents/verification_agent/config.py to be imported before
        the full William/Jarvis BaseAgent implementation exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        def emit_event(self, *args: Any, **kwargs: Any) -> None:
            return None

        def log_audit(self, *args: Any, **kwargs: Any) -> None:
            return None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODULE_NAME = "verification_agent"
FILE_NAME = "config.py"
CLASS_NAME = "VerificationConfig"
CONFIG_VERSION = "1.0.0"

DEFAULT_MAX_SCREENSHOT_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_PROOF_ITEMS = 25
DEFAULT_MAX_RETRY_ATTEMPTS = 3
DEFAULT_RETRY_BACKOFF_SECONDS = 1.5
DEFAULT_RETRY_MAX_DELAY_SECONDS = 30.0
DEFAULT_VERIFICATION_TIMEOUT_SECONDS = 60.0

ENV_PREFIX = "WILLIAM_VERIFICATION_"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class VerificationMode(str, Enum):
    """Verification strictness mode."""

    SAFE = "safe"
    STANDARD = "standard"
    STRICT = "strict"
    DEBUG = "debug"


class ScreenshotFormat(str, Enum):
    """Supported screenshot formats for proof collection."""

    PNG = "png"
    JPEG = "jpeg"
    WEBP = "webp"


class RetryStrategy(str, Enum):
    """Retry strategy options for safe verification retries."""

    NONE = "none"
    FIXED = "fixed"
    EXPONENTIAL = "exponential"
    LINEAR = "linear"


class RiskLevel(str, Enum):
    """Risk level used by permission/security hooks."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerificationTargetType(str, Enum):
    """Supported target types for verification configuration routing."""

    APP = "app"
    FILE = "file"
    BROWSER = "browser"
    CODE = "code"
    DEVICE = "device"
    UI = "ui"
    SCREENSHOT = "screenshot"
    ACTION_REPLAY = "action_replay"
    ERROR = "error"
    PROOF = "proof"
    REPORT = "report"
    MEMORY = "memory"
    GENERIC = "generic"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ThresholdConfig:
    """
    Confidence and matching thresholds used by result validation.

    Values must stay between 0.0 and 1.0.
    """

    minimum_success_confidence: float = 0.75
    minimum_strict_confidence: float = 0.90
    minimum_visual_match: float = 0.82
    minimum_text_match: float = 0.80
    minimum_ui_element_match: float = 0.78
    minimum_browser_load_confidence: float = 0.80
    minimum_code_validation_confidence: float = 0.85
    minimum_file_state_confidence: float = 0.85
    minimum_device_state_confidence: float = 0.78
    maximum_error_tolerance: float = 0.10
    partial_success_floor: float = 0.50

    def validate(self) -> None:
        for key, value in asdict(self).items():
            if not isinstance(value, (int, float)):
                raise ValueError(f"Threshold '{key}' must be numeric.")
            if value < 0.0 or value > 1.0:
                raise ValueError(f"Threshold '{key}' must be between 0.0 and 1.0.")


@dataclass(frozen=True)
class ScreenshotRules:
    """
    Screenshot capture and proof rules.

    This file only defines rules. Actual screenshot capture belongs in
    screenshot_checker.py or proof_collector.py.
    """

    enabled: bool = True
    capture_before_action: bool = True
    capture_after_action: bool = True
    capture_on_error: bool = True
    capture_on_retry: bool = True
    redact_sensitive_regions: bool = True
    redact_credentials: bool = True
    redact_payment_data: bool = True
    redact_personal_identifiers: bool = True
    allow_full_page_browser_screenshot: bool = True
    allow_device_screenshot: bool = False
    require_security_for_device_screenshot: bool = True
    default_format: ScreenshotFormat = ScreenshotFormat.PNG
    jpeg_quality: int = 85
    max_width: int = 1920
    max_height: int = 1080
    max_file_bytes: int = DEFAULT_MAX_SCREENSHOT_BYTES
    storage_subdir: str = "verification/screenshots"
    filename_prefix: str = "verification"
    include_timestamp_in_filename: bool = True
    include_user_workspace_in_path: bool = True
    retention_days: int = 30

    def validate(self) -> None:
        if self.jpeg_quality < 1 or self.jpeg_quality > 100:
            raise ValueError("jpeg_quality must be between 1 and 100.")
        if self.max_width < 320:
            raise ValueError("max_width must be at least 320.")
        if self.max_height < 240:
            raise ValueError("max_height must be at least 240.")
        if self.max_file_bytes < 1024:
            raise ValueError("max_file_bytes must be at least 1024.")
        if self.retention_days < 0:
            raise ValueError("retention_days cannot be negative.")
        if not self.storage_subdir.strip():
            raise ValueError("storage_subdir cannot be empty.")
        if not self.filename_prefix.strip():
            raise ValueError("filename_prefix cannot be empty.")


@dataclass(frozen=True)
class RetryRules:
    """
    Retry settings for safe failed verification checks.

    These rules are consumed by retry_manager.py. This file does not perform
    retries directly.
    """

    enabled: bool = True
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL
    max_attempts: int = DEFAULT_MAX_RETRY_ATTEMPTS
    base_delay_seconds: float = DEFAULT_RETRY_BACKOFF_SECONDS
    max_delay_seconds: float = DEFAULT_RETRY_MAX_DELAY_SECONDS
    jitter_seconds: float = 0.35
    retry_on_timeout: bool = True
    retry_on_transient_error: bool = True
    retry_on_ui_not_ready: bool = True
    retry_on_browser_loading: bool = True
    retry_on_permission_denied: bool = False
    retry_on_destructive_action: bool = False
    stop_on_security_required: bool = True
    stop_on_user_workspace_mismatch: bool = True
    stop_on_repeated_same_error: bool = True
    repeated_error_limit: int = 2

    def validate(self) -> None:
        if self.max_attempts < 0:
            raise ValueError("max_attempts cannot be negative.")
        if self.base_delay_seconds < 0:
            raise ValueError("base_delay_seconds cannot be negative.")
        if self.max_delay_seconds < self.base_delay_seconds:
            raise ValueError("max_delay_seconds must be >= base_delay_seconds.")
        if self.jitter_seconds < 0:
            raise ValueError("jitter_seconds cannot be negative.")
        if self.repeated_error_limit < 1:
            raise ValueError("repeated_error_limit must be at least 1.")


@dataclass(frozen=True)
class SafeModeRules:
    """
    Safe mode permissions for Verification Agent.

    Safe mode prevents the Verification Agent from becoming an executor of
    risky actions. The agent may verify, inspect, collect proof, and report,
    but sensitive actions should be approved by Security Agent.
    """

    enabled: bool = True
    deny_destructive_actions: bool = True
    deny_financial_actions: bool = True
    deny_message_sending: bool = True
    deny_call_actions: bool = True
    deny_real_browser_clicks_without_security: bool = True
    deny_device_changes_without_security: bool = True
    deny_file_delete_without_security: bool = True
    deny_external_network_mutation: bool = True
    allow_read_only_checks: bool = True
    allow_local_static_analysis: bool = True
    allow_report_generation: bool = True
    require_user_id: bool = True
    require_workspace_id: bool = True
    require_security_for_high_risk: bool = True
    require_security_for_device_state: bool = True
    require_security_for_browser_control: bool = True
    require_security_for_file_mutation_verification: bool = False
    max_verification_timeout_seconds: float = DEFAULT_VERIFICATION_TIMEOUT_SECONDS

    def validate(self) -> None:
        if self.max_verification_timeout_seconds <= 0:
            raise ValueError("max_verification_timeout_seconds must be greater than 0.")


@dataclass(frozen=True)
class ProofRules:
    """Rules for proof collection and reporting."""

    enabled: bool = True
    include_screenshots: bool = True
    include_logs: bool = True
    include_timestamps: bool = True
    include_process_status: bool = True
    include_api_responses: bool = True
    include_error_details: bool = True
    include_confidence_breakdown: bool = True
    max_items: int = DEFAULT_MAX_PROOF_ITEMS
    redact_sensitive_values: bool = True
    max_log_chars: int = 20_000
    max_api_response_chars: int = 30_000

    def validate(self) -> None:
        if self.max_items < 0:
            raise ValueError("max_items cannot be negative.")
        if self.max_log_chars < 0:
            raise ValueError("max_log_chars cannot be negative.")
        if self.max_api_response_chars < 0:
            raise ValueError("max_api_response_chars cannot be negative.")


@dataclass(frozen=True)
class AuditRules:
    """Audit/event logging rules for dashboard and SaaS governance."""

    enabled: bool = True
    emit_agent_events: bool = True
    log_config_reads: bool = False
    log_config_updates: bool = True
    log_validation_failures: bool = True
    log_security_requests: bool = True
    include_user_workspace: bool = True
    include_request_id: bool = True

    def validate(self) -> None:
        return None


@dataclass(frozen=True)
class TargetOverrideConfig:
    """
    Per-target override configuration.

    Example:
        browser verification may need different timeout and threshold than
        code verification.
    """

    target_type: VerificationTargetType
    threshold_overrides: Dict[str, float] = field(default_factory=dict)
    timeout_seconds: Optional[float] = None
    retry_attempts: Optional[int] = None
    screenshot_enabled: Optional[bool] = None
    require_security_check: Optional[bool] = None

    def validate(self) -> None:
        for key, value in self.threshold_overrides.items():
            if value < 0.0 or value > 1.0:
                raise ValueError(
                    f"Target override threshold '{key}' for '{self.target_type.value}' "
                    "must be between 0.0 and 1.0."
                )
        if self.timeout_seconds is not None and self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than 0 when provided.")
        if self.retry_attempts is not None and self.retry_attempts < 0:
            raise ValueError("retry_attempts cannot be negative when provided.")


@dataclass(frozen=True)
class VerificationConfigSnapshot:
    """
    Serializable snapshot of all VerificationConfig settings.
    """

    version: str
    mode: VerificationMode
    thresholds: ThresholdConfig
    screenshot_rules: ScreenshotRules
    retry_rules: RetryRules
    safe_mode: SafeModeRules
    proof_rules: ProofRules
    audit_rules: AuditRules
    target_overrides: Dict[str, TargetOverrideConfig]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        self.thresholds.validate()
        self.screenshot_rules.validate()
        self.retry_rules.validate()
        self.safe_mode.validate()
        self.proof_rules.validate()
        self.audit_rules.validate()
        for override in self.target_overrides.values():
            override.validate()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_epoch() -> float:
    return time.time()


def _now_ms() -> int:
    return int(time.time() * 1000)


def _stringify_identifier(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _is_safe_identifier(value: str) -> bool:
    """
    Validate safe SaaS identifiers.

    Allows common ID formats:
        - uuid
        - database IDs
        - slug-like workspace IDs
        - email-like IDs for internal calendar/contact contexts

    Blocks empty values and path traversal.
    """
    if not value:
        return False
    blocked = ["..", "/", "\\", "\x00", "\n", "\r", "\t"]
    return not any(token in value for token in blocked)


def _coerce_bool_env(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    cleaned = value.strip().lower()
    if cleaned in {"1", "true", "yes", "y", "on"}:
        return True
    if cleaned in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _coerce_float_env(value: Optional[str], default: float) -> float:
    if value is None:
        return default
    try:
        return float(value)
    except Exception:
        return default


def _coerce_int_env(value: Optional[str], default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def _enum_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    return value


def _json_safe(obj: Any) -> Any:
    """
    Convert nested dataclasses/enums/paths to JSON-safe objects.
    """
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, Path):
        return str(obj)
    if hasattr(obj, "__dataclass_fields__"):
        return {key: _json_safe(value) for key, value in asdict(obj).items()}
    if isinstance(obj, Mapping):
        return {str(key): _json_safe(value) for key, value in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_json_safe(value) for value in obj]
    return obj


# ---------------------------------------------------------------------------
# Main Config Class
# ---------------------------------------------------------------------------

class VerificationConfig(BaseAgent):
    """
    Production configuration manager for William/Jarvis Verification Agent.

    This class intentionally stores only configuration, validation, structured
    responses, and compatibility hooks. It does not perform real verification
    actions or side effects.

    Public responsibilities:
        - Provide default verification thresholds.
        - Provide screenshot capture rules.
        - Provide retry policy.
        - Provide safe mode policy.
        - Validate SaaS user/workspace context.
        - Identify whether security approval is required.
        - Build verification and memory payloads.
        - Produce structured API/dashboard-safe results.
        - Export/import config dictionaries safely.
    """

    agent_name = "VerificationConfig"
    module_name = MODULE_NAME
    file_name = FILE_NAME
    config_version = CONFIG_VERSION

    def __init__(
        self,
        mode: Union[VerificationMode, str] = VerificationMode.SAFE,
        thresholds: Optional[ThresholdConfig] = None,
        screenshot_rules: Optional[ScreenshotRules] = None,
        retry_rules: Optional[RetryRules] = None,
        safe_mode: Optional[SafeModeRules] = None,
        proof_rules: Optional[ProofRules] = None,
        audit_rules: Optional[AuditRules] = None,
        target_overrides: Optional[Dict[Union[str, VerificationTargetType], TargetOverrideConfig]] = None,
        event_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(agent_name=self.agent_name)

        self.mode = self._normalize_mode(mode)
        self.thresholds = thresholds or self._build_thresholds_for_mode(self.mode)
        self.screenshot_rules = screenshot_rules or self._build_screenshot_rules_from_env()
        self.retry_rules = retry_rules or self._build_retry_rules_from_env()
        self.safe_mode = safe_mode or self._build_safe_mode_from_env()
        self.proof_rules = proof_rules or ProofRules()
        self.audit_rules = audit_rules or AuditRules()
        self.event_sink = event_sink
        self.audit_sink = audit_sink
        self.security_approval_callback = security_approval_callback
        self.metadata = metadata.copy() if metadata else {}

        self.target_overrides: Dict[str, TargetOverrideConfig] = {}
        for key, value in (target_overrides or self._default_target_overrides()).items():
            normalized_key = self._normalize_target_type(key).value
            self.target_overrides[normalized_key] = value

        self.validate_config()

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def safe_defaults(cls) -> "VerificationConfig":
        """Create a safe default config for production SaaS usage."""
        return cls(mode=VerificationMode.SAFE)

    @classmethod
    def standard_defaults(cls) -> "VerificationConfig":
        """Create a balanced default config for normal verification flows."""
        return cls(mode=VerificationMode.STANDARD)

    @classmethod
    def strict_defaults(cls) -> "VerificationConfig":
        """Create strict verification settings for high-confidence reports."""
        return cls(mode=VerificationMode.STRICT)

    @classmethod
    def debug_defaults(cls) -> "VerificationConfig":
        """
        Create debug verification settings.

        Debug mode still keeps safe mode protections enabled unless explicitly
        overridden by the caller.
        """
        return cls(
            mode=VerificationMode.DEBUG,
            audit_rules=AuditRules(
                enabled=True,
                emit_agent_events=True,
                log_config_reads=True,
                log_config_updates=True,
                log_validation_failures=True,
                log_security_requests=True,
            ),
        )

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "VerificationConfig":
        """
        Build VerificationConfig from a dictionary.

        Unknown keys are ignored to remain forward-compatible with future
        William/Jarvis config versions.
        """
        if not isinstance(raw, Mapping):
            raise TypeError("raw config must be a mapping/dict.")

        mode = raw.get("mode", VerificationMode.SAFE)

        thresholds_raw = raw.get("thresholds") or {}
        screenshot_raw = raw.get("screenshot_rules") or {}
        retry_raw = raw.get("retry_rules") or {}
        safe_raw = raw.get("safe_mode") or {}
        proof_raw = raw.get("proof_rules") or {}
        audit_raw = raw.get("audit_rules") or {}
        overrides_raw = raw.get("target_overrides") or {}
        metadata = raw.get("metadata") or {}

        thresholds = cls._dataclass_from_mapping(ThresholdConfig, thresholds_raw)
        screenshot_rules = cls._screenshot_rules_from_mapping(screenshot_raw)
        retry_rules = cls._retry_rules_from_mapping(retry_raw)
        safe_mode = cls._dataclass_from_mapping(SafeModeRules, safe_raw)
        proof_rules = cls._dataclass_from_mapping(ProofRules, proof_raw)
        audit_rules = cls._dataclass_from_mapping(AuditRules, audit_raw)

        target_overrides: Dict[Union[str, VerificationTargetType], TargetOverrideConfig] = {}
        if isinstance(overrides_raw, Mapping):
            for key, value in overrides_raw.items():
                if not isinstance(value, Mapping):
                    continue
                target_type = cls._normalize_target_type_static(
                    value.get("target_type", key)
                )
                target_overrides[target_type] = TargetOverrideConfig(
                    target_type=target_type,
                    threshold_overrides=dict(value.get("threshold_overrides") or {}),
                    timeout_seconds=value.get("timeout_seconds"),
                    retry_attempts=value.get("retry_attempts"),
                    screenshot_enabled=value.get("screenshot_enabled"),
                    require_security_check=value.get("require_security_check"),
                )

        return cls(
            mode=mode,
            thresholds=thresholds,
            screenshot_rules=screenshot_rules,
            retry_rules=retry_rules,
            safe_mode=safe_mode,
            proof_rules=proof_rules,
            audit_rules=audit_rules,
            target_overrides=target_overrides,
            metadata=dict(metadata) if isinstance(metadata, Mapping) else {},
        )

    @classmethod
    def from_json_file(cls, path: Union[str, Path]) -> "VerificationConfig":
        """
        Load config from a JSON file.

        This method reads configuration only. It does not execute external code.
        """
        config_path = Path(path)
        with config_path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        return cls.from_dict(raw)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_config(self) -> None:
        """Validate all nested config objects."""
        self.thresholds.validate()
        self.screenshot_rules.validate()
        self.retry_rules.validate()
        self.safe_mode.validate()
        self.proof_rules.validate()
        self.audit_rules.validate()

        for key, override in self.target_overrides.items():
            if not isinstance(override, TargetOverrideConfig):
                raise ValueError(f"target override '{key}' must be TargetOverrideConfig.")
            override.validate()

    def _validate_task_context(self, context: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        """
        Validate SaaS context for user/workspace isolation.

        Required by William/Jarvis compatibility hooks.

        Expected context:
            {
                "user_id": "...",
                "workspace_id": "...",
                "request_id": "... optional",
                "task_id": "... optional",
                "agent": "... optional"
            }
        """
        if context is None:
            context = {}

        if not isinstance(context, Mapping):
            return self._error_result(
                message="Invalid task context.",
                code="INVALID_CONTEXT_TYPE",
                details={"expected": "mapping/dict", "received": type(context).__name__},
            )

        user_id = _stringify_identifier(context.get("user_id"))
        workspace_id = _stringify_identifier(context.get("workspace_id"))

        errors: List[Dict[str, Any]] = []

        if self.safe_mode.require_user_id and not user_id:
            errors.append(
                {
                    "field": "user_id",
                    "message": "user_id is required for SaaS isolation.",
                }
            )
        elif user_id and not _is_safe_identifier(user_id):
            errors.append(
                {
                    "field": "user_id",
                    "message": "user_id contains unsafe characters.",
                }
            )

        if self.safe_mode.require_workspace_id and not workspace_id:
            errors.append(
                {
                    "field": "workspace_id",
                    "message": "workspace_id is required for SaaS isolation.",
                }
            )
        elif workspace_id and not _is_safe_identifier(workspace_id):
            errors.append(
                {
                    "field": "workspace_id",
                    "message": "workspace_id contains unsafe characters.",
                }
            )

        if errors:
            self._log_audit_event(
                event_type="verification.context.validation_failed",
                context=dict(context),
                data={"errors": errors},
                risk_level=RiskLevel.MEDIUM,
            )
            return self._error_result(
                message="Task context validation failed.",
                code="CONTEXT_VALIDATION_FAILED",
                details={"errors": errors},
                metadata=self._metadata(context),
            )

        normalized_context = dict(context)
        normalized_context["user_id"] = user_id
        normalized_context["workspace_id"] = workspace_id
        normalized_context.setdefault("request_id", str(uuid.uuid4()))
        normalized_context.setdefault("source_agent", MODULE_NAME)

        return self._safe_result(
            message="Task context is valid.",
            data={"context": normalized_context},
            metadata=self._metadata(normalized_context),
        )

    # ------------------------------------------------------------------
    # Public Config Accessors
    # ------------------------------------------------------------------

    def get_config(
        self,
        context: Optional[Mapping[str, Any]] = None,
        include_sensitive: bool = False,
    ) -> Dict[str, Any]:
        """
        Return current configuration as a structured result.

        No secrets are stored by this config. include_sensitive is accepted for
        future dashboard/API compatibility.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        if self.audit_rules.log_config_reads:
            self._log_audit_event(
                event_type="verification.config.read",
                context=validation["data"]["context"],
                data={"include_sensitive": include_sensitive},
                risk_level=RiskLevel.LOW,
            )

        return self._safe_result(
            message="Verification configuration loaded.",
            data={"config": self.to_dict()},
            metadata=self._metadata(validation["data"]["context"]),
        )

    def get_threshold(
        self,
        key: str,
        target_type: Union[str, VerificationTargetType, None] = None,
        default: Optional[float] = None,
    ) -> Optional[float]:
        """
        Get threshold by key, respecting target overrides.

        Example:
            get_threshold("minimum_visual_match", "browser")
        """
        if not key:
            return default

        if target_type is not None:
            override = self.get_target_override(target_type)
            if override and key in override.threshold_overrides:
                return override.threshold_overrides[key]

        value = getattr(self.thresholds, key, default)
        if isinstance(value, (int, float)):
            return float(value)
        return default

    def get_target_override(
        self,
        target_type: Union[str, VerificationTargetType],
    ) -> Optional[TargetOverrideConfig]:
        """Return per-target override if configured."""
        normalized = self._normalize_target_type(target_type).value
        return self.target_overrides.get(normalized)

    def get_effective_config_for_target(
        self,
        target_type: Union[str, VerificationTargetType],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return effective config for a specific verification target.

        This is useful for dashboard/API and for individual checker files.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        normalized = self._normalize_target_type(target_type)
        override = self.get_target_override(normalized)

        effective_thresholds = asdict(self.thresholds)
        timeout_seconds = self.safe_mode.max_verification_timeout_seconds
        retry_attempts = self.retry_rules.max_attempts
        screenshot_enabled = self.screenshot_rules.enabled
        require_security_check = self._requires_security_check(
            action="verify",
            target_type=normalized,
            context=validation["data"]["context"],
            risk_level=None,
        )["data"]["requires_security_check"]

        if override:
            effective_thresholds.update(override.threshold_overrides)
            if override.timeout_seconds is not None:
                timeout_seconds = override.timeout_seconds
            if override.retry_attempts is not None:
                retry_attempts = override.retry_attempts
            if override.screenshot_enabled is not None:
                screenshot_enabled = override.screenshot_enabled
            if override.require_security_check is not None:
                require_security_check = override.require_security_check

        data = {
            "target_type": normalized.value,
            "mode": self.mode.value,
            "thresholds": effective_thresholds,
            "timeout_seconds": timeout_seconds,
            "retry_attempts": retry_attempts,
            "screenshot_enabled": screenshot_enabled,
            "requires_security_check": require_security_check,
            "safe_mode_enabled": self.safe_mode.enabled,
            "proof_enabled": self.proof_rules.enabled,
        }

        return self._safe_result(
            message=f"Effective verification config resolved for target '{normalized.value}'.",
            data=data,
            metadata=self._metadata(validation["data"]["context"]),
        )

    def get_retry_delay(self, attempt_index: int) -> float:
        """
        Calculate retry delay for the given attempt index.

        attempt_index is zero-based:
            0 = first retry wait
            1 = second retry wait
        """
        if attempt_index < 0:
            attempt_index = 0

        if not self.retry_rules.enabled or self.retry_rules.strategy == RetryStrategy.NONE:
            return 0.0

        base = self.retry_rules.base_delay_seconds

        if self.retry_rules.strategy == RetryStrategy.FIXED:
            delay = base
        elif self.retry_rules.strategy == RetryStrategy.LINEAR:
            delay = base * (attempt_index + 1)
        elif self.retry_rules.strategy == RetryStrategy.EXPONENTIAL:
            delay = base * (2 ** attempt_index)
        else:
            delay = base

        if self.retry_rules.jitter_seconds:
            # Deterministic bounded jitter based on attempt index to avoid
            # importing random for config determinism.
            jitter = min(self.retry_rules.jitter_seconds, self.retry_rules.jitter_seconds * 0.5)
            delay += jitter

        return min(delay, self.retry_rules.max_delay_seconds)

    def should_retry(
        self,
        error_type: Optional[str] = None,
        attempt_count: int = 0,
        context: Optional[Mapping[str, Any]] = None,
        is_destructive: bool = False,
        security_required: bool = False,
    ) -> Dict[str, Any]:
        """
        Determine whether Retry Manager should retry a failed verification step.

        This does not execute a retry. It only returns policy decision.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        normalized_error = (error_type or "unknown").strip().lower()

        if not self.retry_rules.enabled:
            return self._safe_result(
                message="Retry disabled by configuration.",
                data={"should_retry": False, "reason": "retry_disabled"},
                metadata=self._metadata(validation["data"]["context"]),
            )

        if attempt_count >= self.retry_rules.max_attempts:
            return self._safe_result(
                message="Retry limit reached.",
                data={
                    "should_retry": False,
                    "reason": "max_attempts_reached",
                    "attempt_count": attempt_count,
                    "max_attempts": self.retry_rules.max_attempts,
                },
                metadata=self._metadata(validation["data"]["context"]),
            )

        if is_destructive and not self.retry_rules.retry_on_destructive_action:
            return self._safe_result(
                message="Retry blocked for destructive action.",
                data={"should_retry": False, "reason": "destructive_action_blocked"},
                metadata=self._metadata(validation["data"]["context"]),
            )

        if security_required and self.retry_rules.stop_on_security_required:
            return self._safe_result(
                message="Retry blocked because security approval is required.",
                data={"should_retry": False, "reason": "security_required"},
                metadata=self._metadata(validation["data"]["context"]),
            )

        retryable_errors = {
            "timeout": self.retry_rules.retry_on_timeout,
            "transient_error": self.retry_rules.retry_on_transient_error,
            "ui_not_ready": self.retry_rules.retry_on_ui_not_ready,
            "browser_loading": self.retry_rules.retry_on_browser_loading,
            "permission_denied": self.retry_rules.retry_on_permission_denied,
        }

        allowed = retryable_errors.get(normalized_error, self.retry_rules.retry_on_transient_error)

        if not allowed:
            return self._safe_result(
                message=f"Retry blocked for error type '{normalized_error}'.",
                data={"should_retry": False, "reason": "error_type_not_retryable"},
                metadata=self._metadata(validation["data"]["context"]),
            )

        delay = self.get_retry_delay(attempt_count)

        return self._safe_result(
            message="Retry allowed by policy.",
            data={
                "should_retry": True,
                "reason": "retryable_error",
                "error_type": normalized_error,
                "attempt_count": attempt_count,
                "next_delay_seconds": delay,
            },
            metadata=self._metadata(validation["data"]["context"]),
        )

    def build_screenshot_filename(
        self,
        context: Optional[Mapping[str, Any]] = None,
        target_type: Union[str, VerificationTargetType] = VerificationTargetType.SCREENSHOT,
        suffix: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build a safe screenshot filename/path.

        This does not create files. It only returns a safe relative path.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        ctx = validation["data"]["context"]
        target = self._normalize_target_type(target_type).value
        extension = self.screenshot_rules.default_format.value

        parts = [self.screenshot_rules.filename_prefix, target]

        if suffix:
            safe_suffix = (
                str(suffix)
                .strip()
                .replace(" ", "_")
                .replace("/", "_")
                .replace("\\", "_")
            )
            if safe_suffix:
                parts.append(safe_suffix)

        if self.screenshot_rules.include_timestamp_in_filename:
            parts.append(str(_now_ms()))

        filename = "_".join(parts) + f".{extension}"

        subdir = Path(self.screenshot_rules.storage_subdir)

        if self.screenshot_rules.include_user_workspace_in_path:
            subdir = subdir / ctx["user_id"] / ctx["workspace_id"]

        relative_path = str(subdir / filename).replace("\\", "/")

        return self._safe_result(
            message="Screenshot filename generated.",
            data={
                "filename": filename,
                "relative_path": relative_path,
                "format": extension,
                "max_file_bytes": self.screenshot_rules.max_file_bytes,
                "redaction_required": self.is_screenshot_redaction_required(),
            },
            metadata=self._metadata(ctx),
        )

    def is_screenshot_redaction_required(self) -> bool:
        """Return whether screenshot redaction is required."""
        return bool(
            self.screenshot_rules.redact_sensitive_regions
            or self.screenshot_rules.redact_credentials
            or self.screenshot_rules.redact_payment_data
            or self.screenshot_rules.redact_personal_identifiers
        )

    # ------------------------------------------------------------------
    # Compatibility Hooks
    # ------------------------------------------------------------------

    def _requires_security_check(
        self,
        action: str,
        target_type: Union[str, VerificationTargetType, None] = None,
        context: Optional[Mapping[str, Any]] = None,
        risk_level: Optional[Union[str, RiskLevel]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Determine whether an action needs Security Agent approval.

        This is a compatibility hook required by the William/Jarvis architecture.
        """
        target = self._normalize_target_type(target_type or VerificationTargetType.GENERIC)
        risk = self._normalize_risk_level(risk_level)

        action_normalized = (action or "").strip().lower()
        reasons: List[str] = []

        if self.safe_mode.enabled:
            if risk in {RiskLevel.HIGH, RiskLevel.CRITICAL} and self.safe_mode.require_security_for_high_risk:
                reasons.append("high_or_critical_risk")

            if target == VerificationTargetType.DEVICE and self.safe_mode.require_security_for_device_state:
                reasons.append("device_state_requires_security")

            if target == VerificationTargetType.BROWSER and self.safe_mode.require_security_for_browser_control:
                browser_control_terms = {"click", "control", "navigate", "submit", "login"}
                if any(term in action_normalized for term in browser_control_terms):
                    reasons.append("browser_control_requires_security")

            if target == VerificationTargetType.FILE and self.safe_mode.require_security_for_file_mutation_verification:
                mutation_terms = {"delete", "move", "modify", "write", "chmod", "permission"}
                if any(term in action_normalized for term in mutation_terms):
                    reasons.append("file_mutation_requires_security")

            if self.safe_mode.deny_destructive_actions:
                destructive_terms = {"delete", "destroy", "remove", "wipe", "format", "kill", "shutdown"}
                if any(term in action_normalized for term in destructive_terms):
                    reasons.append("destructive_action_blocked")

            if self.safe_mode.deny_financial_actions:
                financial_terms = {"pay", "purchase", "transfer", "withdraw", "invoice", "billing"}
                if any(term in action_normalized for term in financial_terms):
                    reasons.append("financial_action_blocked")

            if self.safe_mode.deny_message_sending:
                message_terms = {"send_email", "send_message", "sms", "whatsapp", "dm", "reply"}
                if any(term in action_normalized for term in message_terms):
                    reasons.append("message_sending_blocked")

            if self.safe_mode.deny_call_actions:
                call_terms = {"call", "dial", "phone"}
                if any(term in action_normalized for term in call_terms):
                    reasons.append("call_action_blocked")

        override = self.get_target_override(target)
        if override and override.require_security_check is True:
            reasons.append("target_override_requires_security")

        requires = bool(reasons)

        return self._safe_result(
            message="Security requirement evaluated.",
            data={
                "requires_security_check": requires,
                "reasons": sorted(set(reasons)),
                "action": action,
                "target_type": target.value,
                "risk_level": risk.value,
                "metadata": dict(metadata or {}),
            },
            metadata=self._metadata(context),
        )

    def _request_security_approval(
        self,
        action: str,
        target_type: Union[str, VerificationTargetType, None] = None,
        context: Optional[Mapping[str, Any]] = None,
        risk_level: Optional[Union[str, RiskLevel]] = None,
        reason: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare and optionally send a security approval request.

        If a security_approval_callback is supplied, this method calls it.
        Otherwise it returns a structured pending result.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        ctx = validation["data"]["context"]
        target = self._normalize_target_type(target_type or VerificationTargetType.GENERIC)
        risk = self._normalize_risk_level(risk_level)

        approval_payload = {
            "approval_id": str(uuid.uuid4()),
            "module": MODULE_NAME,
            "file": FILE_NAME,
            "class": CLASS_NAME,
            "action": action,
            "target_type": target.value,
            "risk_level": risk.value,
            "reason": reason or "Security approval required by VerificationConfig policy.",
            "context": {
                "user_id": ctx.get("user_id"),
                "workspace_id": ctx.get("workspace_id"),
                "request_id": ctx.get("request_id"),
                "task_id": ctx.get("task_id"),
            },
            "metadata": dict(metadata or {}),
            "created_at_epoch": _now_epoch(),
        }

        self._log_audit_event(
            event_type="verification.security.approval_requested",
            context=ctx,
            data=approval_payload,
            risk_level=risk,
        )

        if self.security_approval_callback:
            try:
                response = self.security_approval_callback(copy.deepcopy(approval_payload))
                if not isinstance(response, Mapping):
                    return self._error_result(
                        message="Security callback returned invalid response.",
                        code="INVALID_SECURITY_CALLBACK_RESPONSE",
                        details={"response_type": type(response).__name__},
                        metadata=self._metadata(ctx),
                    )

                return self._safe_result(
                    message="Security approval callback completed.",
                    data={
                        "approval_payload": approval_payload,
                        "security_response": dict(response),
                    },
                    metadata=self._metadata(ctx),
                )
            except Exception as exc:
                logger.exception("Security approval callback failed.")
                return self._error_result(
                    message="Security approval callback failed.",
                    code="SECURITY_CALLBACK_FAILED",
                    details={"exception": str(exc)},
                    metadata=self._metadata(ctx),
                )

        return self._safe_result(
            message="Security approval request prepared.",
            data={
                "approval_payload": approval_payload,
                "status": "pending_external_security_agent",
            },
            metadata=self._metadata(ctx),
        )

    def _prepare_verification_payload(
        self,
        context: Optional[Mapping[str, Any]],
        target_type: Union[str, VerificationTargetType],
        expected: Optional[Any] = None,
        actual: Optional[Any] = None,
        confidence: Optional[float] = None,
        status: Optional[str] = None,
        proof: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        This payload is consumed by report_generator.py, verification_memory.py,
        dashboard/API, and Master Agent.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        ctx = validation["data"]["context"]
        target = self._normalize_target_type(target_type)

        payload = {
            "verification_id": str(uuid.uuid4()),
            "module": MODULE_NAME,
            "target_type": target.value,
            "status": status or "prepared",
            "expected": expected,
            "actual": actual,
            "confidence": confidence,
            "threshold": self.get_threshold("minimum_success_confidence", target),
            "mode": self.mode.value,
            "safe_mode_enabled": self.safe_mode.enabled,
            "proof": dict(proof or {}),
            "context": {
                "user_id": ctx.get("user_id"),
                "workspace_id": ctx.get("workspace_id"),
                "request_id": ctx.get("request_id"),
                "task_id": ctx.get("task_id"),
            },
            "metadata": dict(metadata or {}),
            "created_at_epoch": _now_epoch(),
        }

        return self._safe_result(
            message="Verification payload prepared.",
            data={"verification_payload": payload},
            metadata=self._metadata(ctx),
        )

    def _prepare_memory_payload(
        self,
        context: Optional[Mapping[str, Any]],
        memory_type: str = "verification_config",
        content: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        This does not write memory directly. Memory Agent decides whether to
        store it.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        ctx = validation["data"]["context"]

        memory_payload = {
            "memory_id": str(uuid.uuid4()),
            "memory_type": memory_type,
            "source_module": MODULE_NAME,
            "source_file": FILE_NAME,
            "scope": "workspace",
            "user_id": ctx.get("user_id"),
            "workspace_id": ctx.get("workspace_id"),
            "content": dict(content or {}),
            "metadata": {
                **dict(metadata or {}),
                "config_version": self.config_version,
                "mode": self.mode.value,
            },
            "created_at_epoch": _now_epoch(),
        }

        return self._safe_result(
            message="Memory payload prepared.",
            data={"memory_payload": memory_payload},
            metadata=self._metadata(ctx),
        )

    def _emit_agent_event(
        self,
        event_type: str,
        context: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
        risk_level: Union[str, RiskLevel] = RiskLevel.LOW,
    ) -> Dict[str, Any]:
        """
        Emit an agent event for dashboard/API/registry integrations.

        If event_sink is provided, it receives the event dict.
        """
        if not self.audit_rules.emit_agent_events:
            return self._safe_result(
                message="Agent event emission disabled.",
                data={"emitted": False, "reason": "disabled"},
                metadata=self._metadata(context),
            )

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "module": MODULE_NAME,
            "file": FILE_NAME,
            "class": CLASS_NAME,
            "risk_level": self._normalize_risk_level(risk_level).value,
            "context": self._safe_context_for_event(context),
            "data": dict(data or {}),
            "created_at_epoch": _now_epoch(),
        }

        try:
            if self.event_sink:
                self.event_sink(copy.deepcopy(event))
            elif hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event)  # type: ignore[misc]
                except Exception:
                    pass

            return self._safe_result(
                message="Agent event emitted.",
                data={"emitted": True, "event": event},
                metadata=self._metadata(context),
            )
        except Exception as exc:
            logger.exception("Failed to emit agent event.")
            return self._error_result(
                message="Failed to emit agent event.",
                code="EVENT_EMIT_FAILED",
                details={"exception": str(exc)},
                metadata=self._metadata(context),
            )

    def _log_audit_event(
        self,
        event_type: str,
        context: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
        risk_level: Union[str, RiskLevel] = RiskLevel.LOW,
    ) -> Dict[str, Any]:
        """
        Log audit event for SaaS governance.

        This method is safe if no audit sink exists.
        """
        if not self.audit_rules.enabled:
            return self._safe_result(
                message="Audit logging disabled.",
                data={"logged": False, "reason": "disabled"},
                metadata=self._metadata(context),
            )

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "event_type": event_type,
            "module": MODULE_NAME,
            "file": FILE_NAME,
            "class": CLASS_NAME,
            "risk_level": self._normalize_risk_level(risk_level).value,
            "context": self._safe_context_for_event(context),
            "data": dict(data or {}),
            "created_at_epoch": _now_epoch(),
        }

        try:
            if self.audit_sink:
                self.audit_sink(copy.deepcopy(audit_event))
            elif hasattr(super(), "log_audit"):
                try:
                    super().log_audit(audit_event)  # type: ignore[misc]
                except Exception:
                    pass

            return self._safe_result(
                message="Audit event logged.",
                data={"logged": True, "audit_event": audit_event},
                metadata=self._metadata(context),
            )
        except Exception as exc:
            logger.exception("Failed to log audit event.")
            return self._error_result(
                message="Failed to log audit event.",
                code="AUDIT_LOG_FAILED",
                details={"exception": str(exc)},
                metadata=self._metadata(context),
            )

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis success result.
        """
        return {
            "success": True,
            "message": message,
            "data": _json_safe(dict(data or {})),
            "error": None,
            "metadata": _json_safe(
                {
                    "module": MODULE_NAME,
                    "file": FILE_NAME,
                    "class": CLASS_NAME,
                    "config_version": self.config_version,
                    "timestamp_epoch": _now_epoch(),
                    **dict(metadata or {}),
                }
            ),
        }

    def _error_result(
        self,
        message: str,
        code: str = "VERIFICATION_CONFIG_ERROR",
        details: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis error result.
        """
        return {
            "success": False,
            "message": message,
            "data": {},
            "error": _json_safe(
                {
                    "code": code,
                    "details": dict(details or {}),
                }
            ),
            "metadata": _json_safe(
                {
                    "module": MODULE_NAME,
                    "file": FILE_NAME,
                    "class": CLASS_NAME,
                    "config_version": self.config_version,
                    "timestamp_epoch": _now_epoch(),
                    **dict(metadata or {}),
                }
            ),
        }

    # ------------------------------------------------------------------
    # Export / Save
    # ------------------------------------------------------------------

    def snapshot(self) -> VerificationConfigSnapshot:
        """Return typed snapshot."""
        snapshot = VerificationConfigSnapshot(
            version=self.config_version,
            mode=self.mode,
            thresholds=self.thresholds,
            screenshot_rules=self.screenshot_rules,
            retry_rules=self.retry_rules,
            safe_mode=self.safe_mode,
            proof_rules=self.proof_rules,
            audit_rules=self.audit_rules,
            target_overrides=self.target_overrides,
            metadata=copy.deepcopy(self.metadata),
        )
        snapshot.validate()
        return snapshot

    def to_dict(self) -> Dict[str, Any]:
        """Return JSON-safe config dictionary."""
        return _json_safe(self.snapshot())

    def to_json(self, indent: int = 2) -> str:
        """Return JSON string for dashboard/API/config export."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def save_json_file(self, path: Union[str, Path]) -> Dict[str, Any]:
        """
        Save config to a JSON file.

        This is a local file write helper for development/config export. It does
        not delete, mutate external systems, or store secrets.
        """
        output_path = Path(path)

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("w", encoding="utf-8") as handle:
                handle.write(self.to_json(indent=2))
            return self._safe_result(
                message="Verification configuration saved.",
                data={"path": str(output_path)},
            )
        except Exception as exc:
            logger.exception("Failed to save VerificationConfig JSON.")
            return self._error_result(
                message="Failed to save VerificationConfig JSON.",
                code="CONFIG_SAVE_FAILED",
                details={"exception": str(exc), "path": str(output_path)},
            )

    # ------------------------------------------------------------------
    # Internal Builders
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_mode(mode: Union[VerificationMode, str]) -> VerificationMode:
        if isinstance(mode, VerificationMode):
            return mode
        cleaned = str(mode).strip().lower()
        for item in VerificationMode:
            if item.value == cleaned:
                return item
        return VerificationMode.SAFE

    @staticmethod
    def _normalize_risk_level(risk_level: Optional[Union[str, RiskLevel]]) -> RiskLevel:
        if isinstance(risk_level, RiskLevel):
            return risk_level
        if risk_level is None:
            return RiskLevel.LOW
        cleaned = str(risk_level).strip().lower()
        for item in RiskLevel:
            if item.value == cleaned:
                return item
        return RiskLevel.LOW

    def _normalize_target_type(
        self,
        target_type: Union[str, VerificationTargetType],
    ) -> VerificationTargetType:
        return self._normalize_target_type_static(target_type)

    @staticmethod
    def _normalize_target_type_static(
        target_type: Union[str, VerificationTargetType],
    ) -> VerificationTargetType:
        if isinstance(target_type, VerificationTargetType):
            return target_type

        cleaned = str(target_type).strip().lower()

        aliases = {
            "application": VerificationTargetType.APP,
            "filesystem": VerificationTargetType.FILE,
            "folder": VerificationTargetType.FILE,
            "directory": VerificationTargetType.FILE,
            "web": VerificationTargetType.BROWSER,
            "page": VerificationTargetType.BROWSER,
            "source": VerificationTargetType.CODE,
            "system": VerificationTargetType.DEVICE,
            "screen": VerificationTargetType.SCREENSHOT,
            "replay": VerificationTargetType.ACTION_REPLAY,
            "errors": VerificationTargetType.ERROR,
            "evidence": VerificationTargetType.PROOF,
        }

        if cleaned in aliases:
            return aliases[cleaned]

        for item in VerificationTargetType:
            if item.value == cleaned:
                return item

        return VerificationTargetType.GENERIC

    @staticmethod
    def _build_thresholds_for_mode(mode: VerificationMode) -> ThresholdConfig:
        if mode == VerificationMode.STRICT:
            return ThresholdConfig(
                minimum_success_confidence=0.88,
                minimum_strict_confidence=0.95,
                minimum_visual_match=0.90,
                minimum_text_match=0.88,
                minimum_ui_element_match=0.86,
                minimum_browser_load_confidence=0.88,
                minimum_code_validation_confidence=0.92,
                minimum_file_state_confidence=0.92,
                minimum_device_state_confidence=0.86,
                maximum_error_tolerance=0.05,
                partial_success_floor=0.65,
            )

        if mode == VerificationMode.DEBUG:
            return ThresholdConfig(
                minimum_success_confidence=0.65,
                minimum_strict_confidence=0.85,
                minimum_visual_match=0.70,
                minimum_text_match=0.70,
                minimum_ui_element_match=0.68,
                minimum_browser_load_confidence=0.70,
                minimum_code_validation_confidence=0.75,
                minimum_file_state_confidence=0.75,
                minimum_device_state_confidence=0.70,
                maximum_error_tolerance=0.20,
                partial_success_floor=0.40,
            )

        if mode == VerificationMode.STANDARD:
            return ThresholdConfig(
                minimum_success_confidence=0.78,
                minimum_strict_confidence=0.90,
                minimum_visual_match=0.84,
                minimum_text_match=0.82,
                minimum_ui_element_match=0.80,
                minimum_browser_load_confidence=0.82,
                minimum_code_validation_confidence=0.86,
                minimum_file_state_confidence=0.86,
                minimum_device_state_confidence=0.80,
                maximum_error_tolerance=0.10,
                partial_success_floor=0.52,
            )

        return ThresholdConfig()

    @staticmethod
    def _build_screenshot_rules_from_env() -> ScreenshotRules:
        default_format_raw = os.getenv(f"{ENV_PREFIX}SCREENSHOT_FORMAT", ScreenshotFormat.PNG.value)
        try:
            screenshot_format = ScreenshotFormat(default_format_raw.strip().lower())
        except Exception:
            screenshot_format = ScreenshotFormat.PNG

        return ScreenshotRules(
            enabled=_coerce_bool_env(os.getenv(f"{ENV_PREFIX}SCREENSHOT_ENABLED"), True),
            capture_before_action=_coerce_bool_env(
                os.getenv(f"{ENV_PREFIX}SCREENSHOT_BEFORE_ACTION"), True
            ),
            capture_after_action=_coerce_bool_env(
                os.getenv(f"{ENV_PREFIX}SCREENSHOT_AFTER_ACTION"), True
            ),
            capture_on_error=_coerce_bool_env(
                os.getenv(f"{ENV_PREFIX}SCREENSHOT_ON_ERROR"), True
            ),
            capture_on_retry=_coerce_bool_env(
                os.getenv(f"{ENV_PREFIX}SCREENSHOT_ON_RETRY"), True
            ),
            default_format=screenshot_format,
            jpeg_quality=_coerce_int_env(
                os.getenv(f"{ENV_PREFIX}SCREENSHOT_JPEG_QUALITY"), 85
            ),
            max_width=_coerce_int_env(
                os.getenv(f"{ENV_PREFIX}SCREENSHOT_MAX_WIDTH"), 1920
            ),
            max_height=_coerce_int_env(
                os.getenv(f"{ENV_PREFIX}SCREENSHOT_MAX_HEIGHT"), 1080
            ),
            max_file_bytes=_coerce_int_env(
                os.getenv(f"{ENV_PREFIX}SCREENSHOT_MAX_BYTES"),
                DEFAULT_MAX_SCREENSHOT_BYTES,
            ),
            storage_subdir=os.getenv(
                f"{ENV_PREFIX}SCREENSHOT_STORAGE_SUBDIR",
                "verification/screenshots",
            ),
            retention_days=_coerce_int_env(
                os.getenv(f"{ENV_PREFIX}SCREENSHOT_RETENTION_DAYS"), 30
            ),
        )

    @staticmethod
    def _build_retry_rules_from_env() -> RetryRules:
        strategy_raw = os.getenv(f"{ENV_PREFIX}RETRY_STRATEGY", RetryStrategy.EXPONENTIAL.value)
        try:
            strategy = RetryStrategy(strategy_raw.strip().lower())
        except Exception:
            strategy = RetryStrategy.EXPONENTIAL

        return RetryRules(
            enabled=_coerce_bool_env(os.getenv(f"{ENV_PREFIX}RETRY_ENABLED"), True),
            strategy=strategy,
            max_attempts=_coerce_int_env(
                os.getenv(f"{ENV_PREFIX}RETRY_MAX_ATTEMPTS"),
                DEFAULT_MAX_RETRY_ATTEMPTS,
            ),
            base_delay_seconds=_coerce_float_env(
                os.getenv(f"{ENV_PREFIX}RETRY_BASE_DELAY_SECONDS"),
                DEFAULT_RETRY_BACKOFF_SECONDS,
            ),
            max_delay_seconds=_coerce_float_env(
                os.getenv(f"{ENV_PREFIX}RETRY_MAX_DELAY_SECONDS"),
                DEFAULT_RETRY_MAX_DELAY_SECONDS,
            ),
            jitter_seconds=_coerce_float_env(
                os.getenv(f"{ENV_PREFIX}RETRY_JITTER_SECONDS"),
                0.35,
            ),
        )

    @staticmethod
    def _build_safe_mode_from_env() -> SafeModeRules:
        return SafeModeRules(
            enabled=_coerce_bool_env(os.getenv(f"{ENV_PREFIX}SAFE_MODE_ENABLED"), True),
            require_user_id=_coerce_bool_env(
                os.getenv(f"{ENV_PREFIX}REQUIRE_USER_ID"), True
            ),
            require_workspace_id=_coerce_bool_env(
                os.getenv(f"{ENV_PREFIX}REQUIRE_WORKSPACE_ID"), True
            ),
            max_verification_timeout_seconds=_coerce_float_env(
                os.getenv(f"{ENV_PREFIX}TIMEOUT_SECONDS"),
                DEFAULT_VERIFICATION_TIMEOUT_SECONDS,
            ),
        )

    @staticmethod
    def _default_target_overrides() -> Dict[VerificationTargetType, TargetOverrideConfig]:
        return {
            VerificationTargetType.BROWSER: TargetOverrideConfig(
                target_type=VerificationTargetType.BROWSER,
                threshold_overrides={
                    "minimum_success_confidence": 0.80,
                    "minimum_browser_load_confidence": 0.84,
                    "minimum_visual_match": 0.82,
                },
                timeout_seconds=75.0,
                retry_attempts=3,
                screenshot_enabled=True,
                require_security_check=False,
            ),
            VerificationTargetType.CODE: TargetOverrideConfig(
                target_type=VerificationTargetType.CODE,
                threshold_overrides={
                    "minimum_success_confidence": 0.85,
                    "minimum_code_validation_confidence": 0.88,
                },
                timeout_seconds=120.0,
                retry_attempts=2,
                screenshot_enabled=False,
                require_security_check=False,
            ),
            VerificationTargetType.FILE: TargetOverrideConfig(
                target_type=VerificationTargetType.FILE,
                threshold_overrides={
                    "minimum_success_confidence": 0.86,
                    "minimum_file_state_confidence": 0.88,
                },
                timeout_seconds=45.0,
                retry_attempts=2,
                screenshot_enabled=False,
                require_security_check=False,
            ),
            VerificationTargetType.DEVICE: TargetOverrideConfig(
                target_type=VerificationTargetType.DEVICE,
                threshold_overrides={
                    "minimum_success_confidence": 0.78,
                    "minimum_device_state_confidence": 0.80,
                },
                timeout_seconds=60.0,
                retry_attempts=2,
                screenshot_enabled=True,
                require_security_check=True,
            ),
            VerificationTargetType.UI: TargetOverrideConfig(
                target_type=VerificationTargetType.UI,
                threshold_overrides={
                    "minimum_ui_element_match": 0.82,
                    "minimum_visual_match": 0.84,
                },
                timeout_seconds=60.0,
                retry_attempts=3,
                screenshot_enabled=True,
                require_security_check=False,
            ),
            VerificationTargetType.ACTION_REPLAY: TargetOverrideConfig(
                target_type=VerificationTargetType.ACTION_REPLAY,
                threshold_overrides={
                    "minimum_success_confidence": 0.82,
                },
                timeout_seconds=180.0,
                retry_attempts=1,
                screenshot_enabled=True,
                require_security_check=True,
            ),
        }

    @staticmethod
    def _dataclass_from_mapping(cls_type: Any, raw: Mapping[str, Any]) -> Any:
        if not isinstance(raw, Mapping):
            raw = {}

        allowed = getattr(cls_type, "__dataclass_fields__", {})
        filtered = {key: value for key, value in raw.items() if key in allowed}
        return cls_type(**filtered)

    @staticmethod
    def _screenshot_rules_from_mapping(raw: Mapping[str, Any]) -> ScreenshotRules:
        if not isinstance(raw, Mapping):
            raw = {}

        data = dict(raw)
        if "default_format" in data:
            try:
                data["default_format"] = ScreenshotFormat(str(data["default_format"]).strip().lower())
            except Exception:
                data["default_format"] = ScreenshotFormat.PNG

        allowed = ScreenshotRules.__dataclass_fields__
        filtered = {key: value for key, value in data.items() if key in allowed}
        return ScreenshotRules(**filtered)

    @staticmethod
    def _retry_rules_from_mapping(raw: Mapping[str, Any]) -> RetryRules:
        if not isinstance(raw, Mapping):
            raw = {}

        data = dict(raw)
        if "strategy" in data:
            try:
                data["strategy"] = RetryStrategy(str(data["strategy"]).strip().lower())
            except Exception:
                data["strategy"] = RetryStrategy.EXPONENTIAL

        allowed = RetryRules.__dataclass_fields__
        filtered = {key: value for key, value in data.items() if key in allowed}
        return RetryRules(**filtered)

    def _metadata(self, context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        base = {
            "mode": self.mode.value,
            "safe_mode_enabled": self.safe_mode.enabled,
        }

        if isinstance(context, Mapping):
            if self.audit_rules.include_user_workspace:
                base["user_id"] = context.get("user_id")
                base["workspace_id"] = context.get("workspace_id")
            if self.audit_rules.include_request_id:
                base["request_id"] = context.get("request_id")
                base["task_id"] = context.get("task_id")

        return base

    def _safe_context_for_event(
        self,
        context: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        if not isinstance(context, Mapping):
            return {}

        safe = {}

        for key in ("user_id", "workspace_id", "request_id", "task_id", "source_agent"):
            if key in context:
                safe[key] = context.get(key)

        return safe

    # ------------------------------------------------------------------
    # Developer Diagnostics
    # ------------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        """
        Lightweight import/config health check.

        Useful for registry, loader, dashboard, or FastAPI startup checks.
        """
        try:
            self.validate_config()
            return self._safe_result(
                message="VerificationConfig health check passed.",
                data={
                    "healthy": True,
                    "module": MODULE_NAME,
                    "file": FILE_NAME,
                    "class": CLASS_NAME,
                    "version": self.config_version,
                    "mode": self.mode.value,
                    "target_overrides": sorted(self.target_overrides.keys()),
                },
            )
        except Exception as exc:
            logger.exception("VerificationConfig health check failed.")
            return self._error_result(
                message="VerificationConfig health check failed.",
                code="CONFIG_HEALTH_CHECK_FAILED",
                details={"exception": str(exc)},
            )

    def describe(self) -> Dict[str, Any]:
        """
        Return registry-friendly description of this config module.
        """
        return self._safe_result(
            message="VerificationConfig description generated.",
            data={
                "agent_module": MODULE_NAME,
                "file": FILE_NAME,
                "class": CLASS_NAME,
                "purpose": "Verification thresholds, screenshot rules, retry settings, safe mode.",
                "version": self.config_version,
                "compatible_with": [
                    "BaseAgent",
                    "Agent Registry",
                    "Agent Loader",
                    "Agent Router",
                    "Master Agent",
                    "Security Agent",
                    "Memory Agent",
                    "Dashboard/API",
                ],
                "public_methods": [
                    "safe_defaults",
                    "standard_defaults",
                    "strict_defaults",
                    "debug_defaults",
                    "from_dict",
                    "from_json_file",
                    "get_config",
                    "get_threshold",
                    "get_target_override",
                    "get_effective_config_for_target",
                    "get_retry_delay",
                    "should_retry",
                    "build_screenshot_filename",
                    "is_screenshot_redaction_required",
                    "snapshot",
                    "to_dict",
                    "to_json",
                    "save_json_file",
                    "health_check",
                    "describe",
                ],
                "compatibility_hooks": [
                    "_validate_task_context",
                    "_requires_security_check",
                    "_request_security_approval",
                    "_prepare_verification_payload",
                    "_prepare_memory_payload",
                    "_emit_agent_event",
                    "_log_audit_event",
                    "_safe_result",
                    "_error_result",
                ],
            },
        )


# ---------------------------------------------------------------------------
# Module-level safe default instance/helper
# ---------------------------------------------------------------------------

def get_default_verification_config() -> VerificationConfig:
    """
    Return a fresh safe default VerificationConfig.

    A fresh instance avoids cross-user/workspace mutable state.
    """
    return VerificationConfig.safe_defaults()


def build_config_from_env() -> VerificationConfig:
    """
    Build config using environment-aware defaults.

    Supported environment variables:
        WILLIAM_VERIFICATION_SAFE_MODE_ENABLED
        WILLIAM_VERIFICATION_REQUIRE_USER_ID
        WILLIAM_VERIFICATION_REQUIRE_WORKSPACE_ID
        WILLIAM_VERIFICATION_TIMEOUT_SECONDS

        WILLIAM_VERIFICATION_SCREENSHOT_ENABLED
        WILLIAM_VERIFICATION_SCREENSHOT_FORMAT
        WILLIAM_VERIFICATION_SCREENSHOT_BEFORE_ACTION
        WILLIAM_VERIFICATION_SCREENSHOT_AFTER_ACTION
        WILLIAM_VERIFICATION_SCREENSHOT_ON_ERROR
        WILLIAM_VERIFICATION_SCREENSHOT_ON_RETRY
        WILLIAM_VERIFICATION_SCREENSHOT_JPEG_QUALITY
        WILLIAM_VERIFICATION_SCREENSHOT_MAX_WIDTH
        WILLIAM_VERIFICATION_SCREENSHOT_MAX_HEIGHT
        WILLIAM_VERIFICATION_SCREENSHOT_MAX_BYTES
        WILLIAM_VERIFICATION_SCREENSHOT_STORAGE_SUBDIR
        WILLIAM_VERIFICATION_SCREENSHOT_RETENTION_DAYS

        WILLIAM_VERIFICATION_RETRY_ENABLED
        WILLIAM_VERIFICATION_RETRY_STRATEGY
        WILLIAM_VERIFICATION_RETRY_MAX_ATTEMPTS
        WILLIAM_VERIFICATION_RETRY_BASE_DELAY_SECONDS
        WILLIAM_VERIFICATION_RETRY_MAX_DELAY_SECONDS
        WILLIAM_VERIFICATION_RETRY_JITTER_SECONDS
    """
    mode_raw = os.getenv(f"{ENV_PREFIX}MODE", VerificationMode.SAFE.value)
    return VerificationConfig(mode=mode_raw)


__all__ = [
    "AuditRules",
    "CONFIG_VERSION",
    "CLASS_NAME",
    "DEFAULT_MAX_PROOF_ITEMS",
    "DEFAULT_MAX_RETRY_ATTEMPTS",
    "DEFAULT_MAX_SCREENSHOT_BYTES",
    "DEFAULT_RETRY_BACKOFF_SECONDS",
    "DEFAULT_RETRY_MAX_DELAY_SECONDS",
    "DEFAULT_VERIFICATION_TIMEOUT_SECONDS",
    "FILE_NAME",
    "MODULE_NAME",
    "ProofRules",
    "RetryRules",
    "RetryStrategy",
    "RiskLevel",
    "SafeModeRules",
    "ScreenshotFormat",
    "ScreenshotRules",
    "TargetOverrideConfig",
    "ThresholdConfig",
    "VerificationConfig",
    "VerificationConfigSnapshot",
    "VerificationMode",
    "VerificationTargetType",
    "build_config_from_env",
    "get_default_verification_config",
]