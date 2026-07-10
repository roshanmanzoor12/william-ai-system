"""
agents/code_agent/config.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Code Agent Configuration Layer

Purpose:
    This file defines the production-safe configuration system for the Code Agent.

Responsibilities:
    - Code Agent safe mode configuration
    - Backup rules before file/code/project changes
    - Terminal command permission settings
    - Deployment permission settings
    - Git operation permission settings
    - SaaS user/workspace isolation validation
    - Security Agent approval policy helpers
    - Verification Agent payload preparation
    - Memory Agent payload preparation
    - Dashboard/API/Registry/Master Agent compatible structured results

Architecture Notes:
    - This file is intentionally import-safe.
    - It does not execute terminal, git, deployment, browser, financial, messaging,
      call, or destructive actions.
    - It provides policy/configuration only.
    - Every user-specific operation must include user_id and workspace_id.
    - Sensitive actions are routed through Security Agent approval helpers.
    - Completed configuration decisions can be sent to Verification Agent.
    - Useful configuration context can be stored by Memory Agent.
    - Events and audit payloads are structured for dashboard/API usage.

Compatibility:
    - BaseAgent compatible through shared hook method names.
    - Agent Registry compatible through get_registry_metadata().
    - Agent Loader compatible through safe construction and no hard dependency imports.
    - Agent Router / Master Agent compatible through structured dict responses.
"""

from __future__ import annotations

import copy
import fnmatch
import logging
import os
import platform
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Optional imports / fallback stubs
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early build stages
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps config.py import-safe while the full William/Jarvis
        architecture is still being generated.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early build stages
    class SecurityAgent:  # type: ignore
        """
        Fallback SecurityAgent stub.

        Real Security Agent should replace this when available.
        """

        def request_approval(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "SecurityAgent is not available. Approval cannot be granted automatically.",
                "data": {
                    "approval_status": "unavailable",
                    "requires_manual_review": True,
                    "payload": dict(payload),
                },
                "error": "SECURITY_AGENT_UNAVAILABLE",
                "metadata": {
                    "source": "CodeConfig.fallback.SecurityAgent",
                    "timestamp": _utc_now_iso(),
                },
            }


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONFIG_VERSION = "1.0.0"
AGENT_MODULE = "code_agent"
AGENT_NAME = "Code Agent"
CONFIG_CLASS_NAME = "CodeConfig"

DEFAULT_MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024
DEFAULT_MAX_BACKUP_SIZE_BYTES = 50 * 1024 * 1024
DEFAULT_TERMINAL_TIMEOUT_SECONDS = 120
DEFAULT_DEPLOY_TIMEOUT_SECONDS = 900
DEFAULT_GIT_TIMEOUT_SECONDS = 180

RESULT_SUCCESS_KEY = "success"
RESULT_MESSAGE_KEY = "message"
RESULT_DATA_KEY = "data"
RESULT_ERROR_KEY = "error"
RESULT_METADATA_KEY = "metadata"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class CodeOperation(str, Enum):
    """
    Supported Code Agent operation types.

    These values are used by Code Agent, Master Agent, dashboard/API,
    audit logs, Security Agent, and Verification Agent payloads.
    """

    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    EDIT_FILE = "edit_file"
    DELETE_FILE = "delete_file"
    CREATE_FILE = "create_file"
    CREATE_DIRECTORY = "create_directory"
    DELETE_DIRECTORY = "delete_directory"
    ANALYZE_PROJECT = "analyze_project"
    GENERATE_CODE = "generate_code"
    REFACTOR_CODE = "refactor_code"
    RUN_TESTS = "run_tests"
    RUN_TERMINAL = "run_terminal"
    INSTALL_DEPENDENCY = "install_dependency"
    UPDATE_DEPENDENCY = "update_dependency"
    GIT_STATUS = "git_status"
    GIT_DIFF = "git_diff"
    GIT_ADD = "git_add"
    GIT_COMMIT = "git_commit"
    GIT_PUSH = "git_push"
    GIT_PULL = "git_pull"
    GIT_BRANCH = "git_branch"
    GIT_CHECKOUT = "git_checkout"
    DEPLOY_PREVIEW = "deploy_preview"
    DEPLOY_STAGING = "deploy_staging"
    DEPLOY_PRODUCTION = "deploy_production"
    BACKUP_CREATE = "backup_create"
    BACKUP_RESTORE = "backup_restore"
    CONFIG_READ = "config_read"
    CONFIG_UPDATE = "config_update"


class PermissionLevel(str, Enum):
    """
    Permission level used for sensitive Code Agent operations.
    """

    DENY = "deny"
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    REQUIRE_SECURITY_AGENT = "require_security_agent"
    REQUIRE_OWNER = "require_owner"
    REQUIRE_ADMIN = "require_admin"


class SafetyMode(str, Enum):
    """
    Code Agent safety mode.

    STRICT:
        Maximum protection. Destructive actions and external effects require
        security approval or are denied.

    BALANCED:
        Practical development mode. Safe reads/analyzes allowed. Mutations
        require backups and sometimes approvals.

    PERMISSIVE:
        Useful for trusted local/dev workspaces only. Still blocks highly
        dangerous commands by default.

    READ_ONLY:
        No writes, terminal mutations, git mutations, deploys, or deletes.
    """

    STRICT = "strict"
    BALANCED = "balanced"
    PERMISSIVE = "permissive"
    READ_ONLY = "read_only"


class EnvironmentType(str, Enum):
    """
    Deployment/runtime environment type.
    """

    LOCAL = "local"
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TEST = "test"


class RiskLevel(str, Enum):
    """
    Risk level used for policy decisions and audit records.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class SaaSContextPolicy:
    """
    Defines user/workspace isolation requirements for Code Agent operations.
    """

    require_user_id: bool = True
    require_workspace_id: bool = True
    allow_system_workspace: bool = False
    allow_cross_workspace_access: bool = False
    allow_cross_user_access: bool = False
    require_role_for_sensitive_actions: bool = True
    allowed_sensitive_roles: Tuple[str, ...] = ("owner", "admin", "developer")
    allowed_read_roles: Tuple[str, ...] = ("owner", "admin", "developer", "viewer")
    allowed_write_roles: Tuple[str, ...] = ("owner", "admin", "developer")
    allowed_deploy_roles: Tuple[str, ...] = ("owner", "admin")
    allowed_git_roles: Tuple[str, ...] = ("owner", "admin", "developer")


@dataclass
class BackupPolicy:
    """
    Backup rules before Code Agent mutates files, directories, git state,
    dependencies, or deployment artifacts.
    """

    enabled: bool = True
    require_backup_before_write: bool = True
    require_backup_before_edit: bool = True
    require_backup_before_delete: bool = True
    require_backup_before_dependency_change: bool = True
    require_backup_before_git_mutation: bool = True
    require_backup_before_deploy: bool = True
    backup_root_dir: str = ".william_backups"
    include_timestamp: bool = True
    include_user_workspace_scope: bool = True
    max_backup_size_bytes: int = DEFAULT_MAX_BACKUP_SIZE_BYTES
    max_backup_files_per_workspace: int = 100
    backup_file_suffix: str = ".bak"
    backup_manifest_name: str = "backup_manifest.json"
    preserve_permissions_metadata: bool = True
    compress_large_backups: bool = False
    large_backup_threshold_bytes: int = 10 * 1024 * 1024


@dataclass
class TerminalPolicy:
    """
    Terminal execution policy.

    This class does not run commands. It only defines what commands are safe,
    denied, or require Security Agent approval.
    """

    enabled: bool = True
    default_permission: PermissionLevel = PermissionLevel.REQUIRE_APPROVAL
    timeout_seconds: int = DEFAULT_TERMINAL_TIMEOUT_SECONDS
    allow_shell: bool = False
    allow_interactive: bool = False
    allow_sudo: bool = False
    allow_network_commands: bool = False
    allow_package_install: bool = False
    allow_process_kill: bool = False
    allow_env_printing: bool = False
    max_output_chars: int = 100_000
    safe_commands: Tuple[str, ...] = (
        "python --version",
        "python3 --version",
        "pip --version",
        "pip3 --version",
        "node --version",
        "npm --version",
        "yarn --version",
        "pnpm --version",
        "git status",
        "git diff",
        "git log",
        "git branch",
        "pytest",
        "python -m pytest",
        "npm test",
        "npm run test",
        "yarn test",
        "pnpm test",
        "ls",
        "dir",
        "pwd",
    )
    allowed_executable_prefixes: Tuple[str, ...] = (
        "python",
        "python3",
        "pip",
        "pip3",
        "node",
        "npm",
        "yarn",
        "pnpm",
        "git",
        "pytest",
        "ls",
        "dir",
        "pwd",
    )
    denied_patterns: Tuple[str, ...] = (
        "rm -rf *",
        "rm -rf /",
        "rm -rf /*",
        "del /f /s /q *",
        "format *",
        "mkfs*",
        "dd if=*",
        ":(){ :|:& };:",
        "shutdown*",
        "reboot*",
        "poweroff*",
        "halt*",
        "sudo *",
        "su *",
        "chmod 777 *",
        "chown -R *",
        "curl * | sh",
        "wget * | sh",
        "curl * | bash",
        "wget * | bash",
        "eval *",
        "exec *",
        "kill -9 *",
        "taskkill /f *",
        "net user *",
        "net localgroup *",
        "reg delete *",
        "bcdedit *",
    )
    approval_required_patterns: Tuple[str, ...] = (
        "pip install *",
        "pip3 install *",
        "python -m pip install *",
        "npm install *",
        "npm i *",
        "yarn add *",
        "pnpm add *",
        "git reset *",
        "git clean *",
        "git checkout *",
        "git merge *",
        "git rebase *",
        "git push *",
        "docker *",
        "kubectl *",
        "terraform *",
        "ansible *",
        "ssh *",
        "scp *",
        "rsync *",
        "curl *",
        "wget *",
    )


@dataclass
class GitPolicy:
    """
    Git operation policy for Code Agent.
    """

    enabled: bool = True
    allow_status: bool = True
    allow_diff: bool = True
    allow_log: bool = True
    allow_add: bool = True
    allow_commit: bool = True
    allow_branch: bool = True
    allow_checkout: bool = False
    allow_pull: bool = False
    allow_push: bool = False
    allow_reset: bool = False
    allow_clean: bool = False
    allow_rebase: bool = False
    require_approval_for_commit: bool = False
    require_approval_for_push: bool = True
    require_approval_for_pull: bool = True
    require_approval_for_checkout: bool = True
    require_approval_for_branch_delete: bool = True
    require_approval_for_remote_change: bool = True
    require_backup_before_mutation: bool = True
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS
    protected_branches: Tuple[str, ...] = ("main", "master", "production", "prod", "release")
    denied_git_args: Tuple[str, ...] = (
        "--force",
        "--force-with-lease",
        "reset --hard",
        "clean -fd",
        "clean -fdx",
        "push --delete",
        "branch -D",
        "remote remove",
        "remote set-url",
    )


@dataclass
class DeployPolicy:
    """
    Deployment policy.

    Deployments should always pass through Security Agent in production.
    """

    enabled: bool = True
    allow_preview_deploy: bool = True
    allow_staging_deploy: bool = True
    allow_production_deploy: bool = False
    require_approval_for_preview: bool = False
    require_approval_for_staging: bool = True
    require_approval_for_production: bool = True
    require_tests_before_deploy: bool = True
    require_security_scan_before_deploy: bool = True
    require_backup_before_deploy: bool = True
    require_git_clean_state_before_deploy: bool = True
    timeout_seconds: int = DEFAULT_DEPLOY_TIMEOUT_SECONDS
    allowed_deploy_targets: Tuple[str, ...] = ("preview", "staging")
    denied_deploy_targets: Tuple[str, ...] = ("production",)
    allowed_providers: Tuple[str, ...] = (
        "vercel",
        "netlify",
        "render",
        "railway",
        "fly",
        "docker",
        "custom",
    )


@dataclass
class FileSafetyPolicy:
    """
    File and directory safety policy.
    """

    allow_read: bool = True
    allow_write: bool = True
    allow_edit: bool = True
    allow_delete: bool = False
    allow_create_directory: bool = True
    allow_delete_directory: bool = False
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES
    require_approval_for_delete: bool = True
    require_approval_for_overwrite: bool = False
    require_approval_for_binary_files: bool = True
    require_backup_before_mutation: bool = True
    denied_paths: Tuple[str, ...] = (
        ".env",
        ".env.*",
        "**/.env",
        "**/.env.*",
        "**/id_rsa",
        "**/id_dsa",
        "**/id_ed25519",
        "**/*.pem",
        "**/*.key",
        "**/*.p12",
        "**/*.pfx",
        "**/secrets.*",
        "**/credentials.*",
        "**/service-account*.json",
        "/etc/*",
        "/var/*",
        "/usr/*",
        "/bin/*",
        "/sbin/*",
        "C:\\Windows\\*",
        "C:\\Program Files\\*",
        "C:\\Program Files (x86)\\*",
    )
    approval_required_paths: Tuple[str, ...] = (
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        ".github/workflows/*",
        "nginx.conf",
        "apache.conf",
        "Caddyfile",
    )
    generated_file_header: str = (
        "# Generated/managed by William Jarvis Code Agent. "
        "Review before production use."
    )


@dataclass
class SecurityPolicy:
    """
    Security Agent routing and approval rules.
    """

    enabled: bool = True
    require_security_agent_for_sensitive_actions: bool = True
    require_security_agent_for_destructive_actions: bool = True
    require_security_agent_for_external_actions: bool = True
    require_security_agent_for_secret_paths: bool = True
    require_security_agent_for_production: bool = True
    approval_ttl_seconds: int = 900
    allow_fallback_manual_review: bool = True
    auto_deny_when_security_unavailable: bool = True
    sensitive_operations: Tuple[str, ...] = (
        CodeOperation.DELETE_FILE.value,
        CodeOperation.DELETE_DIRECTORY.value,
        CodeOperation.RUN_TERMINAL.value,
        CodeOperation.INSTALL_DEPENDENCY.value,
        CodeOperation.UPDATE_DEPENDENCY.value,
        CodeOperation.GIT_PUSH.value,
        CodeOperation.GIT_PULL.value,
        CodeOperation.GIT_CHECKOUT.value,
        CodeOperation.DEPLOY_STAGING.value,
        CodeOperation.DEPLOY_PRODUCTION.value,
        CodeOperation.BACKUP_RESTORE.value,
        CodeOperation.CONFIG_UPDATE.value,
    )
    destructive_operations: Tuple[str, ...] = (
        CodeOperation.DELETE_FILE.value,
        CodeOperation.DELETE_DIRECTORY.value,
        CodeOperation.GIT_PUSH.value,
        CodeOperation.BACKUP_RESTORE.value,
        CodeOperation.DEPLOY_PRODUCTION.value,
    )


@dataclass
class AuditPolicy:
    """
    Audit/event settings for dashboard and compliance.
    """

    enabled: bool = True
    log_reads: bool = False
    log_writes: bool = True
    log_terminal_requests: bool = True
    log_git_requests: bool = True
    log_deploy_requests: bool = True
    log_security_requests: bool = True
    log_config_reads: bool = True
    log_config_updates: bool = True
    redact_sensitive_values: bool = True
    max_event_payload_chars: int = 20_000


@dataclass
class VerificationPolicy:
    """
    Verification Agent payload settings.
    """

    enabled: bool = True
    prepare_payload_for_completed_actions: bool = True
    include_policy_snapshot: bool = True
    include_security_decision: bool = True
    include_backup_requirement: bool = True
    include_risk_level: bool = True


@dataclass
class MemoryPolicy:
    """
    Memory Agent compatibility settings.

    This does not store memory directly. It prepares safe payloads.
    """

    enabled: bool = True
    prepare_memory_payload: bool = True
    store_user_preferences: bool = True
    store_workspace_code_preferences: bool = True
    store_denied_action_patterns: bool = False
    store_sensitive_paths: bool = False
    redact_paths_when_needed: bool = True


@dataclass
class CodeConfigSnapshot:
    """
    Serializable snapshot of current Code Agent configuration.
    """

    config_version: str
    safety_mode: str
    environment: str
    saas_context_policy: Dict[str, Any]
    backup_policy: Dict[str, Any]
    terminal_policy: Dict[str, Any]
    git_policy: Dict[str, Any]
    deploy_policy: Dict[str, Any]
    file_safety_policy: Dict[str, Any]
    security_policy: Dict[str, Any]
    audit_policy: Dict[str, Any]
    verification_policy: Dict[str, Any]
    memory_policy: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _safe_lower(value: Any) -> str:
    """Safely convert a value to lowercase stripped string."""
    return str(value or "").strip().lower()


def _normalize_path(path: Union[str, os.PathLike[str], None]) -> str:
    """
    Normalize a path for policy matching without requiring the path to exist.
    """
    if path is None:
        return ""

    raw = str(path).strip()
    if not raw:
        return ""

    normalized = raw.replace("\\", "/")
    normalized = re.sub(r"/+", "/", normalized)
    return normalized.strip()


def _normalize_command(command: Union[str, Sequence[str], None]) -> str:
    """
    Normalize command input into a single string for policy checks.
    """
    if command is None:
        return ""

    if isinstance(command, str):
        command_text = command
    else:
        command_text = " ".join(str(part) for part in command)

    command_text = command_text.strip()
    command_text = re.sub(r"\s+", " ", command_text)
    return command_text


def _enum_value(value: Any) -> Any:
    """Convert Enum values to their raw values for serialization."""
    if isinstance(value, Enum):
        return value.value
    return value


def _to_plain_dict(value: Any) -> Any:
    """
    Convert dataclasses, enums, tuples, and nested structures into JSON-style
    serializable dict/list/scalar objects.
    """
    if hasattr(value, "__dataclass_fields__"):
        return {k: _to_plain_dict(v) for k, v in asdict(value).items()}

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, Mapping):
        return {str(k): _to_plain_dict(v) for k, v in value.items()}

    if isinstance(value, tuple):
        return [_to_plain_dict(v) for v in value]

    if isinstance(value, list):
        return [_to_plain_dict(v) for v in value]

    if isinstance(value, set):
        return sorted(_to_plain_dict(v) for v in value)

    return value


def _matches_any_pattern(value: str, patterns: Iterable[str]) -> bool:
    """
    Match a string against shell-style patterns and simple substring patterns.
    """
    checked_value = value.strip()
    checked_lower = checked_value.lower()

    for pattern in patterns:
        pattern_text = str(pattern or "").strip()
        if not pattern_text:
            continue

        pattern_lower = pattern_text.lower()

        if fnmatch.fnmatch(checked_lower, pattern_lower):
            return True

        if "*" not in pattern_lower and pattern_lower in checked_lower:
            return True

    return False


def _redact_sensitive_text(value: Any) -> Any:
    """
    Redact obvious sensitive values from audit/event payloads.
    """
    if isinstance(value, Mapping):
        redacted: Dict[str, Any] = {}
        sensitive_keys = {
            "token",
            "secret",
            "password",
            "api_key",
            "apikey",
            "private_key",
            "credential",
            "credentials",
            "authorization",
            "auth",
        }

        for key, item in value.items():
            key_text = str(key)
            key_lower = key_text.lower()
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                redacted[key_text] = "[REDACTED]"
            else:
                redacted[key_text] = _redact_sensitive_text(item)
        return redacted

    if isinstance(value, list):
        return [_redact_sensitive_text(item) for item in value]

    if isinstance(value, tuple):
        return tuple(_redact_sensitive_text(item) for item in value)

    if isinstance(value, str):
        patterns = [
            r"(?i)(token|secret|password|api[_-]?key)\s*[:=]\s*['\"]?[^'\"\s]+",
            r"(?i)(authorization:\s*bearer\s+)[a-z0-9._\-]+",
        ]
        output = value
        for pattern in patterns:
            output = re.sub(pattern, lambda m: m.group(0).split("=")[0] + "=[REDACTED]" if "=" in m.group(0) else "[REDACTED]", output)
        return output

    return value


def _truncate_payload(payload: Any, max_chars: int) -> Any:
    """
    Truncate large payload string representations for audit safety.
    """
    text = repr(payload)
    if len(text) <= max_chars:
        return payload

    return {
        "truncated": True,
        "max_chars": max_chars,
        "preview": text[:max_chars],
    }


# ---------------------------------------------------------------------------
# Main CodeConfig class
# ---------------------------------------------------------------------------

class CodeConfig(BaseAgent):
    """
    Production-ready Code Agent configuration class.

    This class centralizes safety decisions for the Code Agent. It is not a
    command runner, deployment runner, git executor, or file editor. Other
    Code Agent components should call this class before performing sensitive
    actions.

    Key public methods:
        - validate_operation()
        - get_operation_policy()
        - should_backup_before_operation()
        - is_terminal_command_allowed()
        - is_git_operation_allowed()
        - is_deploy_allowed()
        - is_path_allowed()
        - create_snapshot()
        - get_registry_metadata()

    Required architecture hooks:
        - _validate_task_context()
        - _requires_security_check()
        - _request_security_approval()
        - _prepare_verification_payload()
        - _prepare_memory_payload()
        - _emit_agent_event()
        - _log_audit_event()
        - _safe_result()
        - _error_result()
    """

    def __init__(
        self,
        safety_mode: Union[SafetyMode, str] = SafetyMode.STRICT,
        environment: Union[EnvironmentType, str] = EnvironmentType.DEVELOPMENT,
        saas_context_policy: Optional[SaaSContextPolicy] = None,
        backup_policy: Optional[BackupPolicy] = None,
        terminal_policy: Optional[TerminalPolicy] = None,
        git_policy: Optional[GitPolicy] = None,
        deploy_policy: Optional[DeployPolicy] = None,
        file_safety_policy: Optional[FileSafetyPolicy] = None,
        security_policy: Optional[SecurityPolicy] = None,
        audit_policy: Optional[AuditPolicy] = None,
        verification_policy: Optional[VerificationPolicy] = None,
        memory_policy: Optional[MemoryPolicy] = None,
        security_agent: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(agent_name=AGENT_NAME)

        self.config_id = str(uuid.uuid4())
        self.config_version = CONFIG_VERSION
        self.safety_mode = self._coerce_safety_mode(safety_mode)
        self.environment = self._coerce_environment(environment)

        self.saas_context_policy = saas_context_policy or SaaSContextPolicy()
        self.backup_policy = backup_policy or BackupPolicy()
        self.terminal_policy = terminal_policy or TerminalPolicy()
        self.git_policy = git_policy or GitPolicy()
        self.deploy_policy = deploy_policy or DeployPolicy()
        self.file_safety_policy = file_safety_policy or FileSafetyPolicy()
        self.security_policy = security_policy or SecurityPolicy()
        self.audit_policy = audit_policy or AuditPolicy()
        self.verification_policy = verification_policy or VerificationPolicy()
        self.memory_policy = memory_policy or MemoryPolicy()

        self.security_agent = security_agent or SecurityAgent()

        self.metadata: Dict[str, Any] = {
            "agent_module": AGENT_MODULE,
            "agent_name": AGENT_NAME,
            "config_class": CONFIG_CLASS_NAME,
            "created_at": _utc_now_iso(),
            "host_platform": platform.platform(),
            "python_version": platform.python_version(),
        }
        if metadata:
            self.metadata.update(dict(metadata))

        self._apply_safety_mode_defaults()

    # ------------------------------------------------------------------
    # Coercion helpers
    # ------------------------------------------------------------------

    def _coerce_safety_mode(self, value: Union[SafetyMode, str]) -> SafetyMode:
        """Coerce input into SafetyMode."""
        if isinstance(value, SafetyMode):
            return value

        normalized = _safe_lower(value)
        for mode in SafetyMode:
            if mode.value == normalized:
                return mode

        logger.warning("Unknown safety mode %r. Falling back to STRICT.", value)
        return SafetyMode.STRICT

    def _coerce_environment(self, value: Union[EnvironmentType, str]) -> EnvironmentType:
        """Coerce input into EnvironmentType."""
        if isinstance(value, EnvironmentType):
            return value

        normalized = _safe_lower(value)
        for env in EnvironmentType:
            if env.value == normalized:
                return env

        logger.warning("Unknown environment %r. Falling back to DEVELOPMENT.", value)
        return EnvironmentType.DEVELOPMENT

    def _coerce_operation(self, value: Union[CodeOperation, str]) -> Optional[CodeOperation]:
        """Coerce input into CodeOperation if possible."""
        if isinstance(value, CodeOperation):
            return value

        normalized = _safe_lower(value)
        for operation in CodeOperation:
            if operation.value == normalized:
                return operation

        return None

    # ------------------------------------------------------------------
    # Safety mode defaults
    # ------------------------------------------------------------------

    def _apply_safety_mode_defaults(self) -> None:
        """
        Apply safety defaults based on selected mode and environment.

        Existing explicit dataclass values remain mostly intact, but highly
        dangerous capabilities are constrained in strict/read-only/production.
        """

        if self.safety_mode == SafetyMode.READ_ONLY:
            self.file_safety_policy.allow_write = False
            self.file_safety_policy.allow_edit = False
            self.file_safety_policy.allow_delete = False
            self.file_safety_policy.allow_create_directory = False
            self.file_safety_policy.allow_delete_directory = False

            self.terminal_policy.enabled = False

            self.git_policy.allow_add = False
            self.git_policy.allow_commit = False
            self.git_policy.allow_checkout = False
            self.git_policy.allow_pull = False
            self.git_policy.allow_push = False
            self.git_policy.allow_reset = False
            self.git_policy.allow_clean = False
            self.git_policy.allow_rebase = False

            self.deploy_policy.enabled = False

        elif self.safety_mode == SafetyMode.STRICT:
            self.file_safety_policy.allow_delete = False
            self.file_safety_policy.allow_delete_directory = False
            self.file_safety_policy.require_approval_for_overwrite = True
            self.file_safety_policy.require_backup_before_mutation = True

            self.terminal_policy.default_permission = PermissionLevel.REQUIRE_SECURITY_AGENT
            self.terminal_policy.allow_shell = False
            self.terminal_policy.allow_sudo = False
            self.terminal_policy.allow_network_commands = False
            self.terminal_policy.allow_package_install = False

            self.git_policy.allow_push = False
            self.git_policy.allow_pull = False
            self.git_policy.allow_checkout = False
            self.git_policy.require_approval_for_commit = True

            self.deploy_policy.allow_production_deploy = False
            self.deploy_policy.require_approval_for_staging = True
            self.deploy_policy.require_approval_for_production = True

        elif self.safety_mode == SafetyMode.BALANCED:
            self.file_safety_policy.allow_delete = False
            self.file_safety_policy.require_backup_before_mutation = True
            self.terminal_policy.default_permission = PermissionLevel.REQUIRE_APPROVAL
            self.git_policy.require_approval_for_push = True
            self.deploy_policy.allow_production_deploy = False

        elif self.safety_mode == SafetyMode.PERMISSIVE:
            self.terminal_policy.default_permission = PermissionLevel.ALLOW
            self.git_policy.allow_checkout = True
            self.git_policy.allow_pull = True
            self.deploy_policy.allow_preview_deploy = True
            self.deploy_policy.allow_staging_deploy = True

        if self.environment == EnvironmentType.PRODUCTION:
            self.deploy_policy.allow_production_deploy = False
            self.deploy_policy.require_approval_for_production = True
            self.security_policy.require_security_agent_for_production = True
            self.file_safety_policy.require_approval_for_overwrite = True
            self.git_policy.require_approval_for_push = True
            self.git_policy.require_approval_for_pull = True
            self.terminal_policy.allow_shell = False
            self.terminal_policy.allow_sudo = False

    # ------------------------------------------------------------------
    # Structured result helpers
    # ------------------------------------------------------------------

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return a standard success result for Master Agent, Router, API, and dashboard.
        """
        return {
            RESULT_SUCCESS_KEY: True,
            RESULT_MESSAGE_KEY: message,
            RESULT_DATA_KEY: dict(data or {}),
            RESULT_ERROR_KEY: None,
            RESULT_METADATA_KEY: self._build_metadata(metadata),
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception, Mapping[str, Any]]] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return a standard error result for Master Agent, Router, API, and dashboard.
        """
        if isinstance(error, Exception):
            error_value: Any = {
                "type": error.__class__.__name__,
                "detail": str(error),
            }
        elif isinstance(error, Mapping):
            error_value = dict(error)
        elif error is None:
            error_value = "UNKNOWN_ERROR"
        else:
            error_value = str(error)

        return {
            RESULT_SUCCESS_KEY: False,
            RESULT_MESSAGE_KEY: message,
            RESULT_DATA_KEY: dict(data or {}),
            RESULT_ERROR_KEY: error_value,
            RESULT_METADATA_KEY: self._build_metadata(metadata),
        }

    def _build_metadata(self, metadata: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Build common metadata for structured results."""
        output = {
            "config_id": self.config_id,
            "config_version": self.config_version,
            "agent_module": AGENT_MODULE,
            "agent_name": AGENT_NAME,
            "safety_mode": self.safety_mode.value,
            "environment": self.environment.value,
            "timestamp": _utc_now_iso(),
        }
        if metadata:
            output.update(dict(metadata))
        return output

    # ------------------------------------------------------------------
    # SaaS context validation
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        task_context: Optional[Mapping[str, Any]],
        operation: Optional[Union[CodeOperation, str]] = None,
    ) -> Dict[str, Any]:
        """
        Validate user_id/workspace_id and role for SaaS isolation.

        Required by William/Jarvis architecture.

        Args:
            task_context:
                Dict-like context from Master Agent / Agent Router / API.
            operation:
                Optional operation being validated.

        Returns:
            Structured result.
        """
        context = dict(task_context or {})
        operation_enum = self._coerce_operation(operation) if operation else None

        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")
        role = _safe_lower(context.get("role") or context.get("user_role") or "")

        errors: List[str] = []

        if self.saas_context_policy.require_user_id and not user_id:
            errors.append("user_id is required for Code Agent user-specific execution.")

        if self.saas_context_policy.require_workspace_id and not workspace_id:
            errors.append("workspace_id is required for Code Agent workspace-specific execution.")

        if not self.saas_context_policy.allow_system_workspace:
            if _safe_lower(workspace_id) in {"system", "global", "shared", "*"}:
                errors.append("System/global workspace access is not allowed by current SaaS policy.")

        if context.get("target_user_id") and context.get("target_user_id") != user_id:
            if not self.saas_context_policy.allow_cross_user_access:
                errors.append("Cross-user access is denied by Code Agent SaaS isolation policy.")

        if context.get("target_workspace_id") and context.get("target_workspace_id") != workspace_id:
            if not self.saas_context_policy.allow_cross_workspace_access:
                errors.append("Cross-workspace access is denied by Code Agent SaaS isolation policy.")

        if operation_enum:
            role_error = self._validate_role_for_operation(role, operation_enum)
            if role_error:
                errors.append(role_error)

        if errors:
            return self._error_result(
                "Task context validation failed.",
                error="TASK_CONTEXT_INVALID",
                data={
                    "valid": False,
                    "errors": errors,
                    "operation": operation_enum.value if operation_enum else None,
                    "required": {
                        "user_id": self.saas_context_policy.require_user_id,
                        "workspace_id": self.saas_context_policy.require_workspace_id,
                    },
                },
            )

        return self._safe_result(
            "Task context validation passed.",
            data={
                "valid": True,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "role": role or None,
                "operation": operation_enum.value if operation_enum else None,
                "isolation": {
                    "cross_user_access": self.saas_context_policy.allow_cross_user_access,
                    "cross_workspace_access": self.saas_context_policy.allow_cross_workspace_access,
                },
            },
        )

    def _validate_role_for_operation(
        self,
        role: str,
        operation: CodeOperation,
    ) -> Optional[str]:
        """
        Validate role against operation type.
        """
        if not self.saas_context_policy.require_role_for_sensitive_actions:
            return None

        if not role:
            return f"Role is required for operation '{operation.value}'."

        read_ops = {
            CodeOperation.READ_FILE,
            CodeOperation.ANALYZE_PROJECT,
            CodeOperation.GIT_STATUS,
            CodeOperation.GIT_DIFF,
            CodeOperation.CONFIG_READ,
        }

        write_ops = {
            CodeOperation.WRITE_FILE,
            CodeOperation.EDIT_FILE,
            CodeOperation.CREATE_FILE,
            CodeOperation.CREATE_DIRECTORY,
            CodeOperation.GENERATE_CODE,
            CodeOperation.REFACTOR_CODE,
            CodeOperation.CONFIG_UPDATE,
        }

        deploy_ops = {
            CodeOperation.DEPLOY_PREVIEW,
            CodeOperation.DEPLOY_STAGING,
            CodeOperation.DEPLOY_PRODUCTION,
        }

        git_ops = {
            CodeOperation.GIT_ADD,
            CodeOperation.GIT_COMMIT,
            CodeOperation.GIT_PUSH,
            CodeOperation.GIT_PULL,
            CodeOperation.GIT_BRANCH,
            CodeOperation.GIT_CHECKOUT,
        }

        if operation in read_ops and role not in self.saas_context_policy.allowed_read_roles:
            return f"Role '{role}' is not allowed to perform read operation '{operation.value}'."

        if operation in write_ops and role not in self.saas_context_policy.allowed_write_roles:
            return f"Role '{role}' is not allowed to perform write operation '{operation.value}'."

        if operation in deploy_ops and role not in self.saas_context_policy.allowed_deploy_roles:
            return f"Role '{role}' is not allowed to perform deploy operation '{operation.value}'."

        if operation in git_ops and role not in self.saas_context_policy.allowed_git_roles:
            return f"Role '{role}' is not allowed to perform git operation '{operation.value}'."

        if operation.value in self.security_policy.sensitive_operations:
            if role not in self.saas_context_policy.allowed_sensitive_roles:
                return f"Role '{role}' is not allowed to perform sensitive operation '{operation.value}'."

        return None

    # ------------------------------------------------------------------
    # Security approval helpers
    # ------------------------------------------------------------------

    def _requires_security_check(
        self,
        operation: Union[CodeOperation, str],
        task_context: Optional[Mapping[str, Any]] = None,
        target: Optional[str] = None,
        command: Optional[Union[str, Sequence[str]]] = None,
        deploy_target: Optional[str] = None,
        git_args: Optional[str] = None,
    ) -> bool:
        """
        Decide if operation requires Security Agent approval.

        Required by William/Jarvis architecture.
        """
        if not self.security_policy.enabled:
            return False

        operation_enum = self._coerce_operation(operation)
        operation_value = operation_enum.value if operation_enum else str(operation)

        context = dict(task_context or {})

        if self.security_policy.require_security_agent_for_sensitive_actions:
            if operation_value in self.security_policy.sensitive_operations:
                return True

        if self.security_policy.require_security_agent_for_destructive_actions:
            if operation_value in self.security_policy.destructive_operations:
                return True

        if self.security_policy.require_security_agent_for_production:
            if self.environment == EnvironmentType.PRODUCTION:
                if operation_value not in {
                    CodeOperation.READ_FILE.value,
                    CodeOperation.ANALYZE_PROJECT.value,
                    CodeOperation.GIT_STATUS.value,
                    CodeOperation.GIT_DIFF.value,
                    CodeOperation.CONFIG_READ.value,
                }:
                    return True

        if target and self.is_sensitive_path(target):
            return True

        if command:
            command_policy = self.is_terminal_command_allowed(command, task_context=context)
            if command_policy.get("data", {}).get("requires_approval"):
                return True

        if deploy_target and _safe_lower(deploy_target) == "production":
            return True

        if git_args and _matches_any_pattern(git_args, self.git_policy.denied_git_args):
            return True

        return False

    def _request_security_approval(
        self,
        operation: Union[CodeOperation, str],
        task_context: Optional[Mapping[str, Any]] = None,
        details: Optional[Mapping[str, Any]] = None,
        risk_level: Union[RiskLevel, str] = RiskLevel.MEDIUM,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent.

        Required by William/Jarvis architecture.

        This method does not bypass security. If the real Security Agent is
        unavailable and auto_deny_when_security_unavailable is true, approval
        is denied.
        """
        operation_enum = self._coerce_operation(operation)
        operation_value = operation_enum.value if operation_enum else str(operation)
        context = dict(task_context or {})

        validation = self._validate_task_context(context, operation=operation_value)
        if not validation.get("success"):
            return validation

        risk_value = risk_level.value if isinstance(risk_level, RiskLevel) else _safe_lower(risk_level)

        payload = {
            "request_id": str(uuid.uuid4()),
            "request_type": "code_agent_security_approval",
            "agent_module": AGENT_MODULE,
            "agent_name": AGENT_NAME,
            "operation": operation_value,
            "risk_level": risk_value,
            "task_context": {
                "user_id": context.get("user_id"),
                "workspace_id": context.get("workspace_id"),
                "role": context.get("role") or context.get("user_role"),
                "task_id": context.get("task_id"),
                "session_id": context.get("session_id"),
            },
            "details": _redact_sensitive_text(dict(details or {})),
            "policy": {
                "safety_mode": self.safety_mode.value,
                "environment": self.environment.value,
                "approval_ttl_seconds": self.security_policy.approval_ttl_seconds,
            },
            "timestamp": _utc_now_iso(),
        }

        self._log_audit_event(
            event_type="security_approval_requested",
            task_context=context,
            payload=payload,
        )

        try:
            if hasattr(self.security_agent, "request_approval"):
                response = self.security_agent.request_approval(payload)
            elif hasattr(self.security_agent, "approve_action"):
                response = self.security_agent.approve_action(payload)
            else:
                response = {
                    "success": False,
                    "message": "Security Agent does not expose an approval method.",
                    "data": {
                        "approval_status": "unavailable",
                        "requires_manual_review": True,
                    },
                    "error": "SECURITY_APPROVAL_METHOD_MISSING",
                    "metadata": {
                        "timestamp": _utc_now_iso(),
                    },
                }

            if not isinstance(response, Mapping):
                return self._error_result(
                    "Security Agent returned an invalid approval response.",
                    error="SECURITY_RESPONSE_INVALID",
                    data={"raw_response_type": type(response).__name__},
                )

            return dict(response)

        except Exception as exc:
            logger.exception("Security approval request failed.")

            if self.security_policy.auto_deny_when_security_unavailable:
                return self._error_result(
                    "Security approval failed and action is denied by policy.",
                    error=exc,
                    data={
                        "approval_status": "denied",
                        "requires_manual_review": self.security_policy.allow_fallback_manual_review,
                        "operation": operation_value,
                    },
                )

            return self._error_result(
                "Security approval failed.",
                error=exc,
                data={
                    "approval_status": "failed",
                    "requires_manual_review": True,
                    "operation": operation_value,
                },
            )

    # ------------------------------------------------------------------
    # Policy checks
    # ------------------------------------------------------------------

    def validate_operation(
        self,
        operation: Union[CodeOperation, str],
        task_context: Optional[Mapping[str, Any]] = None,
        target_path: Optional[str] = None,
        command: Optional[Union[str, Sequence[str]]] = None,
        deploy_target: Optional[str] = None,
        git_args: Optional[str] = None,
        request_security: bool = False,
    ) -> Dict[str, Any]:
        """
        Validate a Code Agent operation before execution.

        This is the main method other Code Agent files should call.
        """
        operation_enum = self._coerce_operation(operation)
        if not operation_enum:
            return self._error_result(
                "Unsupported Code Agent operation.",
                error="UNSUPPORTED_OPERATION",
                data={"operation": str(operation)},
            )

        context_validation = self._validate_task_context(task_context or {}, operation_enum)
        if not context_validation.get("success"):
            return context_validation

        policy = self.get_operation_policy(
            operation_enum,
            task_context=task_context,
            target_path=target_path,
            command=command,
            deploy_target=deploy_target,
            git_args=git_args,
        )

        if not policy.get("success"):
            return policy

        policy_data = policy.get("data", {})
        allowed = bool(policy_data.get("allowed"))
        requires_security = bool(policy_data.get("requires_security_check"))

        if not allowed:
            self._log_audit_event(
                event_type="operation_denied",
                task_context=task_context,
                payload={
                    "operation": operation_enum.value,
                    "reason": policy_data.get("reason"),
                    "target_path": target_path,
                    "deploy_target": deploy_target,
                },
            )
            return self._error_result(
                "Operation is denied by Code Agent configuration.",
                error="OPERATION_DENIED_BY_POLICY",
                data=policy_data,
            )

        if requires_security and request_security:
            approval = self._request_security_approval(
                operation=operation_enum,
                task_context=task_context,
                details={
                    "target_path": target_path,
                    "command": _normalize_command(command),
                    "deploy_target": deploy_target,
                    "git_args": git_args,
                    "policy": policy_data,
                },
                risk_level=policy_data.get("risk_level", RiskLevel.MEDIUM.value),
            )

            policy_data["security_approval"] = approval

            if not approval.get("success"):
                return self._error_result(
                    "Operation requires Security Agent approval and approval was not granted.",
                    error="SECURITY_APPROVAL_REQUIRED",
                    data=policy_data,
                )

        self._emit_agent_event(
            event_type="operation_validated",
            task_context=task_context,
            payload={
                "operation": operation_enum.value,
                "policy": policy_data,
            },
        )

        return self._safe_result(
            "Operation validated successfully.",
            data=policy_data,
        )

    def get_operation_policy(
        self,
        operation: Union[CodeOperation, str],
        task_context: Optional[Mapping[str, Any]] = None,
        target_path: Optional[str] = None,
        command: Optional[Union[str, Sequence[str]]] = None,
        deploy_target: Optional[str] = None,
        git_args: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Return detailed policy decision for a Code Agent operation.
        """
        operation_enum = self._coerce_operation(operation)
        if not operation_enum:
            return self._error_result(
                "Unsupported Code Agent operation.",
                error="UNSUPPORTED_OPERATION",
                data={"operation": str(operation)},
            )

        allowed = True
        reason = "Allowed by current Code Agent policy."
        permission = PermissionLevel.ALLOW
        risk_level = self.get_operation_risk_level(operation_enum).value
        requires_backup = self.should_backup_before_operation(operation_enum).get("data", {}).get("requires_backup", False)

        if self.safety_mode == SafetyMode.READ_ONLY:
            mutation_ops = {
                CodeOperation.WRITE_FILE,
                CodeOperation.EDIT_FILE,
                CodeOperation.DELETE_FILE,
                CodeOperation.CREATE_FILE,
                CodeOperation.CREATE_DIRECTORY,
                CodeOperation.DELETE_DIRECTORY,
                CodeOperation.RUN_TERMINAL,
                CodeOperation.INSTALL_DEPENDENCY,
                CodeOperation.UPDATE_DEPENDENCY,
                CodeOperation.GIT_ADD,
                CodeOperation.GIT_COMMIT,
                CodeOperation.GIT_PUSH,
                CodeOperation.GIT_PULL,
                CodeOperation.GIT_BRANCH,
                CodeOperation.GIT_CHECKOUT,
                CodeOperation.DEPLOY_PREVIEW,
                CodeOperation.DEPLOY_STAGING,
                CodeOperation.DEPLOY_PRODUCTION,
                CodeOperation.BACKUP_RESTORE,
                CodeOperation.CONFIG_UPDATE,
            }
            if operation_enum in mutation_ops:
                allowed = False
                reason = "Read-only mode denies mutation/external-effect operations."
                permission = PermissionLevel.DENY

        if allowed and target_path:
            path_policy = self.is_path_allowed(target_path, operation_enum)
            path_data = path_policy.get("data", {})
            if not path_policy.get("success") or not path_data.get("allowed"):
                allowed = False
                reason = path_data.get("reason") or "Path is denied by file safety policy."
                permission = PermissionLevel.DENY
            elif path_data.get("requires_approval"):
                permission = PermissionLevel.REQUIRE_APPROVAL

        if allowed and operation_enum == CodeOperation.RUN_TERMINAL:
            terminal_decision = self.is_terminal_command_allowed(command or "", task_context=task_context)
            terminal_data = terminal_decision.get("data", {})
            allowed = bool(terminal_data.get("allowed"))
            reason = terminal_data.get("reason", reason)
            permission = PermissionLevel(terminal_data.get("permission", PermissionLevel.ALLOW.value))

        if allowed and operation_enum.value.startswith("git_"):
            git_decision = self.is_git_operation_allowed(operation_enum, git_args=git_args)
            git_data = git_decision.get("data", {})
            allowed = bool(git_data.get("allowed"))
            reason = git_data.get("reason", reason)
            permission = PermissionLevel(git_data.get("permission", PermissionLevel.ALLOW.value))

        if allowed and operation_enum.value.startswith("deploy_"):
            deploy_decision = self.is_deploy_allowed(operation_enum, deploy_target=deploy_target)
            deploy_data = deploy_decision.get("data", {})
            allowed = bool(deploy_data.get("allowed"))
            reason = deploy_data.get("reason", reason)
            permission = PermissionLevel(deploy_data.get("permission", PermissionLevel.ALLOW.value))

        requires_security = self._requires_security_check(
            operation=operation_enum,
            task_context=task_context,
            target=target_path,
            command=command,
            deploy_target=deploy_target,
            git_args=git_args,
        )

        if requires_security:
            permission = PermissionLevel.REQUIRE_SECURITY_AGENT

        return self._safe_result(
            "Operation policy resolved.",
            data={
                "operation": operation_enum.value,
                "allowed": allowed,
                "permission": permission.value,
                "reason": reason,
                "risk_level": risk_level,
                "requires_backup": requires_backup,
                "requires_security_check": requires_security,
                "safety_mode": self.safety_mode.value,
                "environment": self.environment.value,
                "target_path": target_path,
                "deploy_target": deploy_target,
            },
        )

    def get_operation_risk_level(self, operation: Union[CodeOperation, str]) -> RiskLevel:
        """
        Return risk level for operation.
        """
        operation_enum = self._coerce_operation(operation)

        if operation_enum in {
            CodeOperation.READ_FILE,
            CodeOperation.ANALYZE_PROJECT,
            CodeOperation.GIT_STATUS,
            CodeOperation.GIT_DIFF,
            CodeOperation.CONFIG_READ,
        }:
            return RiskLevel.LOW

        if operation_enum in {
            CodeOperation.WRITE_FILE,
            CodeOperation.EDIT_FILE,
            CodeOperation.CREATE_FILE,
            CodeOperation.CREATE_DIRECTORY,
            CodeOperation.GENERATE_CODE,
            CodeOperation.REFACTOR_CODE,
            CodeOperation.RUN_TESTS,
            CodeOperation.GIT_ADD,
            CodeOperation.GIT_COMMIT,
            CodeOperation.BACKUP_CREATE,
        }:
            return RiskLevel.MEDIUM

        if operation_enum in {
            CodeOperation.RUN_TERMINAL,
            CodeOperation.INSTALL_DEPENDENCY,
            CodeOperation.UPDATE_DEPENDENCY,
            CodeOperation.GIT_PULL,
            CodeOperation.GIT_CHECKOUT,
            CodeOperation.DEPLOY_PREVIEW,
            CodeOperation.DEPLOY_STAGING,
            CodeOperation.CONFIG_UPDATE,
        }:
            return RiskLevel.HIGH

        if operation_enum in {
            CodeOperation.DELETE_FILE,
            CodeOperation.DELETE_DIRECTORY,
            CodeOperation.GIT_PUSH,
            CodeOperation.DEPLOY_PRODUCTION,
            CodeOperation.BACKUP_RESTORE,
        }:
            return RiskLevel.CRITICAL

        return RiskLevel.MEDIUM

    # ------------------------------------------------------------------
    # Backup policy
    # ------------------------------------------------------------------

    def should_backup_before_operation(
        self,
        operation: Union[CodeOperation, str],
    ) -> Dict[str, Any]:
        """
        Decide whether backup is required before an operation.
        """
        operation_enum = self._coerce_operation(operation)
        if not operation_enum:
            return self._error_result(
                "Unsupported operation for backup policy.",
                error="UNSUPPORTED_OPERATION",
                data={"operation": str(operation)},
            )

        requires_backup = False
        reason = "Backup not required for this operation."

        if not self.backup_policy.enabled:
            return self._safe_result(
                "Backup policy resolved.",
                data={
                    "operation": operation_enum.value,
                    "requires_backup": False,
                    "reason": "Backups are disabled in current configuration.",
                    "backup_policy_enabled": False,
                },
            )

        if operation_enum in {CodeOperation.WRITE_FILE, CodeOperation.CREATE_FILE}:
            requires_backup = self.backup_policy.require_backup_before_write
            reason = "Backup required before file write/create." if requires_backup else reason

        elif operation_enum in {CodeOperation.EDIT_FILE, CodeOperation.REFACTOR_CODE}:
            requires_backup = self.backup_policy.require_backup_before_edit
            reason = "Backup required before file edit/refactor." if requires_backup else reason

        elif operation_enum in {CodeOperation.DELETE_FILE, CodeOperation.DELETE_DIRECTORY}:
            requires_backup = self.backup_policy.require_backup_before_delete
            reason = "Backup required before delete operation." if requires_backup else reason

        elif operation_enum in {CodeOperation.INSTALL_DEPENDENCY, CodeOperation.UPDATE_DEPENDENCY}:
            requires_backup = self.backup_policy.require_backup_before_dependency_change
            reason = "Backup required before dependency change." if requires_backup else reason

        elif operation_enum in {
            CodeOperation.GIT_ADD,
            CodeOperation.GIT_COMMIT,
            CodeOperation.GIT_PUSH,
            CodeOperation.GIT_PULL,
            CodeOperation.GIT_BRANCH,
            CodeOperation.GIT_CHECKOUT,
        }:
            requires_backup = self.backup_policy.require_backup_before_git_mutation
            reason = "Backup required before git mutation." if requires_backup else reason

        elif operation_enum in {
            CodeOperation.DEPLOY_PREVIEW,
            CodeOperation.DEPLOY_STAGING,
            CodeOperation.DEPLOY_PRODUCTION,
        }:
            requires_backup = self.backup_policy.require_backup_before_deploy
            reason = "Backup required before deployment." if requires_backup else reason

        elif operation_enum == CodeOperation.BACKUP_RESTORE:
            requires_backup = True
            reason = "Backup required before restoring previous backup."

        return self._safe_result(
            "Backup policy resolved.",
            data={
                "operation": operation_enum.value,
                "requires_backup": requires_backup,
                "reason": reason,
                "backup_root_dir": self.backup_policy.backup_root_dir,
                "include_user_workspace_scope": self.backup_policy.include_user_workspace_scope,
                "max_backup_size_bytes": self.backup_policy.max_backup_size_bytes,
            },
        )

    def build_backup_path(
        self,
        source_path: str,
        task_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build a safe backup path for a target file.

        This method does not create the backup. It only returns the target path.
        """
        context_validation = self._validate_task_context(task_context or {})
        if not context_validation.get("success"):
            return context_validation

        normalized_source = _normalize_path(source_path)
        if not normalized_source:
            return self._error_result(
                "Source path is required for backup path generation.",
                error="SOURCE_PATH_REQUIRED",
            )

        context = dict(task_context or {})
        user_id = str(context.get("user_id"))
        workspace_id = str(context.get("workspace_id"))

        safe_source_name = re.sub(r"[^a-zA-Z0-9._-]+", "_", normalized_source.strip("/"))
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        parts = [self.backup_policy.backup_root_dir]

        if self.backup_policy.include_user_workspace_scope:
            parts.extend([f"user_{user_id}", f"workspace_{workspace_id}"])

        backup_name = safe_source_name
        if self.backup_policy.include_timestamp:
            backup_name = f"{safe_source_name}.{timestamp}"

        backup_name = f"{backup_name}{self.backup_policy.backup_file_suffix}"
        backup_path = "/".join(part.strip("/").replace("\\", "/") for part in parts if part)
        backup_path = f"{backup_path}/{backup_name}"

        return self._safe_result(
            "Backup path generated.",
            data={
                "source_path": normalized_source,
                "backup_path": backup_path,
                "backup_root_dir": self.backup_policy.backup_root_dir,
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    # ------------------------------------------------------------------
    # Terminal policy
    # ------------------------------------------------------------------

    def is_terminal_command_allowed(
        self,
        command: Union[str, Sequence[str]],
        task_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Check if terminal command is allowed.

        Does not execute command.
        """
        command_text = _normalize_command(command)

        if not self.terminal_policy.enabled:
            return self._safe_result(
                "Terminal policy resolved.",
                data={
                    "allowed": False,
                    "permission": PermissionLevel.DENY.value,
                    "requires_approval": False,
                    "reason": "Terminal execution is disabled.",
                    "command": command_text,
                },
            )

        if not command_text:
            return self._safe_result(
                "Terminal policy resolved.",
                data={
                    "allowed": False,
                    "permission": PermissionLevel.DENY.value,
                    "requires_approval": False,
                    "reason": "Empty terminal command is denied.",
                    "command": command_text,
                },
            )

        command_lower = command_text.lower()

        if _matches_any_pattern(command_lower, self.terminal_policy.denied_patterns):
            return self._safe_result(
                "Terminal policy resolved.",
                data={
                    "allowed": False,
                    "permission": PermissionLevel.DENY.value,
                    "requires_approval": False,
                    "reason": "Command matches denied terminal pattern.",
                    "command": command_text,
                },
            )

        executable = command_text.split(" ", 1)[0].strip().lower()

        if executable in {"sudo", "su"} and not self.terminal_policy.allow_sudo:
            return self._safe_result(
                "Terminal policy resolved.",
                data={
                    "allowed": False,
                    "permission": PermissionLevel.DENY.value,
                    "requires_approval": False,
                    "reason": "sudo/su commands are denied.",
                    "command": command_text,
                },
            )

        if any(symbol in command_text for symbol in ["|", "&&", ";", "`", "$("]):
            if not self.terminal_policy.allow_shell:
                return self._safe_result(
                    "Terminal policy resolved.",
                    data={
                        "allowed": False,
                        "permission": PermissionLevel.DENY.value,
                        "requires_approval": False,
                        "reason": "Shell chaining/substitution is denied.",
                        "command": command_text,
                    },
                )

        package_install_patterns = (
            "pip install",
            "pip3 install",
            "python -m pip install",
            "npm install",
            "npm i",
            "yarn add",
            "pnpm add",
        )
        if command_lower.startswith(package_install_patterns) and not self.terminal_policy.allow_package_install:
            return self._safe_result(
                "Terminal policy resolved.",
                data={
                    "allowed": True,
                    "permission": PermissionLevel.REQUIRE_SECURITY_AGENT.value,
                    "requires_approval": True,
                    "reason": "Package installation requires Security Agent approval.",
                    "command": command_text,
                },
            )

        network_patterns = ("curl ", "wget ", "ssh ", "scp ", "rsync ")
        if command_lower.startswith(network_patterns) and not self.terminal_policy.allow_network_commands:
            return self._safe_result(
                "Terminal policy resolved.",
                data={
                    "allowed": True,
                    "permission": PermissionLevel.REQUIRE_SECURITY_AGENT.value,
                    "requires_approval": True,
                    "reason": "Network command requires Security Agent approval.",
                    "command": command_text,
                },
            )

        if executable not in self.terminal_policy.allowed_executable_prefixes:
            return self._safe_result(
                "Terminal policy resolved.",
                data={
                    "allowed": True,
                    "permission": PermissionLevel.REQUIRE_APPROVAL.value,
                    "requires_approval": True,
                    "reason": "Executable is not in safe executable allow-list.",
                    "command": command_text,
                },
            )

        if _matches_any_pattern(command_lower, self.terminal_policy.approval_required_patterns):
            return self._safe_result(
                "Terminal policy resolved.",
                data={
                    "allowed": True,
                    "permission": PermissionLevel.REQUIRE_SECURITY_AGENT.value,
                    "requires_approval": True,
                    "reason": "Command matches approval-required terminal pattern.",
                    "command": command_text,
                },
            )

        safe_exact = any(command_lower == safe.lower() for safe in self.terminal_policy.safe_commands)
        safe_prefix = any(command_lower.startswith(f"{safe.lower()} ") for safe in self.terminal_policy.safe_commands)

        if safe_exact or safe_prefix:
            return self._safe_result(
                "Terminal policy resolved.",
                data={
                    "allowed": True,
                    "permission": PermissionLevel.ALLOW.value,
                    "requires_approval": False,
                    "reason": "Command is allowed by safe command policy.",
                    "command": command_text,
                    "timeout_seconds": self.terminal_policy.timeout_seconds,
                    "max_output_chars": self.terminal_policy.max_output_chars,
                },
            )

        permission = self.terminal_policy.default_permission
        requires_approval = permission in {
            PermissionLevel.REQUIRE_APPROVAL,
            PermissionLevel.REQUIRE_SECURITY_AGENT,
            PermissionLevel.REQUIRE_ADMIN,
            PermissionLevel.REQUIRE_OWNER,
        }

        return self._safe_result(
            "Terminal policy resolved.",
            data={
                "allowed": permission != PermissionLevel.DENY,
                "permission": permission.value,
                "requires_approval": requires_approval,
                "reason": "Command follows default terminal permission policy.",
                "command": command_text,
                "timeout_seconds": self.terminal_policy.timeout_seconds,
                "max_output_chars": self.terminal_policy.max_output_chars,
            },
        )

    # ------------------------------------------------------------------
    # Git policy
    # ------------------------------------------------------------------

    def is_git_operation_allowed(
        self,
        operation: Union[CodeOperation, str],
        git_args: Optional[str] = None,
        branch: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Check if a git operation is allowed.

        Does not execute git.
        """
        operation_enum = self._coerce_operation(operation)
        if not operation_enum:
            return self._error_result(
                "Unsupported git operation.",
                error="UNSUPPORTED_GIT_OPERATION",
                data={"operation": str(operation)},
            )

        if not self.git_policy.enabled:
            return self._safe_result(
                "Git policy resolved.",
                data={
                    "allowed": False,
                    "permission": PermissionLevel.DENY.value,
                    "requires_approval": False,
                    "reason": "Git operations are disabled.",
                    "operation": operation_enum.value,
                },
            )

        args = str(git_args or "").strip()
        args_lower = args.lower()

        if args and _matches_any_pattern(args_lower, self.git_policy.denied_git_args):
            return self._safe_result(
                "Git policy resolved.",
                data={
                    "allowed": False,
                    "permission": PermissionLevel.DENY.value,
                    "requires_approval": False,
                    "reason": "Git args match denied git pattern.",
                    "operation": operation_enum.value,
                    "git_args": args,
                },
            )

        branch_name = str(branch or "").strip()
        branch_is_protected = branch_name in self.git_policy.protected_branches

        allowed = True
        permission = PermissionLevel.ALLOW
        requires_approval = False
        reason = "Git operation is allowed by current policy."

        if operation_enum == CodeOperation.GIT_STATUS:
            allowed = self.git_policy.allow_status

        elif operation_enum == CodeOperation.GIT_DIFF:
            allowed = self.git_policy.allow_diff

        elif operation_enum == CodeOperation.GIT_ADD:
            allowed = self.git_policy.allow_add

        elif operation_enum == CodeOperation.GIT_COMMIT:
            allowed = self.git_policy.allow_commit
            requires_approval = self.git_policy.require_approval_for_commit

        elif operation_enum == CodeOperation.GIT_PUSH:
            allowed = self.git_policy.allow_push
            requires_approval = self.git_policy.require_approval_for_push

        elif operation_enum == CodeOperation.GIT_PULL:
            allowed = self.git_policy.allow_pull
            requires_approval = self.git_policy.require_approval_for_pull

        elif operation_enum == CodeOperation.GIT_BRANCH:
            allowed = self.git_policy.allow_branch
            if "-d" in args_lower or "-D" in args:
                requires_approval = self.git_policy.require_approval_for_branch_delete

        elif operation_enum == CodeOperation.GIT_CHECKOUT:
            allowed = self.git_policy.allow_checkout
            requires_approval = self.git_policy.require_approval_for_checkout

        else:
            allowed = False
            reason = "Operation is not a supported git policy action."

        if branch_is_protected and operation_enum in {
            CodeOperation.GIT_PUSH,
            CodeOperation.GIT_CHECKOUT,
            CodeOperation.GIT_BRANCH,
        }:
            requires_approval = True
            reason = "Operation touches a protected branch and requires approval."

        if not allowed:
            permission = PermissionLevel.DENY
            requires_approval = False
            if reason == "Git operation is allowed by current policy.":
                reason = f"Git operation '{operation_enum.value}' is disabled by policy."

        elif requires_approval:
            permission = PermissionLevel.REQUIRE_SECURITY_AGENT
            if reason == "Git operation is allowed by current policy.":
                reason = f"Git operation '{operation_enum.value}' requires approval."

        return self._safe_result(
            "Git policy resolved.",
            data={
                "operation": operation_enum.value,
                "allowed": allowed,
                "permission": permission.value,
                "requires_approval": requires_approval,
                "reason": reason,
                "git_args": args,
                "branch": branch_name or None,
                "branch_is_protected": branch_is_protected,
                "timeout_seconds": self.git_policy.timeout_seconds,
                "requires_backup": self.git_policy.require_backup_before_mutation,
            },
        )

    # ------------------------------------------------------------------
    # Deployment policy
    # ------------------------------------------------------------------

    def is_deploy_allowed(
        self,
        operation: Union[CodeOperation, str],
        deploy_target: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Check if deployment is allowed.

        Does not deploy.
        """
        operation_enum = self._coerce_operation(operation)
        if not operation_enum:
            return self._error_result(
                "Unsupported deploy operation.",
                error="UNSUPPORTED_DEPLOY_OPERATION",
                data={"operation": str(operation)},
            )

        if not self.deploy_policy.enabled:
            return self._safe_result(
                "Deploy policy resolved.",
                data={
                    "allowed": False,
                    "permission": PermissionLevel.DENY.value,
                    "requires_approval": False,
                    "reason": "Deployments are disabled.",
                    "operation": operation_enum.value,
                },
            )

        target = _safe_lower(deploy_target)
        if not target:
            if operation_enum == CodeOperation.DEPLOY_PREVIEW:
                target = "preview"
            elif operation_enum == CodeOperation.DEPLOY_STAGING:
                target = "staging"
            elif operation_enum == CodeOperation.DEPLOY_PRODUCTION:
                target = "production"

        provider_value = _safe_lower(provider) if provider else None

        allowed = True
        requires_approval = False
        permission = PermissionLevel.ALLOW
        reason = "Deploy operation is allowed by current policy."

        if provider_value and provider_value not in self.deploy_policy.allowed_providers:
            allowed = False
            reason = f"Deploy provider '{provider_value}' is not allowed."

        if target in self.deploy_policy.denied_deploy_targets:
            allowed = False
            reason = f"Deploy target '{target}' is denied by policy."

        if target and target not in self.deploy_policy.allowed_deploy_targets:
            if target != "production":
                allowed = False
                reason = f"Deploy target '{target}' is not in allowed target list."

        if operation_enum == CodeOperation.DEPLOY_PREVIEW:
            allowed = allowed and self.deploy_policy.allow_preview_deploy
            requires_approval = self.deploy_policy.require_approval_for_preview

        elif operation_enum == CodeOperation.DEPLOY_STAGING:
            allowed = allowed and self.deploy_policy.allow_staging_deploy
            requires_approval = self.deploy_policy.require_approval_for_staging

        elif operation_enum == CodeOperation.DEPLOY_PRODUCTION:
            allowed = allowed and self.deploy_policy.allow_production_deploy
            requires_approval = self.deploy_policy.require_approval_for_production
            if self.environment == EnvironmentType.PRODUCTION:
                requires_approval = True

        else:
            allowed = False
            reason = "Operation is not a supported deploy action."

        if not allowed:
            permission = PermissionLevel.DENY
            requires_approval = False
            if reason == "Deploy operation is allowed by current policy.":
                reason = f"Deploy operation '{operation_enum.value}' is disabled by policy."

        elif requires_approval:
            permission = PermissionLevel.REQUIRE_SECURITY_AGENT
            if reason == "Deploy operation is allowed by current policy.":
                reason = f"Deploy operation '{operation_enum.value}' requires approval."

        return self._safe_result(
            "Deploy policy resolved.",
            data={
                "operation": operation_enum.value,
                "deploy_target": target,
                "provider": provider_value,
                "allowed": allowed,
                "permission": permission.value,
                "requires_approval": requires_approval,
                "reason": reason,
                "require_tests_before_deploy": self.deploy_policy.require_tests_before_deploy,
                "require_security_scan_before_deploy": self.deploy_policy.require_security_scan_before_deploy,
                "require_backup_before_deploy": self.deploy_policy.require_backup_before_deploy,
                "require_git_clean_state_before_deploy": self.deploy_policy.require_git_clean_state_before_deploy,
                "timeout_seconds": self.deploy_policy.timeout_seconds,
            },
        )

    # ------------------------------------------------------------------
    # File/path policy
    # ------------------------------------------------------------------

    def is_path_allowed(
        self,
        path: str,
        operation: Optional[Union[CodeOperation, str]] = None,
    ) -> Dict[str, Any]:
        """
        Check if a path is allowed for a given Code Agent operation.
        """
        normalized_path = _normalize_path(path)
        operation_enum = self._coerce_operation(operation) if operation else None

        if not normalized_path:
            return self._safe_result(
                "Path policy resolved.",
                data={
                    "allowed": False,
                    "requires_approval": False,
                    "reason": "Path is empty.",
                    "path": normalized_path,
                },
            )

        if _matches_any_pattern(normalized_path, self.file_safety_policy.denied_paths):
            return self._safe_result(
                "Path policy resolved.",
                data={
                    "allowed": False,
                    "requires_approval": False,
                    "reason": "Path matches denied path policy.",
                    "path": normalized_path,
                    "operation": operation_enum.value if operation_enum else None,
                },
            )

        requires_approval = False
        reason = "Path is allowed by current file safety policy."

        if _matches_any_pattern(normalized_path, self.file_safety_policy.approval_required_paths):
            requires_approval = True
            reason = "Path matches approval-required path policy."

        if operation_enum:
            if operation_enum == CodeOperation.READ_FILE and not self.file_safety_policy.allow_read:
                return self._safe_result(
                    "Path policy resolved.",
                    data={
                        "allowed": False,
                        "requires_approval": False,
                        "reason": "File reads are disabled.",
                        "path": normalized_path,
                        "operation": operation_enum.value,
                    },
                )

            if operation_enum in {CodeOperation.WRITE_FILE, CodeOperation.CREATE_FILE}:
                if not self.file_safety_policy.allow_write:
                    return self._safe_result(
                        "Path policy resolved.",
                        data={
                            "allowed": False,
                            "requires_approval": False,
                            "reason": "File writes are disabled.",
                            "path": normalized_path,
                            "operation": operation_enum.value,
                        },
                    )
                if self.file_safety_policy.require_approval_for_overwrite:
                    requires_approval = True
                    reason = "File write/overwrite requires approval."

            if operation_enum in {CodeOperation.EDIT_FILE, CodeOperation.REFACTOR_CODE}:
                if not self.file_safety_policy.allow_edit:
                    return self._safe_result(
                        "Path policy resolved.",
                        data={
                            "allowed": False,
                            "requires_approval": False,
                            "reason": "File edits are disabled.",
                            "path": normalized_path,
                            "operation": operation_enum.value,
                        },
                    )

            if operation_enum == CodeOperation.DELETE_FILE:
                if not self.file_safety_policy.allow_delete:
                    return self._safe_result(
                        "Path policy resolved.",
                        data={
                            "allowed": False,
                            "requires_approval": False,
                            "reason": "File deletion is disabled.",
                            "path": normalized_path,
                            "operation": operation_enum.value,
                        },
                    )
                if self.file_safety_policy.require_approval_for_delete:
                    requires_approval = True
                    reason = "File deletion requires approval."

            if operation_enum == CodeOperation.CREATE_DIRECTORY:
                if not self.file_safety_policy.allow_create_directory:
                    return self._safe_result(
                        "Path policy resolved.",
                        data={
                            "allowed": False,
                            "requires_approval": False,
                            "reason": "Directory creation is disabled.",
                            "path": normalized_path,
                            "operation": operation_enum.value,
                        },
                    )

            if operation_enum == CodeOperation.DELETE_DIRECTORY:
                if not self.file_safety_policy.allow_delete_directory:
                    return self._safe_result(
                        "Path policy resolved.",
                        data={
                            "allowed": False,
                            "requires_approval": False,
                            "reason": "Directory deletion is disabled.",
                            "path": normalized_path,
                            "operation": operation_enum.value,
                        },
                    )
                requires_approval = True
                reason = "Directory deletion requires approval."

        return self._safe_result(
            "Path policy resolved.",
            data={
                "allowed": True,
                "requires_approval": requires_approval,
                "reason": reason,
                "path": normalized_path,
                "operation": operation_enum.value if operation_enum else None,
                "max_file_size_bytes": self.file_safety_policy.max_file_size_bytes,
                "requires_backup": self.file_safety_policy.require_backup_before_mutation,
            },
        )

    def is_sensitive_path(self, path: str) -> bool:
        """
        Return True if path is considered secret/sensitive.
        """
        normalized_path = _normalize_path(path)
        if not normalized_path:
            return False

        sensitive_patterns = (
            ".env",
            ".env.*",
            "**/.env",
            "**/.env.*",
            "**/*.pem",
            "**/*.key",
            "**/*.p12",
            "**/*.pfx",
            "**/id_rsa",
            "**/id_dsa",
            "**/id_ed25519",
            "**/secrets.*",
            "**/credentials.*",
            "**/service-account*.json",
        )

        return _matches_any_pattern(normalized_path, sensitive_patterns)

    # ------------------------------------------------------------------
    # Payload hooks
    # ------------------------------------------------------------------

    def _prepare_verification_payload(
        self,
        operation: Union[CodeOperation, str],
        task_context: Optional[Mapping[str, Any]] = None,
        result: Optional[Mapping[str, Any]] = None,
        extra: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Required by William/Jarvis architecture.
        """
        operation_enum = self._coerce_operation(operation)
        operation_value = operation_enum.value if operation_enum else str(operation)
        context = dict(task_context or {})

        payload: Dict[str, Any] = {
            "payload_id": str(uuid.uuid4()),
            "payload_type": "code_agent_verification",
            "agent_module": AGENT_MODULE,
            "agent_name": AGENT_NAME,
            "operation": operation_value,
            "task_context": {
                "user_id": context.get("user_id"),
                "workspace_id": context.get("workspace_id"),
                "task_id": context.get("task_id"),
                "session_id": context.get("session_id"),
                "role": context.get("role") or context.get("user_role"),
            },
            "result": _redact_sensitive_text(dict(result or {})),
            "timestamp": _utc_now_iso(),
        }

        if self.verification_policy.include_risk_level:
            payload["risk_level"] = self.get_operation_risk_level(operation_value).value

        if self.verification_policy.include_backup_requirement:
            payload["backup_policy"] = self.should_backup_before_operation(operation_value).get("data", {})

        if self.verification_policy.include_policy_snapshot:
            payload["policy_snapshot"] = self.create_snapshot(include_sensitive=False).get("data", {}).get("snapshot")

        if extra:
            payload["extra"] = _redact_sensitive_text(dict(extra))

        return self._safe_result(
            "Verification payload prepared.",
            data={
                "verification_enabled": self.verification_policy.enabled,
                "payload": payload,
            },
        )

    def _prepare_memory_payload(
        self,
        operation: Union[CodeOperation, str],
        task_context: Optional[Mapping[str, Any]] = None,
        useful_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Required by William/Jarvis architecture.

        This method does not write memory directly.
        """
        operation_enum = self._coerce_operation(operation)
        operation_value = operation_enum.value if operation_enum else str(operation)
        context = dict(task_context or {})

        safe_context = dict(useful_context or {})

        if not self.memory_policy.store_sensitive_paths:
            for key in list(safe_context.keys()):
                if "path" in key.lower() and self.memory_policy.redact_paths_when_needed:
                    value = str(safe_context.get(key) or "")
                    if self.is_sensitive_path(value):
                        safe_context[key] = "[REDACTED_SENSITIVE_PATH]"

        payload = {
            "payload_id": str(uuid.uuid4()),
            "payload_type": "code_agent_memory_context",
            "agent_module": AGENT_MODULE,
            "agent_name": AGENT_NAME,
            "operation": operation_value,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "task_id": context.get("task_id"),
            "session_id": context.get("session_id"),
            "memory_scope": "user_workspace",
            "useful_context": _redact_sensitive_text(safe_context),
            "policy": {
                "store_user_preferences": self.memory_policy.store_user_preferences,
                "store_workspace_code_preferences": self.memory_policy.store_workspace_code_preferences,
                "store_denied_action_patterns": self.memory_policy.store_denied_action_patterns,
                "store_sensitive_paths": self.memory_policy.store_sensitive_paths,
            },
            "timestamp": _utc_now_iso(),
        }

        return self._safe_result(
            "Memory payload prepared.",
            data={
                "memory_enabled": self.memory_policy.enabled,
                "payload": payload,
            },
        )

    def _emit_agent_event(
        self,
        event_type: str,
        task_context: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare and log an agent event for dashboard/API/event bus.

        Required by William/Jarvis architecture.

        This method returns the event payload and logs locally. Future event bus
        integration can consume this return value.
        """
        context = dict(task_context or {})
        event_payload = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent_module": AGENT_MODULE,
            "agent_name": AGENT_NAME,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "task_id": context.get("task_id"),
            "session_id": context.get("session_id"),
            "payload": _redact_sensitive_text(dict(payload or {})),
            "timestamp": _utc_now_iso(),
        }

        if self.audit_policy.redact_sensitive_values:
            event_payload = _redact_sensitive_text(event_payload)

        logger.info("CodeConfig event emitted: %s", event_payload.get("event_type"))

        return self._safe_result(
            "Agent event prepared.",
            data={"event": event_payload},
        )

    def _log_audit_event(
        self,
        event_type: str,
        task_context: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare audit event.

        Required by William/Jarvis architecture.

        This file does not write to a database directly. It returns a structured
        audit payload that can be persisted by Audit Log service later.
        """
        if not self.audit_policy.enabled:
            return self._safe_result(
                "Audit logging disabled.",
                data={"audit_enabled": False},
            )

        context = dict(task_context or {})
        audit_payload: Dict[str, Any] = {
            "audit_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent_module": AGENT_MODULE,
            "agent_name": AGENT_NAME,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "task_id": context.get("task_id"),
            "session_id": context.get("session_id"),
            "role": context.get("role") or context.get("user_role"),
            "payload": dict(payload or {}),
            "timestamp": _utc_now_iso(),
            "safety_mode": self.safety_mode.value,
            "environment": self.environment.value,
        }

        if self.audit_policy.redact_sensitive_values:
            audit_payload = _redact_sensitive_text(audit_payload)

        audit_payload = _truncate_payload(
            audit_payload,
            max_chars=self.audit_policy.max_event_payload_chars,
        )

        logger.info("CodeConfig audit event prepared: %s", event_type)

        return self._safe_result(
            "Audit event prepared.",
            data={
                "audit_enabled": True,
                "audit_event": audit_payload,
            },
        )

    # ------------------------------------------------------------------
    # Snapshot / registry / export helpers
    # ------------------------------------------------------------------

    def create_snapshot(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Create serializable config snapshot.

        Args:
            include_sensitive:
                This config should not contain secrets, but when false,
                potentially sensitive path patterns are minimized.
        """
        file_policy = copy.deepcopy(self.file_safety_policy)
        terminal_policy = copy.deepcopy(self.terminal_policy)

        if not include_sensitive:
            file_policy.denied_paths = tuple(
                "[SENSITIVE_PATH_PATTERN_REDACTED]" if "env" in item or "key" in item or "credential" in item
                else item
                for item in file_policy.denied_paths
            )
            terminal_policy.denied_patterns = tuple(terminal_policy.denied_patterns)

        snapshot = CodeConfigSnapshot(
            config_version=self.config_version,
            safety_mode=self.safety_mode.value,
            environment=self.environment.value,
            saas_context_policy=_to_plain_dict(self.saas_context_policy),
            backup_policy=_to_plain_dict(self.backup_policy),
            terminal_policy=_to_plain_dict(terminal_policy),
            git_policy=_to_plain_dict(self.git_policy),
            deploy_policy=_to_plain_dict(self.deploy_policy),
            file_safety_policy=_to_plain_dict(file_policy),
            security_policy=_to_plain_dict(self.security_policy),
            audit_policy=_to_plain_dict(self.audit_policy),
            verification_policy=_to_plain_dict(self.verification_policy),
            memory_policy=_to_plain_dict(self.memory_policy),
            metadata=dict(self.metadata),
        )

        return self._safe_result(
            "Code Agent config snapshot created.",
            data={"snapshot": _to_plain_dict(snapshot)},
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Return plain dict configuration snapshot.
        """
        return self.create_snapshot(include_sensitive=True).get("data", {}).get("snapshot", {})

    def get_registry_metadata(self) -> Dict[str, Any]:
        """
        Return metadata for Agent Registry / Agent Loader.
        """
        return {
            "agent_module": AGENT_MODULE,
            "agent_name": AGENT_NAME,
            "config_class": CONFIG_CLASS_NAME,
            "config_version": self.config_version,
            "capabilities": [
                "safe_mode_config",
                "backup_policy",
                "terminal_permission_policy",
                "git_permission_policy",
                "deploy_permission_policy",
                "file_safety_policy",
                "security_agent_approval_routing",
                "verification_payload_preparation",
                "memory_payload_preparation",
                "audit_event_preparation",
                "saas_user_workspace_isolation",
            ],
            "supported_operations": [operation.value for operation in CodeOperation],
            "safety_mode": self.safety_mode.value,
            "environment": self.environment.value,
            "import_safe": True,
            "executes_actions_directly": False,
            "requires_user_id": self.saas_context_policy.require_user_id,
            "requires_workspace_id": self.saas_context_policy.require_workspace_id,
        }

    # ------------------------------------------------------------------
    # Config update helpers
    # ------------------------------------------------------------------

    def update_safety_mode(
        self,
        safety_mode: Union[SafetyMode, str],
        task_context: Optional[Mapping[str, Any]] = None,
        request_security: bool = True,
    ) -> Dict[str, Any]:
        """
        Update safety mode safely.

        Config changes are sensitive and should be routed through Security Agent.
        """
        context_validation = self._validate_task_context(task_context or {}, CodeOperation.CONFIG_UPDATE)
        if not context_validation.get("success"):
            return context_validation

        new_mode = self._coerce_safety_mode(safety_mode)

        if request_security and self._requires_security_check(CodeOperation.CONFIG_UPDATE, task_context):
            approval = self._request_security_approval(
                operation=CodeOperation.CONFIG_UPDATE,
                task_context=task_context,
                details={
                    "change": "update_safety_mode",
                    "old_safety_mode": self.safety_mode.value,
                    "new_safety_mode": new_mode.value,
                },
                risk_level=RiskLevel.HIGH,
            )
            if not approval.get("success"):
                return self._error_result(
                    "Safety mode update denied because Security Agent approval was not granted.",
                    error="SECURITY_APPROVAL_REQUIRED",
                    data={"approval": approval},
                )

        old_mode = self.safety_mode
        self.safety_mode = new_mode
        self._apply_safety_mode_defaults()

        self._log_audit_event(
            event_type="config_safety_mode_updated",
            task_context=task_context,
            payload={
                "old_safety_mode": old_mode.value,
                "new_safety_mode": new_mode.value,
            },
        )

        return self._safe_result(
            "Safety mode updated.",
            data={
                "old_safety_mode": old_mode.value,
                "new_safety_mode": new_mode.value,
                "snapshot": self.create_snapshot(include_sensitive=False).get("data", {}).get("snapshot"),
            },
        )

    def update_environment(
        self,
        environment: Union[EnvironmentType, str],
        task_context: Optional[Mapping[str, Any]] = None,
        request_security: bool = True,
    ) -> Dict[str, Any]:
        """
        Update environment safely.
        """
        context_validation = self._validate_task_context(task_context or {}, CodeOperation.CONFIG_UPDATE)
        if not context_validation.get("success"):
            return context_validation

        new_environment = self._coerce_environment(environment)

        if request_security and self._requires_security_check(CodeOperation.CONFIG_UPDATE, task_context):
            approval = self._request_security_approval(
                operation=CodeOperation.CONFIG_UPDATE,
                task_context=task_context,
                details={
                    "change": "update_environment",
                    "old_environment": self.environment.value,
                    "new_environment": new_environment.value,
                },
                risk_level=RiskLevel.HIGH,
            )
            if not approval.get("success"):
                return self._error_result(
                    "Environment update denied because Security Agent approval was not granted.",
                    error="SECURITY_APPROVAL_REQUIRED",
                    data={"approval": approval},
                )

        old_environment = self.environment
        self.environment = new_environment
        self._apply_safety_mode_defaults()

        self._log_audit_event(
            event_type="config_environment_updated",
            task_context=task_context,
            payload={
                "old_environment": old_environment.value,
                "new_environment": new_environment.value,
            },
        )

        return self._safe_result(
            "Environment updated.",
            data={
                "old_environment": old_environment.value,
                "new_environment": new_environment.value,
                "snapshot": self.create_snapshot(include_sensitive=False).get("data", {}).get("snapshot"),
            },
        )

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    @classmethod
    def strict(cls, **kwargs: Any) -> "CodeConfig":
        """Create strict Code Agent config."""
        return cls(safety_mode=SafetyMode.STRICT, **kwargs)

    @classmethod
    def balanced(cls, **kwargs: Any) -> "CodeConfig":
        """Create balanced Code Agent config."""
        return cls(safety_mode=SafetyMode.BALANCED, **kwargs)

    @classmethod
    def permissive(cls, **kwargs: Any) -> "CodeConfig":
        """Create permissive Code Agent config."""
        return cls(safety_mode=SafetyMode.PERMISSIVE, **kwargs)

    @classmethod
    def read_only(cls, **kwargs: Any) -> "CodeConfig":
        """Create read-only Code Agent config."""
        return cls(safety_mode=SafetyMode.READ_ONLY, **kwargs)

    @classmethod
    def from_dict(cls, config_data: Mapping[str, Any]) -> "CodeConfig":
        """
        Build CodeConfig from a dict.

        Unknown fields are ignored safely.
        """
        data = dict(config_data or {})

        return cls(
            safety_mode=data.get("safety_mode", SafetyMode.STRICT.value),
            environment=data.get("environment", EnvironmentType.DEVELOPMENT.value),
            metadata=data.get("metadata") if isinstance(data.get("metadata"), Mapping) else None,
        )


# ---------------------------------------------------------------------------
# Module-level default config and helpers
# ---------------------------------------------------------------------------

DEFAULT_CODE_CONFIG = CodeConfig()


def get_default_code_config() -> CodeConfig:
    """
    Return module-level default CodeConfig.

    Useful for Agent Loader and simple imports.
    """
    return DEFAULT_CODE_CONFIG


def create_code_config(
    safety_mode: Union[SafetyMode, str] = SafetyMode.STRICT,
    environment: Union[EnvironmentType, str] = EnvironmentType.DEVELOPMENT,
    **kwargs: Any,
) -> CodeConfig:
    """
    Factory function for creating CodeConfig.
    """
    return CodeConfig(
        safety_mode=safety_mode,
        environment=environment,
        **kwargs,
    )


__all__ = [
    "AGENT_MODULE",
    "AGENT_NAME",
    "CONFIG_CLASS_NAME",
    "CONFIG_VERSION",
    "AuditPolicy",
    "BackupPolicy",
    "CodeConfig",
    "CodeConfigSnapshot",
    "CodeOperation",
    "DEFAULT_CODE_CONFIG",
    "DeployPolicy",
    "EnvironmentType",
    "FileSafetyPolicy",
    "GitPolicy",
    "MemoryPolicy",
    "PermissionLevel",
    "RiskLevel",
    "SaaSContextPolicy",
    "SafetyMode",
    "SecurityPolicy",
    "TerminalPolicy",
    "VerificationPolicy",
    "create_code_config",
    "get_default_code_config",
]