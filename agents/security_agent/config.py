"""
agents/security_agent/config.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Security Agent Configuration

Purpose:
    Central configuration for:

    - Security and risk thresholds
    - Protected folders and files
    - Blocked and restricted commands
    - Biometric verification flags
    - Approval requirements
    - Device trust controls
    - Session protection
    - Payment protection
    - Fraud and anomaly detection
    - Privacy and secret protection
    - Emergency lock behavior
    - Workspace-safe configuration overrides

Architecture connections:
    - Security Agent:
        Reads this module as its central source of safe defaults.

    - Master Agent:
        Can inspect configuration capabilities through get_manifest() and
        get_public_config() without receiving secrets or unsafe internals.

    - Agent Registry / Agent Loader:
        Can safely import this file before other William modules exist.

    - Policy Engine:
        Uses command, path, threshold, and biometric policies defined here.

    - Permission Checker:
        Uses action-level approval and denial policies.

    - Risk Engine:
        Uses risk score boundaries and escalation thresholds.

    - Biometric Gate:
        Uses biometric flags and required verification methods.

    - File Protection:
        Uses protected path policies and backup requirements.

    - Payment Guard:
        Uses transaction limits and mandatory confirmation policies.

    - Threat Monitor / Fraud Detector / Anomaly Detector:
        Use configurable thresholds and monitoring flags.

    - Verification Agent:
        Receives configuration verification payloads after updates.

    - Memory Agent:
        Can receive non-sensitive configuration change summaries.

    - Dashboard / FastAPI:
        Can retrieve redacted public configuration and apply validated,
        tenant-scoped overrides.

Safety principles:
    1. Safety and permissions first.
    2. SaaS user/workspace isolation second.
    3. BaseAgent compatibility third.
    4. Master Agent and Registry compatibility fourth.
    5. Configuration functionality fifth.
    6. Future extensibility last.

Important:
    - No secrets are stored in this file.
    - Real system actions are never executed by this module.
    - Configuration updates are validated and can require security approval.
    - Per-user/workspace overrides are isolated by composite tenant keys.
"""

from __future__ import annotations

import copy
import fnmatch
import hashlib
import json
import logging
import os
import re
import shlex
import threading
import uuid
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path, PurePath
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)


# ============================================================================
# Safe optional imports
# ============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover

    class BaseAgent:  # type: ignore
        """
        Import-safe BaseAgent fallback.

        The real William BaseAgent can replace this automatically when available.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)

        def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent.run() was called.",
                "data": {},
                "error": "BASE_AGENT_NOT_AVAILABLE",
                "metadata": {},
            }


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover

    class SecurityAgent:  # type: ignore
        """
        Import-safe SecurityAgent fallback.

        It permits configuration validation in isolated development and tests.
        Production deployments should inject the real Security Agent.
        """

        def approve_action(self, payload: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback security approval granted.",
                "data": {
                    "approved": True,
                    "fallback": True,
                },
                "error": None,
                "metadata": {
                    "security_agent_available": False,
                },
            }


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ============================================================================
# Constants
# ============================================================================

AGENT_NAME = "SecurityConfig"
CONFIG_VERSION = "1.0.0"
CONFIG_SCHEMA_VERSION = "2026.1"

MAX_OVERRIDE_DEPTH = 8
MAX_OVERRIDE_ITEMS = 500
MAX_PATTERN_LENGTH = 512
MAX_COMMAND_LENGTH = 8192
MAX_PROTECTED_PATHS = 5000
MAX_COMMAND_PATTERNS = 5000
MAX_ALLOWED_BIOMETRIC_METHODS = 8

TENANT_KEY_SEPARATOR = "::"

DEFAULT_ENV_PREFIX = "WILLIAM_SECURITY_"

SENSITIVE_KEY_FRAGMENTS: Tuple[str, ...] = (
    "secret",
    "token",
    "password",
    "credential",
    "private_key",
    "api_key",
    "access_key",
    "refresh_key",
    "encryption_key",
    "signing_key",
    "database_url",
    "dsn",
)

DANGEROUS_SHELL_OPERATORS: Tuple[str, ...] = (
    "&&",
    "||",
    ";",
    "|",
    ">",
    ">>",
    "<",
    "<<",
    "`",
    "$(",
)

WINDOWS_RESERVED_DEVICE_NAMES: Set[str] = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
}


# ============================================================================
# Utility functions
# ============================================================================

def utc_now_iso() -> str:
    """Return the current UTC time in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def stable_json(value: Any) -> str:
    """Serialize JSON-compatible data deterministically."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def stable_hash(value: Any) -> str:
    """Return a deterministic SHA-256 hash for JSON-compatible data."""
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def safe_bool(value: Any, default: bool = False) -> bool:
    """Safely convert common environment/config values to boolean."""
    if isinstance(value, bool):
        return value

    if value is None:
        return default

    if isinstance(value, (int, float)):
        return bool(value)

    normalized = str(value).strip().lower()

    if normalized in {"1", "true", "yes", "on", "enabled", "enable"}:
        return True

    if normalized in {"0", "false", "no", "off", "disabled", "disable"}:
        return False

    return default


def safe_int(
    value: Any,
    default: int,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> int:
    """Convert to integer and optionally clamp it."""
    try:
        converted = int(value)
    except (TypeError, ValueError):
        converted = default

    if minimum is not None:
        converted = max(minimum, converted)

    if maximum is not None:
        converted = min(maximum, converted)

    return converted


def safe_float(
    value: Any,
    default: float,
    minimum: Optional[float] = None,
    maximum: Optional[float] = None,
) -> float:
    """Convert to float and optionally clamp it."""
    try:
        converted = float(value)
    except (TypeError, ValueError):
        converted = default

    if minimum is not None:
        converted = max(minimum, converted)

    if maximum is not None:
        converted = min(maximum, converted)

    return converted


def normalize_identifier(value: Any) -> str:
    """Normalize a SaaS identifier without broadening its scope."""
    return str(value or "").strip()


def normalize_command_text(command: str) -> str:
    """
    Normalize command text for policy matching.

    This function does not execute or rewrite the command.
    """
    command = str(command or "").replace("\x00", "")
    command = re.sub(r"\s+", " ", command).strip()
    return command


def get_command_basename(command: str) -> str:
    """
    Extract the first command token safely.

    Returns an empty string if parsing fails.
    """
    command = normalize_command_text(command)

    if not command:
        return ""

    try:
        tokens = shlex.split(command, posix=os.name != "nt")
    except ValueError:
        tokens = command.split()

    if not tokens:
        return ""

    executable = tokens[0].strip("\"'")
    executable = executable.replace("\\", "/")
    return executable.rsplit("/", 1)[-1].lower()


def normalize_path_text(path_value: Union[str, os.PathLike[str]]) -> str:
    """
    Normalize a path textually without requiring the path to exist.

    This method deliberately does not resolve symlinks because configuration may
    be loaded before filesystem paths exist.
    """
    value = os.path.expandvars(os.path.expanduser(str(path_value or ""))).strip()

    if not value:
        return ""

    value = value.replace("\\", "/")
    value = re.sub(r"/+", "/", value)

    try:
        normalized = os.path.normpath(value).replace("\\", "/")
    except Exception:
        normalized = value

    if os.name == "nt":
        normalized = normalized.lower()

    return normalized.rstrip("/") or "/"


def path_is_within(candidate: str, protected_root: str) -> bool:
    """
    Check whether a candidate path equals or is inside a protected root.

    This is a textual containment check suitable for pre-action policy checks.
    The File Protection agent should additionally perform resolved-path,
    symlink, and filesystem-specific validation before any real action.
    """
    candidate_norm = normalize_path_text(candidate)
    root_norm = normalize_path_text(protected_root)

    if not candidate_norm or not root_norm:
        return False

    if candidate_norm == root_norm:
        return True

    root_prefix = root_norm.rstrip("/") + "/"
    return candidate_norm.startswith(root_prefix)


def deep_merge(
    base: Mapping[str, Any],
    override: Mapping[str, Any],
    *,
    max_depth: int = MAX_OVERRIDE_DEPTH,
    _depth: int = 0,
) -> Dict[str, Any]:
    """
    Merge mappings recursively.

    Lists and scalar values replace defaults instead of being appended. This
    prevents accidental weakening through implicit policy list merging.
    """
    if _depth > max_depth:
        raise ValueError("Maximum configuration override depth exceeded.")

    result: Dict[str, Any] = copy.deepcopy(dict(base))

    for key, value in override.items():
        if (
            key in result
            and isinstance(result[key], Mapping)
            and isinstance(value, Mapping)
        ):
            result[key] = deep_merge(
                result[key],
                value,
                max_depth=max_depth,
                _depth=_depth + 1,
            )
        else:
            result[key] = copy.deepcopy(value)

    return result


def redact_mapping(value: Any) -> Any:
    """Recursively redact fields whose keys suggest secret material."""
    if isinstance(value, Mapping):
        redacted: Dict[str, Any] = {}

        for key, item in value.items():
            normalized_key = str(key).lower()

            if any(fragment in normalized_key for fragment in SENSITIVE_KEY_FRAGMENTS):
                redacted[str(key)] = "[REDACTED]"
            else:
                redacted[str(key)] = redact_mapping(item)

        return redacted

    if isinstance(value, list):
        return [redact_mapping(item) for item in value]

    if isinstance(value, tuple):
        return [redact_mapping(item) for item in value]

    return copy.deepcopy(value)


def dataclass_to_dict(value: Any) -> Any:
    """Recursively convert dataclasses and enums into JSON-compatible objects."""
    if isinstance(value, Enum):
        return value.value

    if is_dataclass(value):
        return {
            item.name: dataclass_to_dict(getattr(value, item.name))
            for item in fields(value)
        }

    if isinstance(value, Mapping):
        return {
            str(key): dataclass_to_dict(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [dataclass_to_dict(item) for item in value]

    return copy.deepcopy(value)


# ============================================================================
# Enums
# ============================================================================

class RiskLevel(str, Enum):
    """Normalized action and threat risk levels."""

    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class PolicyDecision(str, Enum):
    """Possible configuration policy decisions."""

    ALLOW = "allow"
    ALLOW_WITH_AUDIT = "allow_with_audit"
    REQUIRE_CONFIRMATION = "require_confirmation"
    REQUIRE_BIOMETRIC = "require_biometric"
    REQUIRE_ADMIN_APPROVAL = "require_admin_approval"
    BLOCK = "block"
    EMERGENCY_LOCK = "emergency_lock"


class CommandPolicy(str, Enum):
    """Command policy classification."""

    ALLOWED = "allowed"
    AUDITED = "audited"
    RESTRICTED = "restricted"
    BLOCKED = "blocked"


class BiometricMethod(str, Enum):
    """Supported biometric and identity verification methods."""

    FACE = "face"
    FINGERPRINT = "fingerprint"
    VOICE = "voice"
    PIN = "pin"
    PASSKEY = "passkey"
    TOTP = "totp"
    TRUSTED_DEVICE = "trusted_device"
    ADMIN_APPROVAL = "admin_approval"


class OverrideScope(str, Enum):
    """Supported SaaS configuration override scopes."""

    GLOBAL = "global"
    WORKSPACE = "workspace"
    USER = "user"
    USER_WORKSPACE = "user_workspace"


# ============================================================================
# Dataclass configuration models
# ============================================================================

@dataclass
class RiskThresholds:
    """
    Numeric thresholds used by Risk Engine and Policy Engine.

    Risk score range is 0-100.
    """

    low_max: int = 24
    medium_max: int = 49
    high_max: int = 74
    critical_max: int = 89
    emergency_min: int = 90

    confirmation_min_score: int = 40
    biometric_min_score: int = 65
    admin_approval_min_score: int = 80
    automatic_block_min_score: int = 90

    destructive_action_base_score: int = 80
    financial_action_base_score: int = 85
    privacy_action_base_score: int = 70
    terminal_action_base_score: int = 65
    account_action_base_score: int = 75
    device_action_base_score: int = 60

    def validate(self) -> List[str]:
        errors: List[str] = []

        ordered_values = [
            self.low_max,
            self.medium_max,
            self.high_max,
            self.critical_max,
            self.emergency_min,
        ]

        if any(value < 0 or value > 100 for value in ordered_values):
            errors.append("Risk boundaries must be between 0 and 100.")

        if not (
            self.low_max
            < self.medium_max
            < self.high_max
            < self.critical_max
            < self.emergency_min
        ):
            errors.append("Risk level boundaries must be strictly increasing.")

        escalation_values = [
            self.confirmation_min_score,
            self.biometric_min_score,
            self.admin_approval_min_score,
            self.automatic_block_min_score,
        ]

        if any(value < 0 or value > 100 for value in escalation_values):
            errors.append("Escalation thresholds must be between 0 and 100.")

        if not (
            self.confirmation_min_score
            <= self.biometric_min_score
            <= self.admin_approval_min_score
            <= self.automatic_block_min_score
        ):
            errors.append(
                "Escalation thresholds must increase from confirmation to block."
            )

        base_scores = [
            self.destructive_action_base_score,
            self.financial_action_base_score,
            self.privacy_action_base_score,
            self.terminal_action_base_score,
            self.account_action_base_score,
            self.device_action_base_score,
        ]

        if any(value < 0 or value > 100 for value in base_scores):
            errors.append("Action base scores must be between 0 and 100.")

        return errors


@dataclass
class ProtectedPathPolicy:
    """
    Filesystem protection configuration.

    Protected path entries may contain:
        - Environment variables
        - Home-directory references
        - Absolute paths
        - Application-relative paths

    FileProtection must perform final canonical-path and symlink checks.
    """

    enabled: bool = True
    deny_delete: bool = True
    deny_recursive_delete: bool = True
    deny_permission_weakening: bool = True
    deny_ownership_change: bool = True
    deny_overwrite_without_backup: bool = True
    require_backup_before_write: bool = True
    require_approval_for_read: bool = False
    require_biometric_for_destructive_change: bool = True
    protect_symlink_targets: bool = True
    protect_parent_directories: bool = True
    case_sensitive: bool = field(default_factory=lambda: os.name != "nt")

    protected_folders: List[str] = field(
        default_factory=lambda: [
            "/",
            "/boot",
            "/etc",
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin",
            "/lib",
            "/lib64",
            "/var/lib",
            "/var/log",
            "/root",
            "/home",
            "/opt/william",
            "/srv/william",
            "/etc/william",
            "/var/lib/william",
            "/var/log/william",
            "~/.ssh",
            "~/.gnupg",
            "~/.aws",
            "~/.config/gcloud",
            "~/.kube",
            "${WILLIAM_HOME}",
            "${WILLIAM_DATA_DIR}",
            "${WILLIAM_CONFIG_DIR}",
            "C:/Windows",
            "C:/Windows/System32",
            "C:/Program Files",
            "C:/Program Files (x86)",
            "C:/ProgramData",
            "C:/Users",
        ]
    )

    protected_file_patterns: List[str] = field(
        default_factory=lambda: [
            "*.env",
            ".env",
            ".env.*",
            "*.pem",
            "*.key",
            "*.p12",
            "*.pfx",
            "*.crt",
            "*.cer",
            "*.jks",
            "*.keystore",
            "id_rsa",
            "id_ed25519",
            "authorized_keys",
            "known_hosts",
            "credentials.json",
            "service-account*.json",
            "*service_account*.json",
            "secrets*.json",
            "config/secrets.*",
            "*.sqlite",
            "*.sqlite3",
            "*.db",
            "*.bak",
            "*.backup",
            "docker-compose*.yml",
            "docker-compose*.yaml",
            "Dockerfile",
            "requirements*.txt",
            "pyproject.toml",
            "poetry.lock",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            ".git/config",
            ".git/HEAD",
            ".git/index",
        ]
    )

    excluded_safe_paths: List[str] = field(default_factory=list)

    def validate(self) -> List[str]:
        errors: List[str] = []

        if len(self.protected_folders) > MAX_PROTECTED_PATHS:
            errors.append("Too many protected folders configured.")

        if len(self.protected_file_patterns) > MAX_PROTECTED_PATHS:
            errors.append("Too many protected file patterns configured.")

        for path_value in self.protected_folders + self.excluded_safe_paths:
            if not isinstance(path_value, str):
                errors.append("Protected and excluded paths must be strings.")
                continue

            if len(path_value) > MAX_PATTERN_LENGTH:
                errors.append("A protected path exceeds the maximum length.")

        for pattern in self.protected_file_patterns:
            if not isinstance(pattern, str):
                errors.append("Protected file patterns must be strings.")
                continue

            if len(pattern) > MAX_PATTERN_LENGTH:
                errors.append("A protected file pattern exceeds maximum length.")

        return errors


@dataclass
class CommandPolicyConfig:
    """
    Command protection policy.

    Exact basenames and patterns are checked without executing a shell.
    """

    enabled: bool = True
    default_unknown_command_policy: str = CommandPolicy.AUDITED.value
    normalize_case: bool = True
    reject_null_bytes: bool = True
    reject_unbalanced_quotes: bool = True
    block_shell_operator_chaining_for_sensitive_commands: bool = True
    require_confirmation_for_restricted: bool = True
    require_biometric_for_destructive: bool = True
    require_admin_for_system_wide_changes: bool = True
    allow_read_only_diagnostics: bool = True
    audit_all_terminal_commands: bool = True

    blocked_command_basenames: List[str] = field(
        default_factory=lambda: [
            "format",
            "fdisk",
            "mkfs",
            "mkfs.ext2",
            "mkfs.ext3",
            "mkfs.ext4",
            "mkfs.xfs",
            "mkfs.btrfs",
            "diskpart",
            "dd",
            "shred",
            "wipefs",
            "sdelete",
            "cipher",
            "bcdedit",
            "bootrec",
            "reg",
            "regedit",
            "shutdown",
            "reboot",
            "halt",
            "poweroff",
            "init",
            "systemctl",
            "service",
            "iptables",
            "ip6tables",
            "nft",
            "ufw",
            "firewall-cmd",
            "netsh",
            "passwd",
            "chpasswd",
            "userdel",
            "groupdel",
            "deluser",
            "delgroup",
            "visudo",
            "chroot",
            "mount",
            "umount",
            "cryptsetup",
            "lvremove",
            "vgremove",
            "pvremove",
            "zpool",
            "zfs",
            "docker",
            "podman",
            "kubectl",
            "helm",
            "terraform",
            "ansible",
            "powershell",
            "pwsh",
            "cmd",
            "bash",
            "sh",
            "zsh",
            "fish",
        ]
    )

    always_blocked_patterns: List[str] = field(
        default_factory=lambda: [
            r"(?i)(^|\s)rm\s+-[^\n]*r[^\n]*f[^\n]*(/|\s/)",
            r"(?i)(^|\s)rm\s+-rf\s+(\*|/\*?|~/?\*?)",
            r"(?i)(^|\s)del\s+/[a-z]*[sq][a-z]*\s+([a-z]:\\|\\)",
            r"(?i)(^|\s)rmdir\s+/[a-z]*[sq][a-z]*\s+([a-z]:\\|\\)",
            r"(?i)(^|\s)format(\.com)?\s+[a-z]:",
            r"(?i)(^|\s)mkfs(\.[a-z0-9]+)?\s+",
            r"(?i)(^|\s)dd\s+.*\bof=/dev/(sd|nvme|vd|xvd)",
            r"(?i)(^|\s)wipefs\s+.*\s/dev/",
            r"(?i)(^|\s)shred\s+.*\s/dev/",
            r"(?i)(^|\s)chmod\s+(-R\s+)?777\s+(/|~|\$HOME)",
            r"(?i)(^|\s)chown\s+-R\s+.*\s+(/|~|\$HOME)",
            r"(?i)(^|\s)(shutdown|reboot|halt|poweroff)\b",
            r"(?i)(^|\s)(userdel|deluser)\b",
            r"(?i)(^|\s)(iptables|nft)\s+(-F|flush)\b",
            r"(?i)(^|\s)netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off",
            r"(?i)(^|\s)bcdedit\s+.*\bdelete\b",
            r"(?i)(^|\s)reg\s+delete\b",
            r"(?i)(^|\s)docker\s+system\s+prune\s+(-a|--all)",
            r"(?i)(^|\s)docker\s+(rm|rmi)\s+-f\b",
            r"(?i)(^|\s)kubectl\s+delete\s+(namespace|ns|node|crd)\b",
            r"(?i)(^|\s)terraform\s+destroy\b",
            r"(?i)(^|\s)DROP\s+(DATABASE|SCHEMA)\b",
            r"(?i)(^|\s)TRUNCATE\s+TABLE\b",
        ]
    )

    restricted_command_basenames: List[str] = field(
        default_factory=lambda: [
            "rm",
            "rmdir",
            "del",
            "erase",
            "move",
            "mv",
            "cp",
            "copy",
            "chmod",
            "chown",
            "icacls",
            "takeown",
            "kill",
            "killall",
            "pkill",
            "taskkill",
            "apt",
            "apt-get",
            "dnf",
            "yum",
            "pacman",
            "zypper",
            "brew",
            "pip",
            "pip3",
            "npm",
            "yarn",
            "pnpm",
            "git",
            "curl",
            "wget",
            "scp",
            "sftp",
            "ssh",
            "rsync",
            "crontab",
            "schtasks",
            "launchctl",
            "pm2",
            "supervisorctl",
            "mysql",
            "psql",
            "sqlite3",
            "mongosh",
            "redis-cli",
        ]
    )

    safe_read_only_basenames: List[str] = field(
        default_factory=lambda: [
            "pwd",
            "whoami",
            "id",
            "hostname",
            "date",
            "uptime",
            "uname",
            "ver",
            "where",
            "which",
            "type",
            "echo",
            "printf",
            "ls",
            "dir",
            "find",
            "whereis",
            "stat",
            "file",
            "cat",
            "head",
            "tail",
            "less",
            "more",
            "wc",
            "grep",
            "rg",
            "sed",
            "awk",
            "sort",
            "uniq",
            "ps",
            "top",
            "tasklist",
            "ipconfig",
            "ifconfig",
            "ip",
            "ping",
            "traceroute",
            "tracert",
            "nslookup",
            "dig",
            "netstat",
            "ss",
            "df",
            "du",
            "free",
            "vmstat",
            "lscpu",
            "lsblk",
            "git",
            "python",
            "python3",
            "node",
            "php",
        ]
    )

    blocked_argument_fragments: List[str] = field(
        default_factory=lambda: [
            "--no-preserve-root",
            "--force --all",
            "--delete-all",
            "--purge-all",
            "--disable-security",
            "--disable-firewall",
            "--disable-antivirus",
            "--skip-confirmation",
            "--no-confirm",
            "/quiet /norestart",
        ]
    )

    def validate(self) -> List[str]:
        errors: List[str] = []

        valid_default_policies = {item.value for item in CommandPolicy}

        if self.default_unknown_command_policy not in valid_default_policies:
            errors.append("Invalid default unknown command policy.")

        collections = [
            self.blocked_command_basenames,
            self.always_blocked_patterns,
            self.restricted_command_basenames,
            self.safe_read_only_basenames,
            self.blocked_argument_fragments,
        ]

        if any(len(collection) > MAX_COMMAND_PATTERNS for collection in collections):
            errors.append("Too many command policy patterns configured.")

        for pattern in self.always_blocked_patterns:
            if len(pattern) > MAX_PATTERN_LENGTH:
                errors.append("A blocked command pattern exceeds maximum length.")
                continue

            try:
                re.compile(pattern)
            except re.error as exc:
                errors.append(f"Invalid blocked command regex: {exc}")

        return errors


@dataclass
class BiometricPolicy:
    """Biometric Gate configuration."""

    enabled: bool = True
    allow_pin_fallback: bool = True
    allow_totp_fallback: bool = True
    allow_passkey: bool = True
    allow_voice_biometric: bool = True
    allow_face_biometric: bool = True
    allow_fingerprint_biometric: bool = True
    allow_trusted_device_factor: bool = True

    require_liveness_detection: bool = True
    require_fresh_verification: bool = True
    bind_verification_to_action: bool = True
    bind_verification_to_user: bool = True
    bind_verification_to_workspace: bool = True
    bind_verification_to_device: bool = True

    verification_validity_seconds: int = 180
    sensitive_verification_validity_seconds: int = 60
    maximum_attempts: int = 5
    lockout_seconds: int = 900
    confidence_threshold: float = 0.82
    voice_confidence_threshold: float = 0.86
    face_confidence_threshold: float = 0.88
    liveness_confidence_threshold: float = 0.85

    required_for_payments: bool = True
    required_for_bank_actions: bool = True
    required_for_account_recovery: bool = True
    required_for_password_changes: bool = True
    required_for_security_config_changes: bool = True
    required_for_protected_file_changes: bool = True
    required_for_destructive_commands: bool = True
    required_for_exporting_sensitive_data: bool = True
    required_for_disabling_security: bool = True
    required_for_new_unknown_devices: bool = True

    preferred_methods: List[str] = field(
        default_factory=lambda: [
            BiometricMethod.PASSKEY.value,
            BiometricMethod.FINGERPRINT.value,
            BiometricMethod.FACE.value,
            BiometricMethod.PIN.value,
        ]
    )

    def validate(self) -> List[str]:
        errors: List[str] = []

        if self.verification_validity_seconds < 15:
            errors.append("Biometric verification validity must be at least 15 seconds.")

        if self.sensitive_verification_validity_seconds < 10:
            errors.append(
                "Sensitive biometric validity must be at least 10 seconds."
            )

        if self.maximum_attempts < 1 or self.maximum_attempts > 20:
            errors.append("Biometric maximum attempts must be between 1 and 20.")

        if self.lockout_seconds < 30:
            errors.append("Biometric lockout must be at least 30 seconds.")

        confidence_values = [
            self.confidence_threshold,
            self.voice_confidence_threshold,
            self.face_confidence_threshold,
            self.liveness_confidence_threshold,
        ]

        if any(value < 0.0 or value > 1.0 for value in confidence_values):
            errors.append("Biometric confidence thresholds must be between 0 and 1.")

        allowed_methods = {method.value for method in BiometricMethod}

        if len(self.preferred_methods) > MAX_ALLOWED_BIOMETRIC_METHODS:
            errors.append("Too many preferred biometric methods.")

        for method in self.preferred_methods:
            if method not in allowed_methods:
                errors.append(f"Unsupported biometric method: {method}")

        return errors


@dataclass
class ApprovalPolicy:
    """Approval Manager configuration."""

    approval_ttl_seconds: int = 300
    high_risk_approval_ttl_seconds: int = 120
    one_time_approval_only: bool = True
    bind_approval_to_action_hash: bool = True
    bind_approval_to_actor: bool = True
    bind_approval_to_workspace: bool = True
    bind_approval_to_device: bool = True
    prevent_self_approval_for_admin_actions: bool = True
    require_reason_for_denial: bool = False
    require_reason_for_admin_approval: bool = True
    audit_approval_payload_hash: bool = True

    always_confirm_actions: List[str] = field(
        default_factory=lambda: [
            "file.delete",
            "file.overwrite",
            "file.move_protected",
            "terminal.execute_restricted",
            "browser.download_executable",
            "browser.submit_sensitive_form",
            "message.send_external",
            "email.send",
            "email.forward_sensitive",
            "call.place",
            "workflow.publish",
            "workflow.enable",
            "agent.install_plugin",
            "agent.disable",
            "device.remove",
            "session.revoke",
            "memory.export",
            "memory.delete",
            "account.change_email",
            "account.change_password",
        ]
    )

    always_biometric_actions: List[str] = field(
        default_factory=lambda: [
            "payment.initiate",
            "payment.confirm",
            "bank.transfer",
            "bank.add_recipient",
            "security.disable",
            "security.config.update",
            "security.emergency_unlock",
            "file.delete_protected",
            "terminal.execute_destructive",
            "account.recovery",
            "account.delete",
            "privacy.export_sensitive",
            "device.trust_unknown",
        ]
    )

    always_block_actions: List[str] = field(
        default_factory=lambda: [
            "payment.auto_pay_without_confirmation",
            "bank.auto_transfer_without_confirmation",
            "security.disable_without_verification",
            "security.bypass",
            "audit.delete",
            "audit.modify",
            "biometric.bypass",
            "workspace.cross_tenant_access",
            "memory.cross_tenant_access",
            "secret.expose_plaintext",
            "malware.execute",
            "credential.exfiltrate",
        ]
    )

    def validate(self) -> List[str]:
        errors: List[str] = []

        if self.approval_ttl_seconds < 15:
            errors.append("Approval TTL must be at least 15 seconds.")

        if self.high_risk_approval_ttl_seconds < 10:
            errors.append("High-risk approval TTL must be at least 10 seconds.")

        if self.high_risk_approval_ttl_seconds > self.approval_ttl_seconds:
            errors.append("High-risk approval TTL cannot exceed normal approval TTL.")

        return errors


@dataclass
class DeviceSecurityPolicy:
    """Trusted device and unknown-device protection settings."""

    require_device_registration: bool = True
    block_revoked_devices: bool = True
    block_rooted_or_jailbroken_devices: bool = True
    require_biometric_for_unknown_device: bool = True
    require_email_notice_for_new_device: bool = True
    require_security_notice_for_ip_change: bool = True
    allow_multiple_active_devices: bool = True
    automatically_expire_inactive_devices: bool = True
    allow_workspace_admin_device_revocation: bool = True

    maximum_active_devices_per_user: int = 10
    trusted_device_validity_days: int = 90
    inactive_device_expiry_days: int = 45
    new_device_restriction_minutes: int = 30
    failed_device_attempt_limit: int = 5
    device_lockout_minutes: int = 30

    def validate(self) -> List[str]:
        errors: List[str] = []

        if self.maximum_active_devices_per_user < 1:
            errors.append("At least one active device must be allowed.")

        if self.trusted_device_validity_days < 1:
            errors.append("Trusted device validity must be at least one day.")

        if self.failed_device_attempt_limit < 1:
            errors.append("Failed device attempt limit must be positive.")

        return errors


@dataclass
class SessionSecurityPolicy:
    """Session Guard settings."""

    idle_timeout_minutes: int = 30
    absolute_timeout_hours: int = 12
    sensitive_action_reauth_minutes: int = 10
    rotate_session_after_login: bool = True
    rotate_session_after_privilege_change: bool = True
    invalidate_sessions_after_password_change: bool = True
    invalidate_sessions_after_emergency_lock: bool = True
    bind_session_to_workspace: bool = True
    bind_session_to_device: bool = True
    enforce_secure_cookie: bool = True
    enforce_http_only_cookie: bool = True
    enforce_same_site_cookie: bool = True
    allow_concurrent_sessions: bool = True
    maximum_concurrent_sessions: int = 8

    def validate(self) -> List[str]:
        errors: List[str] = []

        if self.idle_timeout_minutes < 1:
            errors.append("Session idle timeout must be at least one minute.")

        if self.absolute_timeout_hours < 1:
            errors.append("Session absolute timeout must be at least one hour.")

        if self.maximum_concurrent_sessions < 1:
            errors.append("Maximum concurrent sessions must be positive.")

        return errors


@dataclass
class FraudDetectionPolicy:
    """Fraud Detector settings."""

    enabled: bool = True
    phishing_detection_enabled: bool = True
    invoice_fraud_detection_enabled: bool = True
    payment_fraud_detection_enabled: bool = True
    fake_login_detection_enabled: bool = True
    domain_similarity_detection_enabled: bool = True
    suspicious_attachment_detection_enabled: bool = True
    malicious_redirect_detection_enabled: bool = True

    block_score: int = 90
    biometric_score: int = 75
    confirmation_score: int = 55
    domain_similarity_threshold: float = 0.82
    invoice_amount_deviation_ratio: float = 2.5
    suspicious_link_limit: int = 3
    maximum_redirect_chain: int = 5

    def validate(self) -> List[str]:
        errors: List[str] = []

        if not (
            0
            <= self.confirmation_score
            <= self.biometric_score
            <= self.block_score
            <= 100
        ):
            errors.append("Fraud escalation scores are invalid.")

        if not 0.0 <= self.domain_similarity_threshold <= 1.0:
            errors.append("Domain similarity threshold must be between 0 and 1.")

        if self.invoice_amount_deviation_ratio < 1.0:
            errors.append("Invoice deviation ratio cannot be less than 1.0.")

        return errors


@dataclass
class AnomalyDetectionPolicy:
    """Anomaly Detector thresholds."""

    enabled: bool = True
    detect_unusual_devices: bool = True
    detect_unusual_voice: bool = True
    detect_command_bursts: bool = True
    detect_failed_attempt_bursts: bool = True
    detect_mass_exports: bool = True
    detect_unusual_locations: bool = True
    detect_rapid_workspace_switching: bool = True

    failed_attempt_window_seconds: int = 300
    failed_attempt_limit: int = 8
    command_window_seconds: int = 60
    command_limit: int = 40
    mass_export_record_limit: int = 1000
    mass_export_bytes_limit: int = 100 * 1024 * 1024
    workspace_switch_limit_per_hour: int = 20
    anomaly_score_for_confirmation: int = 50
    anomaly_score_for_biometric: int = 70
    anomaly_score_for_lock: int = 90

    def validate(self) -> List[str]:
        errors: List[str] = []

        if self.failed_attempt_limit < 1:
            errors.append("Failed-attempt limit must be positive.")

        if self.command_limit < 1:
            errors.append("Command limit must be positive.")

        if self.mass_export_record_limit < 1:
            errors.append("Mass-export record limit must be positive.")

        if not (
            0
            <= self.anomaly_score_for_confirmation
            <= self.anomaly_score_for_biometric
            <= self.anomaly_score_for_lock
            <= 100
        ):
            errors.append("Anomaly escalation scores are invalid.")

        return errors


@dataclass
class PaymentSecurityPolicy:
    """Payment Guard settings. William must never auto-pay."""

    never_auto_pay: bool = True
    never_auto_transfer: bool = True
    require_explicit_confirmation: bool = True
    require_biometric: bool = True
    require_amount_and_recipient_display: bool = True
    require_currency_display: bool = True
    require_fresh_approval: bool = True
    require_duplicate_payment_check: bool = True
    require_recipient_trust_check: bool = True
    block_hidden_fee_payments: bool = True
    block_recipient_mismatch: bool = True
    block_currency_mismatch: bool = True

    payment_approval_validity_seconds: int = 60
    duplicate_payment_window_minutes: int = 60
    high_value_payment_minor_units: int = 100_000
    maximum_unverified_payment_minor_units: int = 0
    new_recipient_cooldown_minutes: int = 30

    def validate(self) -> List[str]:
        errors: List[str] = []

        if not self.never_auto_pay:
            errors.append("never_auto_pay must remain enabled.")

        if not self.never_auto_transfer:
            errors.append("never_auto_transfer must remain enabled.")

        if not self.require_explicit_confirmation:
            errors.append("Explicit payment confirmation must remain enabled.")

        if self.maximum_unverified_payment_minor_units != 0:
            errors.append("Unverified payment limit must remain zero.")

        if self.payment_approval_validity_seconds < 10:
            errors.append("Payment approval validity must be at least 10 seconds.")

        return errors


@dataclass
class PrivacySecurityPolicy:
    """Privacy Guard settings."""

    redact_secrets_in_logs: bool = True
    redact_private_content_in_events: bool = True
    prevent_cross_workspace_access: bool = True
    prevent_cross_user_access: bool = True
    prevent_plaintext_secret_output: bool = True
    prevent_sensitive_screenshot_exposure: bool = True
    prevent_clipboard_secret_persistence: bool = True
    encrypt_sensitive_data_at_rest: bool = True
    encrypt_sensitive_data_in_transit: bool = True
    require_approval_for_sensitive_export: bool = True
    require_biometric_for_sensitive_export: bool = True
    audit_sensitive_reads: bool = True

    maximum_log_value_length: int = 2048
    maximum_event_value_length: int = 4096
    sensitive_export_record_limit: int = 100

    protected_key_patterns: List[str] = field(
        default_factory=lambda: [
            "*password*",
            "*secret*",
            "*token*",
            "*api_key*",
            "*private_key*",
            "*credential*",
            "*authorization*",
            "*cookie*",
            "*session*",
            "*bank*",
            "*card*",
            "*cvv*",
            "*pin*",
            "*biometric*",
        ]
    )

    def validate(self) -> List[str]:
        errors: List[str] = []

        if not self.prevent_cross_workspace_access:
            errors.append("Cross-workspace protection cannot be disabled.")

        if not self.prevent_cross_user_access:
            errors.append("Cross-user protection cannot be disabled.")

        if not self.prevent_plaintext_secret_output:
            errors.append("Plaintext secret-output prevention cannot be disabled.")

        if self.maximum_log_value_length < 64:
            errors.append("Maximum log value length is too small.")

        return errors


@dataclass
class ThreatMonitoringPolicy:
    """Threat Monitor settings."""

    enabled: bool = True
    monitor_processes: bool = True
    monitor_scripts: bool = True
    monitor_downloads: bool = True
    monitor_browser_extensions: bool = True
    monitor_network_behavior: bool = True
    monitor_persistence_changes: bool = True
    monitor_privilege_escalation: bool = True

    suspicious_download_score: int = 65
    malicious_download_score: int = 90
    suspicious_process_score: int = 70
    malicious_process_score: int = 95
    maximum_download_size_bytes: int = 2 * 1024 * 1024 * 1024
    executable_download_requires_confirmation: bool = True
    executable_download_requires_scan: bool = True
    unsigned_executable_requires_biometric: bool = True

    blocked_extension_patterns: List[str] = field(
        default_factory=lambda: [
            "*.exe",
            "*.msi",
            "*.dll",
            "*.scr",
            "*.com",
            "*.bat",
            "*.cmd",
            "*.ps1",
            "*.vbs",
            "*.js",
            "*.jar",
            "*.apk",
            "*.dmg",
            "*.pkg",
            "*.deb",
            "*.rpm",
            "*.appimage",
        ]
    )

    def validate(self) -> List[str]:
        errors: List[str] = []

        score_values = [
            self.suspicious_download_score,
            self.malicious_download_score,
            self.suspicious_process_score,
            self.malicious_process_score,
        ]

        if any(value < 0 or value > 100 for value in score_values):
            errors.append("Threat scores must be between 0 and 100.")

        if self.suspicious_download_score > self.malicious_download_score:
            errors.append("Suspicious download score cannot exceed malicious score.")

        if self.maximum_download_size_bytes < 1:
            errors.append("Maximum download size must be positive.")

        return errors


@dataclass
class EmergencyLockPolicy:
    """Emergency Lock settings."""

    enabled: bool = True
    lock_on_critical_threat: bool = True
    lock_on_repeated_biometric_failure: bool = True
    lock_on_security_bypass_attempt: bool = True
    lock_on_cross_tenant_access_attempt: bool = True
    revoke_active_sessions: bool = True
    pause_agent_execution: bool = True
    block_outbound_actions: bool = True
    preserve_audit_logs: bool = True
    preserve_evidence: bool = True
    require_biometric_to_unlock: bool = True
    require_admin_to_unlock: bool = True
    notify_workspace_owners: bool = True

    biometric_failure_lock_threshold: int = 10
    bypass_attempt_lock_threshold: int = 3
    cross_tenant_attempt_lock_threshold: int = 1
    minimum_lock_seconds: int = 900
    evidence_retention_days: int = 90

    def validate(self) -> List[str]:
        errors: List[str] = []

        if not self.preserve_audit_logs:
            errors.append("Emergency lock must preserve audit logs.")

        if self.cross_tenant_attempt_lock_threshold < 1:
            errors.append("Cross-tenant lock threshold must be at least one.")

        if self.minimum_lock_seconds < 60:
            errors.append("Minimum emergency lock duration must be at least 60 seconds.")

        return errors


@dataclass
class AuditSecurityPolicy:
    """Audit Logger settings."""

    enabled: bool = True
    append_only: bool = True
    tamper_evident_hash_chain: bool = True
    redact_sensitive_values: bool = True
    include_user_id: bool = True
    include_workspace_id: bool = True
    include_actor_id: bool = True
    include_device_id: bool = True
    include_request_id: bool = True
    include_policy_decision: bool = True
    include_risk_score: bool = True
    include_payload_hash: bool = True
    prevent_agent_log_deletion: bool = True

    retention_days: int = 365
    security_event_retention_days: int = 730
    maximum_payload_preview_chars: int = 2048

    def validate(self) -> List[str]:
        errors: List[str] = []

        if not self.append_only:
            errors.append("Security audit logs must remain append-only.")

        if not self.prevent_agent_log_deletion:
            errors.append("Agents must not be allowed to delete audit logs.")

        if self.retention_days < 30:
            errors.append("Audit retention must be at least 30 days.")

        return errors


@dataclass
class SecurityFeatureFlags:
    """
    Central feature flags.

    Security-critical flags default to enabled. Tenant overrides cannot disable
    immutable safety flags through the normal override interface.
    """

    security_agent_enabled: bool = True
    policy_engine_enabled: bool = True
    permission_checker_enabled: bool = True
    risk_engine_enabled: bool = True
    audit_logger_enabled: bool = True
    approval_manager_enabled: bool = True
    biometric_gate_enabled: bool = True
    fraud_detector_enabled: bool = True
    anomaly_detector_enabled: bool = True
    device_access_enabled: bool = True
    file_protection_enabled: bool = True
    payment_guard_enabled: bool = True
    app_lock_enabled: bool = True
    session_guard_enabled: bool = True
    privacy_guard_enabled: bool = True
    threat_monitor_enabled: bool = True
    emergency_lock_enabled: bool = True

    allow_workspace_policy_strengthening: bool = True
    allow_workspace_policy_weakening: bool = False
    allow_user_policy_strengthening: bool = True
    allow_user_policy_weakening: bool = False
    allow_environment_overrides: bool = True
    allow_runtime_overrides: bool = True

    def validate(self) -> List[str]:
        errors: List[str] = []

        mandatory_flags = {
            "security_agent_enabled": self.security_agent_enabled,
            "policy_engine_enabled": self.policy_engine_enabled,
            "permission_checker_enabled": self.permission_checker_enabled,
            "audit_logger_enabled": self.audit_logger_enabled,
            "privacy_guard_enabled": self.privacy_guard_enabled,
        }

        for name, enabled in mandatory_flags.items():
            if not enabled:
                errors.append(f"Mandatory security flag cannot be disabled: {name}")

        if self.allow_workspace_policy_weakening:
            errors.append("Workspace policy weakening must remain disabled.")

        if self.allow_user_policy_weakening:
            errors.append("User policy weakening must remain disabled.")

        return errors


@dataclass
class SecurityTaskContext:
    """SaaS context for configuration reads and updates."""

    user_id: str
    workspace_id: str
    actor_id: Optional[str] = None
    role: Optional[str] = None
    device_id: Optional[str] = None
    request_id: Optional[str] = None
    subscription_plan: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityConfigurationData:
    """Complete configuration data model."""

    config_version: str = CONFIG_VERSION
    schema_version: str = CONFIG_SCHEMA_VERSION
    environment: str = "production"
    strict_mode: bool = True
    fail_closed: bool = True
    generated_at: str = field(default_factory=utc_now_iso)

    risk: RiskThresholds = field(default_factory=RiskThresholds)
    paths: ProtectedPathPolicy = field(default_factory=ProtectedPathPolicy)
    commands: CommandPolicyConfig = field(default_factory=CommandPolicyConfig)
    biometric: BiometricPolicy = field(default_factory=BiometricPolicy)
    approvals: ApprovalPolicy = field(default_factory=ApprovalPolicy)
    devices: DeviceSecurityPolicy = field(default_factory=DeviceSecurityPolicy)
    sessions: SessionSecurityPolicy = field(default_factory=SessionSecurityPolicy)
    fraud: FraudDetectionPolicy = field(default_factory=FraudDetectionPolicy)
    anomaly: AnomalyDetectionPolicy = field(default_factory=AnomalyDetectionPolicy)
    payments: PaymentSecurityPolicy = field(default_factory=PaymentSecurityPolicy)
    privacy: PrivacySecurityPolicy = field(default_factory=PrivacySecurityPolicy)
    threats: ThreatMonitoringPolicy = field(default_factory=ThreatMonitoringPolicy)
    emergency_lock: EmergencyLockPolicy = field(default_factory=EmergencyLockPolicy)
    audit: AuditSecurityPolicy = field(default_factory=AuditSecurityPolicy)
    features: SecurityFeatureFlags = field(default_factory=SecurityFeatureFlags)

    metadata: Dict[str, Any] = field(
        default_factory=lambda: {
            "project": "William / Jarvis",
            "brand": "Digital Promotix",
            "module": "Security Agent",
        }
    )

    def validate(self) -> List[str]:
        """Validate the full configuration."""
        errors: List[str] = []

        if not self.config_version:
            errors.append("config_version is required.")

        if not self.schema_version:
            errors.append("schema_version is required.")

        if not self.strict_mode:
            errors.append("Security configuration must remain in strict mode.")

        if not self.fail_closed:
            errors.append("Security configuration must remain fail-closed.")

        sections = [
            self.risk,
            self.paths,
            self.commands,
            self.biometric,
            self.approvals,
            self.devices,
            self.sessions,
            self.fraud,
            self.anomaly,
            self.payments,
            self.privacy,
            self.threats,
            self.emergency_lock,
            self.audit,
            self.features,
        ]

        for section in sections:
            validate_method = getattr(section, "validate", None)

            if callable(validate_method):
                errors.extend(validate_method())

        return errors


# ============================================================================
# SecurityConfig
# ============================================================================

class SecurityConfig(BaseAgent):
    """
    Production security configuration provider.

    The class stores immutable safe defaults plus isolated tenant overrides.
    It does not execute system actions.

    Public methods return William-standard structured dictionaries:
        {
            "success": bool,
            "message": str,
            "data": dict,
            "error": str | None,
            "metadata": dict
        }
    """

    IMMUTABLE_SAFETY_PATHS: ClassVar[Set[str]] = {
        "strict_mode",
        "fail_closed",
        "payments.never_auto_pay",
        "payments.never_auto_transfer",
        "payments.require_explicit_confirmation",
        "payments.maximum_unverified_payment_minor_units",
        "privacy.prevent_cross_workspace_access",
        "privacy.prevent_cross_user_access",
        "privacy.prevent_plaintext_secret_output",
        "audit.append_only",
        "audit.prevent_agent_log_deletion",
        "emergency_lock.preserve_audit_logs",
        "features.security_agent_enabled",
        "features.policy_engine_enabled",
        "features.permission_checker_enabled",
        "features.audit_logger_enabled",
        "features.privacy_guard_enabled",
        "features.allow_workspace_policy_weakening",
        "features.allow_user_policy_weakening",
    }

    SENSITIVE_UPDATE_ACTIONS: ClassVar[Set[str]] = {
        "security.config.update",
        "security.config.reset",
        "security.config.import",
        "security.paths.update",
        "security.commands.update",
        "security.biometric.update",
        "security.thresholds.update",
        "security.features.update",
    }

    def __init__(
        self,
        config: Optional[Union[SecurityConfigurationData, Mapping[str, Any]]] = None,
        *,
        security_agent: Optional[Any] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        environment: Optional[Mapping[str, str]] = None,
        env_prefix: str = DEFAULT_ENV_PREFIX,
        logger_instance: Optional[logging.Logger] = None,
        load_environment: bool = True,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(agent_name=AGENT_NAME, **kwargs)
        except TypeError:
            try:
                super().__init__()
            except Exception:
                pass

        self.agent_name = AGENT_NAME
        self.logger = logger_instance or logging.getLogger(__name__)
        self.security_agent = security_agent or SecurityAgent()
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.env_prefix = str(env_prefix or DEFAULT_ENV_PREFIX)
        self._environment = dict(environment or os.environ)
        self._lock = threading.RLock()

        self._workspace_overrides: Dict[str, Dict[str, Any]] = {}
        self._user_overrides: Dict[str, Dict[str, Any]] = {}
        self._user_workspace_overrides: Dict[str, Dict[str, Any]] = {}

        self._base_config = self._build_base_config(config)

        if load_environment and self._base_config.features.allow_environment_overrides:
            environment_overrides = self._load_environment_overrides()
            if environment_overrides:
                merged = deep_merge(
                    dataclass_to_dict(self._base_config),
                    environment_overrides,
                )
                self._base_config = self._configuration_from_mapping(merged)

        validation_errors = self._base_config.validate()

        if validation_errors:
            raise ValueError(
                "Invalid SecurityConfig initialization: "
                + "; ".join(validation_errors)
            )

        self._base_config_hash = self._calculate_config_hash(self._base_config)

    # ------------------------------------------------------------------
    # Agent Router / Master Agent compatibility
    # ------------------------------------------------------------------

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Route configuration operations from Master Agent or Agent Router.

        Supported operations:
            - get_config
            - get_public_config
            - get_manifest
            - validate_config
            - classify_command
            - classify_path
            - evaluate_risk_score
            - requires_biometric
            - apply_override
            - remove_override
            - reset_overrides
            - export_config
        """
        try:
            if not isinstance(task, dict):
                return self._error_result(
                    "Task must be a dictionary.",
                    code="INVALID_TASK",
                )

            operation = str(task.get("operation") or "").strip()
            context = self._context_from_mapping(task.get("context") or {})
            data = task.get("data") or {}

            validation = self._validate_task_context(
                context,
                require_user_workspace=operation not in {
                    "get_manifest",
                    "validate_config",
                },
            )

            if not validation["success"]:
                return validation

            if operation == "get_config":
                return self.get_config(
                    context=context,
                    include_internal=bool(data.get("include_internal", False)),
                )

            if operation == "get_public_config":
                return self.get_public_config(context=context)

            if operation == "get_manifest":
                return self.get_manifest()

            if operation == "validate_config":
                return self.validate_configuration(data.get("config"))

            if operation == "classify_command":
                return self.classify_command(
                    command=str(data.get("command") or ""),
                    context=context,
                )

            if operation == "classify_path":
                return self.classify_path(
                    path_value=str(data.get("path") or ""),
                    operation=str(data.get("path_operation") or "read"),
                    context=context,
                )

            if operation == "evaluate_risk_score":
                return self.evaluate_risk_score(
                    score=data.get("score", 0),
                    context=context,
                )

            if operation == "requires_biometric":
                return self.requires_biometric(
                    action=str(data.get("action") or ""),
                    risk_score=data.get("risk_score"),
                    context=context,
                )

            if operation == "apply_override":
                return self.apply_override(
                    context=context,
                    overrides=data.get("overrides") or {},
                    scope=data.get("scope", OverrideScope.USER_WORKSPACE.value),
                )

            if operation == "remove_override":
                return self.remove_override(
                    context=context,
                    scope=data.get("scope", OverrideScope.USER_WORKSPACE.value),
                    keys=data.get("keys"),
                )

            if operation == "reset_overrides":
                return self.reset_overrides(
                    context=context,
                    scope=data.get("scope", OverrideScope.USER_WORKSPACE.value),
                )

            if operation == "export_config":
                return self.export_config(
                    context=context,
                    public_only=bool(data.get("public_only", True)),
                )

            return self._error_result(
                f"Unsupported SecurityConfig operation: {operation}",
                code="UNSUPPORTED_OPERATION",
                metadata={
                    "supported_operations": self.get_manifest()["data"][
                        "supported_operations"
                    ]
                },
            )

        except Exception as exc:
            self.logger.exception("SecurityConfig.run failed.")
            return self._error_result(
                "Security configuration task failed.",
                error=str(exc),
                code="SECURITY_CONFIG_RUN_FAILED",
            )

    def get_manifest(self) -> Dict[str, Any]:
        """Return Agent Registry and Agent Loader metadata."""
        return self._safe_result(
            message="SecurityConfig manifest loaded.",
            data={
                "agent_name": self.agent_name,
                "class_name": self.__class__.__name__,
                "module": "agents.security_agent.config",
                "file": "config.py",
                "version": CONFIG_VERSION,
                "schema_version": CONFIG_SCHEMA_VERSION,
                "purpose": (
                    "Security thresholds, protected folders, blocked commands, "
                    "and biometric flags."
                ),
                "supported_operations": [
                    "get_config",
                    "get_public_config",
                    "get_manifest",
                    "validate_config",
                    "classify_command",
                    "classify_path",
                    "evaluate_risk_score",
                    "requires_biometric",
                    "apply_override",
                    "remove_override",
                    "reset_overrides",
                    "export_config",
                ],
                "registry_compatible": True,
                "router_compatible": True,
                "master_agent_compatible": True,
                "fastapi_ready": True,
                "requires_user_workspace_context": True,
                "stores_secrets": False,
            },
            metadata={
                "generated_at": utc_now_iso(),
            },
        )

    # ------------------------------------------------------------------
    # Configuration access
    # ------------------------------------------------------------------

    def get_config(
        self,
        context: SecurityTaskContext,
        *,
        include_internal: bool = False,
    ) -> Dict[str, Any]:
        """
        Get effective isolated configuration.

        Internal configuration should only be returned to trusted Security Agent
        components or authorized administrators.
        """
        validation = self._validate_task_context(context)

        if not validation["success"]:
            return validation

        try:
            effective = self._get_effective_configuration(context)
            payload = dataclass_to_dict(effective)

            if not include_internal:
                payload = self._make_public_config(payload)

            return self._safe_result(
                message="Effective security configuration loaded.",
                data={
                    "config": payload,
                    "config_hash": self._calculate_config_hash(effective),
                    "scope": {
                        "user_id": context.user_id,
                        "workspace_id": context.workspace_id,
                    },
                },
                metadata={
                    "include_internal": include_internal,
                    "schema_version": effective.schema_version,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to load effective configuration.")
            return self._error_result(
                "Failed to load security configuration.",
                error=str(exc),
                code="CONFIG_LOAD_FAILED",
            )

    def get_public_config(
        self,
        context: SecurityTaskContext,
    ) -> Dict[str, Any]:
        """Return dashboard/API-safe redacted configuration."""
        return self.get_config(context=context, include_internal=False)

    def export_config(
        self,
        context: SecurityTaskContext,
        *,
        public_only: bool = True,
    ) -> Dict[str, Any]:
        """Export configuration as a JSON-safe mapping."""
        validation = self._validate_task_context(context)

        if not validation["success"]:
            return validation

        try:
            effective = self._get_effective_configuration(context)
            payload = dataclass_to_dict(effective)

            if public_only:
                payload = self._make_public_config(payload)
            else:
                payload = redact_mapping(payload)

            export_payload = {
                "export_id": str(uuid.uuid4()),
                "schema_version": effective.schema_version,
                "config_version": effective.config_version,
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "public_only": public_only,
                "config_hash": stable_hash(payload),
                "exported_at": utc_now_iso(),
                "config": payload,
            }

            self._log_audit_event(
                context=context,
                action="security.config.export",
                payload={
                    "public_only": public_only,
                    "config_hash": export_payload["config_hash"],
                },
            )

            return self._safe_result(
                message="Security configuration exported.",
                data=export_payload,
                metadata={
                    "operation": "export_config",
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to export security configuration.",
                error=str(exc),
                code="CONFIG_EXPORT_FAILED",
            )

    # ------------------------------------------------------------------
    # Configuration validation and updates
    # ------------------------------------------------------------------

    def validate_configuration(
        self,
        config: Optional[Union[SecurityConfigurationData, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Validate a complete or partial configuration payload."""
        try:
            if config is None:
                target = copy.deepcopy(self._base_config)
            elif isinstance(config, SecurityConfigurationData):
                target = copy.deepcopy(config)
            elif isinstance(config, Mapping):
                merged = deep_merge(
                    dataclass_to_dict(self._base_config),
                    dict(config),
                )
                target = self._configuration_from_mapping(merged)
            else:
                return self._error_result(
                    "Configuration must be a mapping or SecurityConfigurationData.",
                    code="INVALID_CONFIG_TYPE",
                )

            errors = target.validate()

            return self._safe_result(
                message=(
                    "Security configuration is valid."
                    if not errors
                    else "Security configuration validation failed."
                ),
                data={
                    "valid": not errors,
                    "errors": errors,
                    "config_hash": self._calculate_config_hash(target),
                },
                metadata={
                    "schema_version": target.schema_version,
                },
            ) if not errors else self._error_result(
                "Security configuration validation failed.",
                error="; ".join(errors),
                code="CONFIG_VALIDATION_FAILED",
                data={
                    "valid": False,
                    "errors": errors,
                },
            )

        except Exception as exc:
            return self._error_result(
                "Configuration validation raised an error.",
                error=str(exc),
                code="CONFIG_VALIDATION_EXCEPTION",
            )

    def apply_override(
        self,
        context: SecurityTaskContext,
        overrides: Mapping[str, Any],
        scope: Union[str, OverrideScope] = OverrideScope.USER_WORKSPACE,
    ) -> Dict[str, Any]:
        """
        Apply a validated, isolated runtime override.

        Normal tenant overrides may strengthen security but cannot alter immutable
        safety properties.
        """
        validation = self._validate_task_context(context)

        if not validation["success"]:
            return validation

        if not isinstance(overrides, Mapping):
            return self._error_result(
                "Overrides must be a mapping.",
                code="INVALID_OVERRIDE_TYPE",
            )

        try:
            normalized_scope = OverrideScope(str(scope))
        except ValueError:
            return self._error_result(
                "Invalid override scope.",
                code="INVALID_OVERRIDE_SCOPE",
            )

        if normalized_scope == OverrideScope.GLOBAL:
            return self._error_result(
                "Global runtime overrides are not permitted through tenant APIs.",
                code="GLOBAL_OVERRIDE_BLOCKED",
            )

        override_count = self._count_nested_items(overrides)

        if override_count > MAX_OVERRIDE_ITEMS:
            return self._error_result(
                "Override payload contains too many items.",
                code="OVERRIDE_TOO_LARGE",
                metadata={
                    "maximum_items": MAX_OVERRIDE_ITEMS,
                    "received_items": override_count,
                },
            )

        immutable_attempts = self._find_immutable_override_attempts(overrides)

        if immutable_attempts:
            return self._error_result(
                "Override attempts to modify immutable safety settings.",
                code="IMMUTABLE_SAFETY_SETTING",
                data={
                    "blocked_paths": sorted(immutable_attempts),
                },
            )

        security = self._request_security_approval(
            context=context,
            action="security.config.update",
            payload={
                "scope": normalized_scope.value,
                "override_hash": stable_hash(overrides),
                "override_keys": sorted(self._flatten_paths(overrides)),
            },
        )

        if not security["success"]:
            return security

        try:
            with self._lock:
                current_override = self._get_override_mapping(
                    context,
                    normalized_scope,
                )

                merged_override = deep_merge(current_override, overrides)

                prospective_config_dict = deep_merge(
                    dataclass_to_dict(self._get_effective_configuration(context)),
                    overrides,
                )

                prospective_config = self._configuration_from_mapping(
                    prospective_config_dict
                )

                errors = prospective_config.validate()

                if errors:
                    return self._error_result(
                        "Override would create an invalid security configuration.",
                        error="; ".join(errors),
                        code="INVALID_SECURITY_OVERRIDE",
                        data={
                            "errors": errors,
                        },
                    )

                self._set_override_mapping(
                    context,
                    normalized_scope,
                    merged_override,
                )

            config_hash = self._calculate_config_hash(prospective_config)

            event_payload = {
                "scope": normalized_scope.value,
                "override_hash": stable_hash(overrides),
                "effective_config_hash": config_hash,
                "changed_paths": sorted(self._flatten_paths(overrides)),
            }

            self._emit_agent_event(
                context=context,
                event_type="security.config.updated",
                payload=event_payload,
            )

            self._log_audit_event(
                context=context,
                action="security.config.update",
                payload=event_payload,
            )

            return self._safe_result(
                message="Security configuration override applied.",
                data={
                    "scope": normalized_scope.value,
                    "effective_config_hash": config_hash,
                    "changed_paths": event_payload["changed_paths"],
                    "verification_payload": self._prepare_verification_payload(
                        context=context,
                        action="security.config.update",
                        result=event_payload,
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        context=context,
                        action="security.config.update",
                        useful_context={
                            "scope": normalized_scope.value,
                            "changed_paths": event_payload["changed_paths"],
                        },
                    ),
                },
                metadata={
                    "operation": "apply_override",
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to apply security override.")
            return self._error_result(
                "Failed to apply security configuration override.",
                error=str(exc),
                code="OVERRIDE_APPLY_FAILED",
            )

    def remove_override(
        self,
        context: SecurityTaskContext,
        scope: Union[str, OverrideScope],
        keys: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Remove selected keys or all values from one override scope."""
        validation = self._validate_task_context(context)

        if not validation["success"]:
            return validation

        try:
            normalized_scope = OverrideScope(str(scope))
        except ValueError:
            return self._error_result(
                "Invalid override scope.",
                code="INVALID_OVERRIDE_SCOPE",
            )

        if normalized_scope == OverrideScope.GLOBAL:
            return self._error_result(
                "Global override removal is not available through tenant APIs.",
                code="GLOBAL_OVERRIDE_BLOCKED",
            )

        security = self._request_security_approval(
            context=context,
            action="security.config.reset",
            payload={
                "scope": normalized_scope.value,
                "keys": list(keys or []),
            },
        )

        if not security["success"]:
            return security

        try:
            with self._lock:
                current = self._get_override_mapping(context, normalized_scope)

                if not keys:
                    updated: Dict[str, Any] = {}
                else:
                    updated = copy.deepcopy(current)

                    for dotted_key in keys:
                        self._delete_dotted_key(updated, str(dotted_key))

                self._set_override_mapping(context, normalized_scope, updated)

            effective = self._get_effective_configuration(context)
            payload = {
                "scope": normalized_scope.value,
                "removed_keys": list(keys or ["*"]),
                "effective_config_hash": self._calculate_config_hash(effective),
            }

            self._emit_agent_event(
                context=context,
                event_type="security.config.override_removed",
                payload=payload,
            )

            self._log_audit_event(
                context=context,
                action="security.config.reset",
                payload=payload,
            )

            return self._safe_result(
                message="Security configuration override removed.",
                data={
                    **payload,
                    "verification_payload": self._prepare_verification_payload(
                        context=context,
                        action="security.config.reset",
                        result=payload,
                    ),
                },
                metadata={
                    "operation": "remove_override",
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to remove security configuration override.",
                error=str(exc),
                code="OVERRIDE_REMOVE_FAILED",
            )

    def reset_overrides(
        self,
        context: SecurityTaskContext,
        scope: Union[str, OverrideScope] = OverrideScope.USER_WORKSPACE,
    ) -> Dict[str, Any]:
        """Reset all configuration overrides for one tenant scope."""
        return self.remove_override(
            context=context,
            scope=scope,
            keys=None,
        )

    # ------------------------------------------------------------------
    # Risk and policy helpers
    # ------------------------------------------------------------------

    def evaluate_risk_score(
        self,
        score: Any,
        context: Optional[SecurityTaskContext] = None,
    ) -> Dict[str, Any]:
        """Translate a numeric score into risk level and required decision."""
        try:
            numeric_score = safe_int(score, 0, 0, 100)

            config = (
                self._get_effective_configuration(context)
                if context is not None
                else copy.deepcopy(self._base_config)
            )

            thresholds = config.risk

            if numeric_score >= thresholds.emergency_min:
                risk_level = RiskLevel.EMERGENCY
            elif numeric_score > thresholds.high_max:
                risk_level = RiskLevel.CRITICAL
            elif numeric_score > thresholds.medium_max:
                risk_level = RiskLevel.HIGH
            elif numeric_score > thresholds.low_max:
                risk_level = RiskLevel.MEDIUM
            elif numeric_score > 0:
                risk_level = RiskLevel.LOW
            else:
                risk_level = RiskLevel.MINIMAL

            if numeric_score >= thresholds.automatic_block_min_score:
                decision = PolicyDecision.BLOCK
            elif numeric_score >= thresholds.admin_approval_min_score:
                decision = PolicyDecision.REQUIRE_ADMIN_APPROVAL
            elif numeric_score >= thresholds.biometric_min_score:
                decision = PolicyDecision.REQUIRE_BIOMETRIC
            elif numeric_score >= thresholds.confirmation_min_score:
                decision = PolicyDecision.REQUIRE_CONFIRMATION
            elif numeric_score > 0:
                decision = PolicyDecision.ALLOW_WITH_AUDIT
            else:
                decision = PolicyDecision.ALLOW

            return self._safe_result(
                message="Risk score evaluated.",
                data={
                    "score": numeric_score,
                    "risk_level": risk_level.value,
                    "decision": decision.value,
                },
                metadata={
                    "operation": "evaluate_risk_score",
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to evaluate risk score.",
                error=str(exc),
                code="RISK_EVALUATION_FAILED",
            )

    def requires_biometric(
        self,
        action: str,
        *,
        risk_score: Optional[Any] = None,
        context: Optional[SecurityTaskContext] = None,
    ) -> Dict[str, Any]:
        """Determine whether an action requires biometric verification."""
        action = str(action or "").strip()

        config = (
            self._get_effective_configuration(context)
            if context is not None
            else copy.deepcopy(self._base_config)
        )

        required_reasons: List[str] = []

        if action in config.approvals.always_biometric_actions:
            required_reasons.append("Action is configured as always biometric.")

        action_flags = {
            "payment.": config.biometric.required_for_payments,
            "bank.": config.biometric.required_for_bank_actions,
            "account.recovery": config.biometric.required_for_account_recovery,
            "account.change_password": config.biometric.required_for_password_changes,
            "security.config": config.biometric.required_for_security_config_changes,
            "security.disable": config.biometric.required_for_disabling_security,
            "file.delete_protected": (
                config.biometric.required_for_protected_file_changes
            ),
            "terminal.execute_destructive": (
                config.biometric.required_for_destructive_commands
            ),
            "privacy.export_sensitive": (
                config.biometric.required_for_exporting_sensitive_data
            ),
            "device.trust_unknown": (
                config.biometric.required_for_new_unknown_devices
            ),
        }

        for prefix, enabled in action_flags.items():
            if enabled and action.startswith(prefix):
                required_reasons.append(
                    f"Biometric policy is enabled for action family: {prefix}"
                )

        normalized_score = None

        if risk_score is not None:
            normalized_score = safe_int(risk_score, 0, 0, 100)

            if normalized_score >= config.risk.biometric_min_score:
                required_reasons.append(
                    "Risk score meets biometric escalation threshold."
                )

        required = bool(config.biometric.enabled and required_reasons)

        return self._safe_result(
            message=(
                "Biometric verification is required."
                if required
                else "Biometric verification is not required by configuration."
            ),
            data={
                "required": required,
                "action": action,
                "risk_score": normalized_score,
                "reasons": required_reasons,
                "preferred_methods": list(config.biometric.preferred_methods),
                "verification_validity_seconds": (
                    config.biometric.sensitive_verification_validity_seconds
                    if required
                    else config.biometric.verification_validity_seconds
                ),
            },
            metadata={
                "operation": "requires_biometric",
            },
        )

    # ------------------------------------------------------------------
    # Command classification
    # ------------------------------------------------------------------

    def classify_command(
        self,
        command: str,
        context: Optional[SecurityTaskContext] = None,
    ) -> Dict[str, Any]:
        """
        Classify a command without executing it.

        Final execution must still pass Permission Checker, Risk Engine,
        Policy Engine, Approval Manager, and Verification Agent.
        """
        if not isinstance(command, str):
            return self._error_result(
                "Command must be a string.",
                code="INVALID_COMMAND_TYPE",
            )

        if len(command) > MAX_COMMAND_LENGTH:
            return self._error_result(
                "Command exceeds maximum permitted inspection length.",
                code="COMMAND_TOO_LONG",
            )

        config = (
            self._get_effective_configuration(context)
            if context is not None
            else copy.deepcopy(self._base_config)
        )

        policy = config.commands
        normalized = normalize_command_text(command)
        basename = get_command_basename(normalized)
        reasons: List[str] = []
        matched_patterns: List[str] = []

        if not normalized:
            return self._error_result(
                "Command cannot be empty.",
                code="EMPTY_COMMAND",
            )

        if policy.reject_null_bytes and "\x00" in command:
            return self._safe_result(
                message="Command is blocked.",
                data={
                    "command_policy": CommandPolicy.BLOCKED.value,
                    "decision": PolicyDecision.BLOCK.value,
                    "basename": basename,
                    "reasons": ["Command contains a null byte."],
                    "matched_patterns": [],
                },
            )

        if policy.reject_unbalanced_quotes:
            if normalized.count('"') % 2 != 0 or normalized.count("'") % 2 != 0:
                reasons.append("Command contains unbalanced quotes.")
                return self._safe_result(
                    message="Command is blocked.",
                    data={
                        "command_policy": CommandPolicy.BLOCKED.value,
                        "decision": PolicyDecision.BLOCK.value,
                        "basename": basename,
                        "reasons": reasons,
                        "matched_patterns": [],
                    },
                )

        for pattern in policy.always_blocked_patterns:
            try:
                if re.search(pattern, normalized):
                    matched_patterns.append(pattern)
            except re.error:
                self.logger.error("Invalid command regex skipped: %s", pattern)

        lowered_command = normalized.lower()

        for fragment in policy.blocked_argument_fragments:
            if fragment.lower() in lowered_command:
                matched_patterns.append(f"fragment:{fragment}")

        if matched_patterns:
            reasons.append("Command matched an always-blocked pattern.")
            command_policy = CommandPolicy.BLOCKED
            decision = PolicyDecision.BLOCK

        elif basename in {
            item.lower() for item in policy.blocked_command_basenames
        }:
            reasons.append("Executable is on the blocked command list.")
            command_policy = CommandPolicy.BLOCKED
            decision = PolicyDecision.BLOCK

        elif basename in {
            item.lower() for item in policy.restricted_command_basenames
        }:
            reasons.append("Executable is restricted and requires approval.")
            command_policy = CommandPolicy.RESTRICTED

            if policy.require_biometric_for_destructive:
                decision = PolicyDecision.REQUIRE_BIOMETRIC
            else:
                decision = PolicyDecision.REQUIRE_CONFIRMATION

        elif basename in {
            item.lower() for item in policy.safe_read_only_basenames
        }:
            reasons.append("Executable is recognized as normally read-only.")

            if any(operator in normalized for operator in DANGEROUS_SHELL_OPERATORS):
                reasons.append(
                    "Shell operators require additional inspection and approval."
                )
                command_policy = CommandPolicy.RESTRICTED
                decision = PolicyDecision.REQUIRE_CONFIRMATION
            else:
                command_policy = CommandPolicy.AUDITED
                decision = PolicyDecision.ALLOW_WITH_AUDIT

        else:
            reasons.append("Command is unknown and uses the default command policy.")

            try:
                command_policy = CommandPolicy(
                    policy.default_unknown_command_policy
                )
            except ValueError:
                command_policy = CommandPolicy.AUDITED

            decision_map = {
                CommandPolicy.ALLOWED: PolicyDecision.ALLOW,
                CommandPolicy.AUDITED: PolicyDecision.ALLOW_WITH_AUDIT,
                CommandPolicy.RESTRICTED: PolicyDecision.REQUIRE_CONFIRMATION,
                CommandPolicy.BLOCKED: PolicyDecision.BLOCK,
            }
            decision = decision_map[command_policy]

        if (
            policy.block_shell_operator_chaining_for_sensitive_commands
            and command_policy in {
                CommandPolicy.RESTRICTED,
                CommandPolicy.BLOCKED,
            }
            and any(operator in normalized for operator in DANGEROUS_SHELL_OPERATORS)
        ):
            reasons.append(
                "Sensitive command contains shell chaining or redirection operators."
            )
            command_policy = CommandPolicy.BLOCKED
            decision = PolicyDecision.BLOCK

        result = {
            "command_policy": command_policy.value,
            "decision": decision.value,
            "basename": basename,
            "normalized_command_hash": stable_hash(normalized),
            "reasons": reasons,
            "matched_patterns": matched_patterns,
            "requires_security_agent": True,
            "requires_audit": policy.audit_all_terminal_commands,
        }

        if context is not None:
            self._log_audit_event(
                context=context,
                action="security.command.classify",
                payload={
                    "basename": basename,
                    "decision": decision.value,
                    "command_hash": result["normalized_command_hash"],
                    "matched_pattern_count": len(matched_patterns),
                },
            )

        return self._safe_result(
            message=f"Command classified as {command_policy.value}.",
            data=result,
            metadata={
                "operation": "classify_command",
            },
        )

    # ------------------------------------------------------------------
    # Path classification
    # ------------------------------------------------------------------

    def classify_path(
        self,
        path_value: str,
        *,
        operation: str = "read",
        context: Optional[SecurityTaskContext] = None,
    ) -> Dict[str, Any]:
        """
        Classify a path operation without touching the filesystem.

        Destructive operations include:
            delete, overwrite, truncate, move, chmod, chown, permission_change,
            ownership_change, recursive_delete.
        """
        if not isinstance(path_value, str):
            return self._error_result(
                "Path must be a string.",
                code="INVALID_PATH_TYPE",
            )

        normalized = normalize_path_text(path_value)

        if not normalized:
            return self._error_result(
                "Path cannot be empty.",
                code="EMPTY_PATH",
            )

        config = (
            self._get_effective_configuration(context)
            if context is not None
            else copy.deepcopy(self._base_config)
        )

        path_policy = config.paths
        operation = str(operation or "read").strip().lower()

        protected_roots: List[str] = []
        matched_patterns: List[str] = []
        excluded = False

        for safe_path in path_policy.excluded_safe_paths:
            if path_is_within(normalized, safe_path):
                excluded = True
                break

        if not excluded:
            for protected_root in path_policy.protected_folders:
                expanded_root = normalize_path_text(protected_root)

                if expanded_root and path_is_within(normalized, expanded_root):
                    protected_roots.append(protected_root)

            path_name = PurePath(normalized).name

            for pattern in path_policy.protected_file_patterns:
                candidate = path_name
                pattern_candidate = pattern

                if not path_policy.case_sensitive:
                    candidate = candidate.lower()
                    pattern_candidate = pattern_candidate.lower()

                if fnmatch.fnmatch(candidate, pattern_candidate):
                    matched_patterns.append(pattern)

        protected = bool(protected_roots or matched_patterns) and not excluded

        destructive_operations = {
            "delete",
            "recursive_delete",
            "overwrite",
            "truncate",
            "move",
            "rename",
            "chmod",
            "chown",
            "permission_change",
            "ownership_change",
            "format",
            "encrypt",
            "decrypt",
        }

        write_operations = destructive_operations | {
            "write",
            "append",
            "create",
            "copy_to",
        }

        reasons: List[str] = []

        if excluded:
            reasons.append("Path matched an explicit safe-path exclusion.")

        if protected_roots:
            reasons.append("Path is inside a protected folder.")

        if matched_patterns:
            reasons.append("Filename matched a protected file pattern.")

        if protected and operation in destructive_operations:
            if path_policy.require_biometric_for_destructive_change:
                decision = PolicyDecision.REQUIRE_BIOMETRIC
            else:
                decision = PolicyDecision.REQUIRE_CONFIRMATION

        elif protected and operation in write_operations:
            decision = PolicyDecision.REQUIRE_CONFIRMATION

        elif protected and operation == "read":
            decision = (
                PolicyDecision.REQUIRE_CONFIRMATION
                if path_policy.require_approval_for_read
                else PolicyDecision.ALLOW_WITH_AUDIT
            )

        else:
            decision = PolicyDecision.ALLOW_WITH_AUDIT

        if (
            protected
            and operation in {"delete", "recursive_delete"}
            and path_policy.deny_delete
        ):
            decision = PolicyDecision.BLOCK
            reasons.append("Deletion is denied by protected-path policy.")

        result = {
            "path": normalized,
            "operation": operation,
            "protected": protected,
            "excluded": excluded,
            "decision": decision.value,
            "matched_protected_roots": protected_roots,
            "matched_file_patterns": matched_patterns,
            "requires_backup": bool(
                protected
                and operation in write_operations
                and path_policy.require_backup_before_write
            ),
            "requires_security_agent": protected,
            "reasons": reasons,
        }

        if context is not None:
            self._log_audit_event(
                context=context,
                action="security.path.classify",
                payload={
                    "path_hash": stable_hash(normalized),
                    "operation": operation,
                    "protected": protected,
                    "decision": decision.value,
                },
            )

        return self._safe_result(
            message=(
                "Path is protected."
                if protected
                else "Path is not covered by protected-path rules."
            ),
            data=result,
            metadata={
                "operation": "classify_path",
            },
        )

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: SecurityTaskContext,
        *,
        require_user_workspace: bool = True,
    ) -> Dict[str, Any]:
        """Validate user/workspace isolation context."""
        if not isinstance(context, SecurityTaskContext):
            return self._error_result(
                "Invalid security task context.",
                code="INVALID_TASK_CONTEXT",
            )

        if require_user_workspace:
            if not normalize_identifier(context.user_id):
                return self._error_result(
                    "user_id is required.",
                    code="USER_ID_REQUIRED",
                )

            if not normalize_identifier(context.workspace_id):
                return self._error_result(
                    "workspace_id is required.",
                    code="WORKSPACE_ID_REQUIRED",
                )

        return self._safe_result(
            message="Security task context validated.",
            data={
                "valid": True,
            },
            metadata={
                "hook": "_validate_task_context",
            },
        )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Return whether Security Agent approval is required."""
        action = str(action or "").strip()

        if action in self.SENSITIVE_UPDATE_ACTIONS:
            return True

        payload = payload or {}

        if payload.get("scope") in {
            OverrideScope.WORKSPACE.value,
            OverrideScope.USER.value,
            OverrideScope.USER_WORKSPACE.value,
        }:
            return True

        return False

    def _request_security_approval(
        self,
        context: SecurityTaskContext,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Request approval from the Security Agent."""
        payload = payload or {}

        if not self._requires_security_check(action, payload):
            return self._safe_result(
                message="Security approval is not required.",
                data={
                    "approved": True,
                },
                metadata={
                    "hook": "_request_security_approval",
                },
            )

        approval_payload = {
            "agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_id": context.actor_id,
            "device_id": context.device_id,
            "request_id": context.request_id,
            "payload": redact_mapping(payload),
            "payload_hash": stable_hash(payload),
            "requested_at": utc_now_iso(),
        }

        try:
            if hasattr(self.security_agent, "approve_action"):
                response = self.security_agent.approve_action(approval_payload)
            elif hasattr(self.security_agent, "request_approval"):
                response = self.security_agent.request_approval(approval_payload)
            else:
                return self._error_result(
                    "Security Agent approval method is unavailable.",
                    code="SECURITY_APPROVAL_UNAVAILABLE",
                )

            if not isinstance(response, Mapping):
                return self._error_result(
                    "Security Agent returned an invalid response.",
                    code="INVALID_SECURITY_RESPONSE",
                )

            response_data = response.get("data") or {}
            approved = bool(response.get("success")) and bool(
                response_data.get(
                    "approved",
                    response.get("approved", False),
                )
            )

            if not approved:
                return self._error_result(
                    "Security configuration change was not approved.",
                    error=str(response.get("error") or "Approval denied."),
                    code="SECURITY_APPROVAL_DENIED",
                    metadata={
                        "security_response": redact_mapping(response),
                    },
                )

            return self._safe_result(
                message="Security approval granted.",
                data={
                    "approved": True,
                    "security_response": redact_mapping(response),
                },
                metadata={
                    "hook": "_request_security_approval",
                },
            )

        except Exception as exc:
            self.logger.exception("Security approval request failed.")
            return self._error_result(
                "Security approval request failed.",
                error=str(exc),
                code="SECURITY_APPROVAL_FAILED",
            )

    def _prepare_verification_payload(
        self,
        context: SecurityTaskContext,
        action: str,
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Prepare a Verification Agent compatible payload."""
        return {
            "verification_id": str(uuid.uuid4()),
            "verification_type": "security_configuration_integrity",
            "source_agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_id": context.actor_id,
            "device_id": context.device_id,
            "request_id": context.request_id,
            "result_hash": stable_hash(result),
            "result_summary": redact_mapping(dict(result)),
            "required_checks": [
                "user_workspace_isolation",
                "immutable_safety_rules_preserved",
                "configuration_schema_valid",
                "security_approval_recorded",
                "audit_event_prepared",
                "no_secrets_exposed",
            ],
            "created_at": utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        context: SecurityTaskContext,
        action: str,
        useful_context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare a Memory Agent compatible event.

        Only non-sensitive configuration-change summaries are included.
        """
        return {
            "memory_id": str(uuid.uuid4()),
            "memory_type": "security_configuration_event",
            "category": "security",
            "source_agent": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_id": context.actor_id,
            "privacy_level": "restricted",
            "importance": "high",
            "content": {
                "action": action,
                "summary": redact_mapping(dict(useful_context)),
            },
            "created_at": utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        context: SecurityTaskContext,
        event_type: str,
        payload: Mapping[str, Any],
    ) -> None:
        """Emit an Agent Event Bus compatible event."""
        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "source_agent": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_id": context.actor_id,
            "device_id": context.device_id,
            "request_id": context.request_id,
            "payload": redact_mapping(dict(payload)),
            "payload_hash": stable_hash(payload),
            "created_at": utc_now_iso(),
        }

        try:
            if self.event_callback:
                self.event_callback(event)
        except Exception:
            self.logger.exception("Failed to emit SecurityConfig event.")

    def _log_audit_event(
        self,
        context: SecurityTaskContext,
        action: str,
        payload: Mapping[str, Any],
    ) -> None:
        """Prepare and emit an append-only audit event."""
        event = {
            "audit_id": str(uuid.uuid4()),
            "source_agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_id": context.actor_id,
            "device_id": context.device_id,
            "request_id": context.request_id,
            "payload": redact_mapping(dict(payload)),
            "payload_hash": stable_hash(payload),
            "created_at": utc_now_iso(),
        }

        try:
            if self.audit_callback:
                self.audit_callback(event)
            else:
                self.logger.info(
                    "SecurityConfig audit event: %s",
                    stable_json(event),
                )
        except Exception:
            self.logger.exception("Failed to emit SecurityConfig audit event.")

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return the standard William success structure."""
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
        *,
        error: Optional[str] = None,
        code: str = "SECURITY_CONFIG_ERROR",
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return the standard William error structure."""
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error or code,
            "metadata": {
                "code": code,
                **(metadata or {}),
            },
        }

    # ------------------------------------------------------------------
    # Internal configuration construction
    # ------------------------------------------------------------------

    def _build_base_config(
        self,
        config: Optional[Union[SecurityConfigurationData, Mapping[str, Any]]],
    ) -> SecurityConfigurationData:
        if config is None:
            return SecurityConfigurationData()

        if isinstance(config, SecurityConfigurationData):
            return copy.deepcopy(config)

        if isinstance(config, Mapping):
            defaults = dataclass_to_dict(SecurityConfigurationData())
            merged = deep_merge(defaults, config)
            return self._configuration_from_mapping(merged)

        raise TypeError(
            "config must be SecurityConfigurationData, a mapping, or None."
        )

    def _configuration_from_mapping(
        self,
        value: Mapping[str, Any],
    ) -> SecurityConfigurationData:
        """Construct the full typed configuration from a mapping."""
        return SecurityConfigurationData(
            config_version=str(value.get("config_version", CONFIG_VERSION)),
            schema_version=str(
                value.get("schema_version", CONFIG_SCHEMA_VERSION)
            ),
            environment=str(value.get("environment", "production")),
            strict_mode=safe_bool(value.get("strict_mode"), True),
            fail_closed=safe_bool(value.get("fail_closed"), True),
            generated_at=str(value.get("generated_at") or utc_now_iso()),
            risk=self._dataclass_section(
                RiskThresholds,
                value.get("risk"),
            ),
            paths=self._dataclass_section(
                ProtectedPathPolicy,
                value.get("paths"),
            ),
            commands=self._dataclass_section(
                CommandPolicyConfig,
                value.get("commands"),
            ),
            biometric=self._dataclass_section(
                BiometricPolicy,
                value.get("biometric"),
            ),
            approvals=self._dataclass_section(
                ApprovalPolicy,
                value.get("approvals"),
            ),
            devices=self._dataclass_section(
                DeviceSecurityPolicy,
                value.get("devices"),
            ),
            sessions=self._dataclass_section(
                SessionSecurityPolicy,
                value.get("sessions"),
            ),
            fraud=self._dataclass_section(
                FraudDetectionPolicy,
                value.get("fraud"),
            ),
            anomaly=self._dataclass_section(
                AnomalyDetectionPolicy,
                value.get("anomaly"),
            ),
            payments=self._dataclass_section(
                PaymentSecurityPolicy,
                value.get("payments"),
            ),
            privacy=self._dataclass_section(
                PrivacySecurityPolicy,
                value.get("privacy"),
            ),
            threats=self._dataclass_section(
                ThreatMonitoringPolicy,
                value.get("threats"),
            ),
            emergency_lock=self._dataclass_section(
                EmergencyLockPolicy,
                value.get("emergency_lock"),
            ),
            audit=self._dataclass_section(
                AuditSecurityPolicy,
                value.get("audit"),
            ),
            features=self._dataclass_section(
                SecurityFeatureFlags,
                value.get("features"),
            ),
            metadata=copy.deepcopy(dict(value.get("metadata") or {})),
        )

    @staticmethod
    def _dataclass_section(
        section_class: Any,
        value: Optional[Any],
    ) -> Any:
        """Construct one dataclass section while ignoring unknown keys."""
        if isinstance(value, section_class):
            return copy.deepcopy(value)

        if not isinstance(value, Mapping):
            return section_class()

        valid_field_names = {
            item.name
            for item in fields(section_class)
        }

        kwargs = {
            key: copy.deepcopy(item)
            for key, item in value.items()
            if key in valid_field_names
        }

        return section_class(**kwargs)

    def _get_effective_configuration(
        self,
        context: Optional[SecurityTaskContext],
    ) -> SecurityConfigurationData:
        """Build effective config with tenant-isolated override precedence."""
        base = dataclass_to_dict(self._base_config)

        if context is None:
            return self._configuration_from_mapping(base)

        workspace_key = normalize_identifier(context.workspace_id)
        user_key = normalize_identifier(context.user_id)
        combined_key = self._tenant_key(user_key, workspace_key)

        with self._lock:
            workspace_override = copy.deepcopy(
                self._workspace_overrides.get(workspace_key, {})
            )
            user_override = copy.deepcopy(
                self._user_overrides.get(user_key, {})
            )
            combined_override = copy.deepcopy(
                self._user_workspace_overrides.get(combined_key, {})
            )

        merged = deep_merge(base, workspace_override)
        merged = deep_merge(merged, user_override)
        merged = deep_merge(merged, combined_override)

        config = self._configuration_from_mapping(merged)
        errors = config.validate()

        if errors:
            if self._base_config.fail_closed:
                raise ValueError(
                    "Effective security configuration is invalid: "
                    + "; ".join(errors)
                )

            self.logger.error(
                "Effective security configuration invalid: %s",
                errors,
            )

        return config

    # ------------------------------------------------------------------
    # Override storage helpers
    # ------------------------------------------------------------------

    def _get_override_mapping(
        self,
        context: SecurityTaskContext,
        scope: OverrideScope,
    ) -> Dict[str, Any]:
        if scope == OverrideScope.WORKSPACE:
            return copy.deepcopy(
                self._workspace_overrides.get(context.workspace_id, {})
            )

        if scope == OverrideScope.USER:
            return copy.deepcopy(
                self._user_overrides.get(context.user_id, {})
            )

        if scope == OverrideScope.USER_WORKSPACE:
            key = self._tenant_key(context.user_id, context.workspace_id)
            return copy.deepcopy(
                self._user_workspace_overrides.get(key, {})
            )

        return {}

    def _set_override_mapping(
        self,
        context: SecurityTaskContext,
        scope: OverrideScope,
        value: Mapping[str, Any],
    ) -> None:
        if scope == OverrideScope.WORKSPACE:
            self._workspace_overrides[context.workspace_id] = copy.deepcopy(
                dict(value)
            )
            return

        if scope == OverrideScope.USER:
            self._user_overrides[context.user_id] = copy.deepcopy(dict(value))
            return

        if scope == OverrideScope.USER_WORKSPACE:
            key = self._tenant_key(context.user_id, context.workspace_id)
            self._user_workspace_overrides[key] = copy.deepcopy(dict(value))
            return

        raise ValueError("Unsupported override scope.")

    @staticmethod
    def _tenant_key(user_id: str, workspace_id: str) -> str:
        """Create a deterministic isolated tenant key."""
        return (
            normalize_identifier(user_id)
            + TENANT_KEY_SEPARATOR
            + normalize_identifier(workspace_id)
        )

    # ------------------------------------------------------------------
    # Environment overrides
    # ------------------------------------------------------------------

    def _load_environment_overrides(self) -> Dict[str, Any]:
        """
        Load explicitly supported safe environment overrides.

        Secrets are deliberately unsupported.
        """
        prefix = self.env_prefix

        environment_map: Dict[str, Tuple[str, Callable[[Any], Any]]] = {
            f"{prefix}ENVIRONMENT": (
                "environment",
                str,
            ),
            f"{prefix}STRICT_MODE": (
                "strict_mode",
                lambda value: safe_bool(value, True),
            ),
            f"{prefix}FAIL_CLOSED": (
                "fail_closed",
                lambda value: safe_bool(value, True),
            ),
            f"{prefix}RISK_CONFIRMATION_MIN": (
                "risk.confirmation_min_score",
                lambda value: safe_int(value, 40, 0, 100),
            ),
            f"{prefix}RISK_BIOMETRIC_MIN": (
                "risk.biometric_min_score",
                lambda value: safe_int(value, 65, 0, 100),
            ),
            f"{prefix}RISK_ADMIN_MIN": (
                "risk.admin_approval_min_score",
                lambda value: safe_int(value, 80, 0, 100),
            ),
            f"{prefix}RISK_BLOCK_MIN": (
                "risk.automatic_block_min_score",
                lambda value: safe_int(value, 90, 0, 100),
            ),
            f"{prefix}BIOMETRIC_ENABLED": (
                "biometric.enabled",
                lambda value: safe_bool(value, True),
            ),
            f"{prefix}BIOMETRIC_CONFIDENCE": (
                "biometric.confidence_threshold",
                lambda value: safe_float(value, 0.82, 0.0, 1.0),
            ),
            f"{prefix}BIOMETRIC_MAX_ATTEMPTS": (
                "biometric.maximum_attempts",
                lambda value: safe_int(value, 5, 1, 20),
            ),
            f"{prefix}SESSION_IDLE_MINUTES": (
                "sessions.idle_timeout_minutes",
                lambda value: safe_int(value, 30, 1, 1440),
            ),
            f"{prefix}AUDIT_RETENTION_DAYS": (
                "audit.retention_days",
                lambda value: safe_int(value, 365, 30, 3650),
            ),
            f"{prefix}ANOMALY_FAILED_ATTEMPT_LIMIT": (
                "anomaly.failed_attempt_limit",
                lambda value: safe_int(value, 8, 1, 100),
            ),
            f"{prefix}EMERGENCY_LOCK_ENABLED": (
                "emergency_lock.enabled",
                lambda value: safe_bool(value, True),
            ),
        }

        overrides: Dict[str, Any] = {}

        for environment_key, (config_path, converter) in environment_map.items():
            if environment_key not in self._environment:
                continue

            raw_value = self._environment[environment_key]

            try:
                converted = converter(raw_value)
            except Exception:
                self.logger.warning(
                    "Ignoring invalid security environment value for %s",
                    environment_key,
                )
                continue

            self._set_dotted_key(overrides, config_path, converted)

        immutable_attempts = self._find_immutable_override_attempts(overrides)

        if immutable_attempts:
            for path_value in immutable_attempts:
                self._delete_dotted_key(overrides, path_value)

            self.logger.warning(
                "Ignored immutable security environment overrides: %s",
                sorted(immutable_attempts),
            )

        return overrides

    # ------------------------------------------------------------------
    # Mapping helpers
    # ------------------------------------------------------------------

    def _find_immutable_override_attempts(
        self,
        overrides: Mapping[str, Any],
    ) -> Set[str]:
        attempted_paths = set(self._flatten_paths(overrides))
        blocked: Set[str] = set()

        for attempted in attempted_paths:
            for immutable in self.IMMUTABLE_SAFETY_PATHS:
                if attempted == immutable or attempted.startswith(immutable + "."):
                    blocked.add(attempted)

        return blocked

    def _flatten_paths(
        self,
        value: Mapping[str, Any],
        prefix: str = "",
    ) -> List[str]:
        paths: List[str] = []

        for key, item in value.items():
            current = f"{prefix}.{key}" if prefix else str(key)

            if isinstance(item, Mapping) and item:
                paths.extend(self._flatten_paths(item, current))
            else:
                paths.append(current)

        return paths

    def _count_nested_items(
        self,
        value: Any,
        *,
        depth: int = 0,
    ) -> int:
        if depth > MAX_OVERRIDE_DEPTH:
            raise ValueError("Override depth exceeds allowed maximum.")

        if isinstance(value, Mapping):
            return sum(
                1 + self._count_nested_items(item, depth=depth + 1)
                for item in value.values()
            )

        if isinstance(value, (list, tuple, set)):
            return sum(
                1 + self._count_nested_items(item, depth=depth + 1)
                for item in value
            )

        return 1

    @staticmethod
    def _set_dotted_key(
        target: MutableMapping[str, Any],
        dotted_key: str,
        value: Any,
    ) -> None:
        parts = [part for part in dotted_key.split(".") if part]

        if not parts:
            return

        current: MutableMapping[str, Any] = target

        for part in parts[:-1]:
            existing = current.get(part)

            if not isinstance(existing, MutableMapping):
                existing = {}
                current[part] = existing

            current = existing

        current[parts[-1]] = value

    @staticmethod
    def _delete_dotted_key(
        target: MutableMapping[str, Any],
        dotted_key: str,
    ) -> None:
        parts = [part for part in dotted_key.split(".") if part]

        if not parts:
            return

        current: MutableMapping[str, Any] = target
        parents: List[Tuple[MutableMapping[str, Any], str]] = []

        for part in parts[:-1]:
            next_value = current.get(part)

            if not isinstance(next_value, MutableMapping):
                return

            parents.append((current, part))
            current = next_value

        current.pop(parts[-1], None)

        for parent, key in reversed(parents):
            child = parent.get(key)

            if isinstance(child, Mapping) and not child:
                parent.pop(key, None)
            else:
                break

    # ------------------------------------------------------------------
    # Redaction and hashing
    # ------------------------------------------------------------------

    def _make_public_config(
        self,
        config: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Return dashboard-safe configuration.

        Exact blocked regex patterns and protected root values are summarized to
        reduce information disclosure.
        """
        public = redact_mapping(config)

        commands = public.get("commands")

        if isinstance(commands, dict):
            blocked_patterns = commands.pop("always_blocked_patterns", [])
            blocked_basenames = commands.pop("blocked_command_basenames", [])
            restricted_basenames = commands.pop(
                "restricted_command_basenames",
                [],
            )
            blocked_fragments = commands.pop("blocked_argument_fragments", [])

            commands["blocked_pattern_count"] = len(blocked_patterns)
            commands["blocked_command_count"] = len(blocked_basenames)
            commands["restricted_command_count"] = len(restricted_basenames)
            commands["blocked_argument_fragment_count"] = len(blocked_fragments)

        paths = public.get("paths")

        if isinstance(paths, dict):
            protected_folders = paths.pop("protected_folders", [])
            file_patterns = paths.pop("protected_file_patterns", [])
            excluded_paths = paths.pop("excluded_safe_paths", [])

            paths["protected_folder_count"] = len(protected_folders)
            paths["protected_file_pattern_count"] = len(file_patterns)
            paths["excluded_safe_path_count"] = len(excluded_paths)

        privacy = public.get("privacy")

        if isinstance(privacy, dict):
            protected_patterns = privacy.pop("protected_key_patterns", [])
            privacy["protected_key_pattern_count"] = len(protected_patterns)

        threats = public.get("threats")

        if isinstance(threats, dict):
            blocked_extensions = threats.pop("blocked_extension_patterns", [])
            threats["blocked_extension_pattern_count"] = len(
                blocked_extensions
            )

        return public

    @staticmethod
    def _calculate_config_hash(
        config: SecurityConfigurationData,
    ) -> str:
        payload = dataclass_to_dict(config)
        payload.pop("generated_at", None)
        return stable_hash(payload)

    # ------------------------------------------------------------------
    # Context construction
    # ------------------------------------------------------------------

    @staticmethod
    def _context_from_mapping(
        payload: Mapping[str, Any],
    ) -> SecurityTaskContext:
        return SecurityTaskContext(
            user_id=normalize_identifier(payload.get("user_id")),
            workspace_id=normalize_identifier(payload.get("workspace_id")),
            actor_id=payload.get("actor_id"),
            role=payload.get("role"),
            device_id=payload.get("device_id"),
            request_id=payload.get("request_id"),
            subscription_plan=payload.get("subscription_plan"),
            metadata=copy.deepcopy(dict(payload.get("metadata") or {})),
        )


# ============================================================================
# Factory and module-level defaults
# ============================================================================

def create_security_config(**kwargs: Any) -> SecurityConfig:
    """Create a SecurityConfig instance for dependency injection."""
    return SecurityConfig(**kwargs)


def get_default_security_configuration() -> SecurityConfigurationData:
    """Return an isolated copy of the default typed configuration."""
    return SecurityConfigurationData()


def get_default_security_configuration_dict() -> Dict[str, Any]:
    """Return the complete default configuration as a dictionary."""
    return dataclass_to_dict(SecurityConfigurationData())


DEFAULT_SECURITY_CONFIGURATION = SecurityConfigurationData()


# ============================================================================
# Exports
# ============================================================================

__all__ = [
    "SecurityConfig",
    "SecurityConfigurationData",
    "SecurityTaskContext",
    "RiskThresholds",
    "ProtectedPathPolicy",
    "CommandPolicyConfig",
    "BiometricPolicy",
    "ApprovalPolicy",
    "DeviceSecurityPolicy",
    "SessionSecurityPolicy",
    "FraudDetectionPolicy",
    "AnomalyDetectionPolicy",
    "PaymentSecurityPolicy",
    "PrivacySecurityPolicy",
    "ThreatMonitoringPolicy",
    "EmergencyLockPolicy",
    "AuditSecurityPolicy",
    "SecurityFeatureFlags",
    "RiskLevel",
    "PolicyDecision",
    "CommandPolicy",
    "BiometricMethod",
    "OverrideScope",
    "DEFAULT_SECURITY_CONFIGURATION",
    "create_security_config",
    "get_default_security_configuration",
    "get_default_security_configuration_dict",
]