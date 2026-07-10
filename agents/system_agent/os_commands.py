"""
agents/system_agent/os_commands.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Safe OS command execution and system inspection helper for the System Agent.

Responsibilities:
    - Run safe allowlisted OS commands.
    - Check system status such as CPU, memory, disk, platform, hostname, uptime.
    - Check running processes safely.
    - Check open/listening ports where supported.
    - Check service status using safe platform-aware commands.
    - Maintain SaaS-safe context isolation using user_id and workspace_id.
    - Route sensitive actions through Security Agent compatibility hooks.
    - Prepare Verification Agent payloads for completed actions.
    - Prepare Memory Agent compatible payloads for useful context.
    - Emit dashboard/API/registry compatible events.
    - Log audit events without mixing tenant data.

Design Notes:
    This file is import-safe. If William/Jarvis BaseAgent, Security Agent,
    Memory Agent, Verification Agent, or Event Bus modules do not exist yet,
    safe fallback stubs are used so the file can still import and run.

    This module is intentionally conservative. It does not allow destructive
    commands, shell injection, arbitrary shell execution, package installation,
    privilege escalation, file deletion, process killing, shutdown/reboot,
    network scanning, credential access, or command chaining.

Expected Path:
    agents/system_agent/os_commands.py
"""

from __future__ import annotations

import datetime
import getpass
import json
import logging
import os
import platform
import re
import shlex
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional third-party imports
# ---------------------------------------------------------------------------

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - safe fallback
    psutil = None  # type: ignore


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallbacks
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import safety

    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Used only when the real William/Jarvis BaseAgent has not been created yet.
        Keeps this file import-safe and compatible with future integration.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "system")
            self.logger = logging.getLogger(self.agent_name)


try:
    from core.config import settings  # type: ignore
except Exception:  # pragma: no cover - fallback config

    class _FallbackSettings:
        """
        Fallback settings object.

        The real project settings can override these values later.
        """

        ENVIRONMENT = os.getenv("WILLIAM_ENVIRONMENT", "development")
        DEBUG = os.getenv("WILLIAM_DEBUG", "false").lower() in {"1", "true", "yes"}
        OS_COMMAND_TIMEOUT_SECONDS = int(os.getenv("OS_COMMAND_TIMEOUT_SECONDS", "15"))
        OS_COMMAND_MAX_OUTPUT_CHARS = int(os.getenv("OS_COMMAND_MAX_OUTPUT_CHARS", "12000"))
        OS_COMMAND_ALLOW_NETWORK_STATUS = os.getenv(
            "OS_COMMAND_ALLOW_NETWORK_STATUS", "true"
        ).lower() in {"1", "true", "yes"}
        OS_COMMAND_ALLOW_SERVICE_STATUS = os.getenv(
            "OS_COMMAND_ALLOW_SERVICE_STATUS", "true"
        ).lower() in {"1", "true", "yes"}

    settings = _FallbackSettings()  # type: ignore


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("William.SystemAgent.OSCommands")
if not LOGGER.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CommandPolicy:
    """
    Defines the execution policy for an allowlisted OS command.

    Attributes:
        executable:
            The first executable token allowed, e.g. "python", "df", "uptime".
        allowed_args_prefixes:
            Optional safe argument prefixes. Empty means command without args
            or pre-approved args only.
        description:
            Human-readable command purpose.
        sensitive:
            Whether the command requires Security Agent approval.
        platforms:
            Supported platform.system() names. Empty means all platforms.
        timeout_seconds:
            Optional command-specific timeout.
        max_output_chars:
            Output truncation limit.
        allow_user_args:
            Whether additional user args may be passed after validation.
    """

    executable: str
    allowed_args_prefixes: Tuple[str, ...] = field(default_factory=tuple)
    description: str = ""
    sensitive: bool = False
    platforms: Tuple[str, ...] = field(default_factory=tuple)
    timeout_seconds: Optional[int] = None
    max_output_chars: Optional[int] = None
    allow_user_args: bool = False


@dataclass
class TaskContext:
    """
    Normalized task execution context.

    This context keeps William/Jarvis SaaS tenant boundaries intact.
    Every operation that can be user/workspace-specific must include user_id
    and workspace_id.
    """

    user_id: str
    workspace_id: str
    request_id: str
    role: Optional[str] = None
    session_id: Optional[str] = None
    agent_name: str = "OSCommands"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CommandExecutionRecord:
    """
    Audit-friendly record for a command operation.
    """

    command_id: str
    command: List[str]
    safe_command: str
    started_at: str
    finished_at: Optional[str] = None
    duration_ms: Optional[int] = None
    return_code: Optional[int] = None
    timed_out: bool = False
    output_truncated: bool = False
    user_id: Optional[str] = None
    workspace_id: Optional[str] = None
    request_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Constants and safety rules
# ---------------------------------------------------------------------------

DANGEROUS_COMMANDS: Tuple[str, ...] = (
    "rm",
    "rmdir",
    "del",
    "erase",
    "format",
    "mkfs",
    "dd",
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "init",
    "systemctl",
    "service",
    "sc",
    "net",
    "kill",
    "killall",
    "pkill",
    "taskkill",
    "chmod",
    "chown",
    "chgrp",
    "sudo",
    "su",
    "passwd",
    "useradd",
    "usermod",
    "userdel",
    "groupadd",
    "groupdel",
    "mount",
    "umount",
    "iptables",
    "ufw",
    "firewall-cmd",
    "curl",
    "wget",
    "nc",
    "netcat",
    "nmap",
    "ssh",
    "scp",
    "sftp",
    "ftp",
    "telnet",
    "powershell",
    "pwsh",
    "cmd",
    "bash",
    "sh",
    "zsh",
    "fish",
    "python",
    "python3",
    "pip",
    "pip3",
    "npm",
    "yarn",
    "pnpm",
    "docker",
    "kubectl",
    "helm",
)

DANGEROUS_TOKENS: Tuple[str, ...] = (
    ";",
    "&&",
    "||",
    "|",
    ">",
    ">>",
    "<",
    "$(",
    "`",
    "${",
    "\n",
    "\r",
    "\x00",
)

SECRET_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*[^\s]+"),
    re.compile(r"(?i)(bearer\s+)[a-z0-9._\-]+"),
    re.compile(r"(?i)(authorization:\s*)[^\s]+"),
    re.compile(r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*[^\s]+"),
)

SAFE_SERVICE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.@:+\-]{1,128}$")
SAFE_PROCESS_QUERY_PATTERN = re.compile(r"^[a-zA-Z0-9_.@:+\-\s]{1,128}$")
SAFE_PORT_PATTERN = re.compile(r"^\d{1,5}$")


DEFAULT_ALLOWED_COMMANDS: Dict[str, CommandPolicy] = {
    "whoami": CommandPolicy(
        executable="whoami",
        description="Show current operating system user.",
        platforms=("Linux", "Darwin", "Windows"),
    ),
    "hostname": CommandPolicy(
        executable="hostname",
        description="Show system hostname.",
        platforms=("Linux", "Darwin", "Windows"),
    ),
    "uptime": CommandPolicy(
        executable="uptime",
        description="Show system uptime.",
        platforms=("Linux", "Darwin"),
    ),
    "uname": CommandPolicy(
        executable="uname",
        allowed_args_prefixes=("-a", "-s", "-r", "-m"),
        description="Show Unix system information.",
        platforms=("Linux", "Darwin"),
        allow_user_args=True,
    ),
    "df": CommandPolicy(
        executable="df",
        allowed_args_prefixes=("-h",),
        description="Show disk usage.",
        platforms=("Linux", "Darwin"),
        allow_user_args=True,
    ),
    "free": CommandPolicy(
        executable="free",
        allowed_args_prefixes=("-h", "-m"),
        description="Show memory usage.",
        platforms=("Linux",),
        allow_user_args=True,
    ),
    "ps": CommandPolicy(
        executable="ps",
        allowed_args_prefixes=("aux", "-ef"),
        description="List running processes.",
        platforms=("Linux", "Darwin"),
        sensitive=True,
        allow_user_args=True,
    ),
    "tasklist": CommandPolicy(
        executable="tasklist",
        description="List running processes on Windows.",
        platforms=("Windows",),
        sensitive=True,
    ),
    "netstat": CommandPolicy(
        executable="netstat",
        allowed_args_prefixes=("-ano", "-an", "-tuln", "-tunlp"),
        description="Show network connection and listening port status.",
        platforms=("Linux", "Darwin", "Windows"),
        sensitive=True,
        allow_user_args=True,
    ),
    "ss": CommandPolicy(
        executable="ss",
        allowed_args_prefixes=("-tuln", "-tunlp", "-ltnp", "-ltn"),
        description="Show socket statistics on Linux.",
        platforms=("Linux",),
        sensitive=True,
        allow_user_args=True,
    ),
}


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class OSCommands(BaseAgent):
    """
    Safe OS command and system inspection helper for William/Jarvis System Agent.

    This class connects with:
        - Master Agent:
            Can route tasks to public methods like run_safe_command(),
            get_system_status(), check_ports(), check_processes().
        - Security Agent:
            Sensitive actions call _requires_security_check() and
            _request_security_approval().
        - Verification Agent:
            Every completed action can generate _prepare_verification_payload().
        - Memory Agent:
            Useful context can be transformed with _prepare_memory_payload().
        - Dashboard/API:
            All public methods return structured dicts with success, message,
            data, error, and metadata.
        - Agent Registry/Loader/Router:
            Class name and import-safe design remain stable.
    """

    agent_name = "OSCommands"
    agent_type = "system"
    version = "1.0.0"

    def __init__(
        self,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        allowed_commands: Optional[Mapping[str, CommandPolicy]] = None,
        default_timeout_seconds: Optional[int] = None,
        max_output_chars: Optional[int] = None,
        allow_service_status: Optional[bool] = None,
        allow_network_status: Optional[bool] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.agent_name, agent_type=self.agent_type, **kwargs)

        self.logger = getattr(self, "logger", LOGGER) or LOGGER

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger

        self.allowed_commands: Dict[str, CommandPolicy] = dict(DEFAULT_ALLOWED_COMMANDS)
        if allowed_commands:
            self.allowed_commands.update(dict(allowed_commands))

        self.default_timeout_seconds = int(
            default_timeout_seconds
            if default_timeout_seconds is not None
            else getattr(settings, "OS_COMMAND_TIMEOUT_SECONDS", 15)
        )
        self.max_output_chars = int(
            max_output_chars
            if max_output_chars is not None
            else getattr(settings, "OS_COMMAND_MAX_OUTPUT_CHARS", 12000)
        )
        self.allow_service_status = bool(
            allow_service_status
            if allow_service_status is not None
            else getattr(settings, "OS_COMMAND_ALLOW_SERVICE_STATUS", True)
        )
        self.allow_network_status = bool(
            allow_network_status
            if allow_network_status is not None
            else getattr(settings, "OS_COMMAND_ALLOW_NETWORK_STATUS", True)
        )

        self._execution_history: List[CommandExecutionRecord] = []

    # -----------------------------------------------------------------------
    # Public methods
    # -----------------------------------------------------------------------

    def run_safe_command(
        self,
        command: Union[str, Sequence[str]],
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
        require_security_approval: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Run an allowlisted read-only command safely.

        Args:
            command:
                Command string or token list. Shell is never used.
            user_id:
                SaaS user ID for isolation.
            workspace_id:
                SaaS workspace ID for isolation.
            role:
                Optional user role.
            session_id:
                Optional dashboard/session identifier.
            request_id:
                Optional request trace ID.
            timeout_seconds:
                Optional timeout override.
            metadata:
                Optional request metadata.
            require_security_approval:
                Force Security Agent approval even if policy is not sensitive.

        Returns:
            Structured result dict.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context: TaskContext = context_result["data"]["context"]

        parse_result = self._parse_and_validate_command(command)
        if not parse_result["success"]:
            self._log_audit_event(
                action="os_command_rejected",
                context=context,
                success=False,
                details={"command": str(command), "reason": parse_result.get("error")},
            )
            return parse_result

        command_tokens: List[str] = parse_result["data"]["tokens"]
        policy: CommandPolicy = parse_result["data"]["policy"]

        security_needed = (
            bool(require_security_approval)
            or policy.sensitive
            or self._requires_security_check(
                action="run_safe_command",
                payload={"command": command_tokens, "policy": asdict(policy)},
                context=context,
            )
        )

        if security_needed:
            approval = self._request_security_approval(
                action="run_safe_command",
                payload={
                    "command": command_tokens,
                    "policy": asdict(policy),
                    "reason": "OS command execution requires security review.",
                },
                context=context,
            )
            if not approval.get("approved", False):
                self._log_audit_event(
                    action="os_command_security_denied",
                    context=context,
                    success=False,
                    details={
                        "command": self._safe_command_display(command_tokens),
                        "approval": approval,
                    },
                )
                return self._error_result(
                    message="Security approval denied for OS command.",
                    error="security_approval_denied",
                    metadata=self._result_metadata(context, action="run_safe_command"),
                )

        started = time.time()
        command_id = str(uuid.uuid4())
        record = CommandExecutionRecord(
            command_id=command_id,
            command=list(command_tokens),
            safe_command=self._safe_command_display(command_tokens),
            started_at=self._utc_now(),
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            request_id=context.request_id,
        )

        self._emit_agent_event(
            event_name="os_command_started",
            context=context,
            payload={
                "command_id": command_id,
                "command": record.safe_command,
                "policy": policy.description,
            },
        )

        try:
            effective_timeout = int(
                timeout_seconds
                or policy.timeout_seconds
                or self.default_timeout_seconds
            )
            if effective_timeout <= 0:
                effective_timeout = self.default_timeout_seconds

            completed = subprocess.run(
                command_tokens,
                shell=False,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                check=False,
                cwd=str(Path.cwd()),
            )

            duration_ms = int((time.time() - started) * 1000)
            stdout = self._sanitize_output(completed.stdout or "")
            stderr = self._sanitize_output(completed.stderr or "")

            max_chars = int(policy.max_output_chars or self.max_output_chars)
            stdout, stdout_truncated = self._truncate_output(stdout, max_chars)
            stderr, stderr_truncated = self._truncate_output(stderr, max_chars)

            record.finished_at = self._utc_now()
            record.duration_ms = duration_ms
            record.return_code = completed.returncode
            record.output_truncated = stdout_truncated or stderr_truncated

            self._execution_history.append(record)

            data = {
                "command_id": command_id,
                "command": record.safe_command,
                "return_code": completed.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "duration_ms": duration_ms,
                "timed_out": False,
                "output_truncated": record.output_truncated,
                "policy": {
                    "description": policy.description,
                    "sensitive": policy.sensitive,
                    "platforms": list(policy.platforms),
                },
            }

            verification_payload = self._prepare_verification_payload(
                action="run_safe_command",
                context=context,
                result_data=data,
                success=completed.returncode == 0,
            )
            memory_payload = self._prepare_memory_payload(
                action="run_safe_command",
                context=context,
                result_data={
                    "command": record.safe_command,
                    "return_code": completed.returncode,
                    "duration_ms": duration_ms,
                },
            )

            self._log_audit_event(
                action="os_command_completed",
                context=context,
                success=True,
                details={
                    "command_id": command_id,
                    "command": record.safe_command,
                    "return_code": completed.returncode,
                    "duration_ms": duration_ms,
                },
            )

            self._emit_agent_event(
                event_name="os_command_completed",
                context=context,
                payload={
                    "command_id": command_id,
                    "command": record.safe_command,
                    "return_code": completed.returncode,
                    "duration_ms": duration_ms,
                },
            )

            return self._safe_result(
                message="OS command completed safely.",
                data=data,
                metadata=self._result_metadata(
                    context,
                    action="run_safe_command",
                    verification_payload=verification_payload,
                    memory_payload=memory_payload,
                ),
            )

        except subprocess.TimeoutExpired as exc:
            duration_ms = int((time.time() - started) * 1000)
            record.finished_at = self._utc_now()
            record.duration_ms = duration_ms
            record.timed_out = True
            self._execution_history.append(record)

            stdout = self._sanitize_output(exc.stdout or "") if exc.stdout else ""
            stderr = self._sanitize_output(exc.stderr or "") if exc.stderr else ""

            self._log_audit_event(
                action="os_command_timeout",
                context=context,
                success=False,
                details={
                    "command_id": command_id,
                    "command": record.safe_command,
                    "duration_ms": duration_ms,
                },
            )

            return self._error_result(
                message="OS command timed out.",
                error="command_timeout",
                data={
                    "command_id": command_id,
                    "command": record.safe_command,
                    "stdout": stdout,
                    "stderr": stderr,
                    "duration_ms": duration_ms,
                    "timed_out": True,
                },
                metadata=self._result_metadata(context, action="run_safe_command"),
            )

        except FileNotFoundError:
            self._log_audit_event(
                action="os_command_not_found",
                context=context,
                success=False,
                details={"command_id": command_id, "command": record.safe_command},
            )
            return self._error_result(
                message="Command executable was not found on this system.",
                error="command_not_found",
                data={"command_id": command_id, "command": record.safe_command},
                metadata=self._result_metadata(context, action="run_safe_command"),
            )

        except Exception as exc:
            self.logger.exception("Unexpected OS command execution error.")
            self._log_audit_event(
                action="os_command_error",
                context=context,
                success=False,
                details={
                    "command_id": command_id,
                    "command": record.safe_command,
                    "error": str(exc),
                },
            )
            return self._error_result(
                message="Unexpected OS command execution error.",
                error=str(exc),
                data={"command_id": command_id, "command": record.safe_command},
                metadata=self._result_metadata(context, action="run_safe_command"),
            )

    def get_system_status(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        include_network: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Get safe system status information.

        This avoids sensitive secrets and destructive actions.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context: TaskContext = context_result["data"]["context"]

        try:
            boot_time = None
            uptime_seconds = None
            cpu_percent = None
            memory = None
            disk = None

            if psutil is not None:
                try:
                    boot_timestamp = psutil.boot_time()
                    boot_time = datetime.datetime.fromtimestamp(
                        boot_timestamp,
                        tz=datetime.timezone.utc,
                    ).isoformat()
                    uptime_seconds = int(time.time() - boot_timestamp)
                except Exception:
                    boot_time = None
                    uptime_seconds = None

                try:
                    cpu_percent = psutil.cpu_percent(interval=0.2)
                except Exception:
                    cpu_percent = None

                try:
                    vm = psutil.virtual_memory()
                    memory = {
                        "total": int(vm.total),
                        "available": int(vm.available),
                        "used": int(vm.used),
                        "percent": float(vm.percent),
                    }
                except Exception:
                    memory = None

                try:
                    du = psutil.disk_usage(str(Path.cwd().anchor or "/"))
                    disk = {
                        "path": str(Path.cwd().anchor or "/"),
                        "total": int(du.total),
                        "used": int(du.used),
                        "free": int(du.free),
                        "percent": float(du.percent),
                    }
                except Exception:
                    disk = None

            data: Dict[str, Any] = {
                "platform": {
                    "system": platform.system(),
                    "release": platform.release(),
                    "version": platform.version(),
                    "machine": platform.machine(),
                    "processor": platform.processor(),
                    "python_version": sys.version.split()[0],
                },
                "hostname": self._safe_hostname(),
                "current_os_user": self._safe_current_user(),
                "working_directory": str(Path.cwd()),
                "boot_time": boot_time,
                "uptime_seconds": uptime_seconds,
                "cpu": {
                    "count_logical": os.cpu_count(),
                    "percent": cpu_percent,
                },
                "memory": memory,
                "disk": disk,
                "psutil_available": psutil is not None,
                "timestamp": self._utc_now(),
            }

            if include_network:
                if not self.allow_network_status:
                    data["network"] = {
                        "enabled": False,
                        "message": "Network status collection is disabled by configuration.",
                    }
                else:
                    security_needed = self._requires_security_check(
                        action="get_system_status.include_network",
                        payload={"include_network": True},
                        context=context,
                    )
                    if security_needed:
                        approval = self._request_security_approval(
                            action="get_system_status.include_network",
                            payload={
                                "reason": "Network status may reveal environment details."
                            },
                            context=context,
                        )
                        if not approval.get("approved", False):
                            data["network"] = {
                                "enabled": False,
                                "message": "Security approval denied for network status.",
                            }
                        else:
                            data["network"] = self._get_safe_network_summary()
                    else:
                        data["network"] = self._get_safe_network_summary()

            verification_payload = self._prepare_verification_payload(
                action="get_system_status",
                context=context,
                result_data=data,
                success=True,
            )
            memory_payload = self._prepare_memory_payload(
                action="get_system_status",
                context=context,
                result_data={
                    "platform": data["platform"],
                    "hostname": data["hostname"],
                    "cpu": data["cpu"],
                    "memory_percent": data["memory"]["percent"]
                    if data.get("memory")
                    else None,
                    "disk_percent": data["disk"]["percent"]
                    if data.get("disk")
                    else None,
                },
            )

            self._log_audit_event(
                action="system_status_checked",
                context=context,
                success=True,
                details={
                    "include_network": include_network,
                    "hostname": data["hostname"],
                },
            )

            return self._safe_result(
                message="System status collected successfully.",
                data=data,
                metadata=self._result_metadata(
                    context,
                    action="get_system_status",
                    verification_payload=verification_payload,
                    memory_payload=memory_payload,
                ),
            )

        except Exception as exc:
            self.logger.exception("Failed to collect system status.")
            return self._error_result(
                message="Failed to collect system status.",
                error=str(exc),
                metadata=self._result_metadata(context, action="get_system_status"),
            )

    def check_processes(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        query: Optional[str] = None,
        limit: int = 50,
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Safely inspect running processes.

        Does not kill, stop, suspend, modify, or inject into processes.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context: TaskContext = context_result["data"]["context"]

        if query and not SAFE_PROCESS_QUERY_PATTERN.match(query):
            return self._error_result(
                message="Invalid process query.",
                error="invalid_process_query",
                metadata=self._result_metadata(context, action="check_processes"),
            )

        limit = self._safe_int(limit, default=50, minimum=1, maximum=500)

        approval = self._request_security_approval(
            action="check_processes",
            payload={
                "query": query,
                "limit": limit,
                "reason": "Process inspection can reveal system activity.",
            },
            context=context,
        )
        if not approval.get("approved", False):
            return self._error_result(
                message="Security approval denied for process inspection.",
                error="security_approval_denied",
                metadata=self._result_metadata(context, action="check_processes"),
            )

        try:
            processes: List[Dict[str, Any]] = []

            if psutil is not None:
                for proc in psutil.process_iter(
                    attrs=["pid", "name", "username", "status", "cpu_percent", "memory_percent", "create_time"]
                ):
                    try:
                        info = proc.info
                        name = str(info.get("name") or "")
                        username = str(info.get("username") or "")

                        if query:
                            q = query.lower()
                            if q not in name.lower() and q not in username.lower():
                                continue

                        create_time = info.get("create_time")
                        created_at = None
                        if create_time:
                            created_at = datetime.datetime.fromtimestamp(
                                float(create_time),
                                tz=datetime.timezone.utc,
                            ).isoformat()

                        processes.append(
                            {
                                "pid": info.get("pid"),
                                "name": name,
                                "username": self._redact_username(username),
                                "status": info.get("status"),
                                "cpu_percent": info.get("cpu_percent"),
                                "memory_percent": info.get("memory_percent"),
                                "created_at": created_at,
                            }
                        )

                        if len(processes) >= limit:
                            break

                    except Exception:
                        continue
            else:
                fallback_command: List[str]
                if platform.system() == "Windows":
                    fallback_command = ["tasklist"]
                else:
                    fallback_command = ["ps", "aux"]

                result = self.run_safe_command(
                    fallback_command,
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    role=context.role,
                    session_id=context.session_id,
                    request_id=context.request_id,
                    metadata={"source": "check_processes_fallback"},
                    require_security_approval=False,
                )
                return result

            data = {
                "query": query,
                "limit": limit,
                "count": len(processes),
                "processes": processes,
                "psutil_available": psutil is not None,
            }

            verification_payload = self._prepare_verification_payload(
                action="check_processes",
                context=context,
                result_data={"count": len(processes), "query": query},
                success=True,
            )

            self._log_audit_event(
                action="processes_checked",
                context=context,
                success=True,
                details={"query": query, "count": len(processes)},
            )

            return self._safe_result(
                message="Processes checked successfully.",
                data=data,
                metadata=self._result_metadata(
                    context,
                    action="check_processes",
                    verification_payload=verification_payload,
                ),
            )

        except Exception as exc:
            self.logger.exception("Failed to check processes.")
            return self._error_result(
                message="Failed to check processes.",
                error=str(exc),
                metadata=self._result_metadata(context, action="check_processes"),
            )

    def check_ports(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        ports: Optional[Sequence[Union[int, str]]] = None,
        host: str = "127.0.0.1",
        include_listening: bool = True,
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Safely check if specific localhost ports are reachable and optionally
        list listening ports when psutil is available.

        This is intentionally local and conservative. It is not a network scanner.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context: TaskContext = context_result["data"]["context"]

        if not self.allow_network_status:
            return self._error_result(
                message="Port checks are disabled by configuration.",
                error="network_status_disabled",
                metadata=self._result_metadata(context, action="check_ports"),
            )

        if host not in {"127.0.0.1", "localhost", "::1"}:
            return self._error_result(
                message="Only localhost port checks are allowed.",
                error="non_localhost_port_check_blocked",
                metadata=self._result_metadata(context, action="check_ports"),
            )

        approval = self._request_security_approval(
            action="check_ports",
            payload={
                "ports": list(ports or []),
                "host": host,
                "include_listening": include_listening,
                "reason": "Port inspection can reveal service exposure.",
            },
            context=context,
        )
        if not approval.get("approved", False):
            return self._error_result(
                message="Security approval denied for port inspection.",
                error="security_approval_denied",
                metadata=self._result_metadata(context, action="check_ports"),
            )

        normalized_ports: List[int] = []
        if ports:
            for port in ports:
                port_int = self._normalize_port(port)
                if port_int is None:
                    return self._error_result(
                        message=f"Invalid port value: {port}",
                        error="invalid_port",
                        metadata=self._result_metadata(context, action="check_ports"),
                    )
                normalized_ports.append(port_int)

        try:
            checked_ports: List[Dict[str, Any]] = []
            for port in normalized_ports:
                checked_ports.append(
                    {
                        "host": host,
                        "port": port,
                        "open": self._is_local_port_open(host=host, port=port),
                    }
                )

            listening_ports: List[Dict[str, Any]] = []
            if include_listening and psutil is not None:
                try:
                    for conn in psutil.net_connections(kind="inet"):
                        if conn.status != "LISTEN":
                            continue

                        local_address = conn.laddr
                        ip = getattr(local_address, "ip", None)
                        port = getattr(local_address, "port", None)

                        process_name = None
                        if conn.pid:
                            try:
                                process_name = psutil.Process(conn.pid).name()
                            except Exception:
                                process_name = None

                        listening_ports.append(
                            {
                                "ip": ip,
                                "port": port,
                                "pid": conn.pid,
                                "process_name": process_name,
                                "status": conn.status,
                            }
                        )
                except Exception:
                    listening_ports = []

            data = {
                "checked_ports": checked_ports,
                "listening_ports": listening_ports,
                "include_listening": include_listening,
                "psutil_available": psutil is not None,
            }

            verification_payload = self._prepare_verification_payload(
                action="check_ports",
                context=context,
                result_data={
                    "checked_count": len(checked_ports),
                    "listening_count": len(listening_ports),
                },
                success=True,
            )

            self._log_audit_event(
                action="ports_checked",
                context=context,
                success=True,
                details={
                    "checked_count": len(checked_ports),
                    "listening_count": len(listening_ports),
                },
            )

            return self._safe_result(
                message="Port status checked successfully.",
                data=data,
                metadata=self._result_metadata(
                    context,
                    action="check_ports",
                    verification_payload=verification_payload,
                ),
            )

        except Exception as exc:
            self.logger.exception("Failed to check ports.")
            return self._error_result(
                message="Failed to check ports.",
                error=str(exc),
                metadata=self._result_metadata(context, action="check_ports"),
            )

    def check_service_status(
        self,
        service_name: str,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Check service status safely.

        This method does not start, stop, restart, enable, disable, install,
        or modify services. It only reads service status where supported.

        Linux:
            Uses systemctl is-active <service> only after validation.
        Windows:
            Uses sc query <service> only after validation.
        macOS:
            Uses launchctl print system/<service> only after validation.
            Service naming on macOS can vary, so failure is returned safely.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context: TaskContext = context_result["data"]["context"]

        if not self.allow_service_status:
            return self._error_result(
                message="Service status checks are disabled by configuration.",
                error="service_status_disabled",
                metadata=self._result_metadata(context, action="check_service_status"),
            )

        service_name = str(service_name or "").strip()
        if not service_name or not SAFE_SERVICE_NAME_PATTERN.match(service_name):
            return self._error_result(
                message="Invalid service name.",
                error="invalid_service_name",
                metadata=self._result_metadata(context, action="check_service_status"),
            )

        approval = self._request_security_approval(
            action="check_service_status",
            payload={
                "service_name": service_name,
                "reason": "Service status inspection can reveal system details.",
            },
            context=context,
        )
        if not approval.get("approved", False):
            return self._error_result(
                message="Security approval denied for service status check.",
                error="security_approval_denied",
                metadata=self._result_metadata(context, action="check_service_status"),
            )

        system_name = platform.system()
        command: Optional[List[str]] = None

        if system_name == "Linux":
            command = ["systemctl", "is-active", service_name]
        elif system_name == "Windows":
            command = ["sc", "query", service_name]
        elif system_name == "Darwin":
            command = ["launchctl", "print", f"system/{service_name}"]

        if command is None:
            return self._error_result(
                message="Service status check is not supported on this platform.",
                error="unsupported_platform",
                data={"platform": system_name},
                metadata=self._result_metadata(context, action="check_service_status"),
            )

        try:
            completed = subprocess.run(
                command,
                shell=False,
                capture_output=True,
                text=True,
                timeout=self.default_timeout_seconds,
                check=False,
            )

            stdout = self._sanitize_output(completed.stdout or "")
            stderr = self._sanitize_output(completed.stderr or "")
            stdout, stdout_truncated = self._truncate_output(stdout, 4000)
            stderr, stderr_truncated = self._truncate_output(stderr, 4000)

            status = self._interpret_service_status(
                platform_name=system_name,
                return_code=completed.returncode,
                stdout=stdout,
                stderr=stderr,
            )

            data = {
                "service_name": service_name,
                "platform": system_name,
                "status": status,
                "return_code": completed.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "output_truncated": stdout_truncated or stderr_truncated,
            }

            verification_payload = self._prepare_verification_payload(
                action="check_service_status",
                context=context,
                result_data={
                    "service_name": service_name,
                    "status": status,
                    "return_code": completed.returncode,
                },
                success=True,
            )

            self._log_audit_event(
                action="service_status_checked",
                context=context,
                success=True,
                details={
                    "service_name": service_name,
                    "platform": system_name,
                    "status": status,
                },
            )

            return self._safe_result(
                message="Service status checked successfully.",
                data=data,
                metadata=self._result_metadata(
                    context,
                    action="check_service_status",
                    verification_payload=verification_payload,
                ),
            )

        except subprocess.TimeoutExpired:
            return self._error_result(
                message="Service status command timed out.",
                error="service_status_timeout",
                data={"service_name": service_name},
                metadata=self._result_metadata(context, action="check_service_status"),
            )
        except FileNotFoundError:
            return self._error_result(
                message="Service status tool was not found on this system.",
                error="service_tool_not_found",
                data={"service_name": service_name, "platform": system_name},
                metadata=self._result_metadata(context, action="check_service_status"),
            )
        except Exception as exc:
            self.logger.exception("Failed to check service status.")
            return self._error_result(
                message="Failed to check service status.",
                error=str(exc),
                metadata=self._result_metadata(context, action="check_service_status"),
            )

    def list_allowed_commands(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        List allowlisted command policies for dashboard/API display.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context: TaskContext = context_result["data"]["context"]
        current_platform = platform.system()

        commands = []
        for key, policy in sorted(self.allowed_commands.items()):
            supported = not policy.platforms or current_platform in policy.platforms
            commands.append(
                {
                    "key": key,
                    "executable": policy.executable,
                    "description": policy.description,
                    "sensitive": policy.sensitive,
                    "platforms": list(policy.platforms),
                    "supported_on_current_platform": supported,
                    "allow_user_args": policy.allow_user_args,
                    "allowed_args_prefixes": list(policy.allowed_args_prefixes),
                }
            )

        return self._safe_result(
            message="Allowed OS commands listed successfully.",
            data={
                "platform": current_platform,
                "commands": commands,
                "count": len(commands),
            },
            metadata=self._result_metadata(context, action="list_allowed_commands"),
        )

    def get_execution_history(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        limit: int = 25,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Get in-memory execution history scoped to the current user/workspace.

        This is not a database replacement. Future dashboard/API integration can
        persist audit data separately.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context: TaskContext = context_result["data"]["context"]
        limit = self._safe_int(limit, default=25, minimum=1, maximum=200)

        scoped_history = [
            asdict(record)
            for record in self._execution_history
            if str(record.user_id) == str(context.user_id)
            and str(record.workspace_id) == str(context.workspace_id)
        ][-limit:]

        return self._safe_result(
            message="Execution history loaded successfully.",
            data={
                "history": scoped_history,
                "count": len(scoped_history),
                "limit": limit,
            },
            metadata=self._result_metadata(context, action="get_execution_history"),
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Lightweight import/runtime health check.
        """

        return self._safe_result(
            message="OSCommands is healthy.",
            data={
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "version": self.version,
                "platform": platform.system(),
                "psutil_available": psutil is not None,
                "allowed_command_count": len(self.allowed_commands),
                "timestamp": self._utc_now(),
            },
            metadata={
                "request_id": str(uuid.uuid4()),
                "agent": self.agent_name,
                "action": "health_check",
            },
        )

    # -----------------------------------------------------------------------
    # Compatibility hooks required by architecture
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: Union[str, int, None],
        workspace_id: Union[str, int, None],
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        Every user/workspace-specific action must include both user_id and
        workspace_id to prevent cross-tenant mixing.
        """

        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                message="user_id is required for OS command operations.",
                error="missing_user_id",
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                message="workspace_id is required for OS command operations.",
                error="missing_workspace_id",
            )

        clean_user_id = str(user_id).strip()
        clean_workspace_id = str(workspace_id).strip()

        if len(clean_user_id) > 128 or len(clean_workspace_id) > 128:
            return self._error_result(
                message="Invalid task context identifier length.",
                error="invalid_context_identifier",
            )

        context = TaskContext(
            user_id=clean_user_id,
            workspace_id=clean_workspace_id,
            request_id=str(request_id or uuid.uuid4()),
            role=role,
            session_id=session_id,
            agent_name=self.agent_name,
            metadata=dict(metadata or {}),
        )

        return self._safe_result(
            message="Task context validated.",
            data={"context": context},
            metadata={
                "request_id": context.request_id,
                "agent": self.agent_name,
                "action": "_validate_task_context",
            },
        )

    def _requires_security_check(
        self,
        *,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
        context: Optional[TaskContext] = None,
    ) -> bool:
        """
        Decide whether Security Agent approval is required.

        Default policy:
            - process inspection: yes
            - port/network inspection: yes
            - service status: yes
            - command execution: depends on command policy
        """

        sensitive_actions = {
            "check_processes",
            "check_ports",
            "check_service_status",
            "get_system_status.include_network",
        }

        if action in sensitive_actions:
            return True

        if action == "run_safe_command":
            command = (payload or {}).get("command", [])
            if isinstance(command, (list, tuple)) and command:
                exe = str(command[0]).lower()
                policy = self.allowed_commands.get(exe)
                if policy and policy.sensitive:
                    return True
            return False

        return False

    def _request_security_approval(
        self,
        *,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
        context: Optional[TaskContext] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent.

        If a real Security Agent is attached, this method attempts common
        method names. Otherwise, conservative fallback approval is used for
        read-only allowlisted operations only.

        The fallback never approves destructive actions because those actions
        are not exposed by this file.
        """

        payload = payload or {}

        if self.security_agent is not None:
            for method_name in (
                "approve_action",
                "request_approval",
                "validate_action",
                "check_permission",
            ):
                method = getattr(self.security_agent, method_name, None)
                if callable(method):
                    try:
                        result = method(
                            action=action,
                            payload=payload,
                            user_id=context.user_id if context else None,
                            workspace_id=context.workspace_id if context else None,
                            request_id=context.request_id if context else None,
                            agent_name=self.agent_name,
                        )
                        if isinstance(result, dict):
                            approved = bool(
                                result.get("approved")
                                or result.get("success")
                                or result.get("allowed")
                            )
                            return {
                                "approved": approved,
                                "source": f"security_agent.{method_name}",
                                "raw": result,
                            }
                        if isinstance(result, bool):
                            return {
                                "approved": result,
                                "source": f"security_agent.{method_name}",
                            }
                    except Exception as exc:
                        self.logger.warning(
                            "Security Agent approval method failed: %s", exc
                        )
                        return {
                            "approved": False,
                            "source": f"security_agent.{method_name}",
                            "error": str(exc),
                        }

        return {
            "approved": True,
            "source": "fallback_read_only_policy",
            "message": "Approved by fallback read-only policy.",
        }

    def _prepare_verification_payload(
        self,
        *,
        action: str,
        context: TaskContext,
        result_data: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.
        """

        payload = {
            "verification_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "action": action,
            "success": success,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "timestamp": self._utc_now(),
            "result_summary": self._safe_summary(result_data or {}),
            "checks": {
                "tenant_context_present": bool(context.user_id and context.workspace_id),
                "safe_structured_result": True,
                "destructive_action": False,
            },
        }

        if self.verification_agent is not None:
            method = getattr(self.verification_agent, "prepare_payload", None)
            if callable(method):
                try:
                    external_payload = method(payload)
                    if isinstance(external_payload, dict):
                        return external_payload
                except Exception as exc:
                    self.logger.warning("Verification payload hook failed: %s", exc)

        return payload

    def _prepare_memory_payload(
        self,
        *,
        action: str,
        context: TaskContext,
        result_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Does not store raw stdout/stderr or secrets.
        """

        payload = {
            "memory_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "timestamp": self._utc_now(),
            "memory_type": "system_observation",
            "content": self._safe_summary(result_data or {}),
            "metadata": {
                "source": "OSCommands",
                "safe_to_store": True,
                "contains_raw_command_output": False,
            },
        }

        if self.memory_agent is not None:
            method = getattr(self.memory_agent, "prepare_payload", None)
            if callable(method):
                try:
                    external_payload = method(payload)
                    if isinstance(external_payload, dict):
                        return external_payload
                except Exception as exc:
                    self.logger.warning("Memory payload hook failed: %s", exc)

        return payload

    def _emit_agent_event(
        self,
        *,
        event_name: str,
        context: TaskContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit event for dashboard/API/task history/event bus integration.
        """

        event = {
            "event_id": str(uuid.uuid4()),
            "event_name": event_name,
            "agent": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "timestamp": self._utc_now(),
            "payload": payload or {},
        }

        if self.event_bus is not None:
            for method_name in ("emit", "publish", "send"):
                method = getattr(self.event_bus, method_name, None)
                if callable(method):
                    try:
                        method(event_name, event)
                        return
                    except TypeError:
                        try:
                            method(event)
                            return
                        except Exception:
                            pass
                    except Exception as exc:
                        self.logger.warning("Event bus emit failed: %s", exc)
                        return

        self.logger.debug("Agent event: %s", json.dumps(event, default=str))

    def _log_audit_event(
        self,
        *,
        action: str,
        context: TaskContext,
        success: bool,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log tenant-scoped audit event.

        Future database/API integration can replace the fallback logger.
        """

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "action": action,
            "success": success,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "timestamp": self._utc_now(),
            "details": self._sanitize_audit_details(details or {}),
        }

        if self.audit_logger is not None:
            for method_name in ("log", "write", "record", "create"):
                method = getattr(self.audit_logger, method_name, None)
                if callable(method):
                    try:
                        method(audit_event)
                        return
                    except Exception as exc:
                        self.logger.warning("Audit logger failed: %s", exc)
                        return

        self.logger.info("AUDIT | %s", json.dumps(audit_event, default=str))

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success result.
        """

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Union[str, Dict[str, Any], None],
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result.
        """

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    # -----------------------------------------------------------------------
    # Internal safety helpers
    # -----------------------------------------------------------------------

    def _parse_and_validate_command(
        self,
        command: Union[str, Sequence[str]],
    ) -> Dict[str, Any]:
        """
        Parse command safely and validate it against allowlist.
        """

        if isinstance(command, str):
            raw_command = command.strip()
            if not raw_command:
                return self._error_result(
                    message="Command cannot be empty.",
                    error="empty_command",
                )

            dangerous_token = self._find_dangerous_token(raw_command)
            if dangerous_token:
                return self._error_result(
                    message="Command contains blocked shell/control token.",
                    error={
                        "code": "dangerous_token",
                        "token": dangerous_token,
                    },
                )

            try:
                tokens = shlex.split(raw_command, posix=platform.system() != "Windows")
            except Exception as exc:
                return self._error_result(
                    message="Failed to parse command safely.",
                    error=str(exc),
                )
        else:
            tokens = [str(item).strip() for item in command if str(item).strip()]

        if not tokens:
            return self._error_result(
                message="Command cannot be empty.",
                error="empty_command",
            )

        for token in tokens:
            dangerous_token = self._find_dangerous_token(token)
            if dangerous_token:
                return self._error_result(
                    message="Command contains blocked shell/control token.",
                    error={
                        "code": "dangerous_token",
                        "token": dangerous_token,
                    },
                )

        executable = Path(tokens[0]).name.lower()

        if executable in DANGEROUS_COMMANDS and executable not in self.allowed_commands:
            return self._error_result(
                message="Command executable is blocked by safety policy.",
                error={
                    "code": "dangerous_executable",
                    "executable": executable,
                },
            )

        policy = self.allowed_commands.get(executable)
        if policy is None:
            return self._error_result(
                message="Command is not allowlisted.",
                error={
                    "code": "command_not_allowlisted",
                    "executable": executable,
                    "allowed": sorted(self.allowed_commands.keys()),
                },
            )

        current_platform = platform.system()
        if policy.platforms and current_platform not in policy.platforms:
            return self._error_result(
                message="Command is not supported on this platform.",
                error={
                    "code": "unsupported_platform",
                    "platform": current_platform,
                    "supported_platforms": list(policy.platforms),
                },
            )

        if executable != policy.executable.lower():
            return self._error_result(
                message="Command executable does not match policy.",
                error="policy_executable_mismatch",
            )

        args = tokens[1:]
        if args and not policy.allow_user_args:
            return self._error_result(
                message="This command does not allow user-provided arguments.",
                error="arguments_not_allowed",
            )

        if args and policy.allowed_args_prefixes:
            for arg in args:
                if not self._arg_allowed(arg, policy.allowed_args_prefixes):
                    return self._error_result(
                        message="Command argument is not allowed by policy.",
                        error={
                            "code": "argument_not_allowed",
                            "argument": arg,
                            "allowed_args_prefixes": list(policy.allowed_args_prefixes),
                        },
                    )

        if args and not policy.allowed_args_prefixes and policy.allow_user_args:
            return self._error_result(
                message="User arguments are not configured for this command.",
                error="no_argument_policy",
            )

        return self._safe_result(
            message="Command validated.",
            data={
                "tokens": [policy.executable] + args,
                "policy": policy,
            },
        )

    def _find_dangerous_token(self, value: str) -> Optional[str]:
        """
        Detect dangerous shell/control tokens.
        """

        for token in DANGEROUS_TOKENS:
            if token in value:
                return token
        return None

    def _arg_allowed(self, arg: str, allowed_prefixes: Sequence[str]) -> bool:
        """
        Validate an argument against allowlisted exact values/prefixes.
        """

        arg = str(arg).strip()
        if not arg:
            return False

        if self._find_dangerous_token(arg):
            return False

        for allowed in allowed_prefixes:
            if arg == allowed:
                return True

        return False

    def _sanitize_output(self, output: str) -> str:
        """
        Redact likely secrets from command output.
        """

        sanitized = str(output)
        for pattern in SECRET_PATTERNS:
            sanitized = pattern.sub(self._redact_secret_match, sanitized)
        return sanitized

    def _redact_secret_match(self, match: re.Match[str]) -> str:
        """
        Redact secret regex match.
        """

        text = match.group(0)
        if ":" in text:
            key = text.split(":", 1)[0]
            return f"{key}: [REDACTED]"
        if "=" in text:
            key = text.split("=", 1)[0]
            return f"{key}=[REDACTED]"
        if text.lower().startswith("bearer"):
            return "Bearer [REDACTED]"
        return "[REDACTED]"

    def _truncate_output(self, output: str, max_chars: int) -> Tuple[str, bool]:
        """
        Truncate command output to safe size.
        """

        if len(output) <= max_chars:
            return output, False

        suffix = "\n...[TRUNCATED_BY_OSCOMMANDS_SAFE_LIMIT]..."
        return output[: max(0, max_chars - len(suffix))] + suffix, True

    def _safe_command_display(self, command_tokens: Sequence[str]) -> str:
        """
        Safe command display string for logs/UI.
        """

        safe_tokens = []
        for token in command_tokens:
            token = self._sanitize_output(str(token))
            if " " in token:
                token = shlex.quote(token)
            safe_tokens.append(token)
        return " ".join(safe_tokens)

    def _sanitize_audit_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize audit details before logging/persistence.
        """

        try:
            serialized = json.dumps(details, default=str)
            sanitized = self._sanitize_output(serialized)
            return json.loads(sanitized)
        except Exception:
            return {"summary": self._sanitize_output(str(details))}

    def _safe_summary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build a safe summary without raw stdout/stderr.
        """

        summary: Dict[str, Any] = {}

        for key, value in data.items():
            if key.lower() in {"stdout", "stderr", "raw", "output", "env", "environment"}:
                continue
            if isinstance(value, (str, int, float, bool)) or value is None:
                summary[key] = value
            elif isinstance(value, dict):
                summary[key] = {
                    k: v
                    for k, v in value.items()
                    if isinstance(v, (str, int, float, bool)) or v is None
                }
            elif isinstance(value, list):
                summary[key] = {
                    "type": "list",
                    "count": len(value),
                }
            else:
                summary[key] = str(type(value).__name__)

        return summary

    def _result_metadata(
        self,
        context: TaskContext,
        *,
        action: str,
        verification_payload: Optional[Dict[str, Any]] = None,
        memory_payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Common result metadata.
        """

        metadata = {
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "version": self.version,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "session_id": context.session_id,
            "timestamp": self._utc_now(),
        }

        if verification_payload is not None:
            metadata["verification_payload"] = verification_payload

        if memory_payload is not None:
            metadata["memory_payload"] = memory_payload

        return metadata

    # -----------------------------------------------------------------------
    # System helpers
    # -----------------------------------------------------------------------

    def _safe_hostname(self) -> str:
        """
        Get hostname safely.
        """

        try:
            return socket.gethostname()
        except Exception:
            return "unknown"

    def _safe_current_user(self) -> str:
        """
        Get current OS username safely.
        """

        try:
            return self._redact_username(getpass.getuser())
        except Exception:
            return "unknown"

    def _redact_username(self, username: str) -> str:
        """
        Keep username useful but safer for shared dashboard contexts.
        """

        username = str(username or "")
        if not username:
            return ""

        if "\\" in username:
            domain, name = username.rsplit("\\", 1)
            return f"{domain}\\{self._mask_middle(name)}"

        if "@" in username:
            local, domain = username.split("@", 1)
            return f"{self._mask_middle(local)}@{domain}"

        return self._mask_middle(username)

    def _mask_middle(self, value: str) -> str:
        """
        Mask middle characters of a value.
        """

        value = str(value)
        if len(value) <= 2:
            return "*" * len(value)
        if len(value) <= 4:
            return value[0] + "*" * (len(value) - 1)
        return value[:2] + "*" * (len(value) - 4) + value[-2:]

    def _get_safe_network_summary(self) -> Dict[str, Any]:
        """
        Get safe network summary.

        Avoids exposing full remote connection details.
        """

        summary: Dict[str, Any] = {
            "hostname": self._safe_hostname(),
            "interfaces": [],
            "listening_port_count": None,
        }

        if psutil is None:
            summary["psutil_available"] = False
            return summary

        summary["psutil_available"] = True

        try:
            addrs = psutil.net_if_addrs()
            for interface_name, entries in addrs.items():
                safe_entries = []
                for entry in entries:
                    family_name = str(entry.family)
                    address = getattr(entry, "address", None)

                    if not address:
                        continue

                    if ":" in str(address) and "." not in str(address):
                        masked_address = "[IPv6_REDACTED]"
                    elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(address)):
                        parts = str(address).split(".")
                        masked_address = ".".join(parts[:2] + ["x", "x"])
                    else:
                        masked_address = str(address)

                    safe_entries.append(
                        {
                            "family": family_name,
                            "address": masked_address,
                        }
                    )

                summary["interfaces"].append(
                    {
                        "name": interface_name,
                        "addresses": safe_entries,
                    }
                )
        except Exception:
            summary["interfaces"] = []

        try:
            listening = [
                conn for conn in psutil.net_connections(kind="inet")
                if conn.status == "LISTEN"
            ]
            summary["listening_port_count"] = len(listening)
        except Exception:
            summary["listening_port_count"] = None

        return summary

    def _normalize_port(self, port: Union[int, str]) -> Optional[int]:
        """
        Normalize and validate TCP/UDP port.
        """

        port_str = str(port).strip()
        if not SAFE_PORT_PATTERN.match(port_str):
            return None

        port_int = int(port_str)
        if port_int < 1 or port_int > 65535:
            return None

        return port_int

    def _is_local_port_open(self, *, host: str, port: int) -> bool:
        """
        Check localhost port connectability.
        """

        try:
            with socket.create_connection((host, port), timeout=1.5):
                return True
        except Exception:
            return False

    def _interpret_service_status(
        self,
        *,
        platform_name: str,
        return_code: int,
        stdout: str,
        stderr: str,
    ) -> str:
        """
        Interpret service status from platform command output.
        """

        text = f"{stdout}\n{stderr}".lower()

        if platform_name == "Linux":
            if "active" in text and "inactive" not in text:
                return "active"
            if "inactive" in text:
                return "inactive"
            if "failed" in text:
                return "failed"
            if return_code == 0:
                return "active"
            return "unknown_or_inactive"

        if platform_name == "Windows":
            if "running" in text:
                return "running"
            if "stopped" in text:
                return "stopped"
            if "does not exist" in text:
                return "not_found"
            return "unknown"

        if platform_name == "Darwin":
            if return_code == 0:
                return "loaded_or_available"
            if "could not find service" in text or "not found" in text:
                return "not_found"
            return "unknown"

        return "unknown"

    def _safe_int(
        self,
        value: Any,
        *,
        default: int,
        minimum: int,
        maximum: int,
    ) -> int:
        """
        Safely coerce int with range.
        """

        try:
            number = int(value)
        except Exception:
            number = default

        if number < minimum:
            return minimum
        if number > maximum:
            return maximum
        return number

    def _utc_now(self) -> str:
        """
        UTC timestamp in ISO format.
        """

        return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Standalone smoke test helper
# ---------------------------------------------------------------------------

def _demo() -> None:
    """
    Safe local smoke test.

    Run:
        python agents/system_agent/os_commands.py

    This does not perform destructive actions.
    """

    os_commands = OSCommands()

    print(json.dumps(os_commands.health_check(), indent=2, default=str))

    status = os_commands.get_system_status(
        user_id="demo_user",
        workspace_id="demo_workspace",
        include_network=False,
    )
    print(json.dumps(status, indent=2, default=str))

    allowed = os_commands.list_allowed_commands(
        user_id="demo_user",
        workspace_id="demo_workspace",
    )
    print(json.dumps(allowed, indent=2, default=str))

    hostname_result = os_commands.run_safe_command(
        ["hostname"],
        user_id="demo_user",
        workspace_id="demo_workspace",
    )
    print(json.dumps(hostname_result, indent=2, default=str))


if __name__ == "__main__":
    _demo()