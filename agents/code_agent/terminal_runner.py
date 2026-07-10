"""
agents/code_agent/terminal_runner.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Runs safe terminal commands, servers, installs, builds, and tests with permission.

This file is designed for the Code Agent module and is compatible with:
    - BaseAgent
    - Agent Registry
    - Agent Loader
    - Agent Router
    - Master Agent routing
    - Security Agent approvals
    - Verification Agent payloads
    - Memory Agent context payloads
    - Dashboard/API audit and analytics pipelines

Safety Rules:
    - Never execute destructive or high-risk commands without explicit approval.
    - Never mix user/workspace files, logs, memory, analytics, or audit events.
    - Always validate user_id and workspace_id for SaaS isolation.
    - Return structured dict results only.
    - Import safely even if future William modules do not exist yet.
"""

from __future__ import annotations

import os
import re
import shlex
import signal
import subprocess
import sys
import time
import uuid
import logging
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports for William/Jarvis architecture
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe if the real BaseAgent is not available yet.
        The real William/Jarvis BaseAgent can replace this automatically later.
        """

        agent_name: str = "base_agent"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:
    SecurityAgent = None  # type: ignore


try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:
    VerificationAgent = None  # type: ignore


try:
    from agents.memory_agent.memory_agent import MemoryAgent  # type: ignore
except Exception:
    MemoryAgent = None  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TerminalContext:
    """
    SaaS execution context.

    Every terminal action must be bound to a user_id and workspace_id where
    user-specific execution is involved.
    """

    user_id: Union[int, str]
    workspace_id: Union[int, str]
    actor_id: Optional[Union[int, str]] = None
    role: Optional[str] = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CommandPolicy:
    """
    Policy object controlling what TerminalRunner can execute.
    """

    allowed_commands: List[str] = field(default_factory=lambda: [
        "python",
        "python3",
        sys.executable,
        "pip",
        "pip3",
        "npm",
        "node",
        "npx",
        "yarn",
        "pnpm",
        "pytest",
        "ruff",
        "black",
        "mypy",
        "uvicorn",
        "fastapi",
        "flask",
        "django-admin",
        "git",
        "ls",
        "dir",
        "pwd",
        "cat",
        "type",
        "echo",
        "mkdir",
        "touch",
        "find",
        "grep",
        "where",
        "which",
    ])

    blocked_commands: List[str] = field(default_factory=lambda: [
        "rm",
        "rmdir",
        "del",
        "erase",
        "format",
        "mkfs",
        "shutdown",
        "reboot",
        "halt",
        "poweroff",
        "sudo",
        "su",
        "chown",
        "chmod",
        "dd",
        "diskpart",
        "reg",
        "regedit",
        "taskkill",
        "killall",
        "pkill",
        "curl",
        "wget",
        "scp",
        "ssh",
        "ftp",
        "sftp",
        "nc",
        "netcat",
        "ncat",
        "telnet",
    ])

    blocked_patterns: List[str] = field(default_factory=lambda: [
        r"\brm\s+-rf\b",
        r"\brm\s+-fr\b",
        r"\bdel\s+/[fsq]\b",
        r"\bformat\b",
        r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;",
        r">\s*/dev/sd[a-z]",
        r"\bdd\s+if=.*\s+of=/dev/",
        r"\bmkfs\.",
        r"\bsudo\b",
        r"\bsu\s",
        r"\bchmod\s+777\b",
        r"\bchown\s+.*\s+/",
        r"\bshutdown\b",
        r"\breboot\b",
        r"\bpoweroff\b",
        r"\bhalt\b",
        r"\btaskkill\s+/f\b",
        r"\bkill\s+-9\b",
        r"\bInvoke-WebRequest\b",
        r"\bInvoke-Expression\b",
        r"\biex\b",
        r"\bcurl\b.*\|\s*(bash|sh|python|python3)",
        r"\bwget\b.*\|\s*(bash|sh|python|python3)",
    ])

    sensitive_patterns: List[str] = field(default_factory=lambda: [
        r"\bpip\s+install\b",
        r"\bnpm\s+install\b",
        r"\byarn\s+add\b",
        r"\bpnpm\s+add\b",
        r"\bgit\s+clone\b",
        r"\bgit\s+push\b",
        r"\bgit\s+pull\b",
        r"\bgit\s+reset\b",
        r"\bgit\s+checkout\b",
        r"\buvicorn\b",
        r"\bflask\s+run\b",
        r"\bpython\s+manage\.py\s+runserver\b",
    ])

    max_timeout_seconds: int = 600
    default_timeout_seconds: int = 120
    max_output_chars: int = 80_000
    allow_shell: bool = False
    allow_network_commands: bool = False
    require_security_for_installs: bool = True
    require_security_for_servers: bool = True
    require_security_for_git_write: bool = True


@dataclass
class RunningProcess:
    """
    Tracks a long-running process started by TerminalRunner.
    """

    process_id: str
    command: List[str]
    cwd: str
    started_at: str
    context: TerminalContext
    popen: subprocess.Popen
    purpose: str = "server"
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Terminal Runner
# ---------------------------------------------------------------------------

class TerminalRunner(BaseAgent):
    """
    Safe terminal execution helper for the William/Jarvis Code Agent.

    Public methods:
        - run_command()
        - run_python()
        - run_install()
        - run_tests()
        - run_build()
        - start_server()
        - stop_process()
        - stop_all_processes()
        - list_processes()
        - check_command_safety()

    How it connects to the wider system:
        - Master Agent can route code execution tasks here.
        - Security Agent can approve sensitive actions.
        - Verification Agent can verify command results.
        - Memory Agent can store useful execution context.
        - Dashboard/API can use structured audit events and metadata.
    """

    agent_name = "code_agent.terminal_runner"

    def __init__(
        self,
        base_dir: Optional[Union[str, Path]] = None,
        policy: Optional[CommandPolicy] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        agent_name: Optional[str] = None,
    ) -> None:
        super().__init__(agent_name=agent_name or self.agent_name)

        self.base_dir = Path(base_dir or os.getcwd()).resolve()
        self.policy = policy or CommandPolicy()

        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent

        self.event_callback = event_callback
        self.audit_callback = audit_callback

        self._processes: Dict[str, RunningProcess] = {}
        self._process_lock = threading.RLock()

        self.base_dir.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # Result helpers
    # -----------------------------------------------------------------------

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": bool(success),
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
            "timestamp": self._now(),
            "agent": self.agent_name,
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=error or message,
            metadata=metadata or {},
        )

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # -----------------------------------------------------------------------
    # Context and isolation
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[TerminalContext, Dict[str, Any]],
    ) -> Tuple[bool, Optional[TerminalContext], Optional[str]]:
        """
        Validate SaaS user/workspace isolation context.
        """

        if isinstance(context, TerminalContext):
            ctx = context
        elif isinstance(context, dict):
            try:
                ctx = TerminalContext(
                    user_id=context.get("user_id"),
                    workspace_id=context.get("workspace_id"),
                    actor_id=context.get("actor_id"),
                    role=context.get("role"),
                    request_id=context.get("request_id") or str(uuid.uuid4()),
                    session_id=context.get("session_id"),
                    metadata=context.get("metadata") or {},
                )
            except Exception as exc:
                return False, None, f"Invalid context format: {exc}"
        else:
            return False, None, "Context must be TerminalContext or dict."

        if ctx.user_id is None or str(ctx.user_id).strip() == "":
            return False, None, "Missing required user_id."

        if ctx.workspace_id is None or str(ctx.workspace_id).strip() == "":
            return False, None, "Missing required workspace_id."

        return True, ctx, None

    def _workspace_root(self, context: TerminalContext) -> Path:
        """
        Returns an isolated workspace execution root.
        """

        safe_user = self._safe_path_part(str(context.user_id))
        safe_workspace = self._safe_path_part(str(context.workspace_id))
        root = self.base_dir / "workspaces" / safe_user / safe_workspace
        root.mkdir(parents=True, exist_ok=True)
        return root.resolve()

    @staticmethod
    def _safe_path_part(value: str) -> str:
        value = value.strip()
        value = re.sub(r"[^a-zA-Z0-9_.-]", "_", value)
        return value[:120] or "unknown"

    def _resolve_cwd(
        self,
        context: TerminalContext,
        cwd: Optional[Union[str, Path]] = None,
        allow_base_dir: bool = False,
    ) -> Tuple[bool, Optional[Path], Optional[str]]:
        """
        Resolve cwd safely inside the user's workspace root.

        By default, commands cannot run outside:
            base_dir/workspaces/{user_id}/{workspace_id}
        """

        workspace_root = self._workspace_root(context)

        if cwd is None:
            return True, workspace_root, None

        raw_cwd = Path(cwd)
        if not raw_cwd.is_absolute():
            resolved = (workspace_root / raw_cwd).resolve()
        else:
            resolved = raw_cwd.resolve()

        allowed_root = self.base_dir if allow_base_dir else workspace_root

        try:
            resolved.relative_to(allowed_root.resolve())
        except ValueError:
            return (
                False,
                None,
                f"cwd is outside the allowed execution root: {resolved}",
            )

        resolved.mkdir(parents=True, exist_ok=True)
        return True, resolved, None

    # -----------------------------------------------------------------------
    # Safety checks
    # -----------------------------------------------------------------------

    def check_command_safety(
        self,
        command: Union[str, List[str], Tuple[str, ...]],
        shell: bool = False,
    ) -> Dict[str, Any]:
        """
        Check whether a command is allowed, blocked, or requires approval.
        """

        try:
            cmd_list = self._normalize_command(command, shell=shell)
            cmd_text = self._command_to_text(cmd_list)

            if not cmd_list:
                return self._error_result(
                    message="Empty command.",
                    error="empty_command",
                )

            executable = self._extract_executable(cmd_list)

            blocked_reason = self._get_blocked_reason(cmd_text, executable)
            if blocked_reason:
                return self._safe_result(
                    success=True,
                    message="Command is blocked by policy.",
                    data={
                        "safe": False,
                        "blocked": True,
                        "requires_security": True,
                        "reason": blocked_reason,
                        "command": cmd_list,
                    },
                )

            if shell and not self.policy.allow_shell:
                return self._safe_result(
                    success=True,
                    message="Shell execution is disabled by policy.",
                    data={
                        "safe": False,
                        "blocked": True,
                        "requires_security": True,
                        "reason": "shell_execution_disabled",
                        "command": cmd_list,
                    },
                )

            if not self._is_allowed_executable(executable):
                return self._safe_result(
                    success=True,
                    message="Command executable is not in allowed command list.",
                    data={
                        "safe": False,
                        "blocked": True,
                        "requires_security": True,
                        "reason": f"executable_not_allowed:{executable}",
                        "command": cmd_list,
                    },
                )

            requires_security, security_reason = self._requires_security_check(
                command=cmd_list,
                shell=shell,
            )

            return self._safe_result(
                success=True,
                message="Command safety checked.",
                data={
                    "safe": True,
                    "blocked": False,
                    "requires_security": requires_security,
                    "reason": security_reason,
                    "command": cmd_list,
                    "executable": executable,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to check command safety.",
                error=str(exc),
            )

    def _normalize_command(
        self,
        command: Union[str, List[str], Tuple[str, ...]],
        shell: bool = False,
    ) -> List[str]:
        if isinstance(command, str):
            if shell:
                return [command]
            return shlex.split(command, posix=os.name != "nt")

        if isinstance(command, tuple):
            return [str(part) for part in command]

        if isinstance(command, list):
            return [str(part) for part in command]

        raise ValueError("Command must be a string, list, or tuple.")

    @staticmethod
    def _command_to_text(command: List[str]) -> str:
        if len(command) == 1:
            return command[0]
        return " ".join(shlex.quote(str(part)) for part in command)

    @staticmethod
    def _extract_executable(command: List[str]) -> str:
        if not command:
            return ""

        first = str(command[0]).strip()

        if first in {"cmd", "cmd.exe"} and len(command) > 1:
            return "cmd"

        if first.lower() in {"powershell", "powershell.exe", "pwsh"}:
            return first.lower()

        return Path(first).name

    def _is_allowed_executable(self, executable: str) -> bool:
        normalized = executable.lower().strip()
        allowed = {Path(cmd).name.lower().strip() for cmd in self.policy.allowed_commands}
        return normalized in allowed

    def _get_blocked_reason(self, cmd_text: str, executable: str) -> Optional[str]:
        exe = executable.lower().strip()
        blocked = {cmd.lower().strip() for cmd in self.policy.blocked_commands}

        if exe in blocked:
            return f"blocked_executable:{exe}"

        for pattern in self.policy.blocked_patterns:
            if re.search(pattern, cmd_text, flags=re.IGNORECASE):
                return f"blocked_pattern:{pattern}"

        if not self.policy.allow_network_commands:
            network_tools = {"curl", "wget", "scp", "ssh", "ftp", "sftp", "nc", "netcat", "ncat"}
            if exe in network_tools:
                return f"network_command_disabled:{exe}"

        return None

    def _requires_security_check(
        self,
        command: Optional[List[str]] = None,
        action_type: Optional[str] = None,
        shell: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        """
        Decide if the action must be approved by Security Agent.
        """

        metadata = metadata or {}

        if shell:
            return True, "shell_execution"

        if action_type in {"install", "server", "git_write", "sensitive"}:
            return True, f"sensitive_action:{action_type}"

        cmd_text = self._command_to_text(command or [])

        for pattern in self.policy.sensitive_patterns:
            if re.search(pattern, cmd_text, flags=re.IGNORECASE):
                return True, f"sensitive_pattern:{pattern}"

        if metadata.get("requires_security") is True:
            return True, "metadata_requires_security"

        return False, "not_required"

    def _request_security_approval(
        self,
        context: TerminalContext,
        action: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent.

        If a real Security Agent is unavailable, this method uses strict safe default:
        sensitive actions are denied unless payload contains:
            approved_by_security=True

        This prevents accidental execution in incomplete deployments.
        """

        approval_payload = {
            "action": action,
            "agent": self.agent_name,
            "context": asdict(context),
            "payload": payload,
            "timestamp": self._now(),
        }

        if self.security_agent and hasattr(self.security_agent, "approve_action"):
            try:
                decision = self.security_agent.approve_action(approval_payload)
                if isinstance(decision, dict):
                    return decision
            except Exception as exc:
                return {
                    "approved": False,
                    "reason": f"Security Agent approval failed: {exc}",
                    "source": "security_agent_exception",
                }

        if payload.get("approved_by_security") is True:
            return {
                "approved": True,
                "reason": "Pre-approved by trusted caller payload.",
                "source": "payload_flag",
            }

        return {
            "approved": False,
            "reason": "Security Agent unavailable or approval missing.",
            "source": "safe_default_deny",
        }

    # -----------------------------------------------------------------------
    # Public execution methods
    # -----------------------------------------------------------------------

    def run_command(
        self,
        command: Union[str, List[str], Tuple[str, ...]],
        context: Union[TerminalContext, Dict[str, Any]],
        cwd: Optional[Union[str, Path]] = None,
        timeout: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
        shell: bool = False,
        input_text: Optional[str] = None,
        approved_by_security: bool = False,
        allow_base_dir: bool = False,
        purpose: str = "command",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run a safe terminal command.

        Returns structured:
            success, message, data, error, metadata
        """

        started = time.time()
        metadata = metadata or {}

        valid, ctx, ctx_error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(
                message="Invalid task context.",
                error=ctx_error,
                metadata={"purpose": purpose},
            )

        normalized_command: List[str] = []

        try:
            normalized_command = self._normalize_command(command, shell=shell)

            cwd_ok, resolved_cwd, cwd_error = self._resolve_cwd(
                context=ctx,
                cwd=cwd,
                allow_base_dir=allow_base_dir,
            )
            if not cwd_ok or resolved_cwd is None:
                return self._error_result(
                    message="Invalid working directory.",
                    error=cwd_error,
                    metadata={"context": asdict(ctx), "purpose": purpose},
                )

            safety = self.check_command_safety(normalized_command, shell=shell)
            safety_data = safety.get("data", {})

            if safety_data.get("blocked") is True:
                self._log_audit_event(
                    context=ctx,
                    action="terminal.command.blocked",
                    payload={
                        "command": normalized_command,
                        "cwd": str(resolved_cwd),
                        "reason": safety_data.get("reason"),
                        "purpose": purpose,
                    },
                )
                return self._error_result(
                    message="Command blocked by security policy.",
                    error=safety_data.get("reason"),
                    data={"safety": safety_data},
                    metadata={"context": asdict(ctx), "purpose": purpose},
                )

            requires_security = bool(safety_data.get("requires_security"))

            if requires_security:
                approval = self._request_security_approval(
                    context=ctx,
                    action="terminal.run_command",
                    payload={
                        "command": normalized_command,
                        "cwd": str(resolved_cwd),
                        "purpose": purpose,
                        "approved_by_security": approved_by_security,
                        "metadata": metadata,
                    },
                )
                if not approval.get("approved"):
                    self._log_audit_event(
                        context=ctx,
                        action="terminal.command.denied",
                        payload={
                            "command": normalized_command,
                            "cwd": str(resolved_cwd),
                            "approval": approval,
                            "purpose": purpose,
                        },
                    )
                    return self._error_result(
                        message="Command requires Security Agent approval.",
                        error=approval.get("reason"),
                        data={
                            "approval": approval,
                            "safety": safety_data,
                        },
                        metadata={"context": asdict(ctx), "purpose": purpose},
                    )

            timeout_seconds = self._safe_timeout(timeout)

            safe_env = self._build_safe_env(env=env, context=ctx)

            self._emit_agent_event(
                context=ctx,
                event_type="terminal.command.started",
                payload={
                    "command": normalized_command,
                    "cwd": str(resolved_cwd),
                    "timeout": timeout_seconds,
                    "purpose": purpose,
                },
            )

            completed = subprocess.run(
                normalized_command if not shell else self._command_to_text(normalized_command),
                cwd=str(resolved_cwd),
                env=safe_env,
                input=input_text,
                text=True,
                capture_output=True,
                timeout=timeout_seconds,
                shell=shell,
            )

            duration_ms = int((time.time() - started) * 1000)

            stdout = self._truncate_output(completed.stdout or "")
            stderr = self._truncate_output(completed.stderr or "")

            result_data = {
                "command": normalized_command,
                "command_text": self._command_to_text(normalized_command),
                "cwd": str(resolved_cwd),
                "return_code": completed.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "duration_ms": duration_ms,
                "timeout_seconds": timeout_seconds,
                "purpose": purpose,
            }

            success = completed.returncode == 0
            message = "Command completed successfully." if success else "Command completed with errors."

            verification_payload = self._prepare_verification_payload(
                context=ctx,
                action="terminal.run_command",
                result_data=result_data,
                success=success,
            )

            memory_payload = self._prepare_memory_payload(
                context=ctx,
                action="terminal.run_command",
                result_data=result_data,
                success=success,
            )

            self._log_audit_event(
                context=ctx,
                action="terminal.command.completed",
                payload={
                    "command": normalized_command,
                    "cwd": str(resolved_cwd),
                    "return_code": completed.returncode,
                    "duration_ms": duration_ms,
                    "purpose": purpose,
                    "success": success,
                },
            )

            self._emit_agent_event(
                context=ctx,
                event_type="terminal.command.completed",
                payload={
                    "command": normalized_command,
                    "return_code": completed.returncode,
                    "duration_ms": duration_ms,
                    "purpose": purpose,
                    "success": success,
                },
            )

            return self._safe_result(
                success=success,
                message=message,
                data=result_data,
                error=None if success else stderr or f"Command failed with return code {completed.returncode}",
                metadata={
                    "context": asdict(ctx),
                    "safety": safety_data,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                    "purpose": purpose,
                },
            )

        except subprocess.TimeoutExpired as exc:
            duration_ms = int((time.time() - started) * 1000)
            self._log_audit_event(
                context=ctx,
                action="terminal.command.timeout",
                payload={
                    "command": normalized_command,
                    "timeout": timeout,
                    "duration_ms": duration_ms,
                    "purpose": purpose,
                },
            )
            return self._error_result(
                message="Command timed out.",
                error=str(exc),
                data={
                    "command": normalized_command,
                    "stdout": self._truncate_output(exc.stdout or ""),
                    "stderr": self._truncate_output(exc.stderr or ""),
                    "duration_ms": duration_ms,
                },
                metadata={"context": asdict(ctx), "purpose": purpose},
            )

        except FileNotFoundError as exc:
            return self._error_result(
                message="Command executable not found.",
                error=str(exc),
                data={"command": normalized_command},
                metadata={"context": asdict(ctx), "purpose": purpose},
            )

        except Exception as exc:
            logger.exception("Terminal command execution failed.")
            return self._error_result(
                message="Terminal command execution failed.",
                error=str(exc),
                data={"command": normalized_command},
                metadata={"context": asdict(ctx), "purpose": purpose},
            )

    def run_python(
        self,
        script_or_args: Union[str, List[str], Tuple[str, ...]],
        context: Union[TerminalContext, Dict[str, Any]],
        cwd: Optional[Union[str, Path]] = None,
        timeout: Optional[int] = None,
        approved_by_security: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run a Python script or Python command safely.

        Examples:
            run_python(["manage.py", "test"], context)
            run_python("-m pytest", context)
        """

        if isinstance(script_or_args, str):
            args = shlex.split(script_or_args, posix=os.name != "nt")
        else:
            args = [str(x) for x in script_or_args]

        command = [sys.executable] + args

        return self.run_command(
            command=command,
            context=context,
            cwd=cwd,
            timeout=timeout,
            approved_by_security=approved_by_security,
            purpose="python",
            metadata=metadata,
        )

    def run_install(
        self,
        package_manager: str,
        packages: Optional[List[str]],
        context: Union[TerminalContext, Dict[str, Any]],
        cwd: Optional[Union[str, Path]] = None,
        dev: bool = False,
        timeout: Optional[int] = None,
        approved_by_security: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run dependency install commands with Security Agent approval.

        Supported package managers:
            pip, npm, yarn, pnpm
        """

        package_manager = package_manager.strip().lower()
        packages = packages or []

        if package_manager not in {"pip", "pip3", "npm", "yarn", "pnpm"}:
            return self._error_result(
                message="Unsupported package manager.",
                error=f"Unsupported package manager: {package_manager}",
            )

        command: List[str]

        if package_manager in {"pip", "pip3"}:
            command = [sys.executable, "-m", "pip", "install"] + packages

        elif package_manager == "npm":
            command = ["npm", "install"]
            if dev:
                command.append("--save-dev")
            command.extend(packages)

        elif package_manager == "yarn":
            command = ["yarn", "add"]
            if dev:
                command.append("--dev")
            command.extend(packages)

        else:
            command = ["pnpm", "add"]
            if dev:
                command.append("--save-dev")
            command.extend(packages)

        return self.run_command(
            command=command,
            context=context,
            cwd=cwd,
            timeout=timeout or self.policy.max_timeout_seconds,
            approved_by_security=approved_by_security,
            purpose="install",
            metadata={
                **(metadata or {}),
                "package_manager": package_manager,
                "packages": packages,
                "dev": dev,
                "requires_security": self.policy.require_security_for_installs,
            },
        )

    def run_tests(
        self,
        context: Union[TerminalContext, Dict[str, Any]],
        cwd: Optional[Union[str, Path]] = None,
        test_command: Optional[Union[str, List[str]]] = None,
        timeout: Optional[int] = None,
        approved_by_security: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run project tests.

        Default:
            python -m pytest
        """

        command: Union[str, List[str]]

        if test_command:
            command = test_command
        else:
            command = [sys.executable, "-m", "pytest"]

        return self.run_command(
            command=command,
            context=context,
            cwd=cwd,
            timeout=timeout or self.policy.max_timeout_seconds,
            approved_by_security=approved_by_security,
            purpose="tests",
            metadata=metadata,
        )

    def run_build(
        self,
        context: Union[TerminalContext, Dict[str, Any]],
        cwd: Optional[Union[str, Path]] = None,
        build_command: Optional[Union[str, List[str]]] = None,
        project_type: Optional[str] = None,
        timeout: Optional[int] = None,
        approved_by_security: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run a safe build command.

        Auto defaults:
            node/frontend -> npm run build
            python       -> python -m compileall .
        """

        if build_command:
            command = build_command
        elif project_type in {"node", "frontend", "react", "next", "vite"}:
            command = ["npm", "run", "build"]
        else:
            command = [sys.executable, "-m", "compileall", "."]

        return self.run_command(
            command=command,
            context=context,
            cwd=cwd,
            timeout=timeout or self.policy.max_timeout_seconds,
            approved_by_security=approved_by_security,
            purpose="build",
            metadata={
                **(metadata or {}),
                "project_type": project_type,
            },
        )

    def start_server(
        self,
        command: Union[str, List[str], Tuple[str, ...]],
        context: Union[TerminalContext, Dict[str, Any]],
        cwd: Optional[Union[str, Path]] = None,
        env: Optional[Dict[str, str]] = None,
        shell: bool = False,
        approved_by_security: bool = False,
        allow_base_dir: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Start a long-running server process.

        The process is tracked by process_id and can be stopped with stop_process().
        """

        metadata = metadata or {}

        valid, ctx, ctx_error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(
                message="Invalid task context.",
                error=ctx_error,
                metadata={"purpose": "server"},
            )

        try:
            normalized_command = self._normalize_command(command, shell=shell)

            cwd_ok, resolved_cwd, cwd_error = self._resolve_cwd(
                context=ctx,
                cwd=cwd,
                allow_base_dir=allow_base_dir,
            )
            if not cwd_ok or resolved_cwd is None:
                return self._error_result(
                    message="Invalid working directory.",
                    error=cwd_error,
                    metadata={"context": asdict(ctx), "purpose": "server"},
                )

            safety = self.check_command_safety(normalized_command, shell=shell)
            safety_data = safety.get("data", {})

            if safety_data.get("blocked") is True:
                return self._error_result(
                    message="Server command blocked by security policy.",
                    error=safety_data.get("reason"),
                    data={"safety": safety_data},
                    metadata={"context": asdict(ctx), "purpose": "server"},
                )

            requires_security, reason = self._requires_security_check(
                command=normalized_command,
                action_type="server" if self.policy.require_security_for_servers else None,
                shell=shell,
            )

            if requires_security:
                approval = self._request_security_approval(
                    context=ctx,
                    action="terminal.start_server",
                    payload={
                        "command": normalized_command,
                        "cwd": str(resolved_cwd),
                        "approved_by_security": approved_by_security,
                        "reason": reason,
                        "metadata": metadata,
                    },
                )
                if not approval.get("approved"):
                    return self._error_result(
                        message="Starting server requires Security Agent approval.",
                        error=approval.get("reason"),
                        data={
                            "approval": approval,
                            "safety": safety_data,
                        },
                        metadata={"context": asdict(ctx), "purpose": "server"},
                    )

            safe_env = self._build_safe_env(env=env, context=ctx)

            process = subprocess.Popen(
                normalized_command if not shell else self._command_to_text(normalized_command),
                cwd=str(resolved_cwd),
                env=safe_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                shell=shell,
                start_new_session=(os.name != "nt"),
            )

            process_id = str(uuid.uuid4())

            running = RunningProcess(
                process_id=process_id,
                command=normalized_command,
                cwd=str(resolved_cwd),
                started_at=self._now(),
                context=ctx,
                popen=process,
                purpose="server",
                metadata=metadata,
            )

            with self._process_lock:
                self._processes[process_id] = running

            self._log_audit_event(
                context=ctx,
                action="terminal.server.started",
                payload={
                    "process_id": process_id,
                    "pid": process.pid,
                    "command": normalized_command,
                    "cwd": str(resolved_cwd),
                },
            )

            self._emit_agent_event(
                context=ctx,
                event_type="terminal.server.started",
                payload={
                    "process_id": process_id,
                    "pid": process.pid,
                    "command": normalized_command,
                },
            )

            return self._safe_result(
                success=True,
                message="Server process started.",
                data={
                    "process_id": process_id,
                    "pid": process.pid,
                    "command": normalized_command,
                    "cwd": str(resolved_cwd),
                    "running": self._is_process_running(process),
                },
                metadata={
                    "context": asdict(ctx),
                    "safety": safety_data,
                    "verification_payload": self._prepare_verification_payload(
                        context=ctx,
                        action="terminal.start_server",
                        result_data={
                            "process_id": process_id,
                            "pid": process.pid,
                            "command": normalized_command,
                        },
                        success=True,
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        context=ctx,
                        action="terminal.start_server",
                        result_data={
                            "process_id": process_id,
                            "pid": process.pid,
                            "command": normalized_command,
                        },
                        success=True,
                    ),
                },
            )

        except Exception as exc:
            logger.exception("Failed to start server.")
            return self._error_result(
                message="Failed to start server.",
                error=str(exc),
                metadata={"context": asdict(ctx), "purpose": "server"},
            )

    def stop_process(
        self,
        process_id: str,
        context: Union[TerminalContext, Dict[str, Any]],
        force: bool = False,
    ) -> Dict[str, Any]:
        """
        Stop a tracked process by process_id.
        """

        valid, ctx, ctx_error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(
                message="Invalid task context.",
                error=ctx_error,
            )

        with self._process_lock:
            running = self._processes.get(process_id)

        if not running:
            return self._error_result(
                message="Process not found.",
                error=f"No tracked process for id: {process_id}",
                metadata={"context": asdict(ctx)},
            )

        if str(running.context.user_id) != str(ctx.user_id) or str(running.context.workspace_id) != str(ctx.workspace_id):
            return self._error_result(
                message="Process does not belong to this user/workspace.",
                error="workspace_isolation_violation",
                metadata={"context": asdict(ctx)},
            )

        try:
            process = running.popen

            if self._is_process_running(process):
                if os.name == "nt":
                    process.terminate()
                else:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)

                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    if force:
                        if os.name == "nt":
                            process.kill()
                        else:
                            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                        process.wait(timeout=10)
                    else:
                        return self._error_result(
                            message="Process did not stop within timeout.",
                            error="process_stop_timeout",
                            data={
                                "process_id": process_id,
                                "pid": process.pid,
                                "force_available": True,
                            },
                            metadata={"context": asdict(ctx)},
                        )

            stdout, stderr = self._collect_process_output(process)

            with self._process_lock:
                self._processes.pop(process_id, None)

            self._log_audit_event(
                context=ctx,
                action="terminal.process.stopped",
                payload={
                    "process_id": process_id,
                    "pid": process.pid,
                    "force": force,
                    "return_code": process.returncode,
                },
            )

            return self._safe_result(
                success=True,
                message="Process stopped.",
                data={
                    "process_id": process_id,
                    "pid": process.pid,
                    "return_code": process.returncode,
                    "stdout": stdout,
                    "stderr": stderr,
                },
                metadata={
                    "context": asdict(ctx),
                    "verification_payload": self._prepare_verification_payload(
                        context=ctx,
                        action="terminal.stop_process",
                        result_data={
                            "process_id": process_id,
                            "pid": process.pid,
                            "return_code": process.returncode,
                        },
                        success=True,
                    ),
                },
            )

        except Exception as exc:
            logger.exception("Failed to stop process.")
            return self._error_result(
                message="Failed to stop process.",
                error=str(exc),
                metadata={"context": asdict(ctx), "process_id": process_id},
            )

    def stop_all_processes(
        self,
        context: Union[TerminalContext, Dict[str, Any]],
        force: bool = False,
    ) -> Dict[str, Any]:
        """
        Stop all tracked processes for a user/workspace.
        """

        valid, ctx, ctx_error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(
                message="Invalid task context.",
                error=ctx_error,
            )

        with self._process_lock:
            process_ids = [
                pid for pid, proc in self._processes.items()
                if str(proc.context.user_id) == str(ctx.user_id)
                and str(proc.context.workspace_id) == str(ctx.workspace_id)
            ]

        results = []
        for pid in process_ids:
            results.append(self.stop_process(pid, ctx, force=force))

        return self._safe_result(
            success=True,
            message="Stop all processes completed.",
            data={
                "count": len(process_ids),
                "results": results,
            },
            metadata={"context": asdict(ctx)},
        )

    def list_processes(
        self,
        context: Union[TerminalContext, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        List tracked processes for this user/workspace only.
        """

        valid, ctx, ctx_error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(
                message="Invalid task context.",
                error=ctx_error,
            )

        processes = []

        with self._process_lock:
            for process_id, running in self._processes.items():
                if str(running.context.user_id) != str(ctx.user_id):
                    continue
                if str(running.context.workspace_id) != str(ctx.workspace_id):
                    continue

                processes.append({
                    "process_id": process_id,
                    "pid": running.popen.pid,
                    "command": running.command,
                    "cwd": running.cwd,
                    "started_at": running.started_at,
                    "purpose": running.purpose,
                    "running": self._is_process_running(running.popen),
                    "return_code": running.popen.poll(),
                    "metadata": running.metadata,
                })

        return self._safe_result(
            success=True,
            message="Processes listed.",
            data={"processes": processes},
            metadata={"context": asdict(ctx)},
        )

    # -----------------------------------------------------------------------
    # Payload hooks
    # -----------------------------------------------------------------------

    def _prepare_verification_payload(
        self,
        context: TerminalContext,
        action: str,
        result_data: Dict[str, Any],
        success: bool,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent-compatible payload.
        """

        payload = {
            "verification_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "action": action,
            "success": success,
            "context": asdict(context),
            "result_summary": {
                "return_code": result_data.get("return_code"),
                "duration_ms": result_data.get("duration_ms"),
                "process_id": result_data.get("process_id"),
                "pid": result_data.get("pid"),
                "purpose": result_data.get("purpose"),
            },
            "checks": {
                "command_completed": success,
                "workspace_isolated": True,
                "structured_result": True,
                "audit_prepared": True,
            },
            "timestamp": self._now(),
        }

        if self.verification_agent and hasattr(self.verification_agent, "prepare_payload"):
            try:
                maybe_payload = self.verification_agent.prepare_payload(payload)
                if isinstance(maybe_payload, dict):
                    return maybe_payload
            except Exception:
                logger.exception("Verification Agent payload hook failed.")

        return payload

    def _prepare_memory_payload(
        self,
        context: TerminalContext,
        action: str,
        result_data: Dict[str, Any],
        success: bool,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.
        """

        stdout = result_data.get("stdout") or ""
        stderr = result_data.get("stderr") or ""

        payload = {
            "memory_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "action": action,
            "context": asdict(context),
            "success": success,
            "summary": self._summarize_execution(result_data, success),
            "signals": {
                "command": result_data.get("command"),
                "cwd": result_data.get("cwd"),
                "return_code": result_data.get("return_code"),
                "has_stdout": bool(stdout),
                "has_stderr": bool(stderr),
                "purpose": result_data.get("purpose"),
            },
            "timestamp": self._now(),
        }

        if self.memory_agent and hasattr(self.memory_agent, "prepare_payload"):
            try:
                maybe_payload = self.memory_agent.prepare_payload(payload)
                if isinstance(maybe_payload, dict):
                    return maybe_payload
            except Exception:
                logger.exception("Memory Agent payload hook failed.")

        return payload

    @staticmethod
    def _summarize_execution(result_data: Dict[str, Any], success: bool) -> str:
        command_text = result_data.get("command_text") or result_data.get("command")
        purpose = result_data.get("purpose", "command")
        return_code = result_data.get("return_code")
        status = "succeeded" if success else "failed"
        return f"Terminal {purpose} {status}. Command={command_text}, return_code={return_code}."

    def _emit_agent_event(
        self,
        context: TerminalContext,
        event_type: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Emit agent event for dashboard/API/analytics integrations.
        """

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": self.agent_name,
            "context": asdict(context),
            "payload": payload,
            "timestamp": self._now(),
        }

        if self.event_callback:
            try:
                self.event_callback(event)
            except Exception:
                logger.exception("Event callback failed.")

        logger.info("Agent event: %s", event_type)

    def _log_audit_event(
        self,
        context: TerminalContext,
        action: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Log audit event for security and dashboard history.
        """

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "action": action,
            "agent": self.agent_name,
            "context": asdict(context),
            "payload": payload,
            "timestamp": self._now(),
        }

        if self.audit_callback:
            try:
                self.audit_callback(audit_event)
            except Exception:
                logger.exception("Audit callback failed.")

        logger.info("Audit event: %s", action)

    # -----------------------------------------------------------------------
    # Utility methods
    # -----------------------------------------------------------------------

    def _safe_timeout(self, timeout: Optional[int]) -> int:
        if timeout is None:
            return self.policy.default_timeout_seconds

        try:
            timeout_int = int(timeout)
        except Exception:
            return self.policy.default_timeout_seconds

        if timeout_int <= 0:
            return self.policy.default_timeout_seconds

        return min(timeout_int, self.policy.max_timeout_seconds)

    def _build_safe_env(
        self,
        env: Optional[Dict[str, str]],
        context: TerminalContext,
    ) -> Dict[str, str]:
        """
        Build environment variables without hardcoding secrets.

        Sensitive values are not injected automatically.
        """

        safe_env = os.environ.copy()

        safe_env["WILLIAM_USER_ID"] = str(context.user_id)
        safe_env["WILLIAM_WORKSPACE_ID"] = str(context.workspace_id)
        safe_env["WILLIAM_REQUEST_ID"] = str(context.request_id)
        safe_env["WILLIAM_AGENT"] = self.agent_name

        if env:
            for key, value in env.items():
                if not self._is_safe_env_key(key):
                    continue
                safe_env[str(key)] = str(value)

        return safe_env

    @staticmethod
    def _is_safe_env_key(key: str) -> bool:
        """
        Reject obvious secret-like env keys from casual injection.
        Real secret handling should go through a secure secrets manager.
        """

        key_upper = key.upper()
        blocked_fragments = [
            "SECRET",
            "PASSWORD",
            "TOKEN",
            "PRIVATE_KEY",
            "API_KEY",
            "ACCESS_KEY",
        ]
        return not any(fragment in key_upper for fragment in blocked_fragments)

    def _truncate_output(self, value: str) -> str:
        if value is None:
            return ""

        value = str(value)

        if len(value) <= self.policy.max_output_chars:
            return value

        return (
            value[: self.policy.max_output_chars]
            + "\n\n...[output truncated by TerminalRunner safety policy]..."
        )

    @staticmethod
    def _is_process_running(process: subprocess.Popen) -> bool:
        return process.poll() is None

    def _collect_process_output(self, process: subprocess.Popen) -> Tuple[str, str]:
        stdout = ""
        stderr = ""

        try:
            if process.stdout:
                stdout = process.stdout.read() or ""
        except Exception:
            stdout = ""

        try:
            if process.stderr:
                stderr = process.stderr.read() or ""
        except Exception:
            stderr = ""

        return self._truncate_output(stdout), self._truncate_output(stderr)

    # -----------------------------------------------------------------------
    # Registry / router compatibility
    # -----------------------------------------------------------------------

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Expose capabilities to Agent Registry, Agent Loader, Agent Router,
        and Master Agent routing.
        """

        return {
            "agent": self.agent_name,
            "module": "code_agent",
            "file": "terminal_runner.py",
            "class": self.__class__.__name__,
            "capabilities": [
                "run_safe_terminal_commands",
                "run_python_commands",
                "run_dependency_installs_with_approval",
                "run_tests",
                "run_builds",
                "start_servers",
                "stop_servers",
                "audit_terminal_actions",
                "prepare_verification_payloads",
                "prepare_memory_payloads",
            ],
            "requires_context": ["user_id", "workspace_id"],
            "security_sensitive": True,
            "supports_saas_isolation": True,
            "supports_dashboard_events": True,
            "supports_audit_logs": True,
        }

    def health_check(self) -> Dict[str, Any]:
        """
        Basic health check for dashboard/API.
        """

        return self._safe_result(
            success=True,
            message="TerminalRunner is healthy.",
            data={
                "base_dir": str(self.base_dir),
                "base_dir_exists": self.base_dir.exists(),
                "tracked_processes": len(self._processes),
                "policy": {
                    "max_timeout_seconds": self.policy.max_timeout_seconds,
                    "default_timeout_seconds": self.policy.default_timeout_seconds,
                    "allow_shell": self.policy.allow_shell,
                    "allow_network_commands": self.policy.allow_network_commands,
                },
            },
        )


# ---------------------------------------------------------------------------
# Simple manual test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    runner = TerminalRunner(base_dir=Path.cwd() / ".william_terminal_runner_test")

    demo_context = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "actor_id": "local_test",
        "role": "developer",
    }

    result = runner.run_command(
        command=[sys.executable, "--version"],
        context=demo_context,
        timeout=20,
    )

    print(result)