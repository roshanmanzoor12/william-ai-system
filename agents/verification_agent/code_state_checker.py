"""
agents/verification_agent/code_state_checker.py

William / Jarvis Multi-Agent AI SaaS System
Verification Agent - Code State Checker

Purpose:
    Confirms code edits, syntax, builds, tests, servers, and endpoints.

This module is intentionally import-safe:
    - It does not require the rest of William/Jarvis to exist.
    - It provides fallback BaseAgent behavior if core modules are not available.
    - It avoids secrets and destructive actions.
    - It supports SaaS user/workspace isolation through required task context.

Responsibilities:
    - Verify code file existence and content expectations.
    - Verify Python syntax using AST/compile validation.
    - Verify Python files with py_compile.
    - Verify file hashes for edit confirmation.
    - Run safe build/test commands with allowlist protection.
    - Check local TCP ports for server readiness.
    - Check HTTP/HTTPS endpoints with timeout, method, status, and body expectations.
    - Produce structured result dictionaries.
    - Prepare Verification Agent payloads.
    - Prepare Memory Agent payloads for useful context.
    - Emit agent events and audit logs where integrations are available.

Connections:
    - Master Agent:
        Can call public methods on CodeStateChecker for post-task confirmation.
    - Security Agent:
        Sensitive or command-based checks route through security approval hooks.
    - Verification Agent:
        This is a helper/checker under the Verification Agent module.
    - Memory Agent:
        Useful verification summaries can be sent as memory-compatible payloads.
    - Dashboard/API:
        All public methods return dict/JSON-style data.
    - Agent Registry / Agent Loader:
        Exposes stable class name CodeStateChecker and metadata methods.
"""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import os
import py_compile
import re
import shlex
import socket
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    try:
        from core.base_agent import BaseAgent  # type: ignore
    except Exception:

        class BaseAgent:  # type: ignore
            """
            Import-safe fallback BaseAgent.

            Real William/Jarvis deployments should provide their own BaseAgent.
            This fallback keeps the file usable in isolation during early builds,
            tests, or partial repository generation.
            """

            def __init__(self, *args: Any, **kwargs: Any) -> None:
                self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
                self.logger = logging.getLogger(self.agent_name)

            def emit_event(self, event_type: str, payload: Dict[str, Any]) -> None:
                self.logger.debug("Fallback emit_event: %s %s", event_type, payload)

            def log_audit(self, payload: Dict[str, Any]) -> None:
                self.logger.info("Fallback audit_log: %s", payload)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("William.VerificationAgent.CodeStateChecker")
if not LOGGER.handlers:
    logging.basicConfig(
        level=os.getenv("WILLIAM_LOG_LEVEL", "INFO"),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CodeCheckConfig:
    """
    Safe defaults for code verification.

    This checker is designed to confirm state, not mutate production systems.
    Commands are limited to a conservative allowlist and may be further gated
    by Security Agent in production.
    """

    max_file_bytes: int = 5 * 1024 * 1024
    command_timeout_seconds: int = 120
    endpoint_timeout_seconds: int = 10
    socket_timeout_seconds: int = 5
    max_command_output_chars: int = 12000
    allow_subprocess: bool = True
    allow_network_checks: bool = True
    allow_external_http: bool = False
    allowed_command_roots: Tuple[str, ...] = (
        "python",
        "python3",
        sys.executable,
        "pytest",
        "ruff",
        "mypy",
        "npm",
        "pnpm",
        "yarn",
        "node",
        "uv",
        "poetry",
        "pip",
        "pipenv",
        "tox",
        "coverage",
    )
    dangerous_tokens: Tuple[str, ...] = (
        "rm",
        "del",
        "erase",
        "format",
        "mkfs",
        "shutdown",
        "reboot",
        "halt",
        "poweroff",
        "killall",
        "taskkill",
        "curl",
        "wget",
        "scp",
        "ssh",
        "ftp",
        "sftp",
        "chmod",
        "chown",
        "sudo",
        "su",
        "dd",
        ">",
        ">>",
        "|",
        "&&",
        "||",
        ";",
        "`",
        "$(",
    )
    safe_http_methods: Tuple[str, ...] = ("GET", "HEAD", "OPTIONS")


@dataclass
class CodeFileExpectation:
    """
    Expectations for confirming a code edit.

    Attributes:
        path:
            File path to inspect.
        expected_contains:
            Strings expected to exist in the file.
        expected_absent:
            Strings expected not to exist in the file.
        expected_regex:
            Regex patterns expected to match.
        expected_sha256:
            Exact sha256 hash expected for the file.
        min_size_bytes:
            Minimum allowed file size.
        max_size_bytes:
            Maximum allowed file size.
    """

    path: Union[str, Path]
    expected_contains: List[str] = field(default_factory=list)
    expected_absent: List[str] = field(default_factory=list)
    expected_regex: List[str] = field(default_factory=list)
    expected_sha256: Optional[str] = None
    min_size_bytes: Optional[int] = None
    max_size_bytes: Optional[int] = None


@dataclass
class CommandCheck:
    """
    Build/test command check.

    Commands are verified against safety rules before execution.
    """

    command: Union[str, Sequence[str]]
    cwd: Optional[Union[str, Path]] = None
    timeout_seconds: Optional[int] = None
    expected_exit_codes: Tuple[int, ...] = (0,)
    expected_stdout_contains: List[str] = field(default_factory=list)
    expected_stderr_absent: List[str] = field(default_factory=list)
    label: str = "command_check"


@dataclass
class EndpointCheck:
    """
    HTTP endpoint verification check.
    """

    url: str
    method: str = "GET"
    expected_statuses: Tuple[int, ...] = (200,)
    expected_body_contains: List[str] = field(default_factory=list)
    expected_body_absent: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    timeout_seconds: Optional[int] = None
    allow_external: Optional[bool] = None
    label: str = "endpoint_check"


@dataclass
class PortCheck:
    """
    TCP port readiness check.
    """

    host: str = "127.0.0.1"
    port: int = 8000
    timeout_seconds: Optional[int] = None
    expected_open: bool = True
    label: str = "port_check"


# ---------------------------------------------------------------------------
# Main checker
# ---------------------------------------------------------------------------

class CodeStateChecker(BaseAgent):
    """
    Verification Agent helper for code-related state checks.

    Public methods return structured dicts using:
        success, message, data, error, metadata

    Typical usage:
        checker = CodeStateChecker()
        result = checker.verify_python_syntax(
            user_id="u_123",
            workspace_id="w_123",
            file_paths=["app/main.py"],
        )
    """

    agent_type = "verification_agent.helper"
    checker_name = "code_state_checker"
    file_path = "agents/verification_agent/code_state_checker.py"
    version = "1.0.0"

    def __init__(
        self,
        config: Optional[CodeCheckConfig] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name="CodeStateChecker", **kwargs)
        self.config = config or CodeCheckConfig()
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger
        self.logger = logger or LOGGER

    # -----------------------------------------------------------------------
    # Registry / loader metadata
    # -----------------------------------------------------------------------

    def get_agent_metadata(self) -> Dict[str, Any]:
        """
        Metadata used by Agent Registry, Agent Loader, Agent Router, and Dashboard.
        """

        return {
            "name": self.__class__.__name__,
            "checker_name": self.checker_name,
            "agent_type": self.agent_type,
            "module": "verification_agent",
            "file_path": self.file_path,
            "version": self.version,
            "capabilities": [
                "code_edit_confirmation",
                "file_hash_verification",
                "python_syntax_check",
                "python_compile_check",
                "safe_build_command_check",
                "safe_test_command_check",
                "server_port_check",
                "http_endpoint_check",
                "verification_payload_generation",
                "memory_payload_generation",
            ],
            "requires_user_context": True,
            "requires_workspace_context": True,
            "safe_to_import": True,
        }

    def health_check(self) -> Dict[str, Any]:
        """
        Lightweight import/runtime readiness check.
        """

        return self._safe_result(
            success=True,
            message="CodeStateChecker is ready.",
            data={
                "metadata": self.get_agent_metadata(),
                "python_version": sys.version,
                "cwd": str(Path.cwd()),
                "allow_subprocess": self.config.allow_subprocess,
                "allow_network_checks": self.config.allow_network_checks,
            },
        )

    # -----------------------------------------------------------------------
    # Required compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        task_id: Optional[str] = None,
        extra: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Enforces SaaS user/workspace isolation.

        All user-specific verification checks must include user_id and workspace_id.
        """

        errors: List[str] = []

        if not user_id or not str(user_id).strip():
            errors.append("Missing required user_id.")
        if not workspace_id or not str(workspace_id).strip():
            errors.append("Missing required workspace_id.")

        context = {
            "user_id": str(user_id).strip() if user_id else None,
            "workspace_id": str(workspace_id).strip() if workspace_id else None,
            "task_id": str(task_id).strip() if task_id else None,
            "extra": dict(extra or {}),
        }

        if errors:
            return self._error_result(
                message="Invalid task context.",
                error={
                    "code": "INVALID_TASK_CONTEXT",
                    "details": errors,
                },
                metadata={"context": context},
            )

        return self._safe_result(
            success=True,
            message="Task context validated.",
            data={"context": context},
        )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Determines whether Security Agent approval is needed.

        Command execution and external HTTP checks are gated. File reads,
        hashing, parsing, local port checks, and syntax checks are non-destructive
        but still audited.
        """

        action = (action or "").lower().strip()
        payload_dict = dict(payload or {})

        if action in {
            "run_command",
            "run_build",
            "run_tests",
            "check_endpoint_external",
        }:
            return True

        command = payload_dict.get("command")
        if command:
            return True

        url = str(payload_dict.get("url") or "")
        if url and not self._is_local_url(url):
            return True

        return False

    def _request_security_approval(
        self,
        user_id: str,
        workspace_id: str,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Requests Security Agent approval when available.

        If no Security Agent is connected, this method applies strict local safety
        rules and only approves actions that pass conservative checks.
        """

        request_payload = {
            "agent": self.__class__.__name__,
            "module": "verification_agent",
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": dict(payload or {}),
            "timestamp": self._utc_timestamp(),
        }

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
                        approval = method(request_payload)
                        if isinstance(approval, dict):
                            approved = bool(
                                approval.get("approved")
                                or approval.get("success")
                                or approval.get("allowed")
                            )
                            return self._safe_result(
                                success=approved,
                                message=approval.get(
                                    "message",
                                    "Security approval returned.",
                                ),
                                data={"approval": approval},
                                error=None if approved else approval.get("error"),
                            )
                    except Exception as exc:
                        return self._error_result(
                            message="Security approval request failed.",
                            error={
                                "code": "SECURITY_AGENT_ERROR",
                                "exception": str(exc),
                            },
                            metadata={"request": request_payload},
                        )

        local_approval = self._local_security_check(action, payload or {})
        return local_approval

    def _prepare_verification_payload(
        self,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str],
        check_type: str,
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Creates a Verification Agent-compatible payload.
        """

        return {
            "agent": "VerificationAgent",
            "checker": self.__class__.__name__,
            "check_type": check_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "data": result.get("data", {}),
            "error": result.get("error"),
            "metadata": {
                **dict(result.get("metadata") or {}),
                "generated_by": self.__class__.__name__,
                "generated_at": self._utc_timestamp(),
            },
        }

    def _prepare_memory_payload(
        self,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str],
        summary: str,
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Creates a Memory Agent-compatible payload.

        Only stores useful verification context, not secrets or full command output.
        """

        sanitized = self._sanitize_for_memory(dict(result))
        return {
            "type": "verification_code_state",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "summary": summary,
            "source_agent": self.__class__.__name__,
            "timestamp": self._utc_timestamp(),
            "data": sanitized,
        }

    def _emit_agent_event(
        self,
        event_type: str,
        payload: Mapping[str, Any],
    ) -> None:
        """
        Emits an event to the event bus or BaseAgent fallback.
        """

        safe_payload = dict(payload)
        try:
            if self.event_bus is not None:
                if hasattr(self.event_bus, "emit") and callable(self.event_bus.emit):
                    self.event_bus.emit(event_type, safe_payload)
                    return
                if hasattr(self.event_bus, "publish") and callable(self.event_bus.publish):
                    self.event_bus.publish(event_type, safe_payload)
                    return

            emit_event = getattr(super(), "emit_event", None)
            if callable(emit_event):
                emit_event(event_type, safe_payload)
        except Exception as exc:
            self.logger.debug("Unable to emit event %s: %s", event_type, exc)

    def _log_audit_event(
        self,
        user_id: str,
        workspace_id: str,
        action: str,
        result: Mapping[str, Any],
        task_id: Optional[str] = None,
    ) -> None:
        """
        Writes audit metadata without leaking secrets or excessive output.
        """

        audit_payload = {
            "agent": self.__class__.__name__,
            "module": "verification_agent",
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "timestamp": self._utc_timestamp(),
            "metadata": self._sanitize_for_memory(dict(result.get("metadata") or {})),
        }

        try:
            if self.audit_logger is not None:
                if hasattr(self.audit_logger, "log") and callable(self.audit_logger.log):
                    self.audit_logger.log(audit_payload)
                    return
                if hasattr(self.audit_logger, "write") and callable(self.audit_logger.write):
                    self.audit_logger.write(audit_payload)
                    return

            log_audit = getattr(super(), "log_audit", None)
            if callable(log_audit):
                log_audit(audit_payload)
                return

            self.logger.info("Audit event: %s", json.dumps(audit_payload, default=str))
        except Exception as exc:
            self.logger.debug("Unable to log audit event: %s", exc)

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success/result wrapper.
        """

        return {
            "success": bool(success),
            "message": str(message),
            "data": dict(data or {}),
            "error": error,
            "metadata": {
                "checker": self.__class__.__name__,
                "timestamp": self._utc_timestamp(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Any] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error wrapper.
        """

        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=error or {"code": "UNKNOWN_ERROR"},
            metadata=metadata or {},
        )

    # -----------------------------------------------------------------------
    # Public orchestration method
    # -----------------------------------------------------------------------

    def verify_code_state(
        self,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        file_expectations: Optional[Sequence[Union[CodeFileExpectation, Mapping[str, Any]]]] = None,
        syntax_files: Optional[Sequence[Union[str, Path]]] = None,
        compile_files: Optional[Sequence[Union[str, Path]]] = None,
        build_commands: Optional[Sequence[Union[CommandCheck, Mapping[str, Any]]]] = None,
        test_commands: Optional[Sequence[Union[CommandCheck, Mapping[str, Any]]]] = None,
        port_checks: Optional[Sequence[Union[PortCheck, Mapping[str, Any]]]] = None,
        endpoint_checks: Optional[Sequence[Union[EndpointCheck, Mapping[str, Any]]]] = None,
        base_dir: Optional[Union[str, Path]] = None,
        emit_events: bool = True,
        save_memory: bool = False,
    ) -> Dict[str, Any]:
        """
        Runs multiple code-state verifications and combines the outcome.

        This is the easiest Master Agent / Dashboard entrypoint after a code task.
        """

        context_result = self._validate_task_context(user_id, workspace_id, task_id)
        if not context_result["success"]:
            return context_result

        checks: List[Dict[str, Any]] = []

        try:
            if file_expectations:
                checks.append(
                    self.verify_code_edits(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task_id=task_id,
                        expectations=file_expectations,
                        base_dir=base_dir,
                    )
                )

            if syntax_files:
                checks.append(
                    self.verify_python_syntax(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task_id=task_id,
                        file_paths=syntax_files,
                        base_dir=base_dir,
                    )
                )

            if compile_files:
                checks.append(
                    self.verify_python_compile(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task_id=task_id,
                        file_paths=compile_files,
                        base_dir=base_dir,
                    )
                )

            if build_commands:
                checks.append(
                    self.verify_build(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task_id=task_id,
                        commands=build_commands,
                        base_dir=base_dir,
                    )
                )

            if test_commands:
                checks.append(
                    self.verify_tests(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task_id=task_id,
                        commands=test_commands,
                        base_dir=base_dir,
                    )
                )

            if port_checks:
                checks.append(
                    self.verify_server_ports(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task_id=task_id,
                        checks=port_checks,
                    )
                )

            if endpoint_checks:
                checks.append(
                    self.verify_endpoints(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task_id=task_id,
                        checks=endpoint_checks,
                    )
                )

            overall_success = bool(checks) and all(bool(item.get("success")) for item in checks)
            failed_count = sum(1 for item in checks if not item.get("success"))

            result = self._safe_result(
                success=overall_success,
                message=(
                    "Code state verification completed successfully."
                    if overall_success
                    else "Code state verification completed with failures."
                ),
                data={
                    "checks": checks,
                    "total_checks": len(checks),
                    "failed_checks": failed_count,
                    "passed_checks": len(checks) - failed_count,
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": task_id,
                    "check_type": "code_state",
                },
            )

            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                check_type="code_state",
                result=result,
            )
            result["data"]["verification_payload"] = verification_payload

            if emit_events:
                self._emit_agent_event("verification.code_state.completed", verification_payload)

            self._log_audit_event(user_id, workspace_id, "verify_code_state", result, task_id)

            if save_memory:
                memory_payload = self._prepare_memory_payload(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_id=task_id,
                    summary=result["message"],
                    result=result,
                )
                result["data"]["memory_payload"] = memory_payload
                self._send_memory_payload(memory_payload)

            return result

        except Exception as exc:
            result = self._exception_result(
                message="Code state verification failed unexpectedly.",
                exc=exc,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
            )
            self._log_audit_event(user_id, workspace_id, "verify_code_state_exception", result, task_id)
            return result

    # -----------------------------------------------------------------------
    # Public file/edit checks
    # -----------------------------------------------------------------------

    def verify_code_edits(
        self,
        user_id: str,
        workspace_id: str,
        expectations: Sequence[Union[CodeFileExpectation, Mapping[str, Any]]],
        task_id: Optional[str] = None,
        base_dir: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Confirms code edits by file existence, size, content, regex, and sha256.
        """

        context_result = self._validate_task_context(user_id, workspace_id, task_id)
        if not context_result["success"]:
            return context_result

        details: List[Dict[str, Any]] = []

        for raw_expectation in expectations:
            expectation = self._coerce_file_expectation(raw_expectation)
            file_result = self._inspect_file_expectation(expectation, base_dir)
            details.append(file_result)

        success = all(item["passed"] for item in details)

        result = self._safe_result(
            success=success,
            message=(
                "Code edit expectations passed."
                if success
                else "One or more code edit expectations failed."
            ),
            data={
                "files": details,
                "total_files": len(details),
                "failed_files": sum(1 for item in details if not item["passed"]),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "check_type": "code_edits",
            },
        )

        self._log_audit_event(user_id, workspace_id, "verify_code_edits", result, task_id)
        return result

    def verify_file_hashes(
        self,
        user_id: str,
        workspace_id: str,
        expected_hashes: Mapping[Union[str, Path], str],
        task_id: Optional[str] = None,
        base_dir: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Verifies sha256 hashes for one or more files.
        """

        expectations = [
            CodeFileExpectation(path=path, expected_sha256=sha)
            for path, sha in expected_hashes.items()
        ]

        return self.verify_code_edits(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            expectations=expectations,
            base_dir=base_dir,
        )

    # -----------------------------------------------------------------------
    # Public syntax / compile checks
    # -----------------------------------------------------------------------

    def verify_python_syntax(
        self,
        user_id: str,
        workspace_id: str,
        file_paths: Sequence[Union[str, Path]],
        task_id: Optional[str] = None,
        base_dir: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Checks Python syntax using ast.parse.
        """

        context_result = self._validate_task_context(user_id, workspace_id, task_id)
        if not context_result["success"]:
            return context_result

        checks: List[Dict[str, Any]] = []

        for file_path in file_paths:
            resolved = self._resolve_path(file_path, base_dir)
            checks.append(self._check_python_ast_syntax(resolved))

        success = all(item["passed"] for item in checks)

        result = self._safe_result(
            success=success,
            message=(
                "Python syntax check passed."
                if success
                else "Python syntax check failed for one or more files."
            ),
            data={
                "files": checks,
                "total_files": len(checks),
                "failed_files": sum(1 for item in checks if not item["passed"]),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "check_type": "python_syntax",
            },
        )

        self._log_audit_event(user_id, workspace_id, "verify_python_syntax", result, task_id)
        return result

    def verify_python_compile(
        self,
        user_id: str,
        workspace_id: str,
        file_paths: Sequence[Union[str, Path]],
        task_id: Optional[str] = None,
        base_dir: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Checks Python files with py_compile.
        """

        context_result = self._validate_task_context(user_id, workspace_id, task_id)
        if not context_result["success"]:
            return context_result

        checks: List[Dict[str, Any]] = []

        for file_path in file_paths:
            resolved = self._resolve_path(file_path, base_dir)
            checks.append(self._check_python_compile(resolved))

        success = all(item["passed"] for item in checks)

        result = self._safe_result(
            success=success,
            message=(
                "Python compile check passed."
                if success
                else "Python compile check failed for one or more files."
            ),
            data={
                "files": checks,
                "total_files": len(checks),
                "failed_files": sum(1 for item in checks if not item["passed"]),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "check_type": "python_compile",
            },
        )

        self._log_audit_event(user_id, workspace_id, "verify_python_compile", result, task_id)
        return result

    # -----------------------------------------------------------------------
    # Public command checks
    # -----------------------------------------------------------------------

    def verify_build(
        self,
        user_id: str,
        workspace_id: str,
        commands: Sequence[Union[CommandCheck, Mapping[str, Any], str, Sequence[str]]],
        task_id: Optional[str] = None,
        base_dir: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Runs safe build commands and verifies exit codes/output expectations.
        """

        return self._verify_commands(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            commands=commands,
            base_dir=base_dir,
            action="run_build",
            check_type="build",
            success_message="Build checks passed.",
            failure_message="One or more build checks failed.",
        )

    def verify_tests(
        self,
        user_id: str,
        workspace_id: str,
        commands: Sequence[Union[CommandCheck, Mapping[str, Any], str, Sequence[str]]],
        task_id: Optional[str] = None,
        base_dir: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Runs safe test commands and verifies exit codes/output expectations.
        """

        return self._verify_commands(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            commands=commands,
            base_dir=base_dir,
            action="run_tests",
            check_type="tests",
            success_message="Test checks passed.",
            failure_message="One or more test checks failed.",
        )

    def run_safe_command_check(
        self,
        user_id: str,
        workspace_id: str,
        command: Union[CommandCheck, Mapping[str, Any], str, Sequence[str]],
        task_id: Optional[str] = None,
        base_dir: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Runs one safe command check.

        Useful for Dashboard/API direct verification.
        """

        result = self._verify_commands(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            commands=[command],
            base_dir=base_dir,
            action="run_command",
            check_type="command",
            success_message="Command check passed.",
            failure_message="Command check failed.",
        )

        command_results = result.get("data", {}).get("commands", [])
        if command_results:
            result["data"]["command"] = command_results[0]

        return result

    # -----------------------------------------------------------------------
    # Public server / endpoint checks
    # -----------------------------------------------------------------------

    def verify_server_ports(
        self,
        user_id: str,
        workspace_id: str,
        checks: Sequence[Union[PortCheck, Mapping[str, Any]]],
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Checks TCP port open/closed state for server verification.
        """

        context_result = self._validate_task_context(user_id, workspace_id, task_id)
        if not context_result["success"]:
            return context_result

        if not self.config.allow_network_checks:
            return self._error_result(
                message="Network checks are disabled by configuration.",
                error={"code": "NETWORK_CHECKS_DISABLED"},
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": task_id,
                },
            )

        results: List[Dict[str, Any]] = []

        for raw_check in checks:
            check = self._coerce_port_check(raw_check)
            results.append(self._check_tcp_port(check))

        success = all(item["passed"] for item in results)

        result = self._safe_result(
            success=success,
            message=(
                "Server port checks passed."
                if success
                else "One or more server port checks failed."
            ),
            data={
                "ports": results,
                "total_ports": len(results),
                "failed_ports": sum(1 for item in results if not item["passed"]),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "check_type": "server_ports",
            },
        )

        self._log_audit_event(user_id, workspace_id, "verify_server_ports", result, task_id)
        return result

    def verify_endpoints(
        self,
        user_id: str,
        workspace_id: str,
        checks: Sequence[Union[EndpointCheck, Mapping[str, Any]]],
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Checks HTTP/HTTPS endpoint status and body expectations.
        """

        context_result = self._validate_task_context(user_id, workspace_id, task_id)
        if not context_result["success"]:
            return context_result

        if not self.config.allow_network_checks:
            return self._error_result(
                message="Network checks are disabled by configuration.",
                error={"code": "NETWORK_CHECKS_DISABLED"},
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": task_id,
                },
            )

        results: List[Dict[str, Any]] = []

        for raw_check in checks:
            check = self._coerce_endpoint_check(raw_check)
            action = "check_endpoint_external" if not self._is_local_url(check.url) else "check_endpoint_local"

            if self._requires_security_check(action, {"url": check.url, "method": check.method}):
                approval = self._request_security_approval(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    action=action,
                    payload={"url": check.url, "method": check.method},
                )
                if not approval["success"]:
                    results.append(
                        {
                            "label": check.label,
                            "url": check.url,
                            "method": check.method,
                            "passed": False,
                            "reason": "Security approval denied.",
                            "security": approval,
                        }
                    )
                    continue

            results.append(self._check_http_endpoint(check))

        success = all(item["passed"] for item in results)

        result = self._safe_result(
            success=success,
            message=(
                "Endpoint checks passed."
                if success
                else "One or more endpoint checks failed."
            ),
            data={
                "endpoints": results,
                "total_endpoints": len(results),
                "failed_endpoints": sum(1 for item in results if not item["passed"]),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "check_type": "endpoints",
            },
        )

        self._log_audit_event(user_id, workspace_id, "verify_endpoints", result, task_id)
        return result

    # -----------------------------------------------------------------------
    # Internal file helpers
    # -----------------------------------------------------------------------

    def _inspect_file_expectation(
        self,
        expectation: CodeFileExpectation,
        base_dir: Optional[Union[str, Path]],
    ) -> Dict[str, Any]:
        resolved = self._resolve_path(expectation.path, base_dir)
        checks: Dict[str, Any] = {
            "exists": False,
            "size_ok": None,
            "contains": [],
            "absent": [],
            "regex": [],
            "sha256": None,
        }
        failures: List[str] = []

        if not resolved.exists():
            return {
                "path": str(resolved),
                "passed": False,
                "checks": checks,
                "failures": ["File does not exist."],
            }

        if not resolved.is_file():
            return {
                "path": str(resolved),
                "passed": False,
                "checks": checks,
                "failures": ["Path exists but is not a file."],
            }

        stat = resolved.stat()
        size = stat.st_size
        checks["exists"] = True
        checks["size_bytes"] = size
        checks["mtime"] = stat.st_mtime

        if size > self.config.max_file_bytes:
            failures.append(
                f"File exceeds checker max size of {self.config.max_file_bytes} bytes."
            )

        if expectation.min_size_bytes is not None and size < expectation.min_size_bytes:
            failures.append(
                f"File size {size} is below expected minimum {expectation.min_size_bytes}."
            )

        if expectation.max_size_bytes is not None and size > expectation.max_size_bytes:
            failures.append(
                f"File size {size} is above expected maximum {expectation.max_size_bytes}."
            )

        checks["size_ok"] = not any("File size" in item or "exceeds" in item for item in failures)

        content = ""
        if size <= self.config.max_file_bytes:
            content = self._read_text_safely(resolved)

        for expected in expectation.expected_contains:
            found = expected in content
            checks["contains"].append({"text": expected, "found": found})
            if not found:
                failures.append(f"Expected text not found: {expected}")

        for forbidden in expectation.expected_absent:
            found = forbidden in content
            checks["absent"].append({"text": forbidden, "absent": not found})
            if found:
                failures.append(f"Forbidden text found: {forbidden}")

        for pattern in expectation.expected_regex:
            try:
                matched = bool(re.search(pattern, content, flags=re.MULTILINE))
                checks["regex"].append({"pattern": pattern, "matched": matched})
                if not matched:
                    failures.append(f"Expected regex did not match: {pattern}")
            except re.error as exc:
                checks["regex"].append(
                    {"pattern": pattern, "matched": False, "regex_error": str(exc)}
                )
                failures.append(f"Invalid regex pattern: {pattern} | {exc}")

        actual_sha = self._sha256_file(resolved)
        checks["sha256"] = actual_sha

        if expectation.expected_sha256:
            expected_sha = expectation.expected_sha256.lower().strip()
            if actual_sha != expected_sha:
                failures.append("sha256 hash mismatch.")
            checks["expected_sha256"] = expected_sha

        return {
            "path": str(resolved),
            "passed": not failures,
            "checks": checks,
            "failures": failures,
        }

    def _check_python_ast_syntax(self, path: Path) -> Dict[str, Any]:
        if not path.exists():
            return {
                "path": str(path),
                "passed": False,
                "reason": "File does not exist.",
            }

        if not path.is_file():
            return {
                "path": str(path),
                "passed": False,
                "reason": "Path is not a file.",
            }

        if path.stat().st_size > self.config.max_file_bytes:
            return {
                "path": str(path),
                "passed": False,
                "reason": f"File exceeds max readable size {self.config.max_file_bytes}.",
            }

        try:
            content = self._read_text_safely(path)
            ast.parse(content, filename=str(path))
            return {
                "path": str(path),
                "passed": True,
                "reason": "AST syntax parse passed.",
            }
        except SyntaxError as exc:
            return {
                "path": str(path),
                "passed": False,
                "reason": "SyntaxError.",
                "error": {
                    "message": exc.msg,
                    "line": exc.lineno,
                    "offset": exc.offset,
                    "text": exc.text.strip() if exc.text else None,
                },
            }
        except Exception as exc:
            return {
                "path": str(path),
                "passed": False,
                "reason": "Unexpected syntax check error.",
                "error": str(exc),
            }

    def _check_python_compile(self, path: Path) -> Dict[str, Any]:
        if not path.exists():
            return {
                "path": str(path),
                "passed": False,
                "reason": "File does not exist.",
            }

        if not path.is_file():
            return {
                "path": str(path),
                "passed": False,
                "reason": "Path is not a file.",
            }

        try:
            py_compile.compile(str(path), doraise=True)
            return {
                "path": str(path),
                "passed": True,
                "reason": "py_compile passed.",
            }
        except py_compile.PyCompileError as exc:
            return {
                "path": str(path),
                "passed": False,
                "reason": "py_compile failed.",
                "error": str(exc),
            }
        except Exception as exc:
            return {
                "path": str(path),
                "passed": False,
                "reason": "Unexpected compile check error.",
                "error": str(exc),
            }

    # -----------------------------------------------------------------------
    # Internal command helpers
    # -----------------------------------------------------------------------

    def _verify_commands(
        self,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str],
        commands: Sequence[Union[CommandCheck, Mapping[str, Any], str, Sequence[str]]],
        base_dir: Optional[Union[str, Path]],
        action: str,
        check_type: str,
        success_message: str,
        failure_message: str,
    ) -> Dict[str, Any]:
        context_result = self._validate_task_context(user_id, workspace_id, task_id)
        if not context_result["success"]:
            return context_result

        if not self.config.allow_subprocess:
            return self._error_result(
                message="Subprocess command checks are disabled by configuration.",
                error={"code": "SUBPROCESS_DISABLED"},
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": task_id,
                    "check_type": check_type,
                },
            )

        results: List[Dict[str, Any]] = []

        for raw_command in commands:
            command_check = self._coerce_command_check(raw_command)
            if command_check.cwd is None and base_dir is not None:
                command_check.cwd = base_dir

            safety = self._validate_command_safety(command_check)
            if not safety["success"]:
                results.append(
                    {
                        "label": command_check.label,
                        "command": self._safe_command_display(command_check.command),
                        "passed": False,
                        "reason": "Command failed local safety validation.",
                        "safety": safety,
                    }
                )
                continue

            if self._requires_security_check(action, {"command": command_check.command}):
                approval = self._request_security_approval(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    action=action,
                    payload={
                        "command": self._safe_command_display(command_check.command),
                        "cwd": str(command_check.cwd) if command_check.cwd else None,
                    },
                )
                if not approval["success"]:
                    results.append(
                        {
                            "label": command_check.label,
                            "command": self._safe_command_display(command_check.command),
                            "passed": False,
                            "reason": "Security approval denied.",
                            "security": approval,
                        }
                    )
                    continue

            results.append(self._run_command_check(command_check, base_dir))

        success = all(item["passed"] for item in results)

        result = self._safe_result(
            success=success,
            message=success_message if success else failure_message,
            data={
                "commands": results,
                "total_commands": len(results),
                "failed_commands": sum(1 for item in results if not item["passed"]),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "check_type": check_type,
            },
        )

        self._log_audit_event(user_id, workspace_id, f"verify_{check_type}", result, task_id)
        return result

    def _run_command_check(
        self,
        check: CommandCheck,
        base_dir: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        command_args = self._command_to_args(check.command)
        cwd = self._resolve_cwd(check.cwd, base_dir)
        timeout = check.timeout_seconds or self.config.command_timeout_seconds
        started = time.time()

        try:
            completed = subprocess.run(
                command_args,
                cwd=str(cwd) if cwd else None,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                shell=False,
            )
            duration = time.time() - started
            stdout = self._truncate(completed.stdout or "", self.config.max_command_output_chars)
            stderr = self._truncate(completed.stderr or "", self.config.max_command_output_chars)

            failures: List[str] = []

            if completed.returncode not in check.expected_exit_codes:
                failures.append(
                    f"Exit code {completed.returncode} not in expected {check.expected_exit_codes}."
                )

            for expected in check.expected_stdout_contains:
                if expected not in stdout:
                    failures.append(f"Expected stdout text not found: {expected}")

            for forbidden in check.expected_stderr_absent:
                if forbidden in stderr:
                    failures.append(f"Forbidden stderr text found: {forbidden}")

            return {
                "label": check.label,
                "command": self._safe_command_display(check.command),
                "cwd": str(cwd) if cwd else None,
                "passed": not failures,
                "exit_code": completed.returncode,
                "expected_exit_codes": list(check.expected_exit_codes),
                "duration_seconds": round(duration, 4),
                "stdout": stdout,
                "stderr": stderr,
                "failures": failures,
            }

        except subprocess.TimeoutExpired as exc:
            return {
                "label": check.label,
                "command": self._safe_command_display(check.command),
                "cwd": str(cwd) if cwd else None,
                "passed": False,
                "reason": f"Command timed out after {timeout} seconds.",
                "stdout": self._truncate(exc.stdout or "", self.config.max_command_output_chars),
                "stderr": self._truncate(exc.stderr or "", self.config.max_command_output_chars),
            }
        except FileNotFoundError as exc:
            return {
                "label": check.label,
                "command": self._safe_command_display(check.command),
                "cwd": str(cwd) if cwd else None,
                "passed": False,
                "reason": "Command executable not found.",
                "error": str(exc),
            }
        except Exception as exc:
            return {
                "label": check.label,
                "command": self._safe_command_display(check.command),
                "cwd": str(cwd) if cwd else None,
                "passed": False,
                "reason": "Unexpected command execution error.",
                "error": str(exc),
            }

    def _validate_command_safety(self, check: CommandCheck) -> Dict[str, Any]:
        args = self._command_to_args(check.command)

        if not args:
            return self._error_result(
                message="Command is empty.",
                error={"code": "EMPTY_COMMAND"},
            )

        root = args[0]
        root_name = Path(root).name.lower()
        allowed_roots = {Path(item).name.lower() for item in self.config.allowed_command_roots}
        allowed_full = {str(item).lower() for item in self.config.allowed_command_roots}

        if root_name not in allowed_roots and str(root).lower() not in allowed_full:
            return self._error_result(
                message="Command root is not allowlisted.",
                error={
                    "code": "COMMAND_NOT_ALLOWLISTED",
                    "root": root,
                    "allowed_roots": sorted(allowed_roots),
                },
            )

        joined = " ".join(args)
        for token in self.config.dangerous_tokens:
            if token in args or token in joined:
                return self._error_result(
                    message="Command contains dangerous token.",
                    error={
                        "code": "DANGEROUS_COMMAND_TOKEN",
                        "token": token,
                    },
                )

        cwd = self._resolve_cwd(check.cwd, None)
        if cwd and not cwd.exists():
            return self._error_result(
                message="Command cwd does not exist.",
                error={
                    "code": "CWD_NOT_FOUND",
                    "cwd": str(cwd),
                },
            )

        return self._safe_result(
            success=True,
            message="Command passed local safety validation.",
            data={
                "command": self._safe_command_display(check.command),
                "cwd": str(cwd) if cwd else None,
            },
        )

    # -----------------------------------------------------------------------
    # Internal server / endpoint helpers
    # -----------------------------------------------------------------------

    def _check_tcp_port(self, check: PortCheck) -> Dict[str, Any]:
        timeout = check.timeout_seconds or self.config.socket_timeout_seconds
        started = time.time()
        is_open = False
        error_message: Optional[str] = None

        try:
            with socket.create_connection((check.host, int(check.port)), timeout=timeout):
                is_open = True
        except OSError as exc:
            error_message = str(exc)

        duration = round(time.time() - started, 4)
        passed = is_open is check.expected_open

        return {
            "label": check.label,
            "host": check.host,
            "port": check.port,
            "expected_open": check.expected_open,
            "actual_open": is_open,
            "passed": passed,
            "duration_seconds": duration,
            "error": error_message,
        }

    def _check_http_endpoint(self, check: EndpointCheck) -> Dict[str, Any]:
        method = check.method.upper().strip()
        timeout = check.timeout_seconds or self.config.endpoint_timeout_seconds
        failures: List[str] = []

        if method not in self.config.safe_http_methods:
            return {
                "label": check.label,
                "url": check.url,
                "method": method,
                "passed": False,
                "reason": "HTTP method is not allowed for safe verification.",
                "allowed_methods": list(self.config.safe_http_methods),
            }

        allow_external = (
            check.allow_external
            if check.allow_external is not None
            else self.config.allow_external_http
        )

        if not allow_external and not self._is_local_url(check.url):
            return {
                "label": check.label,
                "url": check.url,
                "method": method,
                "passed": False,
                "reason": "External HTTP checks are disabled by configuration.",
            }

        request = urllib.request.Request(
            check.url,
            method=method,
            headers={
                "User-Agent": "William-CodeStateChecker/1.0",
                **check.headers,
            },
        )

        started = time.time()
        status_code: Optional[int] = None
        body = ""
        response_headers: Dict[str, str] = {}

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status_code = int(response.getcode())
                raw_body = response.read(1024 * 512)
                body = raw_body.decode("utf-8", errors="replace")
                response_headers = dict(response.headers.items())

        except urllib.error.HTTPError as exc:
            status_code = int(exc.code)
            body = exc.read(1024 * 128).decode("utf-8", errors="replace")
            response_headers = dict(exc.headers.items()) if exc.headers else {}
        except Exception as exc:
            return {
                "label": check.label,
                "url": check.url,
                "method": method,
                "passed": False,
                "reason": "Endpoint request failed.",
                "error": str(exc),
                "duration_seconds": round(time.time() - started, 4),
            }

        if status_code not in check.expected_statuses:
            failures.append(
                f"Status {status_code} not in expected {check.expected_statuses}."
            )

        for expected in check.expected_body_contains:
            if expected not in body:
                failures.append(f"Expected body text not found: {expected}")

        for forbidden in check.expected_body_absent:
            if forbidden in body:
                failures.append(f"Forbidden body text found: {forbidden}")

        return {
            "label": check.label,
            "url": check.url,
            "method": method,
            "passed": not failures,
            "status_code": status_code,
            "expected_statuses": list(check.expected_statuses),
            "duration_seconds": round(time.time() - started, 4),
            "body_preview": self._truncate(body, 3000),
            "headers": response_headers,
            "failures": failures,
        }

    # -----------------------------------------------------------------------
    # Coercion helpers
    # -----------------------------------------------------------------------

    def _coerce_file_expectation(
        self,
        raw: Union[CodeFileExpectation, Mapping[str, Any]],
    ) -> CodeFileExpectation:
        if isinstance(raw, CodeFileExpectation):
            return raw

        data = dict(raw)
        return CodeFileExpectation(
            path=data["path"],
            expected_contains=list(data.get("expected_contains") or []),
            expected_absent=list(data.get("expected_absent") or []),
            expected_regex=list(data.get("expected_regex") or []),
            expected_sha256=data.get("expected_sha256"),
            min_size_bytes=data.get("min_size_bytes"),
            max_size_bytes=data.get("max_size_bytes"),
        )

    def _coerce_command_check(
        self,
        raw: Union[CommandCheck, Mapping[str, Any], str, Sequence[str]],
    ) -> CommandCheck:
        if isinstance(raw, CommandCheck):
            return raw

        if isinstance(raw, str):
            return CommandCheck(command=raw)

        if isinstance(raw, Mapping):
            data = dict(raw)
            expected_exit_codes = data.get("expected_exit_codes", (0,))
            if isinstance(expected_exit_codes, int):
                expected_exit_codes = (expected_exit_codes,)
            return CommandCheck(
                command=data["command"],
                cwd=data.get("cwd"),
                timeout_seconds=data.get("timeout_seconds"),
                expected_exit_codes=tuple(expected_exit_codes),
                expected_stdout_contains=list(data.get("expected_stdout_contains") or []),
                expected_stderr_absent=list(data.get("expected_stderr_absent") or []),
                label=str(data.get("label") or "command_check"),
            )

        return CommandCheck(command=list(raw))

    def _coerce_endpoint_check(
        self,
        raw: Union[EndpointCheck, Mapping[str, Any]],
    ) -> EndpointCheck:
        if isinstance(raw, EndpointCheck):
            return raw

        data = dict(raw)
        expected_statuses = data.get("expected_statuses", (200,))
        if isinstance(expected_statuses, int):
            expected_statuses = (expected_statuses,)

        return EndpointCheck(
            url=str(data["url"]),
            method=str(data.get("method") or "GET"),
            expected_statuses=tuple(int(item) for item in expected_statuses),
            expected_body_contains=list(data.get("expected_body_contains") or []),
            expected_body_absent=list(data.get("expected_body_absent") or []),
            headers=dict(data.get("headers") or {}),
            timeout_seconds=data.get("timeout_seconds"),
            allow_external=data.get("allow_external"),
            label=str(data.get("label") or "endpoint_check"),
        )

    def _coerce_port_check(
        self,
        raw: Union[PortCheck, Mapping[str, Any]],
    ) -> PortCheck:
        if isinstance(raw, PortCheck):
            return raw

        data = dict(raw)
        return PortCheck(
            host=str(data.get("host") or "127.0.0.1"),
            port=int(data["port"]),
            timeout_seconds=data.get("timeout_seconds"),
            expected_open=bool(data.get("expected_open", True)),
            label=str(data.get("label") or "port_check"),
        )

    # -----------------------------------------------------------------------
    # Security helpers
    # -----------------------------------------------------------------------

    def _local_security_check(
        self,
        action: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Conservative fallback security validation.

        Real production should connect Security Agent for policy decisions.
        """

        action = action.lower().strip()

        if action in {"run_command", "run_build", "run_tests"}:
            command = payload.get("command")
            try:
                check = CommandCheck(command=command)  # type: ignore[arg-type]
                return self._validate_command_safety(check)
            except Exception as exc:
                return self._error_result(
                    message="Local security command validation failed.",
                    error={
                        "code": "LOCAL_SECURITY_COMMAND_ERROR",
                        "exception": str(exc),
                    },
                )

        if action == "check_endpoint_external":
            url = str(payload.get("url") or "")
            if not self.config.allow_external_http:
                return self._error_result(
                    message="External endpoint check denied by local security config.",
                    error={
                        "code": "EXTERNAL_ENDPOINT_DENIED",
                        "url": url,
                    },
                )

        return self._safe_result(
            success=True,
            message="Local security check approved.",
            data={"action": action},
        )

    # -----------------------------------------------------------------------
    # General helpers
    # -----------------------------------------------------------------------

    def _resolve_path(
        self,
        path: Union[str, Path],
        base_dir: Optional[Union[str, Path]] = None,
    ) -> Path:
        raw_path = Path(path).expanduser()

        if raw_path.is_absolute():
            return raw_path.resolve()

        if base_dir is not None:
            return (Path(base_dir).expanduser().resolve() / raw_path).resolve()

        return raw_path.resolve()

    def _resolve_cwd(
        self,
        cwd: Optional[Union[str, Path]],
        base_dir: Optional[Union[str, Path]],
    ) -> Optional[Path]:
        if cwd is not None:
            return self._resolve_path(cwd, None)

        if base_dir is not None:
            return Path(base_dir).expanduser().resolve()

        return None

    def _read_text_safely(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return path.read_text(encoding="utf-8", errors="replace")

    def _sha256_file(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _command_to_args(self, command: Union[str, Sequence[str]]) -> List[str]:
        if isinstance(command, str):
            return shlex.split(command, posix=os.name != "nt")
        return [str(item) for item in command]

    def _safe_command_display(self, command: Union[str, Sequence[str]]) -> str:
        args = self._command_to_args(command)
        redacted: List[str] = []

        secret_markers = (
            "token",
            "secret",
            "password",
            "passwd",
            "apikey",
            "api_key",
            "auth",
            "credential",
            "key=",
        )

        for arg in args:
            lower = arg.lower()
            if any(marker in lower for marker in secret_markers):
                if "=" in arg:
                    key = arg.split("=", 1)[0]
                    redacted.append(f"{key}=<REDACTED>")
                else:
                    redacted.append("<REDACTED>")
            else:
                redacted.append(arg)

        return " ".join(shlex.quote(item) for item in redacted)

    def _truncate(self, text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        return text[:limit] + "\n...[truncated]"

    def _is_local_url(self, url: str) -> bool:
        try:
            parsed = urllib.parse.urlparse(url)
            host = (parsed.hostname or "").lower()
            return host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"} or host.startswith(
                "192.168."
            ) or host.startswith("10.") or host.startswith("172.16.")
        except Exception:
            return False

    def _utc_timestamp(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def _sanitize_for_memory(self, value: Any) -> Any:
        """
        Sanitizes nested result payloads before memory/audit storage.
        """

        if isinstance(value, Mapping):
            sanitized: Dict[str, Any] = {}
            for key, item in value.items():
                lower_key = str(key).lower()
                if any(
                    marker in lower_key
                    for marker in (
                        "token",
                        "secret",
                        "password",
                        "passwd",
                        "api_key",
                        "apikey",
                        "credential",
                        "authorization",
                    )
                ):
                    sanitized[str(key)] = "<REDACTED>"
                elif lower_key in {"stdout", "stderr", "body_preview"}:
                    sanitized[str(key)] = self._truncate(str(item), 1000)
                else:
                    sanitized[str(key)] = self._sanitize_for_memory(item)
            return sanitized

        if isinstance(value, list):
            return [self._sanitize_for_memory(item) for item in value]

        if isinstance(value, tuple):
            return tuple(self._sanitize_for_memory(item) for item in value)

        return value

    def _send_memory_payload(self, payload: Mapping[str, Any]) -> None:
        """
        Sends useful verification context to Memory Agent if connected.
        """

        if self.memory_agent is None:
            return

        for method_name in ("store", "remember", "save_memory", "add"):
            method = getattr(self.memory_agent, method_name, None)
            if callable(method):
                try:
                    method(dict(payload))
                    return
                except Exception as exc:
                    self.logger.debug("Unable to send memory payload: %s", exc)
                    return

    def _exception_result(
        self,
        message: str,
        exc: Exception,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self._error_result(
            message=message,
            error={
                "code": "UNEXPECTED_EXCEPTION",
                "exception": str(exc),
                "traceback": traceback.format_exc(),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
            },
        )


# ---------------------------------------------------------------------------
# Convenience factory for Agent Loader / Registry
# ---------------------------------------------------------------------------

def create_code_state_checker(**kwargs: Any) -> CodeStateChecker:
    """
    Factory used by Agent Loader or tests.
    """

    return CodeStateChecker(**kwargs)


def get_module_metadata() -> Dict[str, Any]:
    """
    Module-level metadata for registry discovery.
    """

    return {
        "module": "agents.verification_agent.code_state_checker",
        "file_path": "agents/verification_agent/code_state_checker.py",
        "class_name": "CodeStateChecker",
        "factory": "create_code_state_checker",
        "version": CodeStateChecker.version,
        "safe_to_import": True,
        "purpose": "Confirms code edits, syntax, builds, tests, servers, endpoints.",
        "agent_module": "Verification Agent",
    }


__all__ = [
    "CodeStateChecker",
    "CodeCheckConfig",
    "CodeFileExpectation",
    "CommandCheck",
    "EndpointCheck",
    "PortCheck",
    "create_code_state_checker",
    "get_module_metadata",
]


if __name__ == "__main__":
    checker = CodeStateChecker()
    print(json.dumps(checker.health_check(), indent=2, default=str))