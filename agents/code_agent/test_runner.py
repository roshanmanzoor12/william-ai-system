"""
agents/code_agent/test_runner.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Runs/generates tests, endpoint checks, build checks, smoke tests.

This module provides the TestRunner class used by the Code Agent layer to:
    - Run Python test suites safely.
    - Run syntax checks.
    - Run smoke checks.
    - Run endpoint checks.
    - Run build checks for common stacks.
    - Generate simple Python smoke/unit test files.
    - Validate SaaS user/workspace context.
    - Request Security Agent approval for command execution.
    - Prepare Verification Agent payloads.
    - Prepare Memory Agent payloads.
    - Emit dashboard/API-ready audit and agent events.

Design:
    - Import-safe even if William/Jarvis base modules are not created yet.
    - No hardcoded secrets.
    - No shell=True execution.
    - Commands are allowlisted and run inside project_root.
    - Every public method returns structured dict/JSON style:
        success, message, data, error, metadata.
"""

from __future__ import annotations

import ast
import json
import logging
import os
import platform
import re
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Optional BaseAgent compatibility
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe before the complete William/Jarvis
        agent framework exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent does not implement run().",
                "data": {},
                "error": None,
                "metadata": {
                    "fallback": True,
                    "agent": self.__class__.__name__,
                },
            }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TaskContext:
    """
    SaaS execution context.

    user_id and workspace_id are required for user-specific execution.
    This prevents test results, logs, analytics, memory, and audit data
    from mixing across SaaS users/workspaces.
    """

    user_id: Union[str, int]
    workspace_id: Union[str, int]
    role: Optional[str] = None
    subscription: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CommandResult:
    """
    Normalized command execution result.
    """

    command: List[str]
    cwd: str
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EndpointCheck:
    """
    Endpoint smoke check definition.
    """

    url: str
    method: str = "GET"
    expected_status: Union[int, List[int]] = 200
    timeout_seconds: int = 10
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[Union[str, bytes, Dict[str, Any]]] = None
    name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TestPlan:
    """
    A dashboard/API-friendly test plan.

    Master Agent can create this plan and route it to TestRunner.
    """

    name: str
    commands: List[List[str]] = field(default_factory=list)
    endpoint_checks: List[EndpointCheck] = field(default_factory=list)
    syntax_paths: List[str] = field(default_factory=list)
    build_type: Optional[str] = None
    timeout_seconds: int = 120
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["endpoint_checks"] = [check.to_dict() for check in self.endpoint_checks]
        return data


# ---------------------------------------------------------------------------
# TestRunner
# ---------------------------------------------------------------------------

class TestRunner(BaseAgent):
    """
    Production-ready safe test runner for the William/Jarvis Code Agent.

    Master Agent:
        Routes test, build, smoke, syntax, and endpoint-check tasks here.

    Security Agent:
        Command execution is sensitive. Every command goes through
        _requires_security_check() and _request_security_approval().

    Verification Agent:
        Every completed run prepares a verification payload.

    Memory Agent:
        Test summaries can be stored safely as user/workspace-scoped memory.

    Dashboard/API:
        Structured results are ready for FastAPI, analytics, task history,
        build cards, and audit logs.

    Registry/Loader:
        Safe to import with fallback BaseAgent.
    """

    DEFAULT_ALLOWED_EXECUTABLES = {
        "python",
        "python3",
        sys.executable,
        "pytest",
        "unittest",
        "npm",
        "yarn",
        "pnpm",
        "node",
        "flutter",
        "dart",
        "pip",
        "mypy",
        "ruff",
        "flake8",
        "coverage",
    }

    DEFAULT_DENIED_TOKENS = {
        "rm",
        "del",
        "erase",
        "format",
        "shutdown",
        "reboot",
        "mkfs",
        "dd",
        "sudo",
        "su",
        "chmod",
        "chown",
        "scp",
        "ssh",
        "curl",
        "wget",
        "powershell",
        "pwsh",
        "reg",
        "net",
        "netsh",
    }

    DEFAULT_DENIED_PATH_PARTS = {
        ".git",
        ".svn",
        ".hg",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        "node_modules",
        "dist",
        "build",
    }

    DEFAULT_ALLOWED_TEST_EXTENSIONS = {
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".dart",
        ".php",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".md",
        ".txt",
    }

    SENSITIVE_PATTERNS = [
        re.compile(r"\b(api[_-]?key|secret|token|password|passwd|private[_-]?key)\b", re.I),
        re.compile(r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", re.I),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"\bghp_[A-Za-z0-9_]{20,}\b"),
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ]

    def __init__(
        self,
        project_root: Optional[Union[str, Path]] = None,
        *,
        agent_name: str = "TestRunner",
        allowed_executables: Optional[Iterable[str]] = None,
        denied_tokens: Optional[Iterable[str]] = None,
        denied_path_parts: Optional[Iterable[str]] = None,
        allowed_test_extensions: Optional[Iterable[str]] = None,
        default_timeout_seconds: int = 120,
        max_output_chars: int = 30000,
        security_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        super().__init__(agent_name=agent_name)

        self.agent_name = agent_name
        self.project_root = Path(project_root or os.getcwd()).resolve()

        self.allowed_executables = set(allowed_executables or self.DEFAULT_ALLOWED_EXECUTABLES)
        self.denied_tokens = set(denied_tokens or self.DEFAULT_DENIED_TOKENS)
        self.denied_path_parts = set(denied_path_parts or self.DEFAULT_DENIED_PATH_PARTS)
        self.allowed_test_extensions = set(allowed_test_extensions or self.DEFAULT_ALLOWED_TEST_EXTENSIONS)

        self.default_timeout_seconds = default_timeout_seconds
        self.max_output_chars = max_output_chars

        self.security_callback = security_callback
        self.audit_callback = audit_callback
        self.event_callback = event_callback

    # ------------------------------------------------------------------
    # BaseAgent-compatible entrypoint
    # ------------------------------------------------------------------

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible entrypoint.

        Supported operation values:
            - run_command
            - run_pytest
            - run_unittest
            - run_python_syntax_check
            - run_smoke_tests
            - run_endpoint_checks
            - run_build_check
            - generate_python_smoke_test
            - run_test_plan
        """

        try:
            context = self._coerce_context(task.get("context") or {})
            operation = task.get("operation")

            if not operation:
                return self._error_result(
                    "Missing operation.",
                    error_code="missing_operation",
                    metadata={"agent": self.agent_name},
                )

            if operation == "run_command":
                return self.run_command(
                    command=task.get("command") or [],
                    context=context,
                    timeout_seconds=int(task.get("timeout_seconds", self.default_timeout_seconds)),
                    cwd=task.get("cwd"),
                )

            if operation == "run_pytest":
                return self.run_pytest(
                    context=context,
                    test_path=task.get("test_path"),
                    extra_args=task.get("extra_args") or [],
                    timeout_seconds=int(task.get("timeout_seconds", self.default_timeout_seconds)),
                )

            if operation == "run_unittest":
                return self.run_unittest(
                    context=context,
                    test_module=task.get("test_module"),
                    timeout_seconds=int(task.get("timeout_seconds", self.default_timeout_seconds)),
                )

            if operation == "run_python_syntax_check":
                return self.run_python_syntax_check(
                    context=context,
                    paths=task.get("paths") or task.get("syntax_paths") or [],
                )

            if operation == "run_smoke_tests":
                return self.run_smoke_tests(
                    context=context,
                    commands=task.get("commands") or [],
                    endpoint_checks=task.get("endpoint_checks") or [],
                    timeout_seconds=int(task.get("timeout_seconds", self.default_timeout_seconds)),
                )

            if operation == "run_endpoint_checks":
                return self.run_endpoint_checks(
                    context=context,
                    endpoint_checks=task.get("endpoint_checks") or [],
                )

            if operation == "run_build_check":
                return self.run_build_check(
                    context=context,
                    build_type=task.get("build_type"),
                    timeout_seconds=int(task.get("timeout_seconds", self.default_timeout_seconds)),
                )

            if operation == "generate_python_smoke_test":
                return self.generate_python_smoke_test(
                    context=context,
                    target_module=task.get("target_module", ""),
                    output_path=task.get("output_path"),
                    class_or_function_names=task.get("class_or_function_names") or [],
                    overwrite=bool(task.get("overwrite", False)),
                )

            if operation == "run_test_plan":
                return self.run_test_plan(
                    context=context,
                    plan=task.get("plan") or {},
                )

            return self._error_result(
                f"Unsupported operation: {operation}",
                error_code="unsupported_operation",
                metadata={"operation": operation},
            )

        except Exception as exc:
            logger.exception("TestRunner.run failed.")
            return self._error_result(
                "TestRunner task failed.",
                error=exc,
                error_code="run_failed",
                metadata={"agent": self.agent_name},
            )

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def run_command(
        self,
        command: Union[str, List[str]],
        *,
        context: Union[TaskContext, Dict[str, Any]],
        timeout_seconds: Optional[int] = None,
        cwd: Optional[Union[str, Path]] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Run a safe allowlisted command inside project_root.

        shell=True is never used.
        """

        ctx = self._coerce_context(context)
        validation = self._validate_task_context(ctx)
        if not validation["success"]:
            return validation

        command_list = self._normalize_command(command)
        if not command_list:
            return self._error_result(
                "Command cannot be empty.",
                error_code="empty_command",
            )

        cwd_result = self._resolve_safe_cwd(cwd)
        if not cwd_result["success"]:
            return cwd_result

        command_validation = self._validate_command(command_list)
        if not command_validation["success"]:
            return command_validation

        operation_payload = {
            "operation": "run_command",
            "command": command_list,
            "cwd": cwd_result["data"]["cwd"],
            "timeout_seconds": timeout_seconds or self.default_timeout_seconds,
        }

        security = self._handle_security_if_required(operation_payload, ctx)
        if not security["success"]:
            return security

        started = time.time()
        timed_out = False

        try:
            safe_env = self._build_safe_env(env)

            process = subprocess.run(
                command_list,
                cwd=cwd_result["data"]["cwd"],
                env=safe_env,
                capture_output=True,
                text=True,
                timeout=timeout_seconds or self.default_timeout_seconds,
                shell=False,
                check=False,
            )

            duration = time.time() - started

            result = CommandResult(
                command=command_list,
                cwd=cwd_result["data"]["cwd"],
                exit_code=process.returncode,
                stdout=self._truncate_output(process.stdout),
                stderr=self._truncate_output(process.stderr),
                duration_seconds=round(duration, 4),
                timed_out=False,
            )

            final = self._finalize_execution_result(
                command_result=result,
                context=ctx,
                operation="run_command",
                extra_data={},
            )
            return final

        except subprocess.TimeoutExpired as exc:
            timed_out = True
            duration = time.time() - started

            result = CommandResult(
                command=command_list,
                cwd=cwd_result["data"]["cwd"],
                exit_code=-1,
                stdout=self._truncate_output(exc.stdout.decode() if isinstance(exc.stdout, bytes) else str(exc.stdout or "")),
                stderr=self._truncate_output(exc.stderr.decode() if isinstance(exc.stderr, bytes) else str(exc.stderr or "")),
                duration_seconds=round(duration, 4),
                timed_out=True,
            )

            final = self._finalize_execution_result(
                command_result=result,
                context=ctx,
                operation="run_command",
                extra_data={"timed_out": timed_out},
            )
            final["success"] = False
            final["message"] = "Command timed out."
            final["error"] = {
                "code": "command_timeout",
                "detail": f"Command exceeded timeout of {timeout_seconds or self.default_timeout_seconds} seconds.",
            }
            return final

        except Exception as exc:
            return self._error_result(
                "Failed to run command.",
                error=exc,
                error_code="command_execution_failed",
                metadata={
                    "command": command_list,
                    "cwd": cwd_result["data"]["cwd"],
                },
            )

    def run_pytest(
        self,
        *,
        context: Union[TaskContext, Dict[str, Any]],
        test_path: Optional[Union[str, Path]] = None,
        extra_args: Optional[List[str]] = None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Run pytest safely.

        Uses:
            python -m pytest
        """

        args = [sys.executable, "-m", "pytest"]

        if test_path:
            path_result = self._resolve_safe_path(test_path, must_exist=True)
            if not path_result["success"]:
                return path_result
            args.append(path_result["data"]["relative_path"])

        for arg in extra_args or []:
            if not self._is_safe_arg(str(arg)):
                return self._error_result(
                    "Unsafe pytest argument blocked.",
                    error_code="unsafe_pytest_arg",
                    metadata={"arg": arg},
                )
            args.append(str(arg))

        return self.run_command(
            args,
            context=context,
            timeout_seconds=timeout_seconds or self.default_timeout_seconds,
        )

    def run_unittest(
        self,
        *,
        context: Union[TaskContext, Dict[str, Any]],
        test_module: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Run Python unittest safely.

        Uses:
            python -m unittest discover
        or:
            python -m unittest module.name
        """

        if test_module:
            if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_.]*$", test_module):
                return self._error_result(
                    "Invalid unittest module name.",
                    error_code="invalid_unittest_module",
                    metadata={"test_module": test_module},
                )
            command = [sys.executable, "-m", "unittest", test_module]
        else:
            command = [sys.executable, "-m", "unittest", "discover"]

        return self.run_command(
            command,
            context=context,
            timeout_seconds=timeout_seconds or self.default_timeout_seconds,
        )

    def run_python_syntax_check(
        self,
        *,
        context: Union[TaskContext, Dict[str, Any]],
        paths: List[Union[str, Path]],
    ) -> Dict[str, Any]:
        """
        Parse Python files with ast.parse without executing them.

        This is safer than importing modules.
        """

        ctx = self._coerce_context(context)
        validation = self._validate_task_context(ctx)
        if not validation["success"]:
            return validation

        if not paths:
            paths = ["."]

        files = self._collect_python_files(paths)
        results: List[Dict[str, Any]] = []
        failed: List[Dict[str, Any]] = []

        for file_path in files:
            try:
                source = file_path.read_text(encoding="utf-8")
                ast.parse(source, filename=str(file_path))
                item = {
                    "path": self._relative_path(file_path),
                    "success": True,
                    "message": "Syntax OK.",
                    "error": None,
                }
                results.append(item)
            except SyntaxError as exc:
                item = {
                    "path": self._relative_path(file_path),
                    "success": False,
                    "message": "Syntax error.",
                    "error": {
                        "line": exc.lineno,
                        "offset": exc.offset,
                        "text": exc.text,
                        "detail": str(exc),
                    },
                }
                results.append(item)
                failed.append(item)
            except Exception as exc:
                item = {
                    "path": self._relative_path(file_path),
                    "success": False,
                    "message": "Failed to parse file.",
                    "error": self._serialize_error(exc),
                }
                results.append(item)
                failed.append(item)

        data = {
            "total_files": len(files),
            "passed": len(files) - len(failed),
            "failed": len(failed),
            "results": results,
        }

        verification_payload = self._prepare_verification_payload(
            operation="run_python_syntax_check",
            context=ctx,
            data=data,
            success=not failed,
        )
        memory_payload = self._prepare_memory_payload(
            operation="run_python_syntax_check",
            context=ctx,
            data=data,
            success=not failed,
        )

        final = self._safe_result(
            message="Python syntax check completed." if not failed else "Python syntax check found errors.",
            data={
                **data,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent": self.agent_name,
                "operation": "run_python_syntax_check",
                "context": ctx.to_dict(),
            },
        )
        final["success"] = not failed

        if failed:
            final["error"] = {
                "code": "syntax_check_failed",
                "detail": f"{len(failed)} file(s) failed syntax check.",
            }

        self._emit_agent_event("test_runner.syntax_check_completed", final)
        self._log_audit_event("test_runner.syntax_check_completed", final)

        return final

    def run_smoke_tests(
        self,
        *,
        context: Union[TaskContext, Dict[str, Any]],
        commands: Optional[List[Union[str, List[str]]]] = None,
        endpoint_checks: Optional[List[Dict[str, Any]]] = None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Run a smoke test group made of commands and endpoint checks.
        """

        ctx = self._coerce_context(context)
        validation = self._validate_task_context(ctx)
        if not validation["success"]:
            return validation

        command_results: List[Dict[str, Any]] = []
        endpoint_result: Optional[Dict[str, Any]] = None
        failures = 0

        for command in commands or []:
            result = self.run_command(
                command,
                context=ctx,
                timeout_seconds=timeout_seconds or self.default_timeout_seconds,
            )
            command_results.append(result)
            if not result.get("success"):
                failures += 1

        if endpoint_checks:
            endpoint_result = self.run_endpoint_checks(
                context=ctx,
                endpoint_checks=endpoint_checks,
            )
            if not endpoint_result.get("success"):
                failures += 1

        data = {
            "command_results": command_results,
            "endpoint_result": endpoint_result,
            "failures": failures,
            "passed": failures == 0,
        }

        verification_payload = self._prepare_verification_payload(
            operation="run_smoke_tests",
            context=ctx,
            data=data,
            success=failures == 0,
        )

        memory_payload = self._prepare_memory_payload(
            operation="run_smoke_tests",
            context=ctx,
            data=data,
            success=failures == 0,
        )

        final = self._safe_result(
            message="Smoke tests passed." if failures == 0 else "Smoke tests completed with failures.",
            data={
                **data,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent": self.agent_name,
                "operation": "run_smoke_tests",
                "context": ctx.to_dict(),
            },
        )
        final["success"] = failures == 0

        if failures:
            final["error"] = {
                "code": "smoke_tests_failed",
                "detail": f"{failures} smoke test group(s) failed.",
            }

        self._emit_agent_event("test_runner.smoke_tests_completed", final)
        self._log_audit_event("test_runner.smoke_tests_completed", final)

        return final

    def run_endpoint_checks(
        self,
        *,
        context: Union[TaskContext, Dict[str, Any]],
        endpoint_checks: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Run HTTP endpoint checks using urllib from Python standard library.

        Only http:// and https:// URLs are allowed.
        """

        ctx = self._coerce_context(context)
        validation = self._validate_task_context(ctx)
        if not validation["success"]:
            return validation

        if not endpoint_checks:
            return self._error_result(
                "endpoint_checks must be a non-empty list.",
                error_code="missing_endpoint_checks",
            )

        normalized_checks: List[EndpointCheck] = []
        for raw in endpoint_checks:
            check = self._coerce_endpoint_check(raw)
            url_validation = self._validate_endpoint_url(check.url)
            if not url_validation["success"]:
                return url_validation
            normalized_checks.append(check)

        operation_payload = {
            "operation": "run_endpoint_checks",
            "endpoint_checks": [check.to_dict() for check in normalized_checks],
        }

        security = self._handle_security_if_required(operation_payload, ctx)
        if not security["success"]:
            return security

        results: List[Dict[str, Any]] = []
        failures: List[Dict[str, Any]] = []

        for check in normalized_checks:
            result = self._run_single_endpoint_check(check)
            results.append(result)
            if not result.get("success"):
                failures.append(result)

        data = {
            "total": len(results),
            "passed": len(results) - len(failures),
            "failed": len(failures),
            "results": results,
        }

        verification_payload = self._prepare_verification_payload(
            operation="run_endpoint_checks",
            context=ctx,
            data=data,
            success=not failures,
        )

        memory_payload = self._prepare_memory_payload(
            operation="run_endpoint_checks",
            context=ctx,
            data=data,
            success=not failures,
        )

        final = self._safe_result(
            message="Endpoint checks passed." if not failures else "Endpoint checks completed with failures.",
            data={
                **data,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent": self.agent_name,
                "operation": "run_endpoint_checks",
                "context": ctx.to_dict(),
            },
        )
        final["success"] = not failures

        if failures:
            final["error"] = {
                "code": "endpoint_checks_failed",
                "detail": f"{len(failures)} endpoint check(s) failed.",
            }

        self._emit_agent_event("test_runner.endpoint_checks_completed", final)
        self._log_audit_event("test_runner.endpoint_checks_completed", final)

        return final

    def run_build_check(
        self,
        *,
        context: Union[TaskContext, Dict[str, Any]],
        build_type: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Run build/check commands for common stacks.

        build_type:
            - auto
            - python
            - node
            - flutter
            - dart
        """

        ctx = self._coerce_context(context)
        validation = self._validate_task_context(ctx)
        if not validation["success"]:
            return validation

        detected = build_type or "auto"
        commands = self._detect_build_commands(detected)

        if not commands:
            return self._error_result(
                "No build check command detected.",
                error_code="build_command_not_found",
                metadata={
                    "build_type": detected,
                    "project_root": str(self.project_root),
                },
            )

        results: List[Dict[str, Any]] = []
        failures = 0

        for command in commands:
            result = self.run_command(
                command,
                context=ctx,
                timeout_seconds=timeout_seconds or self.default_timeout_seconds,
            )
            results.append(result)
            if not result.get("success"):
                failures += 1

        data = {
            "build_type": detected,
            "commands": commands,
            "results": results,
            "passed": failures == 0,
            "failures": failures,
        }

        verification_payload = self._prepare_verification_payload(
            operation="run_build_check",
            context=ctx,
            data=data,
            success=failures == 0,
        )

        memory_payload = self._prepare_memory_payload(
            operation="run_build_check",
            context=ctx,
            data=data,
            success=failures == 0,
        )

        final = self._safe_result(
            message="Build check passed." if failures == 0 else "Build check completed with failures.",
            data={
                **data,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent": self.agent_name,
                "operation": "run_build_check",
                "context": ctx.to_dict(),
            },
        )
        final["success"] = failures == 0

        if failures:
            final["error"] = {
                "code": "build_check_failed",
                "detail": f"{failures} build command(s) failed.",
            }

        self._emit_agent_event("test_runner.build_check_completed", final)
        self._log_audit_event("test_runner.build_check_completed", final)

        return final

    def generate_python_smoke_test(
        self,
        *,
        context: Union[TaskContext, Dict[str, Any]],
        target_module: str,
        output_path: Optional[Union[str, Path]] = None,
        class_or_function_names: Optional[List[str]] = None,
        overwrite: bool = False,
    ) -> Dict[str, Any]:
        """
        Generate a basic Python smoke test file.

        The generated test imports the target module and optionally checks
        named classes/functions exist.
        """

        ctx = self._coerce_context(context)
        validation = self._validate_task_context(ctx)
        if not validation["success"]:
            return validation

        if not target_module or not re.match(r"^[a-zA-Z_][a-zA-Z0-9_.]*$", target_module):
            return self._error_result(
                "Invalid target_module.",
                error_code="invalid_target_module",
                metadata={"target_module": target_module},
            )

        if output_path is None:
            safe_name = target_module.replace(".", "_")
            output_path = Path("tests") / f"test_smoke_{safe_name}.py"

        path_result = self._resolve_safe_path(output_path, must_exist=False)
        if not path_result["success"]:
            return path_result

        file_path = path_result["data"]["path"]

        if file_path.exists() and not overwrite:
            return self._error_result(
                "Test file already exists and overwrite=False.",
                error_code="test_file_exists",
                metadata={"path": self._relative_path(file_path)},
            )

        names = class_or_function_names or []
        for name in names:
            if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", str(name)):
                return self._error_result(
                    "Invalid class/function name.",
                    error_code="invalid_symbol_name",
                    metadata={"name": name},
                )

        operation_payload = {
            "operation": "generate_python_smoke_test",
            "target_module": target_module,
            "output_path": self._relative_path(file_path),
            "overwrite": overwrite,
        }

        security = self._handle_security_if_required(operation_payload, ctx)
        if not security["success"]:
            return security

        content = self._build_python_smoke_test_content(target_module, names)

        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content, encoding="utf-8")

            data = {
                "path": self._relative_path(file_path),
                "target_module": target_module,
                "symbols_checked": names,
                "content": content,
            }

            verification_payload = self._prepare_verification_payload(
                operation="generate_python_smoke_test",
                context=ctx,
                data=data,
                success=True,
            )

            memory_payload = self._prepare_memory_payload(
                operation="generate_python_smoke_test",
                context=ctx,
                data=data,
                success=True,
            )

            final = self._safe_result(
                message="Python smoke test generated successfully.",
                data={
                    **data,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "agent": self.agent_name,
                    "operation": "generate_python_smoke_test",
                    "context": ctx.to_dict(),
                },
            )

            self._emit_agent_event("test_runner.smoke_test_generated", final)
            self._log_audit_event("test_runner.smoke_test_generated", final)

            return final

        except Exception as exc:
            return self._error_result(
                "Failed to generate Python smoke test.",
                error=exc,
                error_code="generate_python_smoke_test_failed",
                metadata={"path": self._relative_path(file_path)},
            )

    def run_test_plan(
        self,
        *,
        context: Union[TaskContext, Dict[str, Any]],
        plan: Union[TestPlan, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Run a complete test plan.

        Useful for Master Agent routing and dashboard-driven test flows.
        """

        ctx = self._coerce_context(context)
        validation = self._validate_task_context(ctx)
        if not validation["success"]:
            return validation

        test_plan = self._coerce_test_plan(plan)
        if not test_plan.name:
            return self._error_result(
                "Test plan name is required.",
                error_code="missing_test_plan_name",
            )

        results: Dict[str, Any] = {}
        failures = 0

        if test_plan.syntax_paths:
            syntax_result = self.run_python_syntax_check(
                context=ctx,
                paths=test_plan.syntax_paths,
            )
            results["syntax_check"] = syntax_result
            if not syntax_result.get("success"):
                failures += 1

        if test_plan.commands:
            command_results = []
            for command in test_plan.commands:
                command_result = self.run_command(
                    command,
                    context=ctx,
                    timeout_seconds=test_plan.timeout_seconds,
                )
                command_results.append(command_result)
                if not command_result.get("success"):
                    failures += 1
            results["commands"] = command_results

        if test_plan.endpoint_checks:
            endpoint_result = self.run_endpoint_checks(
                context=ctx,
                endpoint_checks=[check.to_dict() for check in test_plan.endpoint_checks],
            )
            results["endpoint_checks"] = endpoint_result
            if not endpoint_result.get("success"):
                failures += 1

        if test_plan.build_type:
            build_result = self.run_build_check(
                context=ctx,
                build_type=test_plan.build_type,
                timeout_seconds=test_plan.timeout_seconds,
            )
            results["build_check"] = build_result
            if not build_result.get("success"):
                failures += 1

        data = {
            "plan": test_plan.to_dict(),
            "results": results,
            "failures": failures,
            "passed": failures == 0,
        }

        verification_payload = self._prepare_verification_payload(
            operation="run_test_plan",
            context=ctx,
            data=data,
            success=failures == 0,
        )

        memory_payload = self._prepare_memory_payload(
            operation="run_test_plan",
            context=ctx,
            data=data,
            success=failures == 0,
        )

        final = self._safe_result(
            message="Test plan passed." if failures == 0 else "Test plan completed with failures.",
            data={
                **data,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent": self.agent_name,
                "operation": "run_test_plan",
                "context": ctx.to_dict(),
            },
        )
        final["success"] = failures == 0

        if failures:
            final["error"] = {
                "code": "test_plan_failed",
                "detail": f"{failures} test plan section(s) failed.",
            }

        self._emit_agent_event("test_runner.test_plan_completed", final)
        self._log_audit_event("test_runner.test_plan_completed", final)

        return final

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: TaskContext) -> Dict[str, Any]:
        """
        Validate SaaS context.
        """

        if context is None:
            return self._error_result(
                "Task context is required.",
                error_code="missing_context",
            )

        if context.user_id in (None, "", 0):
            return self._error_result(
                "user_id is required for SaaS-safe execution.",
                error_code="missing_user_id",
            )

        if context.workspace_id in (None, "", 0):
            return self._error_result(
                "workspace_id is required for SaaS-safe execution.",
                error_code="missing_workspace_id",
            )

        return self._safe_result(
            message="Task context validated.",
            data={"context": context.to_dict()},
            metadata={"agent": self.agent_name},
        )

    def _requires_security_check(
        self,
        operation: Union[str, Dict[str, Any]],
        context: TaskContext,
    ) -> bool:
        """
        Test running can execute code, so command/build/endpoint checks
        require Security Agent approval.
        """

        if isinstance(operation, str):
            return operation in {
                "run_command",
                "run_pytest",
                "run_unittest",
                "run_smoke_tests",
                "run_build_check",
                "run_endpoint_checks",
                "run_test_plan",
                "generate_python_smoke_test",
            }

        op_name = operation.get("operation", "")
        if op_name in {
            "run_command",
            "run_pytest",
            "run_unittest",
            "run_smoke_tests",
            "run_build_check",
            "run_endpoint_checks",
            "run_test_plan",
            "generate_python_smoke_test",
        }:
            return True

        text = json.dumps(operation, default=str)
        return self._contains_sensitive_pattern(text)

    def _request_security_approval(
        self,
        operation: Union[str, Dict[str, Any]],
        context: TaskContext,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent.

        If security_callback is not provided, a safe default policy allows
        allowlisted commands and blocks dangerous tokens.
        """

        payload = {
            "agent": self.agent_name,
            "event": "security_approval_requested",
            "operation": operation,
            "context": context.to_dict(),
            "timestamp": self._utc_now(),
            "risk": self._classify_operation_risk(operation),
        }

        if self.security_callback:
            try:
                response = self.security_callback(payload)
                if not isinstance(response, dict):
                    return self._error_result(
                        "Security callback returned invalid response.",
                        error_code="invalid_security_response",
                        metadata={"payload": payload},
                    )
                return response
            except Exception as exc:
                return self._error_result(
                    "Security approval callback failed.",
                    error=exc,
                    error_code="security_callback_failed",
                    metadata={"payload": payload},
                )

        if isinstance(operation, dict):
            command = operation.get("command")
            if command:
                command_list = self._normalize_command(command)
                validation = self._validate_command(command_list)
                if not validation["success"]:
                    return validation

        text = json.dumps(operation, default=str)
        if self._contains_sensitive_pattern(text):
            return self._error_result(
                "Security policy blocked sensitive-looking operation.",
                error_code="security_blocked_sensitive_operation",
                metadata=payload,
            )

        return self._safe_result(
            message="Security approval granted by default safe policy.",
            data={"approved": True, "security_payload": payload},
            metadata={"agent": self.agent_name},
        )

    def _prepare_verification_payload(
        self,
        *,
        operation: str,
        context: TaskContext,
        data: Dict[str, Any],
        success: bool,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.
        """

        return {
            "agent": self.agent_name,
            "target_agent": "VerificationAgent",
            "type": "test_runner_verification",
            "operation": operation,
            "success": success,
            "checks": {
                "completed": True,
                "passed": success,
                "has_data": bool(data),
            },
            "data_summary": self._summarize_for_payload(data),
            "context": context.to_dict(),
            "timestamp": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        *,
        operation: str,
        context: TaskContext,
        data: Dict[str, Any],
        success: bool,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Stores safe summary only, not full stdout/stderr.
        """

        return {
            "agent": self.agent_name,
            "target_agent": "MemoryAgent",
            "type": "test_runner_memory",
            "summary": f"{operation} {'passed' if success else 'failed'}",
            "operation": operation,
            "success": success,
            "data_summary": self._summarize_for_payload(data),
            "context": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "request_id": context.request_id,
                "session_id": context.session_id,
            },
            "timestamp": self._utc_now(),
        }

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Emit event for Agent Registry, Dashboard, analytics, or task history.
        """

        event = {
            "event": event_name,
            "agent": self.agent_name,
            "payload": payload,
            "timestamp": self._utc_now(),
        }

        if self.event_callback:
            try:
                self.event_callback(event)
            except Exception:
                logger.exception("TestRunner event callback failed.")

        logger.debug("Agent event emitted: %s", event_name)

    def _log_audit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Log audit event.

        In production this can be wired to the Audit Log service.
        """

        audit_event = {
            "event": event_name,
            "agent": self.agent_name,
            "payload": self._safe_audit_payload(payload),
            "timestamp": self._utc_now(),
        }

        if self.audit_callback:
            try:
                self.audit_callback(audit_event)
            except Exception:
                logger.exception("TestRunner audit callback failed.")

        logger.info("Audit event: %s", event_name)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success response.
        """

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": self._serialize_error(error) if error else None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        *,
        error: Optional[Any] = None,
        error_code: str = "error",
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error response.
        """

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": {
                "code": error_code,
                "detail": self._serialize_error(error) if error else message,
            },
            "metadata": metadata or {},
        }

    # ------------------------------------------------------------------
    # Internal execution helpers
    # ------------------------------------------------------------------

    def _finalize_execution_result(
        self,
        *,
        command_result: CommandResult,
        context: TaskContext,
        operation: str,
        extra_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        success = command_result.exit_code == 0 and not command_result.timed_out

        data = {
            "command_result": command_result.to_dict(),
            "passed": success,
            **(extra_data or {}),
        }

        verification_payload = self._prepare_verification_payload(
            operation=operation,
            context=context,
            data=data,
            success=success,
        )

        memory_payload = self._prepare_memory_payload(
            operation=operation,
            context=context,
            data=data,
            success=success,
        )

        final = self._safe_result(
            message="Command completed successfully." if success else "Command completed with failure.",
            data={
                **data,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent": self.agent_name,
                "operation": operation,
                "context": context.to_dict(),
                "platform": platform.platform(),
            },
        )
        final["success"] = success

        if not success:
            final["error"] = {
                "code": "command_failed",
                "detail": f"Command exited with code {command_result.exit_code}.",
            }

        self._emit_agent_event("test_runner.command_completed", final)
        self._log_audit_event("test_runner.command_completed", final)

        return final

    def _normalize_command(self, command: Union[str, List[str]]) -> List[str]:
        """
        Convert command to list without shell=True.
        """

        if isinstance(command, str):
            return shlex.split(command)

        if isinstance(command, list):
            return [str(part) for part in command if str(part).strip()]

        return []

    def _validate_command(self, command: List[str]) -> Dict[str, Any]:
        """
        Validate command against allowlist/denylist.
        """

        if not command:
            return self._error_result(
                "Command cannot be empty.",
                error_code="empty_command",
            )

        executable = command[0]

        executable_name = Path(executable).name
        allowed_names = {Path(item).name for item in self.allowed_executables}

        if executable not in self.allowed_executables and executable_name not in allowed_names:
            return self._error_result(
                "Executable is not allowlisted.",
                error_code="executable_not_allowed",
                metadata={
                    "executable": executable,
                    "allowed": sorted(str(Path(item).name) for item in self.allowed_executables),
                },
            )

        joined = " ".join(command).lower()
        tokens = set(re.split(r"\s+", joined))

        denied_hit = tokens.intersection({token.lower() for token in self.denied_tokens})
        if denied_hit:
            return self._error_result(
                "Command contains denied token.",
                error_code="denied_command_token",
                metadata={
                    "denied": sorted(denied_hit),
                    "command": command,
                },
            )

        unsafe_shell_chars = {";", "&&", "||", "|", "`", "$(", ">", ">>", "<"}
        for part in command:
            if part in unsafe_shell_chars:
                return self._error_result(
                    "Command contains unsafe shell control token.",
                    error_code="unsafe_shell_token",
                    metadata={"token": part, "command": command},
                )

        for part in command[1:]:
            if not self._is_safe_arg(part):
                return self._error_result(
                    "Command contains unsafe argument.",
                    error_code="unsafe_command_arg",
                    metadata={"arg": part, "command": command},
                )

        return self._safe_result(
            message="Command validated.",
            data={"command": command},
            metadata={"agent": self.agent_name},
        )

    def _is_safe_arg(self, arg: str) -> bool:
        """
        Basic safety check for command arguments.
        """

        if not arg:
            return True

        blocked_substrings = [";", "&&", "||", "`", "$(", "\n", "\r"]
        if any(item in arg for item in blocked_substrings):
            return False

        if arg.strip() in {">", ">>", "<", "|"}:
            return False

        return True

    def _build_safe_env(self, extra_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Build safe environment without injecting secrets.
        """

        allowed_keys = {
            "PATH",
            "PYTHONPATH",
            "HOME",
            "USER",
            "USERNAME",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "APPDATA",
            "LOCALAPPDATA",
            "LANG",
            "LC_ALL",
        }

        env = {key: value for key, value in os.environ.items() if key.upper() in allowed_keys}

        if extra_env:
            for key, value in extra_env.items():
                if self._contains_sensitive_pattern(key) or self._contains_sensitive_pattern(str(value)):
                    continue
                env[str(key)] = str(value)

        return env

    def _truncate_output(self, output: str) -> str:
        """
        Keep stdout/stderr dashboard-safe.
        """

        output = output or ""
        if len(output) <= self.max_output_chars:
            return output

        return output[: self.max_output_chars] + "\n...[output truncated]..."

    # ------------------------------------------------------------------
    # Endpoint helpers
    # ------------------------------------------------------------------

    def _run_single_endpoint_check(self, check: EndpointCheck) -> Dict[str, Any]:
        started = time.time()

        try:
            expected_statuses = (
                check.expected_status
                if isinstance(check.expected_status, list)
                else [int(check.expected_status)]
            )

            body_data: Optional[bytes] = None
            headers = dict(check.headers or {})

            if isinstance(check.body, dict):
                body_data = json.dumps(check.body).encode("utf-8")
                headers.setdefault("Content-Type", "application/json")
            elif isinstance(check.body, str):
                body_data = check.body.encode("utf-8")
            elif isinstance(check.body, bytes):
                body_data = check.body

            request = urllib.request.Request(
                check.url,
                data=body_data,
                method=check.method.upper(),
                headers=headers,
            )

            with urllib.request.urlopen(request, timeout=check.timeout_seconds) as response:
                status = int(response.status)
                raw_body = response.read(4096)
                duration = round(time.time() - started, 4)

            success = status in expected_statuses

            return {
                "success": success,
                "name": check.name or check.url,
                "url": check.url,
                "method": check.method.upper(),
                "expected_status": expected_statuses,
                "status": status,
                "duration_seconds": duration,
                "body_preview": raw_body.decode("utf-8", errors="replace")[:1000],
                "error": None if success else {
                    "code": "unexpected_status",
                    "detail": f"Expected {expected_statuses}, got {status}.",
                },
            }

        except urllib.error.HTTPError as exc:
            duration = round(time.time() - started, 4)
            expected_statuses = (
                check.expected_status
                if isinstance(check.expected_status, list)
                else [int(check.expected_status)]
            )
            status = int(exc.code)
            success = status in expected_statuses

            return {
                "success": success,
                "name": check.name or check.url,
                "url": check.url,
                "method": check.method.upper(),
                "expected_status": expected_statuses,
                "status": status,
                "duration_seconds": duration,
                "body_preview": exc.read(4096).decode("utf-8", errors="replace")[:1000],
                "error": None if success else {
                    "code": "http_error",
                    "detail": str(exc),
                },
            }

        except Exception as exc:
            duration = round(time.time() - started, 4)
            return {
                "success": False,
                "name": check.name or check.url,
                "url": check.url,
                "method": check.method.upper(),
                "expected_status": check.expected_status,
                "status": None,
                "duration_seconds": duration,
                "body_preview": "",
                "error": self._serialize_error(exc),
            }

    def _coerce_endpoint_check(self, raw: Dict[str, Any]) -> EndpointCheck:
        return EndpointCheck(
            url=str(raw.get("url", "")),
            method=str(raw.get("method", "GET")).upper(),
            expected_status=raw.get("expected_status", raw.get("status", 200)),
            timeout_seconds=int(raw.get("timeout_seconds", 10)),
            headers=dict(raw.get("headers") or {}),
            body=raw.get("body"),
            name=raw.get("name"),
        )

    def _validate_endpoint_url(self, url: str) -> Dict[str, Any]:
        if not url:
            return self._error_result(
                "Endpoint URL is required.",
                error_code="missing_endpoint_url",
            )

        if not (url.startswith("http://") or url.startswith("https://")):
            return self._error_result(
                "Only http:// and https:// endpoint URLs are allowed.",
                error_code="invalid_endpoint_scheme",
                metadata={"url": url},
            )

        if self._contains_sensitive_pattern(url):
            return self._error_result(
                "Endpoint URL appears to contain sensitive data.",
                error_code="sensitive_endpoint_url",
            )

        return self._safe_result(
            message="Endpoint URL validated.",
            data={"url": url},
        )

    # ------------------------------------------------------------------
    # Build detection
    # ------------------------------------------------------------------

    def _detect_build_commands(self, build_type: str) -> List[List[str]]:
        build_type = (build_type or "auto").lower().strip()

        if build_type == "python":
            return self._python_build_commands()

        if build_type == "node":
            return self._node_build_commands()

        if build_type == "flutter":
            return self._flutter_build_commands()

        if build_type == "dart":
            return self._dart_build_commands()

        if build_type != "auto":
            return []

        commands: List[List[str]] = []

        if (self.project_root / "pyproject.toml").exists() or (self.project_root / "requirements.txt").exists():
            commands.extend(self._python_build_commands())

        if (self.project_root / "package.json").exists():
            commands.extend(self._node_build_commands())

        if (self.project_root / "pubspec.yaml").exists():
            commands.extend(self._flutter_build_commands())

        return commands

    def _python_build_commands(self) -> List[List[str]]:
        commands: List[List[str]] = []

        tests_dir = self.project_root / "tests"
        if tests_dir.exists():
            commands.append([sys.executable, "-m", "pytest"])

        if not commands:
            commands.append([sys.executable, "-m", "compileall", "."])

        return commands

    def _node_build_commands(self) -> List[List[str]]:
        package_json = self.project_root / "package.json"
        if not package_json.exists():
            return []

        try:
            package = json.loads(package_json.read_text(encoding="utf-8"))
            scripts = package.get("scripts") or {}

            if "test" in scripts:
                return ["npm", "test", "--", "--watch=false"] if False else [["npm", "test"]]

            if "build" in scripts:
                return [["npm", "run", "build"]]
        except Exception:
            logger.debug("Failed to inspect package.json.", exc_info=True)

        return [["npm", "--version"]]

    def _flutter_build_commands(self) -> List[List[str]]:
        pubspec = self.project_root / "pubspec.yaml"
        if not pubspec.exists():
            return []

        return [["flutter", "analyze"]]

    def _dart_build_commands(self) -> List[List[str]]:
        pubspec = self.project_root / "pubspec.yaml"
        if not pubspec.exists():
            return []

        return [["dart", "analyze"]]

    # ------------------------------------------------------------------
    # File/path helpers
    # ------------------------------------------------------------------

    def _resolve_safe_cwd(self, cwd: Optional[Union[str, Path]]) -> Dict[str, Any]:
        if cwd is None:
            return self._safe_result(
                message="CWD validated.",
                data={"cwd": str(self.project_root)},
            )

        candidate = (self.project_root / Path(cwd)).resolve() if not Path(cwd).is_absolute() else Path(cwd).resolve()

        try:
            candidate.relative_to(self.project_root)
        except ValueError:
            return self._error_result(
                "cwd escapes project_root and is not allowed.",
                error_code="cwd_escape_blocked",
                metadata={
                    "cwd": str(candidate),
                    "project_root": str(self.project_root),
                },
            )

        if not candidate.exists() or not candidate.is_dir():
            return self._error_result(
                "cwd does not exist or is not a directory.",
                error_code="invalid_cwd",
                metadata={"cwd": str(candidate)},
            )

        return self._safe_result(
            message="CWD validated.",
            data={"cwd": str(candidate)},
        )

    def _resolve_safe_path(
        self,
        path: Union[str, Path],
        *,
        must_exist: bool,
    ) -> Dict[str, Any]:
        if path is None or str(path).strip() == "":
            return self._error_result(
                "Path is required.",
                error_code="missing_path",
            )

        raw = Path(str(path).strip())
        candidate = raw.resolve() if raw.is_absolute() else (self.project_root / raw).resolve()

        try:
            candidate.relative_to(self.project_root)
        except ValueError:
            return self._error_result(
                "Path escapes project_root and is not allowed.",
                error_code="path_escape_blocked",
                metadata={"path": str(candidate)},
            )

        parts_lower = {part.lower() for part in candidate.parts}
        denied_hit = parts_lower.intersection({item.lower() for item in self.denied_path_parts})
        if denied_hit:
            return self._error_result(
                "Path contains denied folder.",
                error_code="denied_path_part",
                metadata={"denied": sorted(denied_hit)},
            )

        if must_exist and not candidate.exists():
            return self._error_result(
                "Path does not exist.",
                error_code="path_not_found",
                metadata={"path": self._relative_path(candidate)},
            )

        if candidate.exists() and candidate.is_file():
            if candidate.suffix.lower() not in self.allowed_test_extensions:
                return self._error_result(
                    "File extension is not allowed for TestRunner.",
                    error_code="extension_not_allowed",
                    metadata={"path": self._relative_path(candidate)},
                )

        return self._safe_result(
            message="Path validated.",
            data={
                "path": candidate,
                "relative_path": self._relative_path(candidate),
            },
        )

    def _collect_python_files(self, paths: List[Union[str, Path]]) -> List[Path]:
        files: List[Path] = []

        for raw_path in paths:
            path_result = self._resolve_safe_path(raw_path, must_exist=True)
            if not path_result["success"]:
                continue

            path = path_result["data"]["path"]

            if path.is_file() and path.suffix == ".py":
                files.append(path)
                continue

            if path.is_dir():
                for item in path.rglob("*.py"):
                    if self._is_denied_path(item):
                        continue
                    files.append(item)

        return sorted(set(files))

    def _is_denied_path(self, path: Path) -> bool:
        parts_lower = {part.lower() for part in path.parts}
        return bool(parts_lower.intersection({item.lower() for item in self.denied_path_parts}))

    def _relative_path(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.project_root))
        except Exception:
            return str(path)

    # ------------------------------------------------------------------
    # Test generation helpers
    # ------------------------------------------------------------------

    def _build_python_smoke_test_content(
        self,
        target_module: str,
        names: List[str],
    ) -> str:
        checks = ""

        for name in names:
            checks += f"""
def test_{name}_exists():
    assert hasattr(module, "{name}")
"""

        if not checks:
            checks = """
def test_module_imports():
    assert module is not None
"""

        return f'''"""
Auto-generated smoke test for {target_module}.

Generated by William/Jarvis Code Agent TestRunner.
"""

import importlib


module = importlib.import_module("{target_module}")


{checks}
'''

    # ------------------------------------------------------------------
    # Test plan helpers
    # ------------------------------------------------------------------

    def _coerce_test_plan(self, plan: Union[TestPlan, Dict[str, Any]]) -> TestPlan:
        if isinstance(plan, TestPlan):
            return plan

        endpoint_checks = [
            self._coerce_endpoint_check(item)
            for item in (plan.get("endpoint_checks") or [])
        ]

        return TestPlan(
            name=str(plan.get("name", "")),
            commands=[self._normalize_command(cmd) for cmd in (plan.get("commands") or [])],
            endpoint_checks=endpoint_checks,
            syntax_paths=list(plan.get("syntax_paths") or []),
            build_type=plan.get("build_type"),
            timeout_seconds=int(plan.get("timeout_seconds", self.default_timeout_seconds)),
            metadata=dict(plan.get("metadata") or {}),
        )

    # ------------------------------------------------------------------
    # Security helpers
    # ------------------------------------------------------------------

    def _handle_security_if_required(
        self,
        operation: Union[str, Dict[str, Any]],
        context: TaskContext,
    ) -> Dict[str, Any]:
        if not self._requires_security_check(operation, context):
            return self._safe_result(
                message="Security check not required.",
                data={"approved": True},
            )

        approval = self._request_security_approval(operation, context)
        if not approval.get("success"):
            return approval

        approved = approval.get("data", {}).get("approved", True)
        if approved is False:
            return self._error_result(
                "Security Agent did not approve this operation.",
                error_code="security_not_approved",
                metadata={"operation": operation},
            )

        return approval

    def _classify_operation_risk(self, operation: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        risk = "medium"
        reasons = ["test_or_command_execution"]

        text = json.dumps(operation, default=str)

        if self._contains_sensitive_pattern(text):
            risk = "high"
            reasons.append("sensitive_pattern_detected")

        if isinstance(operation, dict):
            command = operation.get("command")
            if command:
                command_list = self._normalize_command(command)
                joined = " ".join(command_list).lower()
                if any(token in joined.split() for token in self.denied_tokens):
                    risk = "critical"
                    reasons.append("denied_command_token")

        return {
            "level": risk,
            "reasons": reasons,
        }

    def _contains_sensitive_pattern(self, text: str) -> bool:
        if not text:
            return False
        return any(pattern.search(text) for pattern in self.SENSITIVE_PATTERNS)

    # ------------------------------------------------------------------
    # Payload/audit helpers
    # ------------------------------------------------------------------

    def _summarize_for_payload(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Summarize test data without storing full stdout/stderr in memory.
        """

        summary: Dict[str, Any] = {}

        if "command_result" in data:
            command_result = data.get("command_result") or {}
            summary["command"] = command_result.get("command")
            summary["exit_code"] = command_result.get("exit_code")
            summary["timed_out"] = command_result.get("timed_out")
            summary["duration_seconds"] = command_result.get("duration_seconds")

        for key in [
            "passed",
            "failures",
            "failed",
            "passed_count",
            "total",
            "total_files",
            "build_type",
            "path",
            "target_module",
        ]:
            if key in data:
                summary[key] = data[key]

        if "results" in data and isinstance(data["results"], list):
            summary["results_count"] = len(data["results"])

        return summary

    def _safe_audit_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        safe = json.loads(json.dumps(payload, default=str))

        data = safe.get("data")
        if isinstance(data, dict):
            command_result = data.get("command_result")
            if isinstance(command_result, dict):
                if "stdout" in command_result:
                    command_result["stdout_preview"] = command_result["stdout"][:2000]
                    command_result.pop("stdout", None)
                if "stderr" in command_result:
                    command_result["stderr_preview"] = command_result["stderr"][:2000]
                    command_result.pop("stderr", None)

            if "content" in data:
                data["content_preview"] = str(data["content"])[:1000]
                data.pop("content", None)

        return safe

    # ------------------------------------------------------------------
    # Context/result helpers
    # ------------------------------------------------------------------

    def _coerce_context(self, context: Union[TaskContext, Dict[str, Any]]) -> TaskContext:
        if isinstance(context, TaskContext):
            return context

        if not isinstance(context, dict):
            return TaskContext(user_id="", workspace_id="")

        return TaskContext(
            user_id=context.get("user_id", ""),
            workspace_id=context.get("workspace_id", ""),
            role=context.get("role"),
            subscription=context.get("subscription"),
            permissions=list(context.get("permissions") or []),
            request_id=context.get("request_id"),
            session_id=context.get("session_id"),
            ip_address=context.get("ip_address"),
            user_agent=context.get("user_agent"),
        )

    def _serialize_error(self, error: Any) -> Any:
        if error is None:
            return None

        if isinstance(error, Exception):
            return {
                "type": error.__class__.__name__,
                "message": str(error),
            }

        return str(error)

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Optional standalone smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    runner = TestRunner(project_root=os.getcwd())

    demo_context = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "role": "admin",
        "permissions": ["code:test"],
    }

    print(
        json.dumps(
            runner.run_python_syntax_check(
                context=demo_context,
                paths=["."],
            ),
            indent=2,
            default=str,
        )
    )