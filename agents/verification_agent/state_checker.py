"""
agents/verification_agent/state_checker.py

William / Jarvis Multi-Agent AI SaaS System - Digital Promotix
Verification Agent: StateChecker

Purpose:
    Checks process, window, file, folder, service, port, and device setting states.

Design Goals:
    - Safe, read-only state verification.
    - SaaS user/workspace isolation.
    - Import-safe even when future William/Jarvis modules are not created yet.
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router, Master Agent.
    - Produces structured dict/JSON-style results:
        {
            "success": bool,
            "message": str,
            "data": dict,
            "error": Optional[dict],
            "metadata": dict
        }

Important:
    This file does NOT perform destructive actions.
    It only checks local state using safe read-only operations.
"""

from __future__ import annotations

import os
import sys
import json
import time
import socket
import logging
import platform
import subprocess
from pathlib import Path
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union, Iterable, Tuple


# ---------------------------------------------------------------------------
# Optional imports
# ---------------------------------------------------------------------------

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - optional dependency fallback
    psutil = None  # type: ignore


try:
    import winreg  # type: ignore
except Exception:  # pragma: no cover - Windows only
    winreg = None  # type: ignore


# ---------------------------------------------------------------------------
# Safe fallback BaseAgent
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    try:
        from core.base_agent import BaseAgent  # type: ignore
    except Exception:

        class BaseAgent:  # type: ignore
            """
            Minimal fallback BaseAgent.

            This allows this file to be imported safely before the real
            William/Jarvis BaseAgent exists.
            """

            def __init__(self, *args: Any, **kwargs: Any) -> None:
                self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
                self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
                self.logger = logging.getLogger(self.agent_name)

            async def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
                raise NotImplementedError("Fallback BaseAgent does not implement run().")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("WilliamJarvis.VerificationAgent.StateChecker")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class StateCheckContext:
    """
    SaaS-safe context object used by StateChecker.

    user_id:
        Required when the check is user/workspace-specific.

    workspace_id:
        Required when the check is user/workspace-specific.

    request_id:
        Optional request/correlation ID for dashboard, API, audit logs, and tracing.

    task_id:
        Optional task ID for MasterAgent/WorkflowAgent task history.

    source_agent:
        Agent that requested verification.

    metadata:
        Extra non-sensitive context.
    """

    user_id: Optional[str] = None
    workspace_id: Optional[str] = None
    request_id: Optional[str] = None
    task_id: Optional[str] = None
    source_agent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StateExpectation:
    """
    Optional expected state definition.

    expected:
        The expected value. Example:
        - True
        - False
        - "running"
        - "exists"
        - "open"
        - 8000

    operator:
        Supported operators:
        - equals
        - not_equals
        - contains
        - not_contains
        - greater_than
        - greater_or_equal
        - less_than
        - less_or_equal
        - exists
    """

    expected: Any = None
    operator: str = "equals"


@dataclass
class StateCheckRequest:
    """
    Generic state check request.

    check_type:
        process | window | file | folder | service | port | device_setting

    target:
        Target value. Examples:
        - process name: "chrome.exe"
        - file path: "C:/app/config.json"
        - folder path: "/var/log"
        - service name: "nginx"
        - port number: 8000
        - setting key: "timezone"

    expected:
        Optional expected state comparison.

    options:
        Check-specific options.
    """

    check_type: str
    target: Any
    expected: Optional[StateExpectation] = None
    options: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# StateChecker
# ---------------------------------------------------------------------------

class StateChecker(BaseAgent):
    """
    Verification Agent helper for checking local system state.

    Responsibilities:
        - Check process state.
        - Check window state.
        - Check file state.
        - Check folder state.
        - Check service state.
        - Check port state.
        - Check safe device/system setting state.

    Connections to William/Jarvis architecture:
        - Master Agent:
            Can route verification tasks here using `run()` or public methods.
        - Security Agent:
            `_requires_security_check()` and `_request_security_approval()` hooks exist.
            Current operations are read-only, so default security approval is usually not required.
        - Memory Agent:
            `_prepare_memory_payload()` returns safe non-secret verification context.
        - Verification Agent:
            `_prepare_verification_payload()` produces normalized evidence for validation/reporting.
        - Dashboard/API:
            All methods return structured dicts ready for FastAPI responses.
        - Registry/Loader/Router:
            Public metadata fields and import-safe fallback support agent discovery.
    """

    VERSION = "1.0.0"

    SUPPORTED_CHECK_TYPES = {
        "process",
        "window",
        "file",
        "folder",
        "service",
        "port",
        "device_setting",
    }

    SAFE_DEVICE_SETTINGS = {
        "platform",
        "system",
        "release",
        "version",
        "machine",
        "processor",
        "python_version",
        "hostname",
        "timezone",
        "cwd",
        "home",
        "environment_variable",
        "path_exists",
    }

    WINDOWS_REGISTRY_ROOTS = {
        "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
        "HKCU": "HKEY_CURRENT_USER",
        "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
        "HKLM": "HKEY_LOCAL_MACHINE",
    }

    def __init__(
        self,
        agent_name: str = "StateChecker",
        agent_id: str = "verification_agent.state_checker",
        strict_context: bool = True,
        allow_subprocess_checks: bool = True,
        default_timeout_seconds: float = 3.0,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(agent_name=agent_name, agent_id=agent_id, **kwargs)
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.agent_id = agent_id
        self.strict_context = strict_context
        self.allow_subprocess_checks = allow_subprocess_checks
        self.default_timeout_seconds = default_timeout_seconds
        self.logger = logger_instance or logger

        self.capabilities = [
            "check_process_state",
            "check_window_state",
            "check_file_state",
            "check_folder_state",
            "check_service_state",
            "check_port_state",
            "check_device_setting_state",
            "check_many",
        ]

    # -----------------------------------------------------------------------
    # Compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Optional[Union[StateCheckContext, Dict[str, Any]]] = None,
        require_user_workspace: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS context.

        Every user-specific verification task should include user_id and
        workspace_id to prevent mixing audit logs, memory, task history, or
        dashboard data between tenants.
        """

        require_context = self.strict_context if require_user_workspace is None else require_user_workspace

        normalized = self._normalize_context(context)

        missing: List[str] = []
        if require_context:
            if not normalized.get("user_id"):
                missing.append("user_id")
            if not normalized.get("workspace_id"):
                missing.append("workspace_id")

        if missing:
            return self._error_result(
                message="Task context validation failed.",
                code="MISSING_CONTEXT",
                details={
                    "missing": missing,
                    "required": ["user_id", "workspace_id"],
                },
                metadata={
                    "agent": self.agent_id,
                    "hook": "_validate_task_context",
                },
            )

        return self._safe_result(
            message="Task context validated.",
            data={"context": normalized},
            metadata={
                "agent": self.agent_id,
                "hook": "_validate_task_context",
            },
        )

    def _requires_security_check(
        self,
        check_type: Optional[str] = None,
        target: Any = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Decide whether a state check requires Security Agent approval.

        Current methods are read-only. Security approval is required only for
        potentially sensitive locations or sensitive registry paths.
        """

        options = options or {}
        check_type = (check_type or "").lower().strip()

        sensitive_paths = [
            "/etc/shadow",
            "/etc/sudoers",
            "C:\\Windows\\System32\\config",
            "C:\\Users\\Default\\NTUSER.DAT",
        ]

        target_str = str(target or "")

        if check_type in {"file", "folder"}:
            normalized_target = target_str.replace("/", os.sep).replace("\\", os.sep).lower()
            for path_value in sensitive_paths:
                normalized_sensitive = path_value.replace("/", os.sep).replace("\\", os.sep).lower()
                if normalized_sensitive in normalized_target:
                    return True

        if check_type == "device_setting":
            setting_key = str(options.get("setting_key") or target or "").lower()
            if setting_key in {"registry", "environment_variable"}:
                secret_like = str(options.get("name") or options.get("path") or "").lower()
                sensitive_terms = ["password", "secret", "token", "credential", "private_key", "api_key"]
                if any(term in secret_like for term in sensitive_terms):
                    return True

        return False

    def _request_security_approval(
        self,
        action: str,
        context: Optional[Union[StateCheckContext, Dict[str, Any]]] = None,
        reason: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Security Agent approval hook.

        This fallback does not contact the real Security Agent directly.
        Future integration can override or monkey-patch this method.
        """

        normalized_context = self._normalize_context(context)

        return self._safe_result(
            message="Security approval hook prepared. No external Security Agent connected in this file.",
            data={
                "approval_required": True,
                "approved": False,
                "action": action,
                "reason": reason,
                "details": details or {},
            },
            metadata={
                "agent": self.agent_id,
                "hook": "_request_security_approval",
                "context": self._safe_context_for_metadata(normalized_context),
            },
        )

    def _prepare_verification_payload(
        self,
        check_type: str,
        target: Any,
        result: Dict[str, Any],
        context: Optional[Union[StateCheckContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare normalized payload for Verification Agent reports.
        """

        normalized_context = self._normalize_context(context)

        return {
            "agent": self.agent_id,
            "agent_name": self.agent_name,
            "verification_type": "state_check",
            "check_type": check_type,
            "target": self._redact_if_sensitive(target),
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "data": result.get("data", {}),
            "error": result.get("error"),
            "context": self._safe_context_for_metadata(normalized_context),
            "timestamp": self._utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        check_type: str,
        target: Any,
        result: Dict[str, Any],
        context: Optional[Union[StateCheckContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare safe payload for Memory Agent.

        Avoid storing secrets, private file contents, or sensitive local details.
        """

        normalized_context = self._normalize_context(context)

        return {
            "memory_type": "verification_state_check",
            "agent": self.agent_id,
            "check_type": check_type,
            "target_summary": self._summarize_target(target),
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "context": self._safe_context_for_metadata(normalized_context),
            "created_at": self._utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Optional[Dict[str, Any]] = None,
        context: Optional[Union[StateCheckContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Emit agent event hook.

        This fallback logs the event locally. Future event bus integration can
        override this method.
        """

        normalized_context = self._normalize_context(context)

        event = {
            "event_name": event_name,
            "agent": self.agent_id,
            "payload": payload or {},
            "context": self._safe_context_for_metadata(normalized_context),
            "timestamp": self._utc_now_iso(),
        }

        self.logger.info("Agent event emitted: %s", json.dumps(event, default=str))

        return self._safe_result(
            message="Agent event emitted.",
            data={"event": event},
            metadata={"agent": self.agent_id, "hook": "_emit_agent_event"},
        )

    def _log_audit_event(
        self,
        action: str,
        context: Optional[Union[StateCheckContext, Dict[str, Any]]] = None,
        status: str = "success",
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Audit event hook.

        Keeps audit-safe metadata only. Future AuditLog service can override.
        """

        normalized_context = self._normalize_context(context)

        audit_event = {
            "action": action,
            "status": status,
            "agent": self.agent_id,
            "details": details or {},
            "context": self._safe_context_for_metadata(normalized_context),
            "timestamp": self._utc_now_iso(),
        }

        self.logger.info("Audit event: %s", json.dumps(audit_event, default=str))

        return self._safe_result(
            message="Audit event logged.",
            data={"audit_event": audit_event},
            metadata={"agent": self.agent_id, "hook": "_log_audit_event"},
        )

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success response.
        """

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "agent": self.agent_id,
                "agent_name": self.agent_name,
                "version": self.VERSION,
                "timestamp": self._utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        code: str = "STATE_CHECK_ERROR",
        details: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error response.
        """

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": {
                "code": code,
                "details": details or {},
            },
            "metadata": {
                "agent": self.agent_id,
                "agent_name": self.agent_name,
                "version": self.VERSION,
                "timestamp": self._utc_now_iso(),
                **(metadata or {}),
            },
        }

    # -----------------------------------------------------------------------
    # MasterAgent / Router entrypoint
    # -----------------------------------------------------------------------

    async def run(
        self,
        task: Optional[Dict[str, Any]] = None,
        context: Optional[Union[StateCheckContext, Dict[str, Any]]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Generic router-compatible async entrypoint.

        Expected task examples:
            {
                "check_type": "process",
                "target": "chrome",
                "expected": {"expected": true, "operator": "equals"},
                "options": {"match_mode": "contains"}
            }

            {
                "checks": [
                    {"check_type": "file", "target": "C:/app/.env"},
                    {"check_type": "port", "target": 8000}
                ]
            }
        """

        task = task or kwargs

        if not isinstance(task, dict):
            return self._error_result(
                message="Invalid task. Expected dictionary.",
                code="INVALID_TASK",
                details={"task_type": type(task).__name__},
            )

        if "checks" in task:
            checks = task.get("checks")
            return self.check_many(checks=checks, context=context or task.get("context"))

        check_type = task.get("check_type") or task.get("type")
        target = task.get("target")
        options = task.get("options") or {}

        expected_raw = task.get("expected")
        expected = self._normalize_expectation(expected_raw)

        return self.check_state(
            check_type=check_type,
            target=target,
            expected=expected,
            options=options,
            context=context or task.get("context"),
        )

    # -----------------------------------------------------------------------
    # Public unified methods
    # -----------------------------------------------------------------------

    def check_state(
        self,
        check_type: str,
        target: Any,
        expected: Optional[Union[StateExpectation, Dict[str, Any], Any]] = None,
        options: Optional[Dict[str, Any]] = None,
        context: Optional[Union[StateCheckContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Unified state check dispatcher.
        """

        started = time.time()
        options = options or {}
        check_type_normalized = str(check_type or "").strip().lower()

        context_validation = self._validate_task_context(context)
        if not context_validation["success"]:
            return context_validation

        if check_type_normalized not in self.SUPPORTED_CHECK_TYPES:
            return self._error_result(
                message="Unsupported state check type.",
                code="UNSUPPORTED_CHECK_TYPE",
                details={
                    "check_type": check_type,
                    "supported": sorted(self.SUPPORTED_CHECK_TYPES),
                },
            )

        if target is None or target == "":
            return self._error_result(
                message="State check target is required.",
                code="MISSING_TARGET",
                details={"check_type": check_type_normalized},
            )

        if self._requires_security_check(check_type_normalized, target, options):
            approval = self._request_security_approval(
                action=f"state_check:{check_type_normalized}",
                context=context,
                reason="Sensitive state check target detected.",
                details={"target": self._redact_if_sensitive(target), "options": self._redact_dict(options)},
            )

            if not approval.get("data", {}).get("approved", False):
                return self._error_result(
                    message="Security approval is required before this state check can run.",
                    code="SECURITY_APPROVAL_REQUIRED",
                    details=approval.get("data", {}),
                )

        try:
            if check_type_normalized == "process":
                result = self.check_process_state(target, expected=expected, options=options, context=context)
            elif check_type_normalized == "window":
                result = self.check_window_state(target, expected=expected, options=options, context=context)
            elif check_type_normalized == "file":
                result = self.check_file_state(target, expected=expected, options=options, context=context)
            elif check_type_normalized == "folder":
                result = self.check_folder_state(target, expected=expected, options=options, context=context)
            elif check_type_normalized == "service":
                result = self.check_service_state(target, expected=expected, options=options, context=context)
            elif check_type_normalized == "port":
                result = self.check_port_state(target, expected=expected, options=options, context=context)
            elif check_type_normalized == "device_setting":
                result = self.check_device_setting_state(target, expected=expected, options=options, context=context)
            else:
                result = self._error_result(
                    message="Unhandled check type.",
                    code="UNHANDLED_CHECK_TYPE",
                    details={"check_type": check_type_normalized},
                )

            result.setdefault("metadata", {})
            result["metadata"]["duration_ms"] = round((time.time() - started) * 1000, 3)

            verification_payload = self._prepare_verification_payload(
                check_type=check_type_normalized,
                target=target,
                result=result,
                context=context,
            )

            memory_payload = self._prepare_memory_payload(
                check_type=check_type_normalized,
                target=target,
                result=result,
                context=context,
            )

            result["metadata"]["verification_payload"] = verification_payload
            result["metadata"]["memory_payload"] = memory_payload

            self._log_audit_event(
                action=f"state_check:{check_type_normalized}",
                context=context,
                status="success" if result.get("success") else "failed",
                details={
                    "target": self._summarize_target(target),
                    "result_message": result.get("message"),
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("State check failed.")
            return self._error_result(
                message="State check failed due to an unexpected error.",
                code="UNEXPECTED_STATE_CHECK_ERROR",
                details={
                    "check_type": check_type_normalized,
                    "target": self._redact_if_sensitive(target),
                    "error": str(exc),
                },
            )

    def check_many(
        self,
        checks: Any,
        context: Optional[Union[StateCheckContext, Dict[str, Any]]] = None,
        stop_on_failure: bool = False,
    ) -> Dict[str, Any]:
        """
        Run multiple state checks.

        `checks` should be a list of dicts or StateCheckRequest objects.
        """

        context_validation = self._validate_task_context(context)
        if not context_validation["success"]:
            return context_validation

        if not isinstance(checks, list):
            return self._error_result(
                message="Invalid checks input. Expected list.",
                code="INVALID_CHECKS",
                details={"input_type": type(checks).__name__},
            )

        results: List[Dict[str, Any]] = []
        success_count = 0
        failure_count = 0

        for index, raw_check in enumerate(checks):
            request = self._normalize_check_request(raw_check)
            if not request["success"]:
                failure_count += 1
                item_result = self._error_result(
                    message=f"Invalid check at index {index}.",
                    code="INVALID_CHECK_REQUEST",
                    details=request.get("error", {}).get("details", {}),
                )
                results.append(item_result)
                if stop_on_failure:
                    break
                continue

            check_request: StateCheckRequest = request["data"]["request"]

            item_result = self.check_state(
                check_type=check_request.check_type,
                target=check_request.target,
                expected=check_request.expected,
                options=check_request.options,
                context=context,
            )

            results.append(item_result)

            if item_result.get("success"):
                success_count += 1
            else:
                failure_count += 1
                if stop_on_failure:
                    break

        overall_success = failure_count == 0

        return {
            "success": overall_success,
            "message": "All state checks passed." if overall_success else "One or more state checks failed.",
            "data": {
                "total": len(results),
                "success_count": success_count,
                "failure_count": failure_count,
                "results": results,
            },
            "error": None if overall_success else {
                "code": "MULTI_STATE_CHECK_PARTIAL_FAILURE",
                "details": {
                    "failure_count": failure_count,
                },
            },
            "metadata": {
                "agent": self.agent_id,
                "agent_name": self.agent_name,
                "version": self.VERSION,
                "timestamp": self._utc_now_iso(),
            },
        }

    # -----------------------------------------------------------------------
    # Process checks
    # -----------------------------------------------------------------------

    def check_process_state(
        self,
        target: Union[str, int],
        expected: Optional[Union[StateExpectation, Dict[str, Any], Any]] = None,
        options: Optional[Dict[str, Any]] = None,
        context: Optional[Union[StateCheckContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Check whether a process is running.

        target:
            Process name, command substring, or PID.

        options:
            match_mode:
                - exact
                - contains
                - startswith
                - pid
            include_cmdline:
                Include safe command-line summary when psutil exists.
            case_sensitive:
                Default False.
        """

        del context

        options = options or {}
        match_mode = str(options.get("match_mode") or "contains").lower()
        include_cmdline = bool(options.get("include_cmdline", False))
        case_sensitive = bool(options.get("case_sensitive", False))

        processes = self._list_processes(
            include_cmdline=include_cmdline,
            timeout=float(options.get("timeout_seconds", self.default_timeout_seconds)),
        )

        if not processes["success"]:
            return processes

        matched: List[Dict[str, Any]] = []
        target_value = str(target)

        for proc in processes["data"]["processes"]:
            if self._process_matches(
                proc=proc,
                target=target_value,
                match_mode=match_mode,
                case_sensitive=case_sensitive,
            ):
                matched.append(proc)

        actual_state = {
            "running": bool(matched),
            "matched_count": len(matched),
            "matches": matched,
            "target": target,
            "match_mode": match_mode,
        }

        expectation_result = self._evaluate_expected(
            actual=actual_state["running"],
            expected=expected,
            default_expected=True,
        )

        return self._build_check_result(
            check_type="process",
            target=target,
            actual=actual_state,
            expectation_result=expectation_result,
            pass_message="Process state check passed.",
            fail_message="Process state check failed.",
        )

    def _list_processes(
        self,
        include_cmdline: bool = False,
        timeout: float = 3.0,
    ) -> Dict[str, Any]:
        """
        List processes safely.
        """

        if psutil is not None:
            processes: List[Dict[str, Any]] = []

            attrs = ["pid", "name", "status", "username"]
            if include_cmdline:
                attrs.append("cmdline")

            for proc in psutil.process_iter(attrs=attrs):
                try:
                    info = proc.info
                    process_item = {
                        "pid": info.get("pid"),
                        "name": info.get("name"),
                        "status": info.get("status"),
                        "username": self._redact_username(info.get("username")),
                    }

                    if include_cmdline:
                        process_item["cmdline"] = self._safe_cmdline_summary(info.get("cmdline"))

                    processes.append(process_item)
                except Exception:
                    continue

            return self._safe_result(
                message="Processes listed.",
                data={"processes": processes, "source": "psutil"},
            )

        if not self.allow_subprocess_checks:
            return self._error_result(
                message="Process check requires psutil when subprocess checks are disabled.",
                code="PSUTIL_NOT_AVAILABLE",
            )

        try:
            system_name = platform.system().lower()

            if system_name == "windows":
                command = ["tasklist", "/FO", "CSV", "/NH"]
            else:
                command = ["ps", "-eo", "pid=,comm="]

            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )

            processes = self._parse_process_output(completed.stdout, system_name)

            return self._safe_result(
                message="Processes listed using subprocess fallback.",
                data={"processes": processes, "source": "subprocess"},
            )

        except Exception as exc:
            return self._error_result(
                message="Could not list processes.",
                code="PROCESS_LIST_FAILED",
                details={"error": str(exc)},
            )

    def _parse_process_output(self, output: str, system_name: str) -> List[Dict[str, Any]]:
        """
        Parse safe process list output.
        """

        processes: List[Dict[str, Any]] = []

        if system_name == "windows":
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = self._safe_csv_split(line)
                if len(parts) >= 2:
                    name = parts[0].strip('"')
                    pid_raw = parts[1].strip('"')
                    processes.append({
                        "pid": self._safe_int(pid_raw),
                        "name": name,
                        "status": None,
                        "username": None,
                    })
        else:
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                pieces = line.split(maxsplit=1)
                pid = self._safe_int(pieces[0]) if pieces else None
                name = pieces[1] if len(pieces) > 1 else None
                processes.append({
                    "pid": pid,
                    "name": name,
                    "status": None,
                    "username": None,
                })

        return processes

    def _process_matches(
        self,
        proc: Dict[str, Any],
        target: str,
        match_mode: str,
        case_sensitive: bool,
    ) -> bool:
        """
        Match a process by pid/name/cmdline.
        """

        pid = proc.get("pid")
        name = str(proc.get("name") or "")
        cmdline = " ".join(proc.get("cmdline") or []) if isinstance(proc.get("cmdline"), list) else str(proc.get("cmdline") or "")

        if match_mode == "pid":
            return str(pid) == str(target)

        searchable_values = [name, cmdline]

        if not case_sensitive:
            target_cmp = target.lower()
            searchable_values = [value.lower() for value in searchable_values]
        else:
            target_cmp = target

        for value in searchable_values:
            if match_mode == "exact" and value == target_cmp:
                return True
            if match_mode == "startswith" and value.startswith(target_cmp):
                return True
            if match_mode == "contains" and target_cmp in value:
                return True

        return False

    # -----------------------------------------------------------------------
    # Window checks
    # -----------------------------------------------------------------------

    def check_window_state(
        self,
        target: str,
        expected: Optional[Union[StateExpectation, Dict[str, Any], Any]] = None,
        options: Optional[Dict[str, Any]] = None,
        context: Optional[Union[StateCheckContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Check whether a window title is open.

        This is best-effort and platform dependent.

        options:
            match_mode:
                - contains
                - exact
                - startswith
            case_sensitive:
                Default False.
        """

        del context

        options = options or {}
        match_mode = str(options.get("match_mode") or "contains").lower()
        case_sensitive = bool(options.get("case_sensitive", False))

        windows_result = self._list_windows()

        if not windows_result["success"]:
            return windows_result

        windows = windows_result["data"].get("windows", [])
        matched: List[Dict[str, Any]] = []

        target_str = str(target)
        target_cmp = target_str if case_sensitive else target_str.lower()

        for win in windows:
            title = str(win.get("title") or "")
            title_cmp = title if case_sensitive else title.lower()

            is_match = False
            if match_mode == "exact":
                is_match = title_cmp == target_cmp
            elif match_mode == "startswith":
                is_match = title_cmp.startswith(target_cmp)
            else:
                is_match = target_cmp in title_cmp

            if is_match:
                matched.append(win)

        actual_state = {
            "open": bool(matched),
            "matched_count": len(matched),
            "matches": matched,
            "target": target,
            "match_mode": match_mode,
            "source": windows_result["data"].get("source"),
        }

        expectation_result = self._evaluate_expected(
            actual=actual_state["open"],
            expected=expected,
            default_expected=True,
        )

        return self._build_check_result(
            check_type="window",
            target=target,
            actual=actual_state,
            expectation_result=expectation_result,
            pass_message="Window state check passed.",
            fail_message="Window state check failed.",
        )

    def _list_windows(self) -> Dict[str, Any]:
        """
        List visible/open windows using optional libraries or OS fallback.
        """

        system_name = platform.system().lower()

        try:
            import pygetwindow as gw  # type: ignore

            windows = []
            for window in gw.getAllWindows():
                title = getattr(window, "title", "") or ""
                if not title:
                    continue

                windows.append({
                    "title": title,
                    "is_active": bool(getattr(window, "isActive", False)),
                    "is_minimized": bool(getattr(window, "isMinimized", False)),
                    "left": getattr(window, "left", None),
                    "top": getattr(window, "top", None),
                    "width": getattr(window, "width", None),
                    "height": getattr(window, "height", None),
                })

            return self._safe_result(
                message="Windows listed.",
                data={"windows": windows, "source": "pygetwindow"},
            )

        except Exception:
            pass

        if system_name == "windows":
            windows = self._list_windows_win32()
            if windows["success"]:
                return windows

        return self._safe_result(
            message="Window listing is not available on this system without optional dependencies.",
            data={
                "windows": [],
                "source": "unavailable",
                "note": "Install pygetwindow for cross-platform window title checks.",
            },
        )

    def _list_windows_win32(self) -> Dict[str, Any]:
        """
        Windows-only win32gui fallback.
        """

        try:
            import win32gui  # type: ignore

            windows: List[Dict[str, Any]] = []

            def enum_handler(hwnd: int, _: Any) -> None:
                try:
                    if win32gui.IsWindowVisible(hwnd):
                        title = win32gui.GetWindowText(hwnd)
                        if title:
                            rect = win32gui.GetWindowRect(hwnd)
                            windows.append({
                                "title": title,
                                "handle": hwnd,
                                "left": rect[0],
                                "top": rect[1],
                                "width": rect[2] - rect[0],
                                "height": rect[3] - rect[1],
                            })
                except Exception:
                    return

            win32gui.EnumWindows(enum_handler, None)

            return self._safe_result(
                message="Windows listed using win32gui.",
                data={"windows": windows, "source": "win32gui"},
            )

        except Exception as exc:
            return self._error_result(
                message="Could not list windows.",
                code="WINDOW_LIST_FAILED",
                details={"error": str(exc)},
            )

    # -----------------------------------------------------------------------
    # File checks
    # -----------------------------------------------------------------------

    def check_file_state(
        self,
        target: Union[str, Path],
        expected: Optional[Union[StateExpectation, Dict[str, Any], Any]] = None,
        options: Optional[Dict[str, Any]] = None,
        context: Optional[Union[StateCheckContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Check file existence and metadata.

        options:
            must_be_readable:
                Check read permission.
            min_size_bytes:
                Optional minimum file size.
            max_size_bytes:
                Optional maximum file size.
            extension:
                Optional expected extension such as ".json".
            include_hash:
                Disabled by default. Hashing may be costly and is intentionally
                not implemented in this broad state checker.
        """

        del context

        options = options or {}
        path = Path(str(target)).expanduser()

        exists = path.exists()
        is_file = path.is_file() if exists else False

        info: Dict[str, Any] = {
            "path": str(path),
            "exists": exists,
            "is_file": is_file,
            "is_folder": path.is_dir() if exists else False,
            "name": path.name,
            "suffix": path.suffix,
            "parent": str(path.parent),
        }

        if exists:
            try:
                stat = path.stat()
                info.update({
                    "size_bytes": stat.st_size,
                    "created_at": self._timestamp_to_iso(getattr(stat, "st_ctime", None)),
                    "modified_at": self._timestamp_to_iso(getattr(stat, "st_mtime", None)),
                    "accessed_at": self._timestamp_to_iso(getattr(stat, "st_atime", None)),
                    "readable": os.access(path, os.R_OK),
                    "writable": os.access(path, os.W_OK),
                    "executable": os.access(path, os.X_OK),
                })
            except Exception as exc:
                info["stat_error"] = str(exc)

        validation_errors: List[str] = []

        if exists and not is_file:
            validation_errors.append("Target exists but is not a file.")

        if options.get("must_be_readable") and exists and not os.access(path, os.R_OK):
            validation_errors.append("File is not readable.")

        min_size = options.get("min_size_bytes")
        if min_size is not None and exists and info.get("size_bytes", 0) < int(min_size):
            validation_errors.append(f"File size is less than min_size_bytes={min_size}.")

        max_size = options.get("max_size_bytes")
        if max_size is not None and exists and info.get("size_bytes", 0) > int(max_size):
            validation_errors.append(f"File size is greater than max_size_bytes={max_size}.")

        expected_extension = options.get("extension")
        if expected_extension and str(info.get("suffix", "")).lower() != str(expected_extension).lower():
            validation_errors.append(f"File extension does not match expected extension {expected_extension}.")

        actual_value = exists and is_file and not validation_errors

        actual_state = {
            **info,
            "valid": actual_value,
            "validation_errors": validation_errors,
        }

        expectation_result = self._evaluate_expected(
            actual=actual_state["exists"],
            expected=expected,
            default_expected=True,
        )

        if validation_errors and expectation_result["passed"]:
            expectation_result["passed"] = False
            expectation_result["reason"] = "; ".join(validation_errors)

        return self._build_check_result(
            check_type="file",
            target=str(target),
            actual=actual_state,
            expectation_result=expectation_result,
            pass_message="File state check passed.",
            fail_message="File state check failed.",
        )

    # -----------------------------------------------------------------------
    # Folder checks
    # -----------------------------------------------------------------------

    def check_folder_state(
        self,
        target: Union[str, Path],
        expected: Optional[Union[StateExpectation, Dict[str, Any], Any]] = None,
        options: Optional[Dict[str, Any]] = None,
        context: Optional[Union[StateCheckContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Check folder existence and metadata.

        options:
            must_be_readable:
                Check read permission.
            min_items:
                Minimum number of direct children.
            max_items:
                Maximum number of direct children.
            include_children:
                Include direct child names.
            child_limit:
                Max child names returned. Default 50.
        """

        del context

        options = options or {}
        path = Path(str(target)).expanduser()

        exists = path.exists()
        is_folder = path.is_dir() if exists else False

        info: Dict[str, Any] = {
            "path": str(path),
            "exists": exists,
            "is_folder": is_folder,
            "is_file": path.is_file() if exists else False,
            "name": path.name,
            "parent": str(path.parent),
        }

        children: List[str] = []
        child_count: Optional[int] = None

        if exists:
            try:
                stat = path.stat()
                info.update({
                    "created_at": self._timestamp_to_iso(getattr(stat, "st_ctime", None)),
                    "modified_at": self._timestamp_to_iso(getattr(stat, "st_mtime", None)),
                    "accessed_at": self._timestamp_to_iso(getattr(stat, "st_atime", None)),
                    "readable": os.access(path, os.R_OK),
                    "writable": os.access(path, os.W_OK),
                    "executable": os.access(path, os.X_OK),
                })
            except Exception as exc:
                info["stat_error"] = str(exc)

            if is_folder and os.access(path, os.R_OK):
                try:
                    child_limit = int(options.get("child_limit", 50))
                    all_children = list(path.iterdir())
                    child_count = len(all_children)
                    if options.get("include_children"):
                        children = [child.name for child in all_children[:child_limit]]
                except Exception as exc:
                    info["children_error"] = str(exc)

        validation_errors: List[str] = []

        if exists and not is_folder:
            validation_errors.append("Target exists but is not a folder.")

        if options.get("must_be_readable") and exists and not os.access(path, os.R_OK):
            validation_errors.append("Folder is not readable.")

        min_items = options.get("min_items")
        if min_items is not None and child_count is not None and child_count < int(min_items):
            validation_errors.append(f"Folder item count is less than min_items={min_items}.")

        max_items = options.get("max_items")
        if max_items is not None and child_count is not None and child_count > int(max_items):
            validation_errors.append(f"Folder item count is greater than max_items={max_items}.")

        actual_state = {
            **info,
            "child_count": child_count,
            "children": children,
            "valid": exists and is_folder and not validation_errors,
            "validation_errors": validation_errors,
        }

        expectation_result = self._evaluate_expected(
            actual=actual_state["exists"],
            expected=expected,
            default_expected=True,
        )

        if validation_errors and expectation_result["passed"]:
            expectation_result["passed"] = False
            expectation_result["reason"] = "; ".join(validation_errors)

        return self._build_check_result(
            check_type="folder",
            target=str(target),
            actual=actual_state,
            expectation_result=expectation_result,
            pass_message="Folder state check passed.",
            fail_message="Folder state check failed.",
        )

    # -----------------------------------------------------------------------
    # Service checks
    # -----------------------------------------------------------------------

    def check_service_state(
        self,
        target: str,
        expected: Optional[Union[StateExpectation, Dict[str, Any], Any]] = None,
        options: Optional[Dict[str, Any]] = None,
        context: Optional[Union[StateCheckContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Check operating system service state.

        target:
            Service name.

        options:
            match_mode:
                exact | contains
            timeout_seconds:
                Subprocess timeout for fallback systemctl/sc query.
        """

        del context

        options = options or {}
        service_name = str(target)
        system_name = platform.system().lower()

        if system_name == "windows":
            service_result = self._check_windows_service(service_name, options)
        elif system_name in {"linux", "darwin"}:
            service_result = self._check_unix_service(service_name, options)
        else:
            service_result = self._error_result(
                message="Service checks are not supported on this platform.",
                code="SERVICE_PLATFORM_UNSUPPORTED",
                details={"platform": platform.system()},
            )

        if not service_result["success"]:
            return service_result

        service_data = service_result["data"]
        actual_status = service_data.get("status") or service_data.get("state") or "unknown"

        expectation_result = self._evaluate_expected(
            actual=actual_status,
            expected=expected,
            default_expected="running",
        )

        return self._build_check_result(
            check_type="service",
            target=target,
            actual=service_data,
            expectation_result=expectation_result,
            pass_message="Service state check passed.",
            fail_message="Service state check failed.",
        )

    def _check_windows_service(self, service_name: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Windows service check using psutil or sc query fallback.
        """

        match_mode = str(options.get("match_mode") or "exact").lower()

        if psutil is not None:
            try:
                matches: List[Dict[str, Any]] = []

                for service in psutil.win_service_iter():  # type: ignore[attr-defined]
                    try:
                        svc = service.as_dict()
                        name = str(svc.get("name") or "")
                        display_name = str(svc.get("display_name") or "")

                        if self._simple_match(service_name, name, match_mode) or self._simple_match(service_name, display_name, match_mode):
                            matches.append({
                                "name": name,
                                "display_name": display_name,
                                "status": svc.get("status"),
                                "start_type": svc.get("start_type"),
                                "pid": svc.get("pid"),
                                "source": "psutil",
                            })
                    except Exception:
                        continue

                selected = matches[0] if matches else {
                    "name": service_name,
                    "status": "not_found",
                    "source": "psutil",
                }

                selected["found"] = bool(matches)
                selected["matched_count"] = len(matches)
                selected["matches"] = matches

                return self._safe_result(
                    message="Windows service checked.",
                    data=selected,
                )

            except Exception:
                pass

        if not self.allow_subprocess_checks:
            return self._error_result(
                message="Windows service check requires psutil when subprocess checks are disabled.",
                code="PSUTIL_NOT_AVAILABLE",
            )

        try:
            completed = subprocess.run(
                ["sc", "query", service_name],
                capture_output=True,
                text=True,
                timeout=float(options.get("timeout_seconds", self.default_timeout_seconds)),
                check=False,
            )

            output = completed.stdout + "\n" + completed.stderr
            status = "not_found"
            if "RUNNING" in output.upper():
                status = "running"
            elif "STOPPED" in output.upper():
                status = "stopped"
            elif completed.returncode == 0:
                status = "unknown"

            return self._safe_result(
                message="Windows service checked using sc query.",
                data={
                    "name": service_name,
                    "status": status,
                    "found": status != "not_found",
                    "source": "sc",
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Windows service check failed.",
                code="WINDOWS_SERVICE_CHECK_FAILED",
                details={"error": str(exc)},
            )

    def _check_unix_service(self, service_name: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Linux/macOS service check.

        Linux:
            Uses systemctl if available.

        macOS:
            Uses launchctl list best-effort.
        """

        if not self.allow_subprocess_checks:
            return self._error_result(
                message="Service check requires subprocess fallback on this platform.",
                code="SUBPROCESS_DISABLED",
            )

        timeout = float(options.get("timeout_seconds", self.default_timeout_seconds))
        system_name = platform.system().lower()

        if system_name == "linux":
            try:
                completed = subprocess.run(
                    ["systemctl", "is-active", service_name],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )

                status = completed.stdout.strip() or completed.stderr.strip() or "unknown"
                found = status not in {"unknown", "not-found", "inactive failed"}

                return self._safe_result(
                    message="Linux service checked using systemctl.",
                    data={
                        "name": service_name,
                        "status": status,
                        "found": found,
                        "returncode": completed.returncode,
                        "source": "systemctl",
                    },
                )

            except FileNotFoundError:
                return self._safe_result(
                    message="systemctl is not available.",
                    data={
                        "name": service_name,
                        "status": "unknown",
                        "found": False,
                        "source": "systemctl_unavailable",
                    },
                )
            except Exception as exc:
                return self._error_result(
                    message="Linux service check failed.",
                    code="LINUX_SERVICE_CHECK_FAILED",
                    details={"error": str(exc)},
                )

        if system_name == "darwin":
            try:
                completed = subprocess.run(
                    ["launchctl", "list"],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )

                output = completed.stdout
                found = service_name.lower() in output.lower()
                status = "running" if found else "not_found"

                return self._safe_result(
                    message="macOS service checked using launchctl.",
                    data={
                        "name": service_name,
                        "status": status,
                        "found": found,
                        "source": "launchctl",
                    },
                )

            except Exception as exc:
                return self._error_result(
                    message="macOS service check failed.",
                    code="MACOS_SERVICE_CHECK_FAILED",
                    details={"error": str(exc)},
                )

        return self._error_result(
            message="Unsupported Unix-like platform.",
            code="UNSUPPORTED_UNIX_PLATFORM",
            details={"platform": system_name},
        )

    # -----------------------------------------------------------------------
    # Port checks
    # -----------------------------------------------------------------------

    def check_port_state(
        self,
        target: Union[int, str],
        expected: Optional[Union[StateExpectation, Dict[str, Any], Any]] = None,
        options: Optional[Dict[str, Any]] = None,
        context: Optional[Union[StateCheckContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Check TCP port state.

        target:
            Port number.

        options:
            host:
                Default 127.0.0.1.
            timeout_seconds:
                Socket timeout.
            mode:
                connect | listening
                - connect checks whether host:port accepts connection.
                - listening checks local listening ports with psutil when available.
            protocol:
                tcp only for now.
        """

        del context

        options = options or {}
        port = self._safe_int(target)

        if port is None or port < 1 or port > 65535:
            return self._error_result(
                message="Invalid port number.",
                code="INVALID_PORT",
                details={"target": target},
            )

        host = str(options.get("host") or "127.0.0.1")
        timeout = float(options.get("timeout_seconds", self.default_timeout_seconds))
        mode = str(options.get("mode") or "connect").lower()

        if mode == "listening":
            actual_state = self._check_listening_port(port)
        else:
            actual_state = self._check_connect_port(host, port, timeout)

        actual_state.update({
            "host": host,
            "port": port,
            "mode": mode,
            "protocol": "tcp",
        })

        default_expected = True
        expectation_result = self._evaluate_expected(
            actual=actual_state.get("open") or actual_state.get("listening"),
            expected=expected,
            default_expected=default_expected,
        )

        return self._build_check_result(
            check_type="port",
            target=target,
            actual=actual_state,
            expectation_result=expectation_result,
            pass_message="Port state check passed.",
            fail_message="Port state check failed.",
        )

    def _check_connect_port(self, host: str, port: int, timeout: float) -> Dict[str, Any]:
        """
        Check whether TCP connection can be established.
        """

        started = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            result = sock.connect_ex((host, port))
            open_state = result == 0
            return {
                "open": open_state,
                "connect_ex_code": result,
                "latency_ms": round((time.time() - started) * 1000, 3),
                "source": "socket.connect_ex",
            }
        except Exception as exc:
            return {
                "open": False,
                "error": str(exc),
                "latency_ms": round((time.time() - started) * 1000, 3),
                "source": "socket.connect_ex",
            }
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _check_listening_port(self, port: int) -> Dict[str, Any]:
        """
        Check local listening port with psutil.
        """

        if psutil is None:
            return {
                "listening": False,
                "source": "psutil_unavailable",
                "note": "Install psutil for listening-port checks.",
            }

        matches: List[Dict[str, Any]] = []

        try:
            for conn in psutil.net_connections(kind="inet"):
                try:
                    local_address = conn.laddr
                    conn_port = getattr(local_address, "port", None)
                    status = getattr(conn, "status", None)

                    if conn_port == port and str(status).upper() == "LISTEN":
                        matches.append({
                            "pid": conn.pid,
                            "local_ip": getattr(local_address, "ip", None),
                            "local_port": conn_port,
                            "status": status,
                        })
                except Exception:
                    continue

            return {
                "listening": bool(matches),
                "matched_count": len(matches),
                "matches": matches,
                "source": "psutil.net_connections",
            }

        except Exception as exc:
            return {
                "listening": False,
                "error": str(exc),
                "source": "psutil.net_connections",
            }

    # -----------------------------------------------------------------------
    # Device/system setting checks
    # -----------------------------------------------------------------------

    def check_device_setting_state(
        self,
        target: str,
        expected: Optional[Union[StateExpectation, Dict[str, Any], Any]] = None,
        options: Optional[Dict[str, Any]] = None,
        context: Optional[Union[StateCheckContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Check safe device/system setting state.

        Supported target values:
            - platform
            - system
            - release
            - version
            - machine
            - processor
            - python_version
            - hostname
            - timezone
            - cwd
            - home
            - environment_variable
            - path_exists

        options for environment_variable:
            name:
                Environment variable name.
            redact:
                Default True.

        options for path_exists:
            path:
                Path to check.
        """

        del context

        options = options or {}
        setting_key = str(target or "").strip().lower()

        if setting_key not in self.SAFE_DEVICE_SETTINGS:
            return self._error_result(
                message="Unsupported or unsafe device setting check.",
                code="UNSUPPORTED_DEVICE_SETTING",
                details={
                    "setting_key": setting_key,
                    "supported": sorted(self.SAFE_DEVICE_SETTINGS),
                },
            )

        actual_value: Any
        data: Dict[str, Any] = {
            "setting_key": setting_key,
            "source": "platform/os",
        }

        try:
            if setting_key == "platform":
                actual_value = platform.platform()
            elif setting_key == "system":
                actual_value = platform.system()
            elif setting_key == "release":
                actual_value = platform.release()
            elif setting_key == "version":
                actual_value = platform.version()
            elif setting_key == "machine":
                actual_value = platform.machine()
            elif setting_key == "processor":
                actual_value = platform.processor()
            elif setting_key == "python_version":
                actual_value = platform.python_version()
            elif setting_key == "hostname":
                actual_value = socket.gethostname()
            elif setting_key == "timezone":
                actual_value = time.tzname
            elif setting_key == "cwd":
                actual_value = os.getcwd()
            elif setting_key == "home":
                actual_value = str(Path.home())
            elif setting_key == "environment_variable":
                env_name = str(options.get("name") or "")
                if not env_name:
                    return self._error_result(
                        message="Environment variable name is required.",
                        code="MISSING_ENVIRONMENT_VARIABLE_NAME",
                    )

                raw_value = os.environ.get(env_name)
                redact = bool(options.get("redact", True))

                actual_value = raw_value if not redact else self._redact_if_sensitive(raw_value)
                data["environment_variable"] = env_name
                data["exists"] = raw_value is not None

            elif setting_key == "path_exists":
                path_value = str(options.get("path") or "")
                if not path_value:
                    return self._error_result(
                        message="Path is required for path_exists setting check.",
                        code="MISSING_PATH",
                    )

                path = Path(path_value).expanduser()
                actual_value = path.exists()
                data["path"] = str(path)
                data["is_file"] = path.is_file() if path.exists() else False
                data["is_folder"] = path.is_dir() if path.exists() else False

            else:
                actual_value = None

            data["value"] = actual_value

            expectation_result = self._evaluate_expected(
                actual=actual_value,
                expected=expected,
                default_expected=actual_value,
            )

            return self._build_check_result(
                check_type="device_setting",
                target=target,
                actual=data,
                expectation_result=expectation_result,
                pass_message="Device setting state check passed.",
                fail_message="Device setting state check failed.",
            )

        except Exception as exc:
            return self._error_result(
                message="Device setting check failed.",
                code="DEVICE_SETTING_CHECK_FAILED",
                details={"setting_key": setting_key, "error": str(exc)},
            )

    # -----------------------------------------------------------------------
    # Result builders and expectation evaluation
    # -----------------------------------------------------------------------

    def _build_check_result(
        self,
        check_type: str,
        target: Any,
        actual: Dict[str, Any],
        expectation_result: Dict[str, Any],
        pass_message: str,
        fail_message: str,
    ) -> Dict[str, Any]:
        """
        Build final check result.
        """

        passed = bool(expectation_result.get("passed"))

        result_data = {
            "check_type": check_type,
            "target": self._redact_if_sensitive(target),
            "actual": actual,
            "expectation": expectation_result,
            "passed": passed,
        }

        if passed:
            return self._safe_result(
                message=pass_message,
                data=result_data,
                metadata={"check_type": check_type},
            )

        return {
            "success": False,
            "message": fail_message,
            "data": result_data,
            "error": {
                "code": "STATE_EXPECTATION_FAILED",
                "details": {
                    "reason": expectation_result.get("reason"),
                    "actual": expectation_result.get("actual"),
                    "expected": expectation_result.get("expected"),
                    "operator": expectation_result.get("operator"),
                },
            },
            "metadata": {
                "agent": self.agent_id,
                "agent_name": self.agent_name,
                "version": self.VERSION,
                "timestamp": self._utc_now_iso(),
                "check_type": check_type,
            },
        }

    def _evaluate_expected(
        self,
        actual: Any,
        expected: Optional[Union[StateExpectation, Dict[str, Any], Any]] = None,
        default_expected: Any = True,
    ) -> Dict[str, Any]:
        """
        Evaluate actual value against expected value.

        If expected is None, compares actual against default_expected.
        """

        expectation = self._normalize_expectation(expected)
        if expectation is None:
            expectation = StateExpectation(expected=default_expected, operator="equals")

        operator = str(expectation.operator or "equals").lower().strip()
        expected_value = expectation.expected

        try:
            if operator == "equals":
                passed = actual == expected_value
            elif operator == "not_equals":
                passed = actual != expected_value
            elif operator == "contains":
                passed = str(expected_value).lower() in str(actual).lower()
            elif operator == "not_contains":
                passed = str(expected_value).lower() not in str(actual).lower()
            elif operator == "greater_than":
                passed = float(actual) > float(expected_value)
            elif operator == "greater_or_equal":
                passed = float(actual) >= float(expected_value)
            elif operator == "less_than":
                passed = float(actual) < float(expected_value)
            elif operator == "less_or_equal":
                passed = float(actual) <= float(expected_value)
            elif operator == "exists":
                passed = actual is not None
            else:
                return {
                    "passed": False,
                    "actual": actual,
                    "expected": expected_value,
                    "operator": operator,
                    "reason": f"Unsupported expectation operator: {operator}",
                }

            return {
                "passed": bool(passed),
                "actual": actual,
                "expected": expected_value,
                "operator": operator,
                "reason": "Expectation matched." if passed else "Expectation did not match.",
            }

        except Exception as exc:
            return {
                "passed": False,
                "actual": actual,
                "expected": expected_value,
                "operator": operator,
                "reason": f"Expectation evaluation failed: {exc}",
            }

    # -----------------------------------------------------------------------
    # Normalizers
    # -----------------------------------------------------------------------

    def _normalize_context(
        self,
        context: Optional[Union[StateCheckContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Normalize context to dict.
        """

        if context is None:
            return {}

        if isinstance(context, StateCheckContext):
            return asdict(context)

        if isinstance(context, dict):
            return dict(context)

        return {"raw_context": str(context)}

    def _normalize_expectation(
        self,
        expected: Optional[Union[StateExpectation, Dict[str, Any], Any]],
    ) -> Optional[StateExpectation]:
        """
        Normalize expectation.
        """

        if expected is None:
            return None

        if isinstance(expected, StateExpectation):
            return expected

        if isinstance(expected, dict):
            return StateExpectation(
                expected=expected.get("expected", expected.get("value")),
                operator=expected.get("operator", "equals"),
            )

        return StateExpectation(expected=expected, operator="equals")

    def _normalize_check_request(self, raw_check: Any) -> Dict[str, Any]:
        """
        Normalize one check request.
        """

        if isinstance(raw_check, StateCheckRequest):
            return self._safe_result(
                message="Check request normalized.",
                data={"request": raw_check},
            )

        if not isinstance(raw_check, dict):
            return self._error_result(
                message="Invalid check request.",
                code="INVALID_CHECK_REQUEST",
                details={"input_type": type(raw_check).__name__},
            )

        check_type = raw_check.get("check_type") or raw_check.get("type")
        target = raw_check.get("target")

        if not check_type:
            return self._error_result(
                message="check_type is required.",
                code="MISSING_CHECK_TYPE",
            )

        if target is None or target == "":
            return self._error_result(
                message="target is required.",
                code="MISSING_TARGET",
            )

        request = StateCheckRequest(
            check_type=str(check_type),
            target=target,
            expected=self._normalize_expectation(raw_check.get("expected")),
            options=raw_check.get("options") or {},
        )

        return self._safe_result(
            message="Check request normalized.",
            data={"request": request},
        )

    # -----------------------------------------------------------------------
    # Utility helpers
    # -----------------------------------------------------------------------

    def _utc_now_iso(self) -> str:
        """
        Current UTC timestamp.
        """

        return datetime.now(timezone.utc).isoformat()

    def _timestamp_to_iso(self, timestamp: Optional[float]) -> Optional[str]:
        """
        Convert timestamp to ISO string.
        """

        if timestamp is None:
            return None

        try:
            return datetime.fromtimestamp(float(timestamp), tz=timezone.utc).isoformat()
        except Exception:
            return None

    def _safe_context_for_metadata(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Keep only SaaS-safe context values.
        """

        allowed = {
            "user_id",
            "workspace_id",
            "request_id",
            "task_id",
            "source_agent",
        }

        safe = {key: context.get(key) for key in allowed if context.get(key) is not None}

        metadata = context.get("metadata")
        if isinstance(metadata, dict):
            safe["metadata_keys"] = sorted(metadata.keys())

        return safe

    def _redact_if_sensitive(self, value: Any) -> Any:
        """
        Redact likely sensitive values.
        """

        if value is None:
            return None

        value_str = str(value)
        lower_value = value_str.lower()

        sensitive_terms = [
            "password",
            "secret",
            "token",
            "private_key",
            "api_key",
            "credential",
            "authorization",
            "bearer ",
        ]

        if any(term in lower_value for term in sensitive_terms):
            return "***REDACTED***"

        if len(value_str) > 500:
            return value_str[:250] + "...[TRUNCATED]"

        return value

    def _redact_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact sensitive dict values.
        """

        safe: Dict[str, Any] = {}

        for key, value in data.items():
            key_lower = str(key).lower()
            if any(term in key_lower for term in ["password", "secret", "token", "api_key", "private_key"]):
                safe[key] = "***REDACTED***"
            else:
                safe[key] = self._redact_if_sensitive(value)

        return safe

    def _summarize_target(self, target: Any) -> str:
        """
        Safe target summary for Memory/Audit payloads.
        """

        if target is None:
            return "none"

        target_str = str(target)
        if len(target_str) > 120:
            target_str = target_str[:117] + "..."

        return str(self._redact_if_sensitive(target_str))

    def _redact_username(self, username: Any) -> Optional[str]:
        """
        Redact username partially to avoid storing private local account details.
        """

        if username is None:
            return None

        username_str = str(username)

        if "\\" in username_str:
            domain, user = username_str.rsplit("\\", 1)
            return f"{domain}\\{self._mask_middle(user)}"

        return self._mask_middle(username_str)

    def _mask_middle(self, value: str) -> str:
        """
        Mask middle characters.
        """

        if len(value) <= 2:
            return "*" * len(value)

        return value[0] + ("*" * max(1, len(value) - 2)) + value[-1]

    def _safe_cmdline_summary(self, cmdline: Any) -> List[str]:
        """
        Safely summarize command line without exposing secrets.
        """

        if not isinstance(cmdline, list):
            return []

        safe_parts: List[str] = []
        sensitive_next = False

        for part in cmdline[:20]:
            part_str = str(part)

            if sensitive_next:
                safe_parts.append("***REDACTED***")
                sensitive_next = False
                continue

            lower = part_str.lower()
            if lower in {"--password", "-p", "--token", "--secret", "--api-key"}:
                safe_parts.append(part_str)
                sensitive_next = True
                continue

            safe_parts.append(str(self._redact_if_sensitive(part_str)))

        if len(cmdline) > 20:
            safe_parts.append("...[TRUNCATED]")

        return safe_parts

    def _safe_csv_split(self, line: str) -> List[str]:
        """
        Lightweight CSV split for tasklist fallback.
        """

        try:
            import csv
            return next(csv.reader([line]))
        except Exception:
            return line.split(",")

    def _safe_int(self, value: Any) -> Optional[int]:
        """
        Convert to int safely.
        """

        try:
            return int(str(value).strip())
        except Exception:
            return None

    def _simple_match(self, expected: str, actual: str, match_mode: str = "exact") -> bool:
        """
        Simple case-insensitive match.
        """

        expected_cmp = str(expected or "").lower()
        actual_cmp = str(actual or "").lower()

        if match_mode == "contains":
            return expected_cmp in actual_cmp

        if match_mode == "startswith":
            return actual_cmp.startswith(expected_cmp)

        return expected_cmp == actual_cmp

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Agent Registry / Loader discovery metadata.
        """

        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "class_name": self.__class__.__name__,
            "module": "agents.verification_agent.state_checker",
            "version": self.VERSION,
            "type": "verification_helper",
            "capabilities": self.capabilities,
            "supported_check_types": sorted(self.SUPPORTED_CHECK_TYPES),
            "requires_security_agent": False,
            "read_only": True,
            "safe_to_import": True,
            "saas_context_required": self.strict_context,
        }


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_state_checker(**kwargs: Any) -> StateChecker:
    """
    Factory used by Agent Loader / Registry.
    """

    return StateChecker(**kwargs)


# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------

__all__ = [
    "StateChecker",
    "StateCheckContext",
    "StateExpectation",
    "StateCheckRequest",
    "create_state_checker",
]


# ---------------------------------------------------------------------------
# Safe manual test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    checker = StateChecker(strict_context=False)

    demo_context = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "request_id": "manual_test",
        "source_agent": "manual",
    }

    demo_result = checker.check_many(
        checks=[
            {
                "check_type": "device_setting",
                "target": "platform",
            },
            {
                "check_type": "folder",
                "target": ".",
                "options": {
                    "include_children": True,
                    "child_limit": 5,
                },
            },
            {
                "check_type": "port",
                "target": 80,
                "expected": {
                    "expected": False,
                    "operator": "equals",
                },
            },
        ],
        context=demo_context,
    )

    print(json.dumps(demo_result, indent=2, default=str))


"""
Where to place it:
    agents/verification_agent/state_checker.py

Required dependencies:
    Required:
        - Python 3.10+

    Optional but recommended:
        - psutil
            pip install psutil

    Optional for window checks:
        - pygetwindow
            pip install pygetwindow

    Optional Windows window fallback:
        - pywin32
            pip install pywin32

How to test it:
    1. Save this file as:
        agents/verification_agent/state_checker.py

    2. Run direct smoke test:
        python agents/verification_agent/state_checker.py

    3. Example import test:
        from agents.verification_agent.state_checker import StateChecker

        checker = StateChecker(strict_context=False)
        result = checker.check_file_state("README.md")
        print(result)

    4. Example SaaS context usage:
        checker = StateChecker(strict_context=True)
        result = checker.check_state(
            check_type="process",
            target="python",
            context={
                "user_id": "user_123",
                "workspace_id": "workspace_456",
                "request_id": "req_789",
                "source_agent": "master_agent"
            }
        )
        print(result)

Agent/Module completion percentage after this file:
    11.8%

Next file to generate:
    agents/verification_agent/screenshot_checker.py

Agent/Module: Verification Agent
File Completed: state_checker.py
Completion: 11.8%
Completed Files: ['verification_agent.py', 'state_checker.py']
Remaining Files: ['screenshot_checker.py', 'result_validator.py', 'app_state_checker.py', 'file_state_checker.py', 'browser_state_checker.py', 'code_state_checker.py', 'device_state_checker.py', 'ui_element_checker.py', 'action_replay_checker.py', 'error_detector.py', 'proof_collector.py', 'retry_manager.py', 'report_generator.py', 'verification_memory.py', 'config.py']
Next Recommended File: agents/verification_agent/screenshot_checker.py
FILE COMPLETE
"""