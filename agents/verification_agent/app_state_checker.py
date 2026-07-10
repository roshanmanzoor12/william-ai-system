"""
agents/verification_agent/app_state_checker.py

William / Jarvis Multi-Agent AI SaaS System - Verification Agent

Purpose:
    Confirms whether an application is opened, closed, focused, ready, or crashed.

This file is designed to be:
    - Production-level and import-safe
    - SaaS user/workspace isolated
    - Compatible with BaseAgent, MasterAgent routing, Agent Registry, and Agent Loader
    - Compatible with Security Agent approval hooks
    - Compatible with Memory Agent payload preparation
    - Compatible with Verification Agent structured outputs
    - Ready for FastAPI/dashboard integration

Important:
    This checker is read-only by default. It inspects process/window/application state
    but does not open, close, kill, focus, click, type, call, message, browse, pay,
    or perform destructive actions.

Public class:
    AppStateChecker

Main public methods:
    - verify_app_state()
    - check_app_opened()
    - check_app_closed()
    - check_app_focused()
    - check_app_ready()
    - check_app_crashed()
    - collect_app_state()
    - wait_for_state()
"""

from __future__ import annotations

import csv
import json
import logging
import os
import platform
import socket
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union


try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - optional dependency fallback
    psutil = None  # type: ignore


try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback keeps file import-safe

    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This allows this file to be imported before the real William/Jarvis
        BaseAgent exists. The real project BaseAgent should override this.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent does not implement run().",
                "data": {},
                "error": "BASE_AGENT_FALLBACK_RUN_NOT_IMPLEMENTED",
                "metadata": {},
            }


class AppState(str, Enum):
    """Supported app states checked by AppStateChecker."""

    OPENED = "opened"
    CLOSED = "closed"
    FOCUSED = "focused"
    READY = "ready"
    CRASHED = "crashed"
    UNKNOWN = "unknown"


class AppReadinessSignal(str, Enum):
    """Supported readiness signals for app readiness checks."""

    PROCESS_RUNNING = "process_running"
    WINDOW_VISIBLE = "window_visible"
    FOCUSED = "focused"
    TCP_PORT_OPEN = "tcp_port_open"
    HTTP_HEALTH_OK = "http_health_ok"
    FILE_EXISTS = "file_exists"
    CUSTOM = "custom"


@dataclass
class ProcessSnapshot:
    """Safe process snapshot used for read-only app verification."""

    pid: Optional[int] = None
    name: Optional[str] = None
    executable: Optional[str] = None
    command_line: List[str] = field(default_factory=list)
    status: Optional[str] = None
    username: Optional[str] = None
    create_time: Optional[float] = None
    matched_by: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WindowSnapshot:
    """Safe foreground/window snapshot used for focus verification."""

    title: Optional[str] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None
    platform: str = field(default_factory=lambda: platform.system().lower())
    matched_by: List[str] = field(default_factory=list)
    available: bool = False
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AppIdentity:
    """
    Identifies an application without hardcoded secrets.

    Matching can be done by:
        - process_name
        - executable_path
        - command_contains
        - window_title_contains
        - bundle_id, app_id, package_name for future OS/mobile integrations
    """

    app_name: str
    process_name: Optional[str] = None
    executable_path: Optional[str] = None
    command_contains: Optional[Union[str, Sequence[str]]] = None
    window_title_contains: Optional[Union[str, Sequence[str]]] = None
    bundle_id: Optional[str] = None
    app_id: Optional[str] = None
    package_name: Optional[str] = None
    expected_port: Optional[int] = None
    expected_host: str = "127.0.0.1"
    health_url: Optional[str] = None
    readiness_file: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def normalized_command_terms(self) -> List[str]:
        return _normalize_terms(self.command_contains)

    def normalized_window_terms(self) -> List[str]:
        return _normalize_terms(self.window_title_contains)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AppStateObservation:
    """Complete observation object returned inside structured results."""

    app: Dict[str, Any]
    state_requested: str
    state_detected: str
    success: bool
    confidence: float
    reason: str
    processes: List[Dict[str, Any]] = field(default_factory=list)
    foreground_window: Optional[Dict[str, Any]] = None
    readiness: Dict[str, Any] = field(default_factory=dict)
    crash: Dict[str, Any] = field(default_factory=dict)
    checked_at: str = field(default_factory=lambda: _utc_now_iso())
    user_id: Optional[str] = None
    workspace_id: Optional[str] = None
    correlation_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AppStateCheckRequest:
    """
    Request object for app state verification.

    This can be created directly by APIs, dashboards, MasterAgent, or tests.
    """

    app: AppIdentity
    desired_state: AppState
    user_id: str
    workspace_id: str
    timeout_seconds: float = 0.0
    poll_interval_seconds: float = 1.0
    min_uptime_seconds_for_ready: float = 1.0
    require_all_readiness_signals: bool = False
    readiness_signals: List[AppReadinessSignal] = field(default_factory=list)
    custom_readiness_checker: Optional[Callable[[AppIdentity, Dict[str, Any]], bool]] = None
    task_id: Optional[str] = None
    correlation_id: Optional[str] = None
    source_agent: Optional[str] = None
    requested_by: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_context(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "task_id": self.task_id,
            "correlation_id": self.correlation_id,
            "source_agent": self.source_agent,
            "requested_by": self.requested_by,
            "metadata": self.metadata,
        }


def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""

    return datetime.now(timezone.utc).isoformat()


def _normalize_text(value: Optional[str]) -> str:
    """Normalize text for safe case-insensitive matching."""

    if not value:
        return ""
    return str(value).strip().lower()


def _normalize_terms(value: Optional[Union[str, Sequence[str]]]) -> List[str]:
    """Normalize string or sequence into lowercase matching terms."""

    if value is None:
        return []
    if isinstance(value, str):
        terms = [value]
    else:
        terms = [str(item) for item in value if item is not None]

    return [term.strip().lower() for term in terms if term and term.strip()]


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert a value to float."""

    try:
        return float(value)
    except Exception:
        return default


def _safe_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    """Safely convert a value to int."""

    try:
        return int(value)
    except Exception:
        return default


def _is_truthy(value: Any) -> bool:
    """Return a safe boolean interpretation."""

    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "ok", "success"}
    return bool(value)


class AppStateChecker(BaseAgent):
    """
    Verifies application state for the William/Jarvis Verification Agent.

    Integration notes:
        - Master Agent can route app verification tasks here.
        - Security Agent can approve sensitive verification requests through
          _request_security_approval().
        - Memory Agent can store verification summaries using
          _prepare_memory_payload().
        - Dashboard/API can call verify_app_state() and receive structured JSON.
        - Agent Registry can instantiate this class by name: AppStateChecker.

    This class does not perform destructive app actions.
    """

    AGENT_NAME = "verification_agent.app_state_checker"
    AGENT_VERSION = "1.0.0"

    def __init__(
        self,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], Any]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], Any]] = None,
        logger: Optional[logging.Logger] = None,
        default_timeout_seconds: float = 0.0,
        default_poll_interval_seconds: float = 1.0,
        allow_subprocess_fallback: bool = True,
        max_processes_returned: int = 25,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.AGENT_NAME, **kwargs)

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.logger = logger or logging.getLogger(self.AGENT_NAME)

        self.default_timeout_seconds = max(0.0, _safe_float(default_timeout_seconds, 0.0))
        self.default_poll_interval_seconds = max(0.2, _safe_float(default_poll_interval_seconds, 1.0))
        self.allow_subprocess_fallback = bool(allow_subprocess_fallback)
        self.max_processes_returned = max(1, int(max_processes_returned))

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible async entry point.

        Expected task example:
            {
                "user_id": "user_123",
                "workspace_id": "workspace_456",
                "desired_state": "opened",
                "app": {
                    "app_name": "Chrome",
                    "process_name": "chrome",
                    "window_title_contains": "Google"
                }
            }
        """

        try:
            request = self._build_request_from_task(task)
            return self.verify_app_state(request)
        except Exception as exc:
            return self._error_result(
                message="Failed to run app state verification task.",
                error=exc,
                metadata={"agent": self.AGENT_NAME, "task_type": "run"},
            )

    def verify_app_state(
        self,
        request: Union[AppStateCheckRequest, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Verify the desired app state and return a structured result.

        Supported desired states:
            - opened
            - closed
            - focused
            - ready
            - crashed
        """

        try:
            normalized_request = (
                request if isinstance(request, AppStateCheckRequest) else self._build_request_from_task(request)
            )

            context = normalized_request.to_context()
            context_validation = self._validate_task_context(context)
            if not context_validation["success"]:
                return context_validation

            if self._requires_security_check(
                action="verify_app_state",
                task_context=context,
                app=normalized_request.app,
                desired_state=normalized_request.desired_state,
            ):
                approval = self._request_security_approval(
                    action="verify_app_state",
                    task_context=context,
                    app=normalized_request.app,
                    desired_state=normalized_request.desired_state,
                )
                if not approval.get("approved", False):
                    return self._safe_result(
                        success=False,
                        message="Security approval denied for app state verification.",
                        data={
                            "approval": approval,
                            "verification": self._prepare_verification_payload(
                                success=False,
                                app=normalized_request.app,
                                desired_state=normalized_request.desired_state.value,
                                reason="Security approval denied.",
                                context=context,
                            ),
                        },
                        error="SECURITY_APPROVAL_DENIED",
                        metadata={
                            "agent": self.AGENT_NAME,
                            "version": self.AGENT_VERSION,
                            "user_id": normalized_request.user_id,
                            "workspace_id": normalized_request.workspace_id,
                        },
                    )

            self._emit_agent_event(
                event_type="verification.app_state.started",
                payload={
                    "app": normalized_request.app.to_dict(),
                    "desired_state": normalized_request.desired_state.value,
                    "context": context,
                },
            )

            result = self._verify_with_optional_wait(normalized_request)

            self._log_audit_event(
                action="verify_app_state",
                task_context=context,
                result_summary={
                    "success": result.get("success"),
                    "message": result.get("message"),
                    "desired_state": normalized_request.desired_state.value,
                    "app_name": normalized_request.app.app_name,
                },
            )

            memory_payload = self._prepare_memory_payload(
                task_context=context,
                app=normalized_request.app,
                result=result,
            )

            if self.memory_agent is not None:
                self._send_memory_payload(memory_payload)

            self._emit_agent_event(
                event_type="verification.app_state.completed",
                payload={
                    "app": normalized_request.app.to_dict(),
                    "desired_state": normalized_request.desired_state.value,
                    "success": result.get("success", False),
                    "context": context,
                },
            )

            result.setdefault("data", {})
            result["data"]["memory_payload"] = memory_payload
            return result

        except Exception as exc:
            return self._error_result(
                message="Unhandled error during app state verification.",
                error=exc,
                metadata={"agent": self.AGENT_NAME, "version": self.AGENT_VERSION},
            )

    def check_app_opened(
        self,
        app: Union[AppIdentity, Dict[str, Any]],
        user_id: str,
        workspace_id: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Confirm that an app is currently opened/running."""

        request = AppStateCheckRequest(
            app=self._normalize_app_identity(app),
            desired_state=AppState.OPENED,
            user_id=user_id,
            workspace_id=workspace_id,
            timeout_seconds=_safe_float(kwargs.get("timeout_seconds", self.default_timeout_seconds)),
            poll_interval_seconds=_safe_float(
                kwargs.get("poll_interval_seconds", self.default_poll_interval_seconds)
            ),
            task_id=kwargs.get("task_id"),
            correlation_id=kwargs.get("correlation_id"),
            source_agent=kwargs.get("source_agent"),
            requested_by=kwargs.get("requested_by"),
            metadata=dict(kwargs.get("metadata") or {}),
        )
        return self.verify_app_state(request)

    def check_app_closed(
        self,
        app: Union[AppIdentity, Dict[str, Any]],
        user_id: str,
        workspace_id: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Confirm that an app is currently closed/not running."""

        request = AppStateCheckRequest(
            app=self._normalize_app_identity(app),
            desired_state=AppState.CLOSED,
            user_id=user_id,
            workspace_id=workspace_id,
            timeout_seconds=_safe_float(kwargs.get("timeout_seconds", self.default_timeout_seconds)),
            poll_interval_seconds=_safe_float(
                kwargs.get("poll_interval_seconds", self.default_poll_interval_seconds)
            ),
            task_id=kwargs.get("task_id"),
            correlation_id=kwargs.get("correlation_id"),
            source_agent=kwargs.get("source_agent"),
            requested_by=kwargs.get("requested_by"),
            metadata=dict(kwargs.get("metadata") or {}),
        )
        return self.verify_app_state(request)

    def check_app_focused(
        self,
        app: Union[AppIdentity, Dict[str, Any]],
        user_id: str,
        workspace_id: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Confirm that an app currently owns the foreground/focused window."""

        request = AppStateCheckRequest(
            app=self._normalize_app_identity(app),
            desired_state=AppState.FOCUSED,
            user_id=user_id,
            workspace_id=workspace_id,
            timeout_seconds=_safe_float(kwargs.get("timeout_seconds", self.default_timeout_seconds)),
            poll_interval_seconds=_safe_float(
                kwargs.get("poll_interval_seconds", self.default_poll_interval_seconds)
            ),
            task_id=kwargs.get("task_id"),
            correlation_id=kwargs.get("correlation_id"),
            source_agent=kwargs.get("source_agent"),
            requested_by=kwargs.get("requested_by"),
            metadata=dict(kwargs.get("metadata") or {}),
        )
        return self.verify_app_state(request)

    def check_app_ready(
        self,
        app: Union[AppIdentity, Dict[str, Any]],
        user_id: str,
        workspace_id: str,
        readiness_signals: Optional[List[Union[str, AppReadinessSignal]]] = None,
        require_all_readiness_signals: bool = False,
        custom_readiness_checker: Optional[Callable[[AppIdentity, Dict[str, Any]], bool]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Confirm that an app is ready.

        Default readiness means:
            - Process is running
            - Process is not obviously crashed/zombie/dead
            - Optional configured health signals are passing
        """

        request = AppStateCheckRequest(
            app=self._normalize_app_identity(app),
            desired_state=AppState.READY,
            user_id=user_id,
            workspace_id=workspace_id,
            timeout_seconds=_safe_float(kwargs.get("timeout_seconds", self.default_timeout_seconds)),
            poll_interval_seconds=_safe_float(
                kwargs.get("poll_interval_seconds", self.default_poll_interval_seconds)
            ),
            min_uptime_seconds_for_ready=_safe_float(kwargs.get("min_uptime_seconds_for_ready", 1.0), 1.0),
            require_all_readiness_signals=bool(require_all_readiness_signals),
            readiness_signals=self._normalize_readiness_signals(readiness_signals),
            custom_readiness_checker=custom_readiness_checker,
            task_id=kwargs.get("task_id"),
            correlation_id=kwargs.get("correlation_id"),
            source_agent=kwargs.get("source_agent"),
            requested_by=kwargs.get("requested_by"),
            metadata=dict(kwargs.get("metadata") or {}),
        )
        return self.verify_app_state(request)

    def check_app_crashed(
        self,
        app: Union[AppIdentity, Dict[str, Any]],
        user_id: str,
        workspace_id: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Confirm whether an app appears crashed.

        Crash detection is conservative. It checks visible process states such as
        zombie/dead/crashed where the OS exposes them. It does not fabricate crash
        conclusions when the process simply is not found.
        """

        request = AppStateCheckRequest(
            app=self._normalize_app_identity(app),
            desired_state=AppState.CRASHED,
            user_id=user_id,
            workspace_id=workspace_id,
            timeout_seconds=_safe_float(kwargs.get("timeout_seconds", self.default_timeout_seconds)),
            poll_interval_seconds=_safe_float(
                kwargs.get("poll_interval_seconds", self.default_poll_interval_seconds)
            ),
            task_id=kwargs.get("task_id"),
            correlation_id=kwargs.get("correlation_id"),
            source_agent=kwargs.get("source_agent"),
            requested_by=kwargs.get("requested_by"),
            metadata=dict(kwargs.get("metadata") or {}),
        )
        return self.verify_app_state(request)

    def collect_app_state(
        self,
        app: Union[AppIdentity, Dict[str, Any]],
        user_id: str,
        workspace_id: str,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Collect raw read-only app state observation.

        Useful for dashboard/API pages before asking for a specific desired state.
        """

        try:
            context = {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "correlation_id": correlation_id,
                "metadata": metadata or {},
            }
            context_validation = self._validate_task_context(context)
            if not context_validation["success"]:
                return context_validation

            app_identity = self._normalize_app_identity(app)
            processes = self._find_matching_processes(app_identity)
            foreground = self._get_foreground_window()
            foreground_match = self._window_matches_app(foreground, app_identity)
            crash_info = self._detect_crash(processes)
            readiness = self._evaluate_readiness(
                app=app_identity,
                processes=processes,
                foreground=foreground,
                request=None,
            )

            opened = len(processes) > 0
            closed = not opened
            focused = bool(foreground_match["matched"])
            crashed = bool(crash_info["crashed"])
            ready = bool(readiness["ready"])

            detected_state = AppState.UNKNOWN.value
            if crashed:
                detected_state = AppState.CRASHED.value
            elif focused:
                detected_state = AppState.FOCUSED.value
            elif ready:
                detected_state = AppState.READY.value
            elif opened:
                detected_state = AppState.OPENED.value
            elif closed:
                detected_state = AppState.CLOSED.value

            data = {
                "app": app_identity.to_dict(),
                "state_detected": detected_state,
                "opened": opened,
                "closed": closed,
                "focused": focused,
                "ready": ready,
                "crashed": crashed,
                "process_count": len(processes),
                "processes": [p.to_dict() for p in processes[: self.max_processes_returned]],
                "foreground_window": foreground.to_dict() if foreground else None,
                "foreground_match": foreground_match,
                "readiness": readiness,
                "crash": crash_info,
                "checked_at": _utc_now_iso(),
                "user_id": user_id,
                "workspace_id": workspace_id,
                "correlation_id": correlation_id,
            }

            return self._safe_result(
                success=True,
                message="Collected app state observation.",
                data=data,
                metadata={
                    "agent": self.AGENT_NAME,
                    "version": self.AGENT_VERSION,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to collect app state.",
                error=exc,
                metadata={
                    "agent": self.AGENT_NAME,
                    "version": self.AGENT_VERSION,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

    def wait_for_state(
        self,
        app: Union[AppIdentity, Dict[str, Any]],
        desired_state: Union[str, AppState],
        user_id: str,
        workspace_id: str,
        timeout_seconds: float = 30.0,
        poll_interval_seconds: float = 1.0,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Poll until desired app state is confirmed or timeout occurs.

        This is still read-only. It does not manipulate the app.
        """

        request = AppStateCheckRequest(
            app=self._normalize_app_identity(app),
            desired_state=self._normalize_app_state(desired_state),
            user_id=user_id,
            workspace_id=workspace_id,
            timeout_seconds=max(0.0, _safe_float(timeout_seconds, 30.0)),
            poll_interval_seconds=max(0.2, _safe_float(poll_interval_seconds, 1.0)),
            readiness_signals=self._normalize_readiness_signals(kwargs.get("readiness_signals")),
            require_all_readiness_signals=bool(kwargs.get("require_all_readiness_signals", False)),
            min_uptime_seconds_for_ready=_safe_float(kwargs.get("min_uptime_seconds_for_ready", 1.0), 1.0),
            custom_readiness_checker=kwargs.get("custom_readiness_checker"),
            task_id=kwargs.get("task_id"),
            correlation_id=kwargs.get("correlation_id"),
            source_agent=kwargs.get("source_agent"),
            requested_by=kwargs.get("requested_by"),
            metadata=dict(kwargs.get("metadata") or {}),
        )
        return self.verify_app_state(request)

    def _verify_with_optional_wait(self, request: AppStateCheckRequest) -> Dict[str, Any]:
        """Verify immediately or poll until timeout."""

        timeout = max(0.0, request.timeout_seconds)
        interval = max(0.2, request.poll_interval_seconds)
        started_at = time.monotonic()
        attempts = 0
        last_result: Optional[Dict[str, Any]] = None

        while True:
            attempts += 1
            result = self._verify_once(request, attempts=attempts, started_at_monotonic=started_at)
            last_result = result

            if result.get("success", False):
                result.setdefault("metadata", {})
                result["metadata"]["attempts"] = attempts
                result["metadata"]["waited_seconds"] = round(time.monotonic() - started_at, 3)
                return result

            elapsed = time.monotonic() - started_at
            if timeout <= 0 or elapsed >= timeout:
                result.setdefault("metadata", {})
                result["metadata"]["attempts"] = attempts
                result["metadata"]["waited_seconds"] = round(elapsed, 3)
                result["metadata"]["timeout_seconds"] = timeout
                return result

            time.sleep(min(interval, max(0.0, timeout - elapsed)))

    def _verify_once(
        self,
        request: AppStateCheckRequest,
        attempts: int = 1,
        started_at_monotonic: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Perform one read-only state verification pass."""

        app = request.app
        processes = self._find_matching_processes(app)
        foreground = self._get_foreground_window()

        opened = len(processes) > 0
        closed = not opened

        window_match = self._window_matches_app(foreground, app)
        focused = bool(window_match["matched"])

        crash_info = self._detect_crash(processes)
        crashed = bool(crash_info["crashed"])

        readiness = self._evaluate_readiness(
            app=app,
            processes=processes,
            foreground=foreground,
            request=request,
        )
        ready = bool(readiness["ready"])

        desired = request.desired_state
        state_success = False
        state_detected = AppState.UNKNOWN.value
        reason = "Unable to determine app state."
        confidence = 0.0

        if crashed:
            state_detected = AppState.CRASHED.value
        elif focused:
            state_detected = AppState.FOCUSED.value
        elif ready:
            state_detected = AppState.READY.value
        elif opened:
            state_detected = AppState.OPENED.value
        elif closed:
            state_detected = AppState.CLOSED.value

        if desired == AppState.OPENED:
            state_success = opened and not crashed
            confidence = 0.92 if state_success else 0.82
            reason = (
                f"Application '{app.app_name}' is running with {len(processes)} matching process(es)."
                if state_success
                else f"Application '{app.app_name}' is not running or appears crashed."
            )

        elif desired == AppState.CLOSED:
            state_success = closed
            confidence = 0.9 if state_success else 0.82
            reason = (
                f"Application '{app.app_name}' is closed; no matching process was found."
                if state_success
                else f"Application '{app.app_name}' is not closed; {len(processes)} matching process(es) found."
            )

        elif desired == AppState.FOCUSED:
            state_success = focused and opened and not crashed
            confidence = 0.9 if state_success else 0.72
            reason = (
                f"Application '{app.app_name}' appears focused in the foreground window."
                if state_success
                else f"Application '{app.app_name}' is not confirmed as focused."
            )

        elif desired == AppState.READY:
            state_success = ready and opened and not crashed
            confidence = readiness.get("confidence", 0.8 if state_success else 0.55)
            reason = (
                f"Application '{app.app_name}' appears ready."
                if state_success
                else f"Application '{app.app_name}' is not confirmed ready."
            )

        elif desired == AppState.CRASHED:
            state_success = crashed
            confidence = crash_info.get("confidence", 0.8 if state_success else 0.65)
            reason = (
                f"Application '{app.app_name}' appears crashed: {crash_info.get('reason')}"
                if state_success
                else f"Application '{app.app_name}' is not confirmed crashed."
            )

        observation = AppStateObservation(
            app=app.to_dict(),
            state_requested=desired.value,
            state_detected=state_detected,
            success=state_success,
            confidence=round(float(confidence), 3),
            reason=reason,
            processes=[p.to_dict() for p in processes[: self.max_processes_returned]],
            foreground_window=foreground.to_dict() if foreground else None,
            readiness=readiness,
            crash=crash_info,
            user_id=request.user_id,
            workspace_id=request.workspace_id,
            correlation_id=request.correlation_id,
        )

        verification_payload = self._prepare_verification_payload(
            success=state_success,
            app=app,
            desired_state=desired.value,
            reason=reason,
            context=request.to_context(),
            observation=observation.to_dict(),
        )

        message = (
            f"App state confirmed: {desired.value}."
            if state_success
            else f"App state not confirmed: expected {desired.value}, detected {state_detected}."
        )

        return self._safe_result(
            success=state_success,
            message=message,
            data={
                "observation": observation.to_dict(),
                "verification": verification_payload,
            },
            error=None if state_success else "APP_STATE_NOT_CONFIRMED",
            metadata={
                "agent": self.AGENT_NAME,
                "version": self.AGENT_VERSION,
                "attempts": attempts,
                "desired_state": desired.value,
                "detected_state": state_detected,
                "process_count": len(processes),
                "foreground_available": bool(foreground and foreground.available),
                "started_at_elapsed_seconds": (
                    round(time.monotonic() - started_at_monotonic, 3)
                    if started_at_monotonic is not None
                    else None
                ),
                "user_id": request.user_id,
                "workspace_id": request.workspace_id,
                "correlation_id": request.correlation_id,
            },
        )

    def _find_matching_processes(self, app: AppIdentity) -> List[ProcessSnapshot]:
        """Find processes matching the given AppIdentity."""

        matches: List[ProcessSnapshot] = []

        for process in self._iter_processes():
            matched_by = self._process_matches_app(process, app)
            if matched_by:
                process.matched_by = matched_by
                matches.append(process)

        matches.sort(key=lambda item: (item.name or "", item.pid or 0))
        return matches

    def _iter_processes(self) -> Iterable[ProcessSnapshot]:
        """Iterate processes using psutil when available, otherwise safe subprocess fallback."""

        if psutil is not None:
            yield from self._iter_processes_psutil()
            return

        if not self.allow_subprocess_fallback:
            return

        system_name = platform.system().lower()
        if system_name == "windows":
            yield from self._iter_processes_windows_tasklist()
        else:
            yield from self._iter_processes_posix_ps()

    def _iter_processes_psutil(self) -> Iterable[ProcessSnapshot]:
        """Process enumeration using optional psutil dependency."""

        attrs = ["pid", "name", "exe", "cmdline", "status", "username", "create_time"]

        try:
            for proc in psutil.process_iter(attrs=attrs):  # type: ignore[union-attr]
                try:
                    info = proc.info
                    yield ProcessSnapshot(
                        pid=info.get("pid"),
                        name=info.get("name"),
                        executable=info.get("exe"),
                        command_line=list(info.get("cmdline") or []),
                        status=info.get("status"),
                        username=info.get("username"),
                        create_time=info.get("create_time"),
                    )
                except Exception:
                    continue
        except Exception as exc:
            self.logger.debug("psutil process iteration failed: %s", exc)

    def _iter_processes_windows_tasklist(self) -> Iterable[ProcessSnapshot]:
        """Windows fallback process enumeration using tasklist CSV."""

        try:
            completed = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if completed.returncode != 0:
                return

            rows = csv.reader(completed.stdout.splitlines())
            for row in rows:
                if len(row) < 2:
                    continue
                name = row[0].strip()
                pid = _safe_int(row[1].strip())
                yield ProcessSnapshot(
                    pid=pid,
                    name=name,
                    executable=None,
                    command_line=[],
                    status=None,
                    username=None,
                    create_time=None,
                )
        except Exception as exc:
            self.logger.debug("Windows tasklist fallback failed: %s", exc)

    def _iter_processes_posix_ps(self) -> Iterable[ProcessSnapshot]:
        """POSIX fallback process enumeration using ps."""

        try:
            completed = subprocess.run(
                ["ps", "-eo", "pid=,stat=,comm=,args="],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if completed.returncode != 0:
                return

            for line in completed.stdout.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue

                parts = stripped.split(None, 3)
                if len(parts) < 3:
                    continue

                pid = _safe_int(parts[0])
                status = parts[1]
                name = parts[2]
                args = parts[3] if len(parts) >= 4 else name

                yield ProcessSnapshot(
                    pid=pid,
                    name=name,
                    executable=None,
                    command_line=args.split(),
                    status=status,
                    username=None,
                    create_time=None,
                )
        except Exception as exc:
            self.logger.debug("POSIX ps fallback failed: %s", exc)

    def _process_matches_app(self, process: ProcessSnapshot, app: AppIdentity) -> List[str]:
        """Return match reasons if a process matches the app identity."""

        matched_by: List[str] = []

        process_name = _normalize_text(process.name)
        executable = _normalize_text(process.executable)
        executable_name = _normalize_text(Path(process.executable).name if process.executable else "")
        command_line_text = _normalize_text(" ".join(process.command_line))

        if app.process_name:
            expected = _normalize_text(app.process_name)
            expected_base = _normalize_text(Path(app.process_name).name)

            if process_name == expected or process_name == expected_base:
                matched_by.append("process_name_exact")
            elif executable_name == expected or executable_name == expected_base:
                matched_by.append("executable_name_exact")
            elif expected and expected in process_name:
                matched_by.append("process_name_contains")

        if app.executable_path:
            expected_path = _normalize_text(str(Path(app.executable_path)))
            if executable and executable == expected_path:
                matched_by.append("executable_path_exact")
            elif expected_path and expected_path in executable:
                matched_by.append("executable_path_contains")

        for term in app.normalized_command_terms():
            if term and term in command_line_text:
                matched_by.append(f"command_contains:{term}")

        if app.package_name:
            package_term = _normalize_text(app.package_name)
            if package_term and package_term in command_line_text:
                matched_by.append("package_name_in_command")

        if app.app_id:
            app_id_term = _normalize_text(app.app_id)
            if app_id_term and app_id_term in command_line_text:
                matched_by.append("app_id_in_command")

        if app.bundle_id:
            bundle_term = _normalize_text(app.bundle_id)
            if bundle_term and bundle_term in command_line_text:
                matched_by.append("bundle_id_in_command")

        return matched_by

    def _get_foreground_window(self) -> WindowSnapshot:
        """
        Return foreground window information where safely available.

        This is best-effort and platform-dependent.
        """

        system_name = platform.system().lower()

        if system_name == "windows":
            return self._get_foreground_window_windows()

        if system_name == "darwin":
            return self._get_foreground_window_macos()

        if system_name == "linux":
            return self._get_foreground_window_linux()

        return WindowSnapshot(
            available=False,
            reason=f"Foreground window detection is not implemented for platform: {system_name}",
        )

    def _get_foreground_window_windows(self) -> WindowSnapshot:
        """Get foreground window information on Windows using ctypes."""

        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.windll.user32
            hwnd = user32.GetForegroundWindow()
            if not hwnd:
                return WindowSnapshot(
                    available=False,
                    reason="No foreground window handle returned.",
                )

            length = user32.GetWindowTextLengthW(hwnd)
            buffer = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buffer, length + 1)
            title = buffer.value

            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            process_pid = int(pid.value) if pid.value else None

            process_name = None
            if process_pid is not None and psutil is not None:
                try:
                    process_name = psutil.Process(process_pid).name()  # type: ignore[union-attr]
                except Exception:
                    process_name = None

            return WindowSnapshot(
                title=title,
                pid=process_pid,
                process_name=process_name,
                platform="windows",
                available=True,
            )

        except Exception as exc:
            return WindowSnapshot(
                available=False,
                platform="windows",
                reason=f"Windows foreground detection failed: {exc}",
            )

    def _get_foreground_window_macos(self) -> WindowSnapshot:
        """Get foreground application/window information on macOS using osascript."""

        if not self.allow_subprocess_fallback:
            return WindowSnapshot(
                available=False,
                platform="darwin",
                reason="Subprocess fallback disabled.",
            )

        script = (
            'tell application "System Events"\n'
            'set frontApp to name of first application process whose frontmost is true\n'
            "end tell\n"
            "return frontApp\n"
        )

        try:
            completed = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if completed.returncode != 0:
                return WindowSnapshot(
                    available=False,
                    platform="darwin",
                    reason=completed.stderr.strip() or "osascript returned non-zero status.",
                )

            app_name = completed.stdout.strip()
            return WindowSnapshot(
                title=app_name,
                process_name=app_name,
                platform="darwin",
                available=bool(app_name),
            )

        except Exception as exc:
            return WindowSnapshot(
                available=False,
                platform="darwin",
                reason=f"macOS foreground detection failed: {exc}",
            )

    def _get_foreground_window_linux(self) -> WindowSnapshot:
        """Get foreground window title on Linux using xdotool when available."""

        if not self.allow_subprocess_fallback:
            return WindowSnapshot(
                available=False,
                platform="linux",
                reason="Subprocess fallback disabled.",
            )

        try:
            completed = subprocess.run(
                ["xdotool", "getactivewindow", "getwindowname"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if completed.returncode != 0:
                return WindowSnapshot(
                    available=False,
                    platform="linux",
                    reason=completed.stderr.strip()
                    or "xdotool is unavailable or returned non-zero status.",
                )

            title = completed.stdout.strip()
            return WindowSnapshot(
                title=title,
                platform="linux",
                available=bool(title),
            )

        except FileNotFoundError:
            return WindowSnapshot(
                available=False,
                platform="linux",
                reason="xdotool is not installed.",
            )
        except Exception as exc:
            return WindowSnapshot(
                available=False,
                platform="linux",
                reason=f"Linux foreground detection failed: {exc}",
            )

    def _window_matches_app(self, window: Optional[WindowSnapshot], app: AppIdentity) -> Dict[str, Any]:
        """Return whether the foreground window matches the app identity."""

        if window is None:
            return {
                "matched": False,
                "matched_by": [],
                "reason": "No window snapshot available.",
            }

        if not window.available:
            return {
                "matched": False,
                "matched_by": [],
                "reason": window.reason or "Foreground window information unavailable.",
            }

        matched_by: List[str] = []
        title = _normalize_text(window.title)
        process_name = _normalize_text(window.process_name)

        for term in app.normalized_window_terms():
            if term and term in title:
                matched_by.append(f"window_title_contains:{term}")

        if app.process_name:
            expected = _normalize_text(app.process_name)
            expected_base = _normalize_text(Path(app.process_name).name)
            if process_name in {expected, expected_base} and process_name:
                matched_by.append("foreground_process_name_exact")
            elif expected and expected in process_name:
                matched_by.append("foreground_process_name_contains")

        if app.app_name:
            app_name = _normalize_text(app.app_name)
            if app_name and app_name in title:
                matched_by.append("app_name_in_window_title")
            if app_name and app_name in process_name:
                matched_by.append("app_name_in_foreground_process")

        window.matched_by = matched_by

        return {
            "matched": bool(matched_by),
            "matched_by": matched_by,
            "reason": "Foreground window matched app identity." if matched_by else "Foreground window did not match app identity.",
            "window": window.to_dict(),
        }

    def _evaluate_readiness(
        self,
        app: AppIdentity,
        processes: List[ProcessSnapshot],
        foreground: Optional[WindowSnapshot],
        request: Optional[AppStateCheckRequest],
    ) -> Dict[str, Any]:
        """
        Evaluate whether app appears ready.

        Readiness defaults to safe process-based checks and can use optional signals:
            - process_running
            - window_visible
            - focused
            - tcp_port_open
            - http_health_ok
            - file_exists
            - custom
        """

        signal_results: Dict[str, Dict[str, Any]] = {}
        signals: List[AppReadinessSignal] = []

        if request and request.readiness_signals:
            signals = request.readiness_signals
        else:
            signals = [AppReadinessSignal.PROCESS_RUNNING]
            if app.expected_port:
                signals.append(AppReadinessSignal.TCP_PORT_OPEN)
            if app.health_url:
                signals.append(AppReadinessSignal.HTTP_HEALTH_OK)
            if app.readiness_file:
                signals.append(AppReadinessSignal.FILE_EXISTS)

        for signal in signals:
            if signal == AppReadinessSignal.PROCESS_RUNNING:
                ok = len(processes) > 0
                signal_results[signal.value] = {
                    "success": ok,
                    "message": "Matching process is running." if ok else "No matching process is running.",
                }

            elif signal == AppReadinessSignal.WINDOW_VISIBLE:
                visible = bool(foreground and foreground.available)
                window_match = self._window_matches_app(foreground, app) if foreground else {"matched": False}
                ok = visible and bool(window_match.get("matched"))
                signal_results[signal.value] = {
                    "success": ok,
                    "message": "Matching window appears visible." if ok else "Matching visible window was not confirmed.",
                    "details": window_match,
                }

            elif signal == AppReadinessSignal.FOCUSED:
                window_match = self._window_matches_app(foreground, app) if foreground else {"matched": False}
                ok = bool(window_match.get("matched"))
                signal_results[signal.value] = {
                    "success": ok,
                    "message": "App is focused." if ok else "App focus was not confirmed.",
                    "details": window_match,
                }

            elif signal == AppReadinessSignal.TCP_PORT_OPEN:
                ok, reason = self._check_tcp_port(app.expected_host, app.expected_port)
                signal_results[signal.value] = {
                    "success": ok,
                    "message": reason,
                    "host": app.expected_host,
                    "port": app.expected_port,
                }

            elif signal == AppReadinessSignal.HTTP_HEALTH_OK:
                ok, reason, status_code = self._check_http_health(app.health_url)
                signal_results[signal.value] = {
                    "success": ok,
                    "message": reason,
                    "health_url": app.health_url,
                    "status_code": status_code,
                }

            elif signal == AppReadinessSignal.FILE_EXISTS:
                ok = bool(app.readiness_file and Path(app.readiness_file).exists())
                signal_results[signal.value] = {
                    "success": ok,
                    "message": "Readiness file exists." if ok else "Readiness file does not exist.",
                    "file": app.readiness_file,
                }

            elif signal == AppReadinessSignal.CUSTOM:
                ok = False
                reason = "No custom readiness checker supplied."
                if request and request.custom_readiness_checker:
                    try:
                        ok = bool(
                            request.custom_readiness_checker(
                                app,
                                {
                                    "processes": [p.to_dict() for p in processes],
                                    "foreground_window": foreground.to_dict() if foreground else None,
                                },
                            )
                        )
                        reason = "Custom readiness checker returned true." if ok else "Custom readiness checker returned false."
                    except Exception as exc:
                        reason = f"Custom readiness checker failed: {exc}"

                signal_results[signal.value] = {
                    "success": ok,
                    "message": reason,
                }

        process_uptime_ready = True
        min_uptime = request.min_uptime_seconds_for_ready if request else 0.0
        if processes and min_uptime > 0 and psutil is not None:
            now = time.time()
            uptime_values = [
                now - p.create_time for p in processes if p.create_time is not None and p.create_time > 0
            ]
            if uptime_values:
                process_uptime_ready = max(uptime_values) >= min_uptime

        signal_bools = [bool(value.get("success")) for value in signal_results.values()]
        require_all = bool(request.require_all_readiness_signals) if request else False

        if not signal_bools:
            ready = len(processes) > 0
        elif require_all:
            ready = all(signal_bools)
        else:
            required_process = bool(signal_results.get(AppReadinessSignal.PROCESS_RUNNING.value, {}).get("success", len(processes) > 0))
            any_extra_signal = any(signal_bools)
            ready = required_process and any_extra_signal

        crash_info = self._detect_crash(processes)
        if crash_info["crashed"]:
            ready = False

        if not process_uptime_ready:
            ready = False

        success_count = sum(1 for ok in signal_bools if ok)
        total_count = len(signal_bools)
        confidence = 0.5
        if ready:
            confidence = 0.78 if total_count <= 1 else min(0.96, 0.70 + (success_count / max(total_count, 1)) * 0.25)
        elif total_count:
            confidence = max(0.35, (success_count / total_count) * 0.65)

        return {
            "ready": bool(ready),
            "confidence": round(confidence, 3),
            "signals": signal_results,
            "require_all_readiness_signals": require_all,
            "process_uptime_ready": process_uptime_ready,
            "min_uptime_seconds": min_uptime,
            "reason": "Readiness confirmed." if ready else "Readiness not confirmed.",
        }

    def _detect_crash(self, processes: List[ProcessSnapshot]) -> Dict[str, Any]:
        """
        Conservative crash detection.

        Returns crashed=True only when an observable process state suggests crash/dead/zombie.
        Missing process alone is not treated as crashed.
        """

        if not processes:
            return {
                "crashed": False,
                "confidence": 0.55,
                "reason": "No matching process found; closed/missing is not automatically treated as crashed.",
                "evidence": [],
            }

        crash_status_terms = {
            "zombie",
            "dead",
            "crashed",
            "terminated",
        }

        posix_bad_status_prefixes = {"Z", "X"}

        evidence: List[Dict[str, Any]] = []

        for process in processes:
            status = _normalize_text(process.status)
            status_raw = process.status or ""

            if status in crash_status_terms:
                evidence.append(
                    {
                        "pid": process.pid,
                        "name": process.name,
                        "status": process.status,
                        "reason": "Process status indicates crash/dead/zombie.",
                    }
                )

            if status_raw and status_raw[0:1].upper() in posix_bad_status_prefixes:
                evidence.append(
                    {
                        "pid": process.pid,
                        "name": process.name,
                        "status": process.status,
                        "reason": "POSIX process state indicates zombie/dead state.",
                    }
                )

        crashed = bool(evidence)

        return {
            "crashed": crashed,
            "confidence": 0.86 if crashed else 0.72,
            "reason": "Crash-like process state detected." if crashed else "No crash-like process state detected.",
            "evidence": evidence,
        }

    def _check_tcp_port(
        self,
        host: Optional[str],
        port: Optional[int],
        timeout_seconds: float = 1.5,
    ) -> Tuple[bool, str]:
        """Check whether a TCP port is open."""

        if not host or not port:
            return False, "Host or port was not provided."

        try:
            with socket.create_connection((host, int(port)), timeout=timeout_seconds):
                return True, f"TCP port {host}:{port} is open."
        except Exception as exc:
            return False, f"TCP port {host}:{port} is not open: {exc}"

    def _check_http_health(
        self,
        health_url: Optional[str],
        timeout_seconds: float = 3.0,
    ) -> Tuple[bool, str, Optional[int]]:
        """Check an HTTP health endpoint using standard library only."""

        if not health_url:
            return False, "Health URL was not provided.", None

        parsed = str(health_url).strip().lower()
        if not (parsed.startswith("http://") or parsed.startswith("https://")):
            return False, "Health URL must start with http:// or https://.", None

        try:
            request = urllib.request.Request(
                health_url,
                method="GET",
                headers={"User-Agent": f"William-Jarvis-AppStateChecker/{self.AGENT_VERSION}"},
            )
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                status_code = int(getattr(response, "status", 0) or 0)
                ok = 200 <= status_code < 400
                return ok, f"HTTP health endpoint returned status {status_code}.", status_code

        except urllib.error.HTTPError as exc:
            return False, f"HTTP health endpoint returned status {exc.code}.", int(exc.code)
        except Exception as exc:
            return False, f"HTTP health check failed: {exc}", None

    def _build_request_from_task(self, task: Dict[str, Any]) -> AppStateCheckRequest:
        """Build AppStateCheckRequest from a dict-based MasterAgent/API task."""

        if not isinstance(task, dict):
            raise ValueError("Task must be a dictionary.")

        app_data = task.get("app") or task.get("app_identity") or {}
        if not isinstance(app_data, dict):
            raise ValueError("Task app/app_identity must be a dictionary.")

        app = self._normalize_app_identity(app_data)
        desired_state = self._normalize_app_state(task.get("desired_state") or task.get("state") or AppState.OPENED)

        user_id = str(task.get("user_id") or "").strip()
        workspace_id = str(task.get("workspace_id") or "").strip()

        return AppStateCheckRequest(
            app=app,
            desired_state=desired_state,
            user_id=user_id,
            workspace_id=workspace_id,
            timeout_seconds=_safe_float(task.get("timeout_seconds", self.default_timeout_seconds)),
            poll_interval_seconds=_safe_float(
                task.get("poll_interval_seconds", self.default_poll_interval_seconds)
            ),
            min_uptime_seconds_for_ready=_safe_float(task.get("min_uptime_seconds_for_ready", 1.0), 1.0),
            require_all_readiness_signals=bool(task.get("require_all_readiness_signals", False)),
            readiness_signals=self._normalize_readiness_signals(task.get("readiness_signals")),
            custom_readiness_checker=task.get("custom_readiness_checker"),
            task_id=task.get("task_id"),
            correlation_id=task.get("correlation_id"),
            source_agent=task.get("source_agent"),
            requested_by=task.get("requested_by"),
            metadata=dict(task.get("metadata") or {}),
        )

    def _normalize_app_identity(self, app: Union[AppIdentity, Dict[str, Any]]) -> AppIdentity:
        """Normalize dict/AppIdentity into AppIdentity."""

        if isinstance(app, AppIdentity):
            if not app.app_name or not str(app.app_name).strip():
                raise ValueError("app_name is required.")
            return app

        if not isinstance(app, dict):
            raise ValueError("App identity must be AppIdentity or dictionary.")

        app_name = str(app.get("app_name") or app.get("name") or "").strip()
        if not app_name:
            raise ValueError("app_name is required.")

        expected_port = app.get("expected_port")
        if expected_port is not None:
            expected_port = _safe_int(expected_port)
            if expected_port is not None and not (1 <= expected_port <= 65535):
                raise ValueError("expected_port must be between 1 and 65535.")

        return AppIdentity(
            app_name=app_name,
            process_name=app.get("process_name"),
            executable_path=app.get("executable_path"),
            command_contains=app.get("command_contains"),
            window_title_contains=app.get("window_title_contains"),
            bundle_id=app.get("bundle_id"),
            app_id=app.get("app_id"),
            package_name=app.get("package_name"),
            expected_port=expected_port,
            expected_host=str(app.get("expected_host") or "127.0.0.1").strip() or "127.0.0.1",
            health_url=app.get("health_url"),
            readiness_file=app.get("readiness_file"),
            metadata=dict(app.get("metadata") or {}),
        )

    def _normalize_app_state(self, state: Union[str, AppState]) -> AppState:
        """Normalize desired app state."""

        if isinstance(state, AppState):
            return state

        normalized = str(state or "").strip().lower()
        for possible in AppState:
            if normalized == possible.value:
                return possible

        raise ValueError(
            f"Unsupported app state '{state}'. Supported states: "
            f"{', '.join(item.value for item in AppState if item != AppState.UNKNOWN)}"
        )

    def _normalize_readiness_signals(
        self,
        signals: Optional[Sequence[Union[str, AppReadinessSignal]]],
    ) -> List[AppReadinessSignal]:
        """Normalize readiness signal list."""

        if not signals:
            return []

        normalized: List[AppReadinessSignal] = []
        for signal in signals:
            if isinstance(signal, AppReadinessSignal):
                normalized.append(signal)
                continue

            value = str(signal or "").strip().lower()
            if not value:
                continue

            try:
                normalized.append(AppReadinessSignal(value))
            except ValueError:
                self.logger.warning("Ignoring unsupported readiness signal: %s", signal)

        return normalized

    def _validate_task_context(self, task_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Every user-specific verification task must include user_id and workspace_id
        so results, memory, logs, and dashboard records cannot mix tenants.
        """

        user_id = str(task_context.get("user_id") or "").strip()
        workspace_id = str(task_context.get("workspace_id") or "").strip()

        if not user_id:
            return self._safe_result(
                success=False,
                message="Missing required user_id for SaaS isolation.",
                data={},
                error="MISSING_USER_ID",
                metadata={"agent": self.AGENT_NAME, "hook": "_validate_task_context"},
            )

        if not workspace_id:
            return self._safe_result(
                success=False,
                message="Missing required workspace_id for SaaS isolation.",
                data={},
                error="MISSING_WORKSPACE_ID",
                metadata={"agent": self.AGENT_NAME, "hook": "_validate_task_context"},
            )

        return self._safe_result(
            success=True,
            message="Task context validated.",
            data={"user_id": user_id, "workspace_id": workspace_id},
            metadata={"agent": self.AGENT_NAME, "hook": "_validate_task_context"},
        )

    def _requires_security_check(
        self,
        action: str,
        task_context: Dict[str, Any],
        app: Optional[AppIdentity] = None,
        desired_state: Optional[AppState] = None,
    ) -> bool:
        """
        Decide whether Security Agent approval is needed.

        App state checks are read-only by default. Approval is required when:
            - task metadata marks task as sensitive
            - task metadata requests protected app inspection
            - app metadata marks app as sensitive/protected
        """

        metadata = dict(task_context.get("metadata") or {})
        app_metadata = dict(app.metadata if app else {})

        sensitive_flags = [
            metadata.get("sensitive"),
            metadata.get("requires_security_check"),
            metadata.get("protected_app"),
            app_metadata.get("sensitive"),
            app_metadata.get("protected_app"),
            app_metadata.get("requires_security_check"),
        ]

        return any(_is_truthy(flag) for flag in sensitive_flags)

    def _request_security_approval(
        self,
        action: str,
        task_context: Dict[str, Any],
        app: Optional[AppIdentity] = None,
        desired_state: Optional[AppState] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval if available.

        Fallback behavior:
            If no security agent is attached and the action is read-only,
            approve safely with explicit fallback metadata.
        """

        approval_request = {
            "action": action,
            "agent": self.AGENT_NAME,
            "app": app.to_dict() if app else None,
            "desired_state": desired_state.value if desired_state else None,
            "task_context": task_context,
            "read_only": True,
            "requested_at": _utc_now_iso(),
        }

        if self.security_agent is None:
            return {
                "approved": True,
                "reason": "No Security Agent attached; read-only verification approved by fallback policy.",
                "fallback": True,
                "request": approval_request,
            }

        try:
            if hasattr(self.security_agent, "approve"):
                response = self.security_agent.approve(approval_request)
            elif hasattr(self.security_agent, "request_approval"):
                response = self.security_agent.request_approval(approval_request)
            elif hasattr(self.security_agent, "validate_action"):
                response = self.security_agent.validate_action(approval_request)
            else:
                return {
                    "approved": False,
                    "reason": "Attached Security Agent has no supported approval method.",
                    "fallback": False,
                    "request": approval_request,
                }

            if isinstance(response, dict):
                return {
                    "approved": bool(response.get("approved") or response.get("success")),
                    "reason": response.get("reason") or response.get("message") or "Security Agent returned response.",
                    "fallback": False,
                    "raw_response": response,
                    "request": approval_request,
                }

            return {
                "approved": bool(response),
                "reason": "Security Agent returned boolean-like response.",
                "fallback": False,
                "raw_response": response,
                "request": approval_request,
            }

        except Exception as exc:
            return {
                "approved": False,
                "reason": f"Security approval request failed: {exc}",
                "fallback": False,
                "request": approval_request,
            }

    def _prepare_verification_payload(
        self,
        success: bool,
        app: AppIdentity,
        desired_state: str,
        reason: str,
        context: Dict[str, Any],
        observation: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        This payload can be consumed by report_generator.py, proof_collector.py,
        result_validator.py, MasterAgent, API responses, or dashboard timelines.
        """

        return {
            "verification_type": "app_state",
            "agent": self.AGENT_NAME,
            "agent_version": self.AGENT_VERSION,
            "success": bool(success),
            "desired_state": desired_state,
            "app": app.to_dict(),
            "reason": reason,
            "observation": observation or {},
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "task_id": context.get("task_id"),
            "correlation_id": context.get("correlation_id"),
            "source_agent": context.get("source_agent"),
            "checked_at": _utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        task_context: Dict[str, Any],
        app: AppIdentity,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        The payload stores useful operational context without leaking data across
        users/workspaces.
        """

        observation = (
            result.get("data", {})
            .get("observation", {})
            if isinstance(result.get("data"), dict)
            else {}
        )

        return {
            "memory_type": "verification_app_state",
            "agent": self.AGENT_NAME,
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "task_id": task_context.get("task_id"),
            "correlation_id": task_context.get("correlation_id"),
            "summary": {
                "app_name": app.app_name,
                "desired_state": observation.get("state_requested"),
                "detected_state": observation.get("state_detected"),
                "success": result.get("success", False),
                "message": result.get("message"),
                "confidence": observation.get("confidence"),
            },
            "raw": {
                "app": app.to_dict(),
                "result_metadata": result.get("metadata", {}),
            },
            "created_at": _utc_now_iso(),
        }

    def _send_memory_payload(self, payload: Dict[str, Any]) -> None:
        """Send payload to Memory Agent if a compatible method exists."""

        try:
            if self.memory_agent is None:
                return

            if hasattr(self.memory_agent, "remember"):
                self.memory_agent.remember(payload)
            elif hasattr(self.memory_agent, "store"):
                self.memory_agent.store(payload)
            elif hasattr(self.memory_agent, "save_memory"):
                self.memory_agent.save_memory(payload)
            else:
                self.logger.debug("Memory Agent attached but no supported memory method found.")

        except Exception as exc:
            self.logger.warning("Failed to send app state memory payload: %s", exc)

    def _emit_agent_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        """
        Emit event for dashboard/API/agent bus integration.

        Event emission is optional and failure-safe.
        """

        event = {
            "event_type": event_type,
            "agent": self.AGENT_NAME,
            "version": self.AGENT_VERSION,
            "payload": payload,
            "timestamp": _utc_now_iso(),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event)
            else:
                self.logger.debug("Agent event: %s", json.dumps(event, default=str))
        except Exception as exc:
            self.logger.warning("Failed to emit agent event '%s': %s", event_type, exc)

    def _log_audit_event(
        self,
        action: str,
        task_context: Dict[str, Any],
        result_summary: Dict[str, Any],
    ) -> None:
        """
        Log audit event with SaaS context.

        This keeps audit data tied to user_id/workspace_id and avoids cross-tenant
        mixing.
        """

        audit_event = {
            "action": action,
            "agent": self.AGENT_NAME,
            "version": self.AGENT_VERSION,
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "task_id": task_context.get("task_id"),
            "correlation_id": task_context.get("correlation_id"),
            "source_agent": task_context.get("source_agent"),
            "result_summary": result_summary,
            "timestamp": _utc_now_iso(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit_event)
            else:
                self.logger.info("Audit event: %s", json.dumps(audit_event, default=str))
        except Exception as exc:
            self.logger.warning("Failed to log audit event '%s': %s", action, exc)

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William/Jarvis standard structured result."""

        return {
            "success": bool(success),
            "message": str(message),
            "data": data or {},
            "error": error,
            "metadata": {
                "agent": self.AGENT_NAME,
                "version": self.AGENT_VERSION,
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Union[BaseException, str, Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return structured error result with safe traceback metadata."""

        if isinstance(error, BaseException):
            error_payload: Dict[str, Any] = {
                "type": error.__class__.__name__,
                "message": str(error),
            }

            if metadata and metadata.get("include_traceback"):
                error_payload["traceback"] = traceback.format_exc()
        elif isinstance(error, dict):
            error_payload = error
        else:
            error_payload = {
                "type": "Error",
                "message": str(error),
            }

        self.logger.error("%s Error=%s", message, error_payload)

        return self._safe_result(
            success=False,
            message=message,
            data={},
            error=error_payload,
            metadata=metadata or {},
        )


__all__ = [
    "AppStateChecker",
    "AppState",
    "AppReadinessSignal",
    "AppIdentity",
    "AppStateObservation",
    "AppStateCheckRequest",
    "ProcessSnapshot",
    "WindowSnapshot",
]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    checker = AppStateChecker()

    demo_process_name = "python.exe" if platform.system().lower() == "windows" else "python"

    demo_result = checker.check_app_opened(
        app={
            "app_name": "Python",
            "process_name": demo_process_name,
            "command_contains": ["python"],
        },
        user_id="demo_user",
        workspace_id="demo_workspace",
        metadata={"demo": True},
    )

    print(json.dumps(demo_result, indent=2, default=str))