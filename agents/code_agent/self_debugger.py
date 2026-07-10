"""
agents/code_agent/self_debugger.py

SelfDebugger for the William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Purpose:
    Runs a safe debug cycle:
    1. Analyze execution/test errors.
    2. Build a patch plan.
    3. Apply bounded patches only when allowed.
    4. Rerun verification commands.
    5. Stop after a configured limit.
    6. Return structured payloads for Master Agent, Security Agent, Verification Agent,
       Memory Agent, dashboard/API, audit logs, and registry integration.

Design goals:
    - Import-safe even if the rest of William/Jarvis is not generated yet.
    - SaaS-safe: every user/workspace execution validates user_id and workspace_id.
    - Security-first: sensitive file edits and command execution can be routed through
      Security Agent approval hooks.
    - Testable: deterministic public methods with structured dict results.
    - Future-ready: compatible with BaseAgent, Agent Registry, Agent Loader,
      Agent Router, and Master Agent routing patterns.
"""

from __future__ import annotations

import difflib
import json
import logging
import os
import re
import shlex
import subprocess
import time
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallbacks
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import safety
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        The real William/Jarvis BaseAgent can replace this automatically when
        available. This fallback keeps this file import-safe during incremental
        generation.
        """

        agent_name: str = "base_agent"
        agent_type: str = "generic"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.user_id = kwargs.get("user_id")
            self.workspace_id = kwargs.get("workspace_id")
            self.logger = logging.getLogger(self.__class__.__name__)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_name, payload)

        def log_audit(self, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback audit: %s", payload)


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:  # pragma: no cover
    VerificationAgent = None  # type: ignore


try:
    from agents.memory_agent.memory_agent import MemoryAgent  # type: ignore
except Exception:  # pragma: no cover
    MemoryAgent = None  # type: ignore


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_AGENT_NAME = "self_debugger"
DEFAULT_AGENT_TYPE = "code_agent"
DEFAULT_MAX_CYCLES = 3
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_MAX_PATCH_BYTES = 250_000
DEFAULT_ENCODING = "utf-8"

SENSITIVE_PATH_PARTS = {
    ".env",
    ".ssh",
    ".aws",
    ".gcp",
    ".azure",
    "secrets",
    "secret",
    "credentials",
    "private_key",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
}

DANGEROUS_COMMAND_PATTERNS = (
    r"\brm\s+-rf\b",
    r"\brmdir\b",
    r"\bdel\s+/[fqsa]\b",
    r"\bformat\b",
    r"\bdd\s+if=",
    r"\bmkfs\b",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bpoweroff\b",
    r"\breg\s+delete\b",
    r"\bchmod\s+777\b",
    r"\bchown\s+-R\b",
    r"\bcurl\b.*\|\s*(bash|sh|python)",
    r"\bwget\b.*\|\s*(bash|sh|python)",
    r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;",
)

SAFE_DEFAULT_COMMANDS = (
    "python -m py_compile",
    "python -m compileall",
    "python -m pytest",
    "pytest",
    "python -m unittest",
    "ruff check",
    "mypy",
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DebuggerConfig:
    """
    Runtime configuration for SelfDebugger.

    The config is intentionally strict by default. It can analyze freely but
    only patches or runs commands when allowed by the caller and security hooks.
    """

    project_root: Union[str, Path] = "."
    max_cycles: int = DEFAULT_MAX_CYCLES
    command_timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    max_patch_bytes: int = DEFAULT_MAX_PATCH_BYTES
    encoding: str = DEFAULT_ENCODING
    allow_file_writes: bool = False
    allow_command_execution: bool = False
    require_security_for_writes: bool = True
    require_security_for_commands: bool = True
    create_backups: bool = True
    backup_suffix: str = ".self_debugger.bak"
    allowed_file_extensions: Tuple[str, ...] = (
        ".py",
        ".txt",
        ".md",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".env.example",
        ".html",
        ".css",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
    )
    blocked_directory_names: Tuple[str, ...] = (
        ".git",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        "node_modules",
        "dist",
        "build",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
    )

    def normalized_project_root(self) -> Path:
        return Path(self.project_root).expanduser().resolve()


@dataclass
class DebugTaskContext:
    """
    SaaS execution context.

    user_id and workspace_id are required for all user/workspace-specific debug
    cycles so memory, audit logs, tasks, analytics, and files cannot be mixed.
    """

    user_id: Union[str, int]
    workspace_id: Union[str, int]
    request_id: Optional[str] = None
    role: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CommandResult:
    command: str
    cwd: str
    returncode: Optional[int]
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ErrorFinding:
    category: str
    message: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    symbol: Optional[str] = None
    severity: str = "medium"
    raw: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PatchOperation:
    """
    Represents a safe text replacement patch.

    old_text must exist in the target file exactly once unless allow_multiple is
    set to True. This reduces accidental broad edits.
    """

    file_path: str
    old_text: str
    new_text: str
    reason: str
    allow_multiple: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PatchResult:
    file_path: str
    changed: bool
    reason: str
    backup_path: Optional[str] = None
    diff: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DebugCycleRecord:
    cycle_number: int
    started_at: str
    completed_at: Optional[str] = None
    analysis: Dict[str, Any] = field(default_factory=dict)
    patch_plan: List[Dict[str, Any]] = field(default_factory=list)
    patch_results: List[Dict[str, Any]] = field(default_factory=list)
    verification: Dict[str, Any] = field(default_factory=dict)
    stopped_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# SelfDebugger
# ---------------------------------------------------------------------------

class SelfDebugger(BaseAgent):
    """
    Production-level self-debugging helper for the Code Agent module.

    Public methods:
        - run_debug_cycle(...)
        - analyze_errors(...)
        - build_patch_plan(...)
        - apply_patch_plan(...)
        - rerun_verification(...)
        - verify_debug_success(...)

    This file does not directly bypass permissions. It can run in dry/analyze
    mode by default and only writes/runs commands when enabled by config and
    security approval hooks.
    """

    agent_name = DEFAULT_AGENT_NAME
    agent_type = DEFAULT_AGENT_TYPE
    public_methods = (
        "run_debug_cycle",
        "analyze_errors",
        "build_patch_plan",
        "apply_patch_plan",
        "rerun_verification",
        "verify_debug_success",
    )

    def __init__(
        self,
        config: Optional[DebuggerConfig] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.config = config or DebuggerConfig()
        self.project_root = self.config.normalized_project_root()
        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.logger = logger or logging.getLogger(self.__class__.__name__)

        if self.security_agent is None and SecurityAgent is not None:
            self.security_agent = self._safe_instantiate_agent(SecurityAgent)

        if self.verification_agent is None and VerificationAgent is not None:
            self.verification_agent = self._safe_instantiate_agent(VerificationAgent)

        if self.memory_agent is None and MemoryAgent is not None:
            self.memory_agent = self._safe_instantiate_agent(MemoryAgent)

    # ------------------------------------------------------------------
    # Public orchestration
    # ------------------------------------------------------------------

    def run_debug_cycle(
        self,
        context: Union[DebugTaskContext, Mapping[str, Any]],
        initial_error_text: str = "",
        target_files: Optional[Sequence[Union[str, Path]]] = None,
        verification_commands: Optional[Sequence[Union[str, Sequence[str]]]] = None,
        max_cycles: Optional[int] = None,
        dry_run: bool = True,
        patch_operations: Optional[Sequence[Union[PatchOperation, Mapping[str, Any]]]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run analyze -> patch -> rerun -> verify loop until success or limit.

        Args:
            context: SaaS context containing user_id and workspace_id.
            initial_error_text: stderr/log/traceback/test failure text.
            target_files: files allowed for analysis/patching.
            verification_commands: commands to rerun after each patch attempt.
            max_cycles: cycle cap. Defaults to config.max_cycles.
            dry_run: when True, patch plan is generated but not written.
            patch_operations: optional caller-provided patch operations.
            metadata: additional payload for dashboard/task history.

        Returns:
            Structured dict with success, message, data, error, metadata.
        """

        safe_context = self._coerce_context(context)
        validation = self._validate_task_context(safe_context)
        if not validation["success"]:
            return validation

        run_started = self._utc_now()
        run_metadata = dict(metadata or {})
        max_cycle_count = self._safe_positive_int(max_cycles, self.config.max_cycles, min_value=1)
        max_cycle_count = min(max_cycle_count, max(self.config.max_cycles, 1))

        self._emit_agent_event(
            "code_agent.self_debugger.started",
            {
                "context": self._context_public_dict(safe_context),
                "dry_run": dry_run,
                "max_cycles": max_cycle_count,
                "target_files": [str(p) for p in target_files or []],
                "metadata": run_metadata,
            },
        )

        cycles: List[DebugCycleRecord] = []
        current_error_text = initial_error_text or ""
        latest_verification: Dict[str, Any] = {}
        overall_success = False
        stopped_reason = "max_cycles_reached"

        try:
            for cycle_number in range(1, max_cycle_count + 1):
                cycle = DebugCycleRecord(cycle_number=cycle_number, started_at=self._utc_now())
                cycles.append(cycle)

                analysis_result = self.analyze_errors(
                    context=safe_context,
                    error_text=current_error_text,
                    target_files=target_files,
                    metadata={"cycle_number": cycle_number, **run_metadata},
                )
                cycle.analysis = analysis_result

                if not analysis_result.get("success"):
                    cycle.stopped_reason = "analysis_failed"
                    stopped_reason = "analysis_failed"
                    break

                plan_result = self.build_patch_plan(
                    context=safe_context,
                    analysis=analysis_result.get("data", {}),
                    target_files=target_files,
                    patch_operations=patch_operations,
                    metadata={"cycle_number": cycle_number, **run_metadata},
                )
                cycle.patch_plan = plan_result.get("data", {}).get("patch_operations", [])

                if not plan_result.get("success"):
                    cycle.stopped_reason = "patch_plan_failed"
                    stopped_reason = "patch_plan_failed"
                    break

                if not cycle.patch_plan:
                    cycle.stopped_reason = "no_patch_available"
                    stopped_reason = "no_patch_available"
                    latest_verification = self.rerun_verification(
                        context=safe_context,
                        verification_commands=verification_commands,
                        metadata={"cycle_number": cycle_number, **run_metadata},
                    )
                    cycle.verification = latest_verification
                    overall_success = bool(latest_verification.get("success"))
                    if overall_success:
                        stopped_reason = "already_fixed_or_no_error"
                    break

                apply_result = self.apply_patch_plan(
                    context=safe_context,
                    patch_operations=cycle.patch_plan,
                    dry_run=dry_run,
                    metadata={"cycle_number": cycle_number, **run_metadata},
                )
                cycle.patch_results = apply_result.get("data", {}).get("patch_results", [])

                if not apply_result.get("success"):
                    cycle.stopped_reason = "patch_apply_failed"
                    stopped_reason = "patch_apply_failed"
                    break

                if dry_run:
                    cycle.stopped_reason = "dry_run_completed"
                    stopped_reason = "dry_run_completed"
                    overall_success = True
                    break

                latest_verification = self.rerun_verification(
                    context=safe_context,
                    verification_commands=verification_commands,
                    metadata={"cycle_number": cycle_number, **run_metadata},
                )
                cycle.verification = latest_verification

                verification_data = latest_verification.get("data", {})
                current_error_text = self._extract_error_text_from_verification(verification_data)

                success_check = self.verify_debug_success(
                    context=safe_context,
                    verification_result=latest_verification,
                    metadata={"cycle_number": cycle_number, **run_metadata},
                )

                overall_success = bool(success_check.get("success"))
                if overall_success:
                    cycle.stopped_reason = "verified_success"
                    stopped_reason = "verified_success"
                    cycle.completed_at = self._utc_now()
                    break

                cycle.stopped_reason = "verification_failed_continue"
                cycle.completed_at = self._utc_now()

            for cycle in cycles:
                if cycle.completed_at is None:
                    cycle.completed_at = self._utc_now()

            payload = {
                "run_started_at": run_started,
                "run_completed_at": self._utc_now(),
                "stopped_reason": stopped_reason,
                "dry_run": dry_run,
                "max_cycles": max_cycle_count,
                "cycles": [cycle.to_dict() for cycle in cycles],
                "latest_verification": latest_verification,
                "verification_payload": self._prepare_verification_payload(
                    safe_context,
                    action="self_debugger.run_debug_cycle",
                    success=overall_success,
                    data={
                        "stopped_reason": stopped_reason,
                        "cycle_count": len(cycles),
                        "dry_run": dry_run,
                    },
                ),
                "memory_payload": self._prepare_memory_payload(
                    safe_context,
                    memory_type="code_debug_cycle",
                    content={
                        "stopped_reason": stopped_reason,
                        "success": overall_success,
                        "cycle_count": len(cycles),
                        "target_files": [str(p) for p in target_files or []],
                    },
                ),
            }

            self._log_audit_event(
                safe_context,
                action="self_debugger.run_debug_cycle",
                status="success" if overall_success else "stopped",
                details={
                    "stopped_reason": stopped_reason,
                    "dry_run": dry_run,
                    "cycle_count": len(cycles),
                },
            )

            self._emit_agent_event(
                "code_agent.self_debugger.completed",
                {
                    "context": self._context_public_dict(safe_context),
                    "success": overall_success,
                    "stopped_reason": stopped_reason,
                    "cycle_count": len(cycles),
                },
            )

            return self._safe_result(
                success=overall_success,
                message=(
                    "Debug cycle completed successfully."
                    if overall_success
                    else f"Debug cycle stopped: {stopped_reason}."
                ),
                data=payload,
                metadata={
                    "agent": self.agent_name,
                    "module": self.agent_type,
                    **run_metadata,
                },
            )

        except Exception as exc:
            self.logger.exception("SelfDebugger run_debug_cycle failed")
            self._log_audit_event(
                safe_context,
                action="self_debugger.run_debug_cycle",
                status="error",
                details={"error": str(exc)},
            )
            return self._error_result(
                message="Debug cycle failed unexpectedly.",
                error=exc,
                data={
                    "cycles": [cycle.to_dict() for cycle in cycles],
                    "stopped_reason": "unexpected_error",
                },
                metadata={"agent": self.agent_name, "module": self.agent_type, **run_metadata},
            )

    def analyze_errors(
        self,
        context: Union[DebugTaskContext, Mapping[str, Any]],
        error_text: str,
        target_files: Optional[Sequence[Union[str, Path]]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze tracebacks, syntax errors, import errors, test failures, and
        command output into structured findings.
        """

        safe_context = self._coerce_context(context)
        validation = self._validate_task_context(safe_context)
        if not validation["success"]:
            return validation

        findings = self._parse_error_text(error_text or "")
        file_snapshots = self._collect_file_snapshots(target_files or [])

        summary = self._summarize_findings(findings)
        data = {
            "findings": [finding.to_dict() for finding in findings],
            "summary": summary,
            "target_files": file_snapshots,
            "has_error_text": bool((error_text or "").strip()),
        }

        self._emit_agent_event(
            "code_agent.self_debugger.analysis_completed",
            {
                "context": self._context_public_dict(safe_context),
                "finding_count": len(findings),
                "summary": summary,
                "metadata": dict(metadata or {}),
            },
        )

        return self._safe_result(
            success=True,
            message="Error analysis completed.",
            data=data,
            metadata={"agent": self.agent_name, **dict(metadata or {})},
        )

    def build_patch_plan(
        self,
        context: Union[DebugTaskContext, Mapping[str, Any]],
        analysis: Mapping[str, Any],
        target_files: Optional[Sequence[Union[str, Path]]] = None,
        patch_operations: Optional[Sequence[Union[PatchOperation, Mapping[str, Any]]]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build a safe patch plan.

        The strongest path is caller-provided PatchOperation objects because
        fully automatic source rewriting can be risky. This method also includes
        conservative built-in fixes for common Python issues:
            - missing `if __name__ == "__main__":` guard is not auto-added.
            - SyntaxError caused by literal tab/space inconsistencies can be normalized.
            - Missing imports are suggested, not blindly inserted unless exact and safe.
        """

        safe_context = self._coerce_context(context)
        validation = self._validate_task_context(safe_context)
        if not validation["success"]:
            return validation

        plan: List[PatchOperation] = []

        for operation in patch_operations or []:
            coerced = self._coerce_patch_operation(operation)
            if coerced is not None:
                plan.append(coerced)

        if not plan:
            generated = self._generate_conservative_patch_plan(
                analysis=analysis,
                target_files=target_files or [],
            )
            plan.extend(generated)

        safe_plan: List[PatchOperation] = []
        rejected: List[Dict[str, Any]] = []

        for operation in plan:
            safety = self._validate_patch_operation(operation)
            if safety["success"]:
                safe_plan.append(operation)
            else:
                rejected.append(
                    {
                        "operation": operation.to_dict(),
                        "reason": safety.get("message", "Patch operation rejected."),
                        "error": safety.get("error"),
                    }
                )

        data = {
            "patch_operations": [operation.to_dict() for operation in safe_plan],
            "rejected_operations": rejected,
            "plan_count": len(safe_plan),
        }

        return self._safe_result(
            success=True,
            message=f"Patch plan built with {len(safe_plan)} safe operation(s).",
            data=data,
            metadata={"agent": self.agent_name, **dict(metadata or {})},
        )

    def apply_patch_plan(
        self,
        context: Union[DebugTaskContext, Mapping[str, Any]],
        patch_operations: Sequence[Union[PatchOperation, Mapping[str, Any]]],
        dry_run: bool = True,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Apply a patch plan safely.

        By default, dry_run=True. Real writes require:
            - config.allow_file_writes=True
            - security approval if config.require_security_for_writes=True
            - valid user_id/workspace_id context
            - target path inside project_root and not sensitive
        """

        safe_context = self._coerce_context(context)
        validation = self._validate_task_context(safe_context)
        if not validation["success"]:
            return validation

        normalized_ops: List[PatchOperation] = []
        for operation in patch_operations:
            coerced = self._coerce_patch_operation(operation)
            if coerced is not None:
                normalized_ops.append(coerced)

        if not normalized_ops:
            return self._safe_result(
                success=True,
                message="No patch operations to apply.",
                data={"patch_results": []},
                metadata={"agent": self.agent_name, "dry_run": dry_run, **dict(metadata or {})},
            )

        if not dry_run and not self.config.allow_file_writes:
            return self._error_result(
                message="File writes are disabled by SelfDebugger config.",
                error="file_writes_disabled",
                data={"patch_results": []},
                metadata={"agent": self.agent_name, "dry_run": dry_run, **dict(metadata or {})},
            )

        if self._requires_security_check(action="file_write", operations=normalized_ops):
            approval = self._request_security_approval(
                context=safe_context,
                action="self_debugger.apply_patch_plan",
                resource="file_system",
                payload={
                    "dry_run": dry_run,
                    "operations": [op.to_dict() for op in normalized_ops],
                },
            )
            if not approval.get("success"):
                return approval

        results: List[PatchResult] = []

        for operation in normalized_ops:
            validation_result = self._validate_patch_operation(operation)
            if not validation_result["success"]:
                results.append(
                    PatchResult(
                        file_path=operation.file_path,
                        changed=False,
                        reason=validation_result.get("message", "Patch validation failed."),
                        error=str(validation_result.get("error") or ""),
                    )
                )
                continue

            if dry_run:
                dry_result = self._preview_patch(operation)
                results.append(dry_result)
                continue

            apply_result = self._apply_single_patch(operation)
            results.append(apply_result)

        changed_count = sum(1 for item in results if item.changed)
        error_count = sum(1 for item in results if item.error)

        self._log_audit_event(
            safe_context,
            action="self_debugger.apply_patch_plan",
            status="success" if error_count == 0 else "partial",
            details={
                "dry_run": dry_run,
                "operation_count": len(normalized_ops),
                "changed_count": changed_count,
                "error_count": error_count,
            },
        )

        return self._safe_result(
            success=error_count == 0,
            message=(
                f"Patch plan processed. Changed files: {changed_count}."
                if not dry_run
                else f"Patch plan preview completed. Potential changes: {changed_count}."
            ),
            data={"patch_results": [result.to_dict() for result in results]},
            metadata={
                "agent": self.agent_name,
                "dry_run": dry_run,
                "changed_count": changed_count,
                "error_count": error_count,
                **dict(metadata or {}),
            },
        )

    def rerun_verification(
        self,
        context: Union[DebugTaskContext, Mapping[str, Any]],
        verification_commands: Optional[Sequence[Union[str, Sequence[str]]]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Rerun verification commands such as pytest, py_compile, unit tests, or linters.

        Command execution is disabled unless config.allow_command_execution=True.
        """

        safe_context = self._coerce_context(context)
        validation = self._validate_task_context(safe_context)
        if not validation["success"]:
            return validation

        commands = list(verification_commands or [])
        if not commands:
            commands = self._guess_verification_commands()

        if not commands:
            return self._safe_result(
                success=True,
                message="No verification commands configured; static validation passed.",
                data={"commands": [], "results": [], "all_passed": True},
                metadata={"agent": self.agent_name, **dict(metadata or {})},
            )

        if not self.config.allow_command_execution:
            return self._error_result(
                message="Command execution is disabled by SelfDebugger config.",
                error="command_execution_disabled",
                data={
                    "commands": [self._command_to_display(cmd) for cmd in commands],
                    "results": [],
                    "all_passed": False,
                },
                metadata={"agent": self.agent_name, **dict(metadata or {})},
            )

        for command in commands:
            command_text = self._command_to_display(command)
            command_safety = self._validate_command(command_text)
            if not command_safety["success"]:
                return command_safety

        if self._requires_security_check(action="command_execution", operations=commands):
            approval = self._request_security_approval(
                context=safe_context,
                action="self_debugger.rerun_verification",
                resource="subprocess",
                payload={"commands": [self._command_to_display(cmd) for cmd in commands]},
            )
            if not approval.get("success"):
                return approval

        results = [self._run_command(command) for command in commands]
        all_passed = all(result.returncode == 0 and not result.timed_out and not result.error for result in results)

        self._log_audit_event(
            safe_context,
            action="self_debugger.rerun_verification",
            status="success" if all_passed else "failed",
            details={
                "command_count": len(commands),
                "all_passed": all_passed,
                "commands": [result.command for result in results],
            },
        )

        return self._safe_result(
            success=all_passed,
            message="Verification passed." if all_passed else "Verification failed.",
            data={
                "commands": [self._command_to_display(cmd) for cmd in commands],
                "results": [result.to_dict() for result in results],
                "all_passed": all_passed,
            },
            metadata={"agent": self.agent_name, **dict(metadata or {})},
        )

    def verify_debug_success(
        self,
        context: Union[DebugTaskContext, Mapping[str, Any]],
        verification_result: Mapping[str, Any],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Decide whether debug cycle is successful.

        This method is intentionally simple and deterministic. The Verification
        Agent can consume the payload created here for deeper future validation.
        """

        safe_context = self._coerce_context(context)
        validation = self._validate_task_context(safe_context)
        if not validation["success"]:
            return validation

        data = verification_result.get("data", {}) if isinstance(verification_result, Mapping) else {}
        all_passed = bool(data.get("all_passed", verification_result.get("success", False)))

        payload = self._prepare_verification_payload(
            context=safe_context,
            action="self_debugger.verify_debug_success",
            success=all_passed,
            data={"verification_result": dict(verification_result)},
        )

        return self._safe_result(
            success=all_passed,
            message="Debug verification succeeded." if all_passed else "Debug verification did not pass.",
            data={"verified": all_passed, "verification_payload": payload},
            metadata={"agent": self.agent_name, **dict(metadata or {})},
        )

    # ------------------------------------------------------------------
    # Compatibility hooks required by William/Jarvis
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: DebugTaskContext) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        Required by architecture:
            - user_id
            - workspace_id
            - isolation metadata for audit/memory/verification
        """

        if context is None:
            return self._error_result(
                message="Task context is required.",
                error="missing_context",
                metadata={"agent": self.agent_name},
            )

        if context.user_id in (None, "", 0):
            return self._error_result(
                message="user_id is required for SelfDebugger execution.",
                error="missing_user_id",
                metadata={"agent": self.agent_name},
            )

        if context.workspace_id in (None, "", 0):
            return self._error_result(
                message="workspace_id is required for SelfDebugger execution.",
                error="missing_workspace_id",
                metadata={"agent": self.agent_name},
            )

        return self._safe_result(
            success=True,
            message="Task context validated.",
            data={"context": self._context_public_dict(context)},
            metadata={"agent": self.agent_name},
        )

    def _requires_security_check(self, action: str, operations: Any = None) -> bool:
        """
        Decide if Security Agent approval is needed.

        Sensitive actions:
            - file_write
            - command_execution
            - suspicious paths
            - blocked commands
        """

        if action == "file_write":
            if self.config.require_security_for_writes:
                return True
            for operation in operations or []:
                if isinstance(operation, PatchOperation) and self._is_sensitive_path(operation.file_path):
                    return True
            return False

        if action == "command_execution":
            if self.config.require_security_for_commands:
                return True
            for command in operations or []:
                if self._is_dangerous_command(self._command_to_display(command)):
                    return True
            return False

        return True

    def _request_security_approval(
        self,
        context: DebugTaskContext,
        action: str,
        resource: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent if available.

        Fallback behavior:
            - Deny sensitive actions when real execution is requested and no
              Security Agent is available.
            - Allow dry-run previews because they do not mutate state.
        """

        dry_run = bool(payload.get("dry_run", False))

        if self.security_agent is None:
            if dry_run:
                return self._safe_result(
                    success=True,
                    message="Security approval bypassed for dry-run preview.",
                    data={"approved": True, "fallback": True},
                    metadata={"agent": self.agent_name},
                )

            return self._error_result(
                message="Security approval is required but Security Agent is unavailable.",
                error="security_agent_unavailable",
                data={"approved": False, "action": action, "resource": resource},
                metadata={"agent": self.agent_name},
            )

        approval_methods = (
            "approve_action",
            "request_approval",
            "check_permission",
            "authorize",
        )

        for method_name in approval_methods:
            method = getattr(self.security_agent, method_name, None)
            if callable(method):
                try:
                    response = method(
                        user_id=context.user_id,
                        workspace_id=context.workspace_id,
                        action=action,
                        resource=resource,
                        payload=dict(payload),
                    )
                    return self._normalize_security_response(response)
                except TypeError:
                    try:
                        response = method(
                            {
                                "user_id": context.user_id,
                                "workspace_id": context.workspace_id,
                                "action": action,
                                "resource": resource,
                                "payload": dict(payload),
                            }
                        )
                        return self._normalize_security_response(response)
                    except Exception as exc:
                        return self._error_result(
                            message="Security approval failed.",
                            error=exc,
                            metadata={"agent": self.agent_name},
                        )
                except Exception as exc:
                    return self._error_result(
                        message="Security approval failed.",
                        error=exc,
                        metadata={"agent": self.agent_name},
                    )

        return self._error_result(
            message="Security Agent does not expose an approval method.",
            error="security_approval_method_missing",
            data={"approved": False, "action": action, "resource": resource},
            metadata={"agent": self.agent_name},
        )

    def _prepare_verification_payload(
        self,
        context: DebugTaskContext,
        action: str,
        success: bool,
        data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build a Verification Agent compatible payload.
        """

        payload = {
            "agent": self.agent_name,
            "module": self.agent_type,
            "action": action,
            "success": success,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "data": dict(data or {}),
            "created_at": self._utc_now(),
        }

        if self.verification_agent is not None:
            for method_name in ("prepare_payload", "build_payload", "receive_payload"):
                method = getattr(self.verification_agent, method_name, None)
                if callable(method):
                    try:
                        maybe_payload = method(payload)
                        if isinstance(maybe_payload, Mapping):
                            payload["verification_agent_response"] = dict(maybe_payload)
                        break
                    except Exception as exc:
                        payload["verification_agent_error"] = str(exc)
                        break

        return payload

    def _prepare_memory_payload(
        self,
        context: DebugTaskContext,
        memory_type: str,
        content: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Build a Memory Agent compatible payload.
        """

        payload = {
            "agent": self.agent_name,
            "module": self.agent_type,
            "memory_type": memory_type,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "content": dict(content),
            "created_at": self._utc_now(),
        }

        if self.memory_agent is not None:
            for method_name in ("prepare_memory", "build_memory_payload", "remember"):
                method = getattr(self.memory_agent, method_name, None)
                if callable(method):
                    try:
                        maybe_payload = method(payload)
                        if isinstance(maybe_payload, Mapping):
                            payload["memory_agent_response"] = dict(maybe_payload)
                        break
                    except Exception as exc:
                        payload["memory_agent_error"] = str(exc)
                        break

        return payload

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Emit dashboard/API/registry-friendly events.
        """

        event_payload = {
            "event": event_name,
            "agent": self.agent_name,
            "module": self.agent_type,
            "payload": payload,
            "created_at": self._utc_now(),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event_name, event_payload)
                return

            base_emit = getattr(super(), "emit_event", None)
            if callable(base_emit):
                base_emit(event_name, event_payload)
                return

            self.logger.debug("Agent event: %s", event_payload)
        except Exception:
            self.logger.debug("Failed to emit agent event", exc_info=True)

    def _log_audit_event(
        self,
        context: DebugTaskContext,
        action: str,
        status: str,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Create an audit event without mixing users/workspaces.
        """

        audit_payload = {
            "agent": self.agent_name,
            "module": self.agent_type,
            "action": action,
            "status": status,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "details": dict(details or {}),
            "created_at": self._utc_now(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit_payload)
                return

            base_audit = getattr(super(), "log_audit", None)
            if callable(base_audit):
                base_audit(audit_payload)
                return

            self.logger.info("Audit event: %s", audit_payload)
        except Exception:
            self.logger.debug("Failed to log audit event", exc_info=True)

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard William/Jarvis structured response.
        """

        return {
            "success": bool(success),
            "message": message,
            "data": dict(data or {}),
            "error": self._serialize_error(error) if error else None,
            "metadata": {
                "agent": self.agent_name,
                "module": self.agent_type,
                "timestamp": self._utc_now(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Any,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard error response.
        """

        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=error,
            metadata=metadata or {},
        )

    # ------------------------------------------------------------------
    # Error parsing
    # ------------------------------------------------------------------

    def _parse_error_text(self, error_text: str) -> List[ErrorFinding]:
        findings: List[ErrorFinding] = []
        text = error_text or ""

        if not text.strip():
            return findings

        findings.extend(self._parse_python_traceback(text))
        findings.extend(self._parse_pytest_failures(text))
        findings.extend(self._parse_import_errors(text))
        findings.extend(self._parse_syntax_errors(text))
        findings.extend(self._parse_lint_like_errors(text))

        if not findings:
            findings.append(
                ErrorFinding(
                    category="unknown_error",
                    message=self._truncate(text.strip(), 1000),
                    severity="medium",
                    raw=self._truncate(text, 4000),
                )
            )

        return self._deduplicate_findings(findings)

    def _parse_python_traceback(self, text: str) -> List[ErrorFinding]:
        findings: List[ErrorFinding] = []
        traceback_pattern = re.compile(
            r'File\s+"(?P<file>[^"]+)",\s+line\s+(?P<line>\d+)(?:,\s+in\s+(?P<symbol>[^\n]+))?'
        )
        exception_pattern = re.compile(r"(?P<type>[A-Za-z_][A-Za-z0-9_]*(?:Error|Exception)):\s*(?P<msg>.+)")

        frames = list(traceback_pattern.finditer(text))
        exception_match = None
        for match in exception_pattern.finditer(text):
            exception_match = match

        if frames and exception_match:
            last_frame = frames[-1]
            findings.append(
                ErrorFinding(
                    category=exception_match.group("type"),
                    message=exception_match.group("msg").strip(),
                    file_path=last_frame.group("file"),
                    line_number=self._to_int(last_frame.group("line")),
                    symbol=(last_frame.group("symbol") or "").strip() or None,
                    severity="high",
                    raw=self._truncate(text, 4000),
                )
            )

        return findings

    def _parse_pytest_failures(self, text: str) -> List[ErrorFinding]:
        findings: List[ErrorFinding] = []

        for match in re.finditer(r"FAILED\s+(?P<path>[^\s:]+)(?:::(?P<test>[^\s]+))?", text):
            findings.append(
                ErrorFinding(
                    category="pytest_failure",
                    message=f"Test failed: {match.group('test') or match.group('path')}",
                    file_path=match.group("path"),
                    symbol=match.group("test"),
                    severity="high",
                    raw=self._truncate(match.group(0), 1000),
                )
            )

        short_summary = re.search(r"=+\s+short test summary info\s+=+\n(?P<body>.+)", text, re.DOTALL | re.IGNORECASE)
        if short_summary and not findings:
            findings.append(
                ErrorFinding(
                    category="pytest_failure",
                    message=self._truncate(short_summary.group("body").strip(), 1000),
                    severity="high",
                    raw=self._truncate(short_summary.group(0), 3000),
                )
            )

        return findings

    def _parse_import_errors(self, text: str) -> List[ErrorFinding]:
        findings: List[ErrorFinding] = []
        patterns = [
            (r"ModuleNotFoundError:\s+No module named ['\"](?P<module>[^'\"]+)['\"]", "ModuleNotFoundError"),
            (r"ImportError:\s+cannot import name ['\"](?P<symbol>[^'\"]+)['\"] from ['\"](?P<module>[^'\"]+)['\"]", "ImportError"),
            (r"ImportError:\s+(?P<msg>.+)", "ImportError"),
        ]

        for pattern, category in patterns:
            for match in re.finditer(pattern, text):
                module = match.groupdict().get("module")
                symbol = match.groupdict().get("symbol")
                msg = match.groupdict().get("msg")
                if module and symbol:
                    message = f"Cannot import {symbol} from {module}"
                elif module:
                    message = f"Missing module: {module}"
                else:
                    message = msg or match.group(0)

                findings.append(
                    ErrorFinding(
                        category=category,
                        message=message,
                        symbol=symbol or module,
                        severity="high",
                        raw=self._truncate(match.group(0), 1000),
                    )
                )

        return findings

    def _parse_syntax_errors(self, text: str) -> List[ErrorFinding]:
        findings: List[ErrorFinding] = []

        syntax_file_line = re.compile(
            r'File\s+"(?P<file>[^"]+)",\s+line\s+(?P<line>\d+)\n'
            r"(?P<code>.*?)\n"
            r"\s*\^+\n"
            r"(?P<category>SyntaxError|IndentationError|TabError):\s*(?P<msg>.+)",
            re.DOTALL,
        )

        for match in syntax_file_line.finditer(text):
            findings.append(
                ErrorFinding(
                    category=match.group("category"),
                    message=match.group("msg").strip(),
                    file_path=match.group("file"),
                    line_number=self._to_int(match.group("line")),
                    severity="high",
                    raw=self._truncate(match.group(0), 2000),
                )
            )

        simple_pattern = re.compile(r"(?P<category>SyntaxError|IndentationError|TabError):\s*(?P<msg>.+)")
        if not findings:
            for match in simple_pattern.finditer(text):
                findings.append(
                    ErrorFinding(
                        category=match.group("category"),
                        message=match.group("msg").strip(),
                        severity="high",
                        raw=self._truncate(match.group(0), 1000),
                    )
                )

        return findings

    def _parse_lint_like_errors(self, text: str) -> List[ErrorFinding]:
        findings: List[ErrorFinding] = []
        pattern = re.compile(
            r"(?P<file>[\w./\\-]+\.\w+):(?P<line>\d+):(?:(?P<col>\d+):)?\s*"
            r"(?P<code>[A-Z]\d+|[A-Z]{1,5}\d{1,5}|error|warning)?\s*"
            r"(?P<msg>.+)"
        )

        for match in pattern.finditer(text):
            msg = match.group("msg").strip()
            if not msg:
                continue

            findings.append(
                ErrorFinding(
                    category=match.group("code") or "lint_error",
                    message=msg,
                    file_path=match.group("file"),
                    line_number=self._to_int(match.group("line")),
                    severity="medium",
                    raw=self._truncate(match.group(0), 1000),
                )
            )

        return findings

    def _deduplicate_findings(self, findings: Iterable[ErrorFinding]) -> List[ErrorFinding]:
        seen = set()
        unique: List[ErrorFinding] = []

        for finding in findings:
            key = (
                finding.category,
                finding.message,
                finding.file_path,
                finding.line_number,
                finding.symbol,
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)

        return unique

    def _summarize_findings(self, findings: Sequence[ErrorFinding]) -> Dict[str, Any]:
        by_category: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}

        for finding in findings:
            by_category[finding.category] = by_category.get(finding.category, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        return {
            "total": len(findings),
            "by_category": by_category,
            "by_severity": by_severity,
            "highest_severity": self._highest_severity(findings),
        }

    def _highest_severity(self, findings: Sequence[ErrorFinding]) -> Optional[str]:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        if not findings:
            return None
        return max((finding.severity for finding in findings), key=lambda item: order.get(item, 0))

    # ------------------------------------------------------------------
    # Conservative patch generation
    # ------------------------------------------------------------------

    def _generate_conservative_patch_plan(
        self,
        analysis: Mapping[str, Any],
        target_files: Sequence[Union[str, Path]],
    ) -> List[PatchOperation]:
        """
        Conservative automatic patching.

        This intentionally handles only low-risk text transformations.
        Anything complex is surfaced as analysis for CodeWriter/CodeEditor or a
        human review rather than blindly rewriting code.
        """

        plan: List[PatchOperation] = []
        findings = analysis.get("findings", [])
        normalized_targets = [self._resolve_project_path(path) for path in target_files]

        for finding_raw in findings:
            if not isinstance(finding_raw, Mapping):
                continue

            category = str(finding_raw.get("category") or "")
            file_path = finding_raw.get("file_path")
            message = str(finding_raw.get("message") or "")

            if file_path:
                candidate = self._resolve_project_path(str(file_path))
            elif len(normalized_targets) == 1:
                candidate = normalized_targets[0]
            else:
                candidate = None

            if candidate is None or not candidate.exists() or not candidate.is_file():
                continue

            if category in {"TabError"} or "inconsistent use of tabs and spaces" in message.lower():
                op = self._build_tabs_to_spaces_patch(candidate)
                if op:
                    plan.append(op)

            elif category in {"IndentationError"} and "unindent does not match" in message.lower():
                op = self._build_tabs_to_spaces_patch(candidate)
                if op:
                    plan.append(op)

            elif category == "SyntaxError" and "invalid non-printable character" in message.lower():
                op = self._build_non_printable_cleanup_patch(candidate)
                if op:
                    plan.append(op)

            elif category in {"ModuleNotFoundError", "ImportError"}:
                # Dependency/import errors are not patched blindly. The Dependency
                # Manager or Code Writer should decide exact install/import changes.
                continue

        return plan

    def _build_tabs_to_spaces_patch(self, file_path: Path) -> Optional[PatchOperation]:
        try:
            content = file_path.read_text(encoding=self.config.encoding)
        except Exception:
            return None

        new_content = content.replace("\t", "    ")
        if new_content == content:
            return None

        return PatchOperation(
            file_path=str(file_path),
            old_text=content,
            new_text=new_content,
            reason="Normalize tabs to four spaces to fix TabError/IndentationError.",
            allow_multiple=False,
        )

    def _build_non_printable_cleanup_patch(self, file_path: Path) -> Optional[PatchOperation]:
        try:
            content = file_path.read_text(encoding=self.config.encoding)
        except Exception:
            return None

        cleaned = "".join(ch for ch in content if ch == "\n" or ch == "\t" or ch == "\r" or ord(ch) >= 32)
        if cleaned == content:
            return None

        return PatchOperation(
            file_path=str(file_path),
            old_text=content,
            new_text=cleaned,
            reason="Remove invalid non-printable characters that can cause SyntaxError.",
            allow_multiple=False,
        )

    # ------------------------------------------------------------------
    # Patch validation/application
    # ------------------------------------------------------------------

    def _validate_patch_operation(self, operation: PatchOperation) -> Dict[str, Any]:
        if not operation.file_path:
            return self._error_result("Patch operation missing file_path.", "missing_file_path")

        if operation.old_text is None or operation.new_text is None:
            return self._error_result("Patch operation requires old_text and new_text.", "missing_patch_text")

        target = self._resolve_project_path(operation.file_path)

        if not self._is_path_inside_project(target):
            return self._error_result(
                "Patch target is outside project_root.",
                "path_outside_project",
                data={"file_path": str(target), "project_root": str(self.project_root)},
            )

        if self._is_sensitive_path(str(target)):
            return self._error_result(
                "Patch target appears sensitive and is blocked.",
                "sensitive_path_blocked",
                data={"file_path": str(target)},
            )

        if self._is_in_blocked_directory(target):
            return self._error_result(
                "Patch target is inside a blocked directory.",
                "blocked_directory",
                data={"file_path": str(target)},
            )

        if target.suffix and target.suffix not in self.config.allowed_file_extensions:
            if not str(target).endswith(".env.example"):
                return self._error_result(
                    "Patch target extension is not allowed.",
                    "extension_not_allowed",
                    data={"file_path": str(target), "extension": target.suffix},
                )

        patch_size = len(operation.old_text.encode(self.config.encoding, errors="ignore")) + len(
            operation.new_text.encode(self.config.encoding, errors="ignore")
        )
        if patch_size > self.config.max_patch_bytes:
            return self._error_result(
                "Patch operation exceeds max_patch_bytes.",
                "patch_too_large",
                data={"patch_size": patch_size, "max_patch_bytes": self.config.max_patch_bytes},
            )

        if not target.exists():
            return self._error_result(
                "Patch target file does not exist.",
                "file_not_found",
                data={"file_path": str(target)},
            )

        if not target.is_file():
            return self._error_result(
                "Patch target is not a file.",
                "not_a_file",
                data={"file_path": str(target)},
            )

        return self._safe_result(
            success=True,
            message="Patch operation validated.",
            data={"file_path": str(target)},
        )

    def _preview_patch(self, operation: PatchOperation) -> PatchResult:
        target = self._resolve_project_path(operation.file_path)

        try:
            original = target.read_text(encoding=self.config.encoding)
            replaced, changed = self._replace_text(
                original,
                operation.old_text,
                operation.new_text,
                allow_multiple=operation.allow_multiple,
            )
            diff = self._make_unified_diff(
                original,
                replaced,
                fromfile=str(target),
                tofile=f"{target} (patched preview)",
            )
            return PatchResult(
                file_path=str(target),
                changed=changed,
                reason=operation.reason if changed else "No changes previewed.",
                diff=diff,
            )
        except Exception as exc:
            return PatchResult(
                file_path=str(target),
                changed=False,
                reason="Patch preview failed.",
                error=str(exc),
            )

    def _apply_single_patch(self, operation: PatchOperation) -> PatchResult:
        target = self._resolve_project_path(operation.file_path)

        try:
            original = target.read_text(encoding=self.config.encoding)
            replaced, changed = self._replace_text(
                original,
                operation.old_text,
                operation.new_text,
                allow_multiple=operation.allow_multiple,
            )

            if not changed:
                return PatchResult(
                    file_path=str(target),
                    changed=False,
                    reason="old_text not found or replacement produced no change.",
                    error="no_change",
                )

            backup_path = None
            if self.config.create_backups:
                backup_path_obj = self._build_backup_path(target)
                backup_path_obj.write_text(original, encoding=self.config.encoding)
                backup_path = str(backup_path_obj)

            target.write_text(replaced, encoding=self.config.encoding)

            diff = self._make_unified_diff(
                original,
                replaced,
                fromfile=str(target),
                tofile=f"{target} (patched)",
            )

            return PatchResult(
                file_path=str(target),
                changed=True,
                reason=operation.reason,
                backup_path=backup_path,
                diff=diff,
            )

        except Exception as exc:
            self.logger.exception("Failed to apply patch to %s", target)
            return PatchResult(
                file_path=str(target),
                changed=False,
                reason="Patch application failed.",
                error=str(exc),
            )

    def _replace_text(
        self,
        original: str,
        old_text: str,
        new_text: str,
        allow_multiple: bool = False,
    ) -> Tuple[str, bool]:
        if old_text == "":
            raise ValueError("old_text cannot be empty.")

        count = original.count(old_text)

        if count == 0:
            return original, False

        if count > 1 and not allow_multiple:
            raise ValueError(
                f"old_text appears {count} times. Set allow_multiple=True for broad replacement."
            )

        replaced = original.replace(old_text, new_text if new_text is not None else "", -1 if allow_multiple else 1)
        return replaced, replaced != original

    def _make_unified_diff(self, original: str, changed: str, fromfile: str, tofile: str) -> str:
        return "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                changed.splitlines(keepends=True),
                fromfile=fromfile,
                tofile=tofile,
            )
        )

    def _build_backup_path(self, target: Path) -> Path:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        return target.with_name(f"{target.name}.{timestamp}{self.config.backup_suffix}")

    # ------------------------------------------------------------------
    # Verification command execution
    # ------------------------------------------------------------------

    def _guess_verification_commands(self) -> List[str]:
        commands: List[str] = []

        pyproject = self.project_root / "pyproject.toml"
        pytest_ini = self.project_root / "pytest.ini"
        tests_dir = self.project_root / "tests"

        if tests_dir.exists() or pytest_ini.exists():
            commands.append("python -m pytest")

        if pyproject.exists():
            try:
                content = pyproject.read_text(encoding=self.config.encoding)
                if "[tool.ruff" in content:
                    commands.append("ruff check .")
                if "[tool.mypy" in content:
                    commands.append("mypy .")
            except Exception:
                pass

        if not commands:
            python_files = [path for path in self.project_root.rglob("*.py") if not self._is_in_blocked_directory(path)]
            if python_files:
                commands.append("python -m compileall .")

        return commands

    def _run_command(self, command: Union[str, Sequence[str]]) -> CommandResult:
        command_display = self._command_to_display(command)
        started = time.monotonic()

        try:
            if isinstance(command, str):
                args = shlex.split(command)
            else:
                args = [str(part) for part in command]

            process = subprocess.run(
                args,
                cwd=str(self.project_root),
                capture_output=True,
                text=True,
                timeout=self.config.command_timeout_seconds,
                shell=False,
                check=False,
            )

            return CommandResult(
                command=command_display,
                cwd=str(self.project_root),
                returncode=process.returncode,
                stdout=process.stdout or "",
                stderr=process.stderr or "",
                duration_seconds=round(time.monotonic() - started, 4),
                timed_out=False,
                error=None,
            )

        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                command=command_display,
                cwd=str(self.project_root),
                returncode=None,
                stdout=exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
                stderr=exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
                duration_seconds=round(time.monotonic() - started, 4),
                timed_out=True,
                error=f"Command timed out after {self.config.command_timeout_seconds} seconds.",
            )
        except Exception as exc:
            return CommandResult(
                command=command_display,
                cwd=str(self.project_root),
                returncode=None,
                stdout="",
                stderr="",
                duration_seconds=round(time.monotonic() - started, 4),
                timed_out=False,
                error=str(exc),
            )

    def _validate_command(self, command_text: str) -> Dict[str, Any]:
        if not command_text.strip():
            return self._error_result("Command is empty.", "empty_command")

        if self._is_dangerous_command(command_text):
            return self._error_result(
                "Command is blocked by SelfDebugger safety rules.",
                "dangerous_command_blocked",
                data={"command": command_text},
                metadata={"agent": self.agent_name},
            )

        return self._safe_result(
            success=True,
            message="Command validated.",
            data={"command": command_text},
            metadata={"agent": self.agent_name},
        )

    def _is_dangerous_command(self, command_text: str) -> bool:
        lowered = command_text.lower()
        return any(re.search(pattern, lowered) for pattern in DANGEROUS_COMMAND_PATTERNS)

    def _command_to_display(self, command: Union[str, Sequence[str]]) -> str:
        if isinstance(command, str):
            return command
        return " ".join(shlex.quote(str(part)) for part in command)

    def _extract_error_text_from_verification(self, verification_data: Mapping[str, Any]) -> str:
        chunks: List[str] = []

        for result in verification_data.get("results", []) or []:
            if not isinstance(result, Mapping):
                continue

            if result.get("returncode") not in (0, None):
                chunks.append(str(result.get("stdout") or ""))
                chunks.append(str(result.get("stderr") or ""))

            if result.get("timed_out") or result.get("error"):
                chunks.append(str(result.get("error") or ""))

        return "\n".join(chunk for chunk in chunks if chunk).strip()

    # ------------------------------------------------------------------
    # File helpers
    # ------------------------------------------------------------------

    def _collect_file_snapshots(self, target_files: Sequence[Union[str, Path]]) -> List[Dict[str, Any]]:
        snapshots: List[Dict[str, Any]] = []

        for item in target_files:
            path = self._resolve_project_path(item)
            snapshot: Dict[str, Any] = {
                "file_path": str(path),
                "exists": path.exists(),
                "is_file": path.is_file(),
                "inside_project": self._is_path_inside_project(path),
                "sensitive": self._is_sensitive_path(str(path)),
                "blocked_directory": self._is_in_blocked_directory(path),
            }

            if path.exists() and path.is_file():
                try:
                    stat = path.stat()
                    snapshot.update(
                        {
                            "size_bytes": stat.st_size,
                            "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                            "extension": path.suffix,
                        }
                    )
                    if stat.st_size <= 50_000 and not self._is_sensitive_path(str(path)):
                        content = path.read_text(encoding=self.config.encoding, errors="replace")
                        snapshot["preview"] = self._truncate(content, 4000)
                except Exception as exc:
                    snapshot["read_error"] = str(exc)

            snapshots.append(snapshot)

        return snapshots

    def _resolve_project_path(self, path: Union[str, Path]) -> Path:
        candidate = Path(path).expanduser()
        if candidate.is_absolute():
            return candidate.resolve()
        return (self.project_root / candidate).resolve()

    def _is_path_inside_project(self, path: Path) -> bool:
        try:
            path.resolve().relative_to(self.project_root)
            return True
        except Exception:
            return False

    def _is_sensitive_path(self, path: str) -> bool:
        lowered = path.replace("\\", "/").lower()
        parts = set(Path(lowered).parts)
        if any(part in parts for part in SENSITIVE_PATH_PARTS):
            return True
        return any(token in lowered for token in SENSITIVE_PATH_PARTS)

    def _is_in_blocked_directory(self, path: Path) -> bool:
        lowered_parts = {part.lower() for part in path.parts}
        return any(blocked.lower() in lowered_parts for blocked in self.config.blocked_directory_names)

    # ------------------------------------------------------------------
    # Coercion / normalization
    # ------------------------------------------------------------------

    def _coerce_context(self, context: Union[DebugTaskContext, Mapping[str, Any]]) -> DebugTaskContext:
        if isinstance(context, DebugTaskContext):
            return context

        if isinstance(context, Mapping):
            permissions_raw = context.get("permissions", [])
            if isinstance(permissions_raw, str):
                permissions = [permissions_raw]
            elif isinstance(permissions_raw, Iterable):
                permissions = [str(item) for item in permissions_raw]
            else:
                permissions = []

            metadata_raw = context.get("metadata", {})
            metadata = dict(metadata_raw) if isinstance(metadata_raw, Mapping) else {}

            return DebugTaskContext(
                user_id=context.get("user_id"),
                workspace_id=context.get("workspace_id"),
                request_id=context.get("request_id"),
                role=context.get("role"),
                permissions=permissions,
                metadata=metadata,
            )

        return DebugTaskContext(user_id=None, workspace_id=None)  # type: ignore[arg-type]

    def _coerce_patch_operation(
        self,
        operation: Union[PatchOperation, Mapping[str, Any]],
    ) -> Optional[PatchOperation]:
        if isinstance(operation, PatchOperation):
            return operation

        if isinstance(operation, Mapping):
            try:
                return PatchOperation(
                    file_path=str(operation.get("file_path") or ""),
                    old_text=str(operation.get("old_text") if operation.get("old_text") is not None else ""),
                    new_text=str(operation.get("new_text") if operation.get("new_text") is not None else ""),
                    reason=str(operation.get("reason") or "SelfDebugger patch operation."),
                    allow_multiple=bool(operation.get("allow_multiple", False)),
                )
            except Exception:
                return None

        return None

    def _normalize_security_response(self, response: Any) -> Dict[str, Any]:
        if isinstance(response, Mapping):
            approved = bool(
                response.get("approved")
                if "approved" in response
                else response.get("success", False)
            )
            if approved:
                return self._safe_result(
                    success=True,
                    message=str(response.get("message") or "Security approval granted."),
                    data={"approved": True, "security_response": dict(response)},
                    metadata={"agent": self.agent_name},
                )
            return self._error_result(
                message=str(response.get("message") or "Security approval denied."),
                error=response.get("error") or "security_denied",
                data={"approved": False, "security_response": dict(response)},
                metadata={"agent": self.agent_name},
            )

        if response is True:
            return self._safe_result(
                success=True,
                message="Security approval granted.",
                data={"approved": True},
                metadata={"agent": self.agent_name},
            )

        return self._error_result(
            message="Security approval denied.",
            error="security_denied",
            data={"approved": False, "security_response": response},
            metadata={"agent": self.agent_name},
        )

    def _safe_instantiate_agent(self, cls: Any) -> Optional[Any]:
        try:
            return cls()
        except Exception:
            try:
                return cls(user_id=None, workspace_id=None)
            except Exception:
                return None

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _context_public_dict(self, context: DebugTaskContext) -> Dict[str, Any]:
        return {
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "role": context.role,
            "permissions": list(context.permissions),
            "metadata": dict(context.metadata),
        }

    def _serialize_error(self, error: Any) -> Dict[str, Any]:
        if isinstance(error, BaseException):
            return {
                "type": error.__class__.__name__,
                "message": str(error),
                "traceback": traceback.format_exc(),
            }

        if isinstance(error, Mapping):
            return dict(error)

        return {
            "type": error.__class__.__name__ if error is not None else "None",
            "message": str(error),
        }

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _truncate(self, text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        return text[: max(limit - 3, 0)] + "..."

    def _to_int(self, value: Any) -> Optional[int]:
        try:
            return int(value)
        except Exception:
            return None

    def _safe_positive_int(self, value: Optional[int], default: int, min_value: int = 1) -> int:
        try:
            number = int(value if value is not None else default)
        except Exception:
            number = int(default)
        return max(number, min_value)


# ---------------------------------------------------------------------------
# Standalone smoke test helper
# ---------------------------------------------------------------------------

def _standalone_smoke_test() -> Dict[str, Any]:
    """
    Lightweight smoke test for direct execution.

    This does not write files or run shell commands. It validates that the
    SelfDebugger can parse errors and produce a dry-run structured result.
    """

    debugger = SelfDebugger(
        config=DebuggerConfig(
            project_root=".",
            allow_file_writes=False,
            allow_command_execution=False,
        )
    )

    sample_error = (
        'Traceback (most recent call last):\n'
        '  File "demo.py", line 10, in <module>\n'
        "    import missing_package\n"
        "ModuleNotFoundError: No module named 'missing_package'\n"
    )

    return debugger.run_debug_cycle(
        context={"user_id": "demo_user", "workspace_id": "demo_workspace"},
        initial_error_text=sample_error,
        target_files=[],
        verification_commands=[],
        dry_run=True,
        max_cycles=1,
        metadata={"source": "standalone_smoke_test"},
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(_standalone_smoke_test(), indent=2, default=str))
