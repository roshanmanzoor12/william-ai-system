"""
agents/code_agent/security_checker.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Code Agent Security Checker

Purpose:
    Scans code for:
    - Secrets / hardcoded credentials
    - Injection risks
    - Unsafe system commands
    - Weak access control
    - SaaS isolation violations
    - Dangerous imports / APIs
    - Insecure crypto / hashing
    - Risky file, network, subprocess, eval/exec usage

Architecture Compatibility:
    - BaseAgent compatible with fallback stub
    - Master Agent routable
    - Agent Registry / Loader import-safe
    - Security Agent approval ready
    - Memory Agent payload ready
    - Verification Agent payload ready
    - Dashboard/API structured output ready
    - SaaS user_id/workspace_id isolation enforced

Safety Priority:
    Safety > SaaS isolation > BaseAgent compatibility > MasterAgent routing > file-specific features.
"""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe if the main William/Jarvis BaseAgent
        has not been generated yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "code_agent")
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_name, payload)


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Enums / dataclasses
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(str, Enum):
    SECRET = "secret"
    INJECTION = "injection"
    UNSAFE_COMMAND = "unsafe_command"
    ACCESS_CONTROL = "access_control"
    SAAS_ISOLATION = "saas_isolation"
    DANGEROUS_IMPORT = "dangerous_import"
    INSECURE_CRYPTO = "insecure_crypto"
    FILE_SYSTEM = "file_system"
    NETWORK = "network"
    CONFIG = "config"
    DEPENDENCY = "dependency"
    GENERAL = "general"


@dataclass
class SecurityFinding:
    """
    A normalized security finding.

    Used by Code Agent, Security Agent, Verification Agent, dashboards,
    audit logs, and future reporting tools.
    """

    finding_id: str
    category: str
    severity: str
    title: str
    message: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column: Optional[int] = None
    matched_text: Optional[str] = None
    rule_id: Optional[str] = None
    recommendation: Optional[str] = None
    confidence: float = 0.75
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityRule:
    """
    Regex/static analysis rule definition.
    """

    rule_id: str
    category: FindingCategory
    severity: Severity
    title: str
    pattern: Optional[re.Pattern[str]] = None
    message: str = ""
    recommendation: str = ""
    confidence: float = 0.75
    file_extensions: Tuple[str, ...] = (
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".json",
        ".env",
        ".yml",
        ".yaml",
        ".php",
        ".html",
        ".css",
        ".sh",
        ".dockerfile",
        "Dockerfile",
    )


@dataclass
class ScanSummary:
    """
    Security scan summary for dashboards and verification.
    """

    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    risk_score: int = 0
    passed: bool = True


# ---------------------------------------------------------------------------
# SecurityChecker
# ---------------------------------------------------------------------------

class SecurityChecker(BaseAgent):
    """
    Code Agent helper that scans code for security weaknesses.

    Public methods:
        - scan_code()
        - scan_file()
        - scan_directory()
        - check_before_write()
        - check_before_execute()
        - summarize_findings()

    Master Agent:
        Can route code review/security tasks here.

    Security Agent:
        Sensitive or high-risk code may be forwarded for approval.

    Memory Agent:
        Safe summaries can be stored for future project context.

    Verification Agent:
        Completed scan results can be converted into a verification payload.

    Dashboard/API:
        All results are structured dicts with success, message, data, error,
        metadata.
    """

    SAFE_MAX_FILE_SIZE_BYTES = 750_000
    SAFE_MAX_DIRECTORY_FILES = 500

    SECRET_VALUE_MIN_LENGTH = 12

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        security_agent: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
    ) -> None:
        super().__init__(agent_name="SecurityChecker", agent_type="code_agent")
        self.config = config or {}
        self.security_agent = security_agent
        self.audit_logger = audit_logger
        self.event_bus = event_bus
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.logger = logging.getLogger(self.__class__.__name__)

        self.block_on_critical = bool(self.config.get("block_on_critical", True))
        self.block_on_high = bool(self.config.get("block_on_high", False))
        self.require_saas_context = bool(self.config.get("require_saas_context", True))
        self.scan_dependencies = bool(self.config.get("scan_dependencies", True))

        self.rules = self._build_default_rules()

    # -----------------------------------------------------------------------
    # Required compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(self, context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate user/workspace isolation context.

        Every user-specific execution must carry user_id and workspace_id.
        """
        context = context or {}
        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")

        if self.require_saas_context and (not user_id or not workspace_id):
            return self._error_result(
                message="Missing required SaaS isolation context.",
                error={
                    "code": "missing_context",
                    "details": "user_id and workspace_id are required for security scanning.",
                },
                metadata={
                    "required_fields": ["user_id", "workspace_id"],
                    "received_fields": sorted(list(context.keys())),
                },
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "request_id": context.get("request_id"),
                "actor": context.get("actor"),
            },
        )

    def _requires_security_check(self, action: str, payload: Optional[Dict[str, Any]] = None) -> bool:
        """
        Decide whether an action needs security approval.

        This file itself is a security checker, so high-risk actions always
        require approval if execution/write/deploy is involved.
        """
        payload = payload or {}
        action_lower = action.lower().strip()

        sensitive_actions = {
            "execute_code",
            "run_terminal",
            "write_file",
            "edit_file",
            "deploy",
            "install_dependency",
            "delete_file",
            "modify_permissions",
            "network_request",
            "browser_action",
        }

        if action_lower in sensitive_actions:
            return True

        if payload.get("contains_critical_findings") is True:
            return True

        if payload.get("contains_high_findings") is True and self.block_on_high:
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        payload: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent if available.

        Falls back to deny-by-default for critical dangerous actions when no
        Security Agent exists.
        """
        context = context or {}

        approval_payload = {
            "action": action,
            "payload": payload,
            "context": {
                "user_id": context.get("user_id"),
                "workspace_id": context.get("workspace_id"),
                "request_id": context.get("request_id"),
            },
            "requested_by": "SecurityChecker",
            "timestamp": int(time.time()),
        }

        if self.security_agent and hasattr(self.security_agent, "request_approval"):
            try:
                approval = self.security_agent.request_approval(approval_payload)
                return self._safe_result(
                    message="Security approval requested.",
                    data={"approval": approval},
                    metadata={"action": action},
                )
            except Exception as exc:
                return self._error_result(
                    message="Security approval request failed.",
                    error={"code": "approval_failed", "details": str(exc)},
                    metadata={"action": action},
                )

        critical = bool(payload.get("contains_critical_findings"))
        if critical:
            return self._error_result(
                message="Security Agent unavailable. Critical action denied by safe default.",
                error={
                    "code": "security_agent_unavailable",
                    "details": "Critical findings require explicit approval.",
                },
                metadata={"action": action},
            )

        return self._safe_result(
            message="Security Agent unavailable. No critical findings detected; approval not required.",
            data={"approved": True, "fallback": True},
            metadata={"action": action},
        )

    def _prepare_verification_payload(
        self,
        scan_result: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload after scan completion.
        """
        context = context or {}
        data = scan_result.get("data", {}) if isinstance(scan_result, dict) else {}

        return {
            "verification_type": "code_security_scan",
            "agent": "SecurityChecker",
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "request_id": context.get("request_id"),
            "passed": data.get("summary", {}).get("passed", False),
            "risk_score": data.get("summary", {}).get("risk_score"),
            "findings_count": data.get("summary", {}).get("total_findings"),
            "critical": data.get("summary", {}).get("critical"),
            "high": data.get("summary", {}).get("high"),
            "metadata": {
                "scanned_at": int(time.time()),
                "scan_target": data.get("target"),
                "scanner_version": "1.0.0",
            },
            "raw_result": scan_result,
        }

    def _prepare_memory_payload(
        self,
        scan_result: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare safe Memory Agent payload.

        Does not store full secrets or sensitive matched text.
        """
        context = context or {}
        data = scan_result.get("data", {}) if isinstance(scan_result, dict) else {}
        summary = data.get("summary", {})

        categories = sorted(
            set(
                finding.get("category", "general")
                for finding in data.get("findings", [])
                if isinstance(finding, dict)
            )
        )

        return {
            "memory_type": "code_security_summary",
            "agent": "SecurityChecker",
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "request_id": context.get("request_id"),
            "content": {
                "target": data.get("target"),
                "summary": summary,
                "categories": categories,
                "safe_recommendations": data.get("recommendations", []),
            },
            "sensitive": False,
            "timestamp": int(time.time()),
        }

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Emit event to dashboard/event bus if available.
        """
        try:
            if self.event_bus and hasattr(self.event_bus, "emit"):
                self.event_bus.emit(event_name, payload)
                return

            if hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_name, payload)
                    return
                except Exception:
                    pass

            self.logger.debug("Agent event: %s %s", event_name, payload)
        except Exception as exc:
            self.logger.warning("Failed to emit event %s: %s", event_name, exc)

    def _log_audit_event(
        self,
        action: str,
        context: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event for SaaS dashboards and compliance.
        """
        context = context or {}
        metadata = metadata or {}

        event = {
            "agent": "SecurityChecker",
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "request_id": context.get("request_id"),
            "metadata": metadata,
            "timestamp": int(time.time()),
        }

        try:
            if self.audit_logger and hasattr(self.audit_logger, "log"):
                self.audit_logger.log(event)
            else:
                self.logger.info("AUDIT %s", json.dumps(event, default=str))
        except Exception as exc:
            self.logger.warning("Audit logging failed: %s", exc)

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
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error response.
        """
        normalized_error: Dict[str, Any]
        if isinstance(error, dict):
            normalized_error = error
        elif isinstance(error, str):
            normalized_error = {"code": "error", "details": error}
        else:
            normalized_error = {"code": "unknown_error", "details": message}

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": normalized_error,
            "metadata": metadata or {},
        }

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def scan_code(
        self,
        code: str,
        file_path: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        language: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Scan raw code text.

        Args:
            code: Source code/content to scan.
            file_path: Optional file path for extension-aware rules.
            context: SaaS context with user_id and workspace_id.
            language: Optional language hint.

        Returns:
            Structured scan result.
        """
        context_result = self._validate_task_context(context)
        if not context_result["success"]:
            return context_result

        if not isinstance(code, str):
            return self._error_result(
                message="Code must be a string.",
                error={"code": "invalid_code_type"},
            )

        target = file_path or "<inline_code>"
        start = time.time()

        self._emit_agent_event(
            "code_security_scan_started",
            {
                "target": target,
                "user_id": (context or {}).get("user_id"),
                "workspace_id": (context or {}).get("workspace_id"),
            },
        )

        findings: List[SecurityFinding] = []
        findings.extend(self._scan_regex_rules(code, file_path))
        findings.extend(self._scan_python_ast_if_possible(code, file_path))
        findings.extend(self._scan_saas_isolation(code, file_path))
        findings.extend(self._scan_access_control(code, file_path))
        findings.extend(self._scan_dependency_content(code, file_path))

        findings = self._deduplicate_findings(findings)
        summary = self.summarize_findings(findings)
        recommendations = self._build_recommendations(findings)

        elapsed_ms = int((time.time() - start) * 1000)

        result = self._safe_result(
            message="Security scan completed.",
            data={
                "target": target,
                "language": language or self._guess_language(file_path),
                "summary": asdict(summary),
                "findings": [asdict(finding) for finding in findings],
                "recommendations": recommendations,
                "blocked": self._should_block(summary),
                "verification_payload": None,
                "memory_payload": None,
            },
            metadata={
                "scanner": "SecurityChecker",
                "scanner_version": "1.0.0",
                "elapsed_ms": elapsed_ms,
                "code_sha256": self._sha256_text(code),
            },
        )

        result["data"]["verification_payload"] = self._prepare_verification_payload(result, context)
        result["data"]["memory_payload"] = self._prepare_memory_payload(result, context)

        self._log_audit_event(
            action="scan_code",
            context=context,
            metadata={
                "target": target,
                "total_findings": summary.total_findings,
                "risk_score": summary.risk_score,
                "blocked": result["data"]["blocked"],
            },
        )

        self._emit_agent_event(
            "code_security_scan_completed",
            {
                "target": target,
                "summary": asdict(summary),
                "blocked": result["data"]["blocked"],
            },
        )

        return result

    def scan_file(
        self,
        file_path: Union[str, Path],
        context: Optional[Dict[str, Any]] = None,
        encoding: str = "utf-8",
    ) -> Dict[str, Any]:
        """
        Scan a single file safely.
        """
        context_result = self._validate_task_context(context)
        if not context_result["success"]:
            return context_result

        path = Path(file_path)

        if not path.exists():
            return self._error_result(
                message="File does not exist.",
                error={"code": "file_not_found", "path": str(path)},
            )

        if not path.is_file():
            return self._error_result(
                message="Target path is not a file.",
                error={"code": "not_a_file", "path": str(path)},
            )

        try:
            size = path.stat().st_size
        except OSError as exc:
            return self._error_result(
                message="Could not read file metadata.",
                error={"code": "file_stat_failed", "details": str(exc), "path": str(path)},
            )

        if size > self.SAFE_MAX_FILE_SIZE_BYTES:
            return self._error_result(
                message="File is too large to scan safely.",
                error={
                    "code": "file_too_large",
                    "path": str(path),
                    "size_bytes": size,
                    "max_bytes": self.SAFE_MAX_FILE_SIZE_BYTES,
                },
            )

        try:
            code = path.read_text(encoding=encoding, errors="replace")
        except Exception as exc:
            return self._error_result(
                message="Could not read file.",
                error={"code": "file_read_failed", "details": str(exc), "path": str(path)},
            )

        return self.scan_code(code=code, file_path=str(path), context=context)

    def scan_directory(
        self,
        directory_path: Union[str, Path],
        context: Optional[Dict[str, Any]] = None,
        recursive: bool = True,
        include_extensions: Optional[Sequence[str]] = None,
        exclude_dirs: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """
        Scan a directory of source files.

        Safe limits prevent accidentally scanning massive directories.
        """
        context_result = self._validate_task_context(context)
        if not context_result["success"]:
            return context_result

        root = Path(directory_path)
        if not root.exists():
            return self._error_result(
                message="Directory does not exist.",
                error={"code": "directory_not_found", "path": str(root)},
            )

        if not root.is_dir():
            return self._error_result(
                message="Target path is not a directory.",
                error={"code": "not_a_directory", "path": str(root)},
            )

        include_extensions = tuple(include_extensions or [
            ".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".env", ".yml", ".yaml",
            ".php", ".html", ".css", ".sh", ".md", "Dockerfile",
        ])

        exclude_dirs_set = set(exclude_dirs or [
            ".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
            ".pytest_cache", "dist", "build", ".next", ".nuxt", "vendor",
        ])

        files = list(self._iter_files(root, recursive, include_extensions, exclude_dirs_set))

        if len(files) > self.SAFE_MAX_DIRECTORY_FILES:
            return self._error_result(
                message="Directory contains too many files to scan safely.",
                error={
                    "code": "too_many_files",
                    "count": len(files),
                    "max_files": self.SAFE_MAX_DIRECTORY_FILES,
                },
            )

        all_findings: List[SecurityFinding] = []
        file_results: List[Dict[str, Any]] = []

        for file in files:
            result = self.scan_file(file, context=context)
            file_results.append({
                "file_path": str(file),
                "success": result.get("success"),
                "summary": result.get("data", {}).get("summary", {}),
                "error": result.get("error"),
            })

            if result.get("success"):
                for finding in result.get("data", {}).get("findings", []):
                    all_findings.append(SecurityFinding(**finding))

        all_findings = self._deduplicate_findings(all_findings)
        summary = self.summarize_findings(all_findings)
        recommendations = self._build_recommendations(all_findings)

        final_result = self._safe_result(
            message="Directory security scan completed.",
            data={
                "target": str(root),
                "files_scanned": len(files),
                "summary": asdict(summary),
                "findings": [asdict(finding) for finding in all_findings],
                "file_results": file_results,
                "recommendations": recommendations,
                "blocked": self._should_block(summary),
            },
            metadata={
                "scanner": "SecurityChecker",
                "scanner_version": "1.0.0",
                "recursive": recursive,
            },
        )

        final_result["data"]["verification_payload"] = self._prepare_verification_payload(final_result, context)
        final_result["data"]["memory_payload"] = self._prepare_memory_payload(final_result, context)

        self._log_audit_event(
            action="scan_directory",
            context=context,
            metadata={
                "target": str(root),
                "files_scanned": len(files),
                "total_findings": summary.total_findings,
                "risk_score": summary.risk_score,
                "blocked": final_result["data"]["blocked"],
            },
        )

        return final_result

    def check_before_write(
        self,
        code: str,
        file_path: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Security gate before Code Writer / Code Editor writes code.
        """
        scan = self.scan_code(code=code, file_path=file_path, context=context)
        if not scan.get("success"):
            return scan

        summary = scan.get("data", {}).get("summary", {})
        blocked = scan.get("data", {}).get("blocked", False)

        approval_result: Optional[Dict[str, Any]] = None
        if self._requires_security_check(
            "write_file",
            {
                "contains_critical_findings": summary.get("critical", 0) > 0,
                "contains_high_findings": summary.get("high", 0) > 0,
            },
        ):
            approval_result = self._request_security_approval(
                "write_file",
                {
                    "file_path": file_path,
                    "summary": summary,
                    "blocked": blocked,
                },
                context=context,
            )

        return self._safe_result(
            message="Pre-write security check completed.",
            data={
                "allowed": not blocked and (approval_result is None or approval_result.get("success", False)),
                "scan": scan,
                "approval": approval_result,
            },
            metadata={"file_path": file_path},
        )

    def check_before_execute(
        self,
        command_or_code: str,
        context: Optional[Dict[str, Any]] = None,
        execution_type: str = "terminal",
    ) -> Dict[str, Any]:
        """
        Security gate before Terminal Runner executes any command/code.
        """
        pseudo_file = "terminal_command.sh" if execution_type == "terminal" else "inline_execution.py"
        scan = self.scan_code(code=command_or_code, file_path=pseudo_file, context=context)

        if not scan.get("success"):
            return scan

        summary = scan.get("data", {}).get("summary", {})
        blocked = scan.get("data", {}).get("blocked", False)

        approval = self._request_security_approval(
            "execute_code",
            {
                "execution_type": execution_type,
                "summary": summary,
                "blocked": blocked,
                "contains_critical_findings": summary.get("critical", 0) > 0,
                "contains_high_findings": summary.get("high", 0) > 0,
            },
            context=context,
        )

        return self._safe_result(
            message="Pre-execution security check completed.",
            data={
                "allowed": not blocked and approval.get("success", False),
                "scan": scan,
                "approval": approval,
            },
            metadata={"execution_type": execution_type},
        )

    def summarize_findings(self, findings: Sequence[SecurityFinding]) -> ScanSummary:
        """
        Build severity counts and risk score.
        """
        summary = ScanSummary(total_findings=len(findings))

        for finding in findings:
            severity = finding.severity
            if severity == Severity.CRITICAL.value:
                summary.critical += 1
            elif severity == Severity.HIGH.value:
                summary.high += 1
            elif severity == Severity.MEDIUM.value:
                summary.medium += 1
            elif severity == Severity.LOW.value:
                summary.low += 1
            else:
                summary.info += 1

        risk_score = (
            summary.critical * 30
            + summary.high * 15
            + summary.medium * 7
            + summary.low * 3
            + summary.info
        )
        summary.risk_score = min(100, risk_score)
        summary.passed = summary.critical == 0 and not (self.block_on_high and summary.high > 0)

        return summary

    # -----------------------------------------------------------------------
    # Rule building
    # -----------------------------------------------------------------------

    def _build_default_rules(self) -> List[SecurityRule]:
        """
        Production-minded static rules.

        Regex rules are intentionally conservative to avoid leaking secrets
        while still catching common mistakes.
        """
        flags = re.IGNORECASE | re.MULTILINE

        return [
            SecurityRule(
                rule_id="SECRET_001",
                category=FindingCategory.SECRET,
                severity=Severity.CRITICAL,
                title="Possible hardcoded API key",
                pattern=re.compile(
                    r"""(?x)
                    \b(api[_-]?key|apikey|access[_-]?key|secret[_-]?key)\b
                    \s*[:=]\s*
                    ['"]?([A-Za-z0-9_\-]{16,})['"]?
                    """,
                    flags,
                ),
                message="A possible API key or secret key appears to be hardcoded.",
                recommendation="Move secrets to a secure secret manager or environment variable.",
                confidence=0.85,
            ),
            SecurityRule(
                rule_id="SECRET_002",
                category=FindingCategory.SECRET,
                severity=Severity.CRITICAL,
                title="Possible hardcoded password",
                pattern=re.compile(
                    r"""\b(password|passwd|pwd)\b\s*[:=]\s*['"][^'"]{8,}['"]""",
                    flags,
                ),
                message="A password appears to be hardcoded.",
                recommendation="Never hardcode passwords. Use environment variables or a secret vault.",
                confidence=0.8,
            ),
            SecurityRule(
                rule_id="SECRET_003",
                category=FindingCategory.SECRET,
                severity=Severity.CRITICAL,
                title="Private key detected",
                pattern=re.compile(
                    r"-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
                    flags,
                ),
                message="A private key appears inside the source code.",
                recommendation="Remove the private key immediately and rotate the credential.",
                confidence=0.95,
            ),
            SecurityRule(
                rule_id="SECRET_004",
                category=FindingCategory.SECRET,
                severity=Severity.HIGH,
                title="Possible JWT token",
                pattern=re.compile(r"eyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+", flags),
                message="A possible JWT token appears in code.",
                recommendation="Do not store JWT tokens in source files or logs.",
                confidence=0.75,
            ),
            SecurityRule(
                rule_id="SECRET_005",
                category=FindingCategory.SECRET,
                severity=Severity.CRITICAL,
                title="Possible cloud credential",
                pattern=re.compile(
                    r"\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35})\b",
                    flags,
                ),
                message="A possible AWS or Google credential was detected.",
                recommendation="Remove and rotate the credential. Use IAM roles or managed secrets.",
                confidence=0.95,
            ),
            SecurityRule(
                rule_id="INJECTION_001",
                category=FindingCategory.INJECTION,
                severity=Severity.HIGH,
                title="Possible SQL string interpolation",
                pattern=re.compile(
                    r"(execute|executemany|raw)\s*\(\s*f?['\"].*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER).*({|%s|format\()",
                    flags,
                ),
                message="SQL appears to be built with string interpolation.",
                recommendation="Use parameterized queries or ORM query builders.",
                confidence=0.8,
            ),
            SecurityRule(
                rule_id="INJECTION_002",
                category=FindingCategory.INJECTION,
                severity=Severity.HIGH,
                title="Possible shell injection",
                pattern=re.compile(
                    r"\b(os\.system|subprocess\.(call|run|Popen|check_output|check_call))\s*\(.*(shell\s*=\s*True|f['\"]|format\(|\+)",
                    flags,
                ),
                message="Command execution may be vulnerable to shell injection.",
                recommendation="Avoid shell=True. Pass command arguments as a list and validate input.",
                confidence=0.85,
            ),
            SecurityRule(
                rule_id="UNSAFE_CMD_001",
                category=FindingCategory.UNSAFE_COMMAND,
                severity=Severity.CRITICAL,
                title="Dangerous destructive command",
                pattern=re.compile(
                    r"\b(rm\s+-rf\s+/|mkfs|dd\s+if=|shutdown|reboot|format\s+[A-Z]:|del\s+/f\s+/s\s+/q)\b",
                    flags,
                ),
                message="A dangerous destructive system command was detected.",
                recommendation="Block destructive commands unless explicitly approved by Security Agent.",
                confidence=0.95,
            ),
            SecurityRule(
                rule_id="UNSAFE_CMD_002",
                category=FindingCategory.UNSAFE_COMMAND,
                severity=Severity.HIGH,
                title="Network pipe to shell",
                pattern=re.compile(
                    r"(curl|wget)\s+.*(\|\s*(bash|sh|python|perl)|>\s*/tmp/)",
                    flags,
                ),
                message="Downloading remote content and piping it to a shell is unsafe.",
                recommendation="Download, verify checksum/signature, then execute only after approval.",
                confidence=0.9,
            ),
            SecurityRule(
                rule_id="ACCESS_001",
                category=FindingCategory.ACCESS_CONTROL,
                severity=Severity.HIGH,
                title="Authentication bypass pattern",
                pattern=re.compile(
                    r"(auth\s*=\s*False|skip_auth\s*=\s*True|disable_auth\s*=\s*True|allow_anonymous\s*=\s*True)",
                    flags,
                ),
                message="Code appears to disable or bypass authentication.",
                recommendation="Ensure all sensitive routes/actions require authentication and authorization.",
                confidence=0.8,
            ),
            SecurityRule(
                rule_id="ACCESS_002",
                category=FindingCategory.ACCESS_CONTROL,
                severity=Severity.MEDIUM,
                title="Admin access check may be weak",
                pattern=re.compile(
                    r"(is_admin|role\s*==\s*['\"]admin['\"]|user\.admin)",
                    flags,
                ),
                message="Admin access logic should be reviewed for workspace-scoped authorization.",
                recommendation="Use centralized permission checks with user_id, workspace_id, role, and subscription policy.",
                confidence=0.65,
            ),
            SecurityRule(
                rule_id="CRYPTO_001",
                category=FindingCategory.INSECURE_CRYPTO,
                severity=Severity.HIGH,
                title="Insecure hash algorithm",
                pattern=re.compile(r"\b(hashlib\.(md5|sha1)|MD5|SHA1)\b", flags),
                message="MD5/SHA1 are not safe for security-sensitive hashing.",
                recommendation="Use SHA-256+ for non-password hashing and Argon2/bcrypt/scrypt for passwords.",
                confidence=0.85,
            ),
            SecurityRule(
                rule_id="CRYPTO_002",
                category=FindingCategory.INSECURE_CRYPTO,
                severity=Severity.HIGH,
                title="Insecure random generator",
                pattern=re.compile(r"\brandom\.(random|randint|choice|choices|shuffle)\b", flags),
                message="Non-cryptographic randomness appears in code.",
                recommendation="Use secrets module for tokens, passwords, OTPs, and security-sensitive values.",
                confidence=0.75,
            ),
            SecurityRule(
                rule_id="DANGER_001",
                category=FindingCategory.DANGEROUS_IMPORT,
                severity=Severity.HIGH,
                title="Dynamic code execution",
                pattern=re.compile(r"\b(eval|exec|compile)\s*\(", flags),
                message="Dynamic code execution was detected.",
                recommendation="Avoid eval/exec. Use safe parsers, whitelisted commands, or AST validation.",
                confidence=0.9,
            ),
            SecurityRule(
                rule_id="DANGER_002",
                category=FindingCategory.DANGEROUS_IMPORT,
                severity=Severity.HIGH,
                title="Unsafe deserialization",
                pattern=re.compile(r"\b(pickle\.loads?|yaml\.load|marshal\.loads?)\s*\(", flags),
                message="Unsafe deserialization may allow code execution.",
                recommendation="Use json, yaml.safe_load, or signed/validated serialized data.",
                confidence=0.85,
            ),
            SecurityRule(
                rule_id="FILES_001",
                category=FindingCategory.FILE_SYSTEM,
                severity=Severity.MEDIUM,
                title="Broad file permission change",
                pattern=re.compile(r"\bchmod\s+(-R\s+)?(777|666)\b", flags),
                message="Overly broad file permissions were detected.",
                recommendation="Use least-privilege permissions such as 640/750 where appropriate.",
                confidence=0.85,
            ),
            SecurityRule(
                rule_id="NETWORK_001",
                category=FindingCategory.NETWORK,
                severity=Severity.MEDIUM,
                title="TLS verification disabled",
                pattern=re.compile(r"(verify\s*=\s*False|rejectUnauthorized\s*:\s*false)", flags),
                message="TLS certificate verification appears disabled.",
                recommendation="Keep TLS verification enabled and fix certificate trust issues properly.",
                confidence=0.85,
            ),
            SecurityRule(
                rule_id="CONFIG_001",
                category=FindingCategory.CONFIG,
                severity=Severity.MEDIUM,
                title="Debug mode enabled",
                pattern=re.compile(r"\b(debug\s*=\s*True|DEBUG\s*=\s*True|app\.run\(.*debug\s*=\s*True)", flags),
                message="Debug mode appears enabled.",
                recommendation="Disable debug mode in production and control it through environment configuration.",
                confidence=0.75,
            ),
            SecurityRule(
                rule_id="CONFIG_002",
                category=FindingCategory.CONFIG,
                severity=Severity.MEDIUM,
                title="Wildcard CORS",
                pattern=re.compile(r"(CORS\(.*origins\s*=\s*['\"]\*['\"]|Access-Control-Allow-Origin['\"]?\s*:\s*['\"]\*)", flags),
                message="Wildcard CORS policy detected.",
                recommendation="Restrict CORS origins to trusted domains per workspace/environment.",
                confidence=0.8,
            ),
        ]

    # -----------------------------------------------------------------------
    # Scanners
    # -----------------------------------------------------------------------

    def _scan_regex_rules(self, code: str, file_path: Optional[str]) -> List[SecurityFinding]:
        """
        Apply regex rules line by line.
        """
        findings: List[SecurityFinding] = []
        extension = self._file_extension(file_path)

        lines = code.splitlines()
        for rule in self.rules:
            if not self._rule_applies_to_extension(rule, extension):
                continue

            if not rule.pattern:
                continue

            for index, line in enumerate(lines, start=1):
                for match in rule.pattern.finditer(line):
                    matched_text = self._mask_sensitive_match(match.group(0), rule.category)
                    findings.append(
                        self._make_finding(
                            category=rule.category,
                            severity=rule.severity,
                            title=rule.title,
                            message=rule.message,
                            file_path=file_path,
                            line_number=index,
                            column=match.start() + 1,
                            matched_text=matched_text,
                            rule_id=rule.rule_id,
                            recommendation=rule.recommendation,
                            confidence=rule.confidence,
                        )
                    )

        return findings

    def _scan_python_ast_if_possible(self, code: str, file_path: Optional[str]) -> List[SecurityFinding]:
        """
        Use Python AST for stronger detection when the file is Python-like.
        """
        if file_path and not str(file_path).endswith(".py"):
            return []

        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []

        findings: List[SecurityFinding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                findings.extend(self._scan_ast_call(node, file_path))

            if isinstance(node, ast.Assign):
                findings.extend(self._scan_ast_assignment(node, file_path))

            if isinstance(node, ast.Import):
                findings.extend(self._scan_ast_import(node, file_path))

            if isinstance(node, ast.ImportFrom):
                findings.extend(self._scan_ast_import_from(node, file_path))

        return findings

    def _scan_ast_call(self, node: ast.Call, file_path: Optional[str]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        call_name = self._ast_call_name(node)

        dangerous_calls = {
            "eval": (Severity.CRITICAL, "Use of eval()", "Avoid eval(). Use safe parsing or whitelisted operations."),
            "exec": (Severity.CRITICAL, "Use of exec()", "Avoid exec(). Use explicit functions or validated command maps."),
            "compile": (Severity.HIGH, "Use of compile()", "Avoid dynamic compilation unless strongly sandboxed."),
            "os.system": (Severity.HIGH, "Use of os.system()", "Use subprocess with argument list and no shell=True."),
            "subprocess.Popen": (Severity.HIGH, "Use of subprocess.Popen()", "Validate commands and avoid shell=True."),
            "subprocess.run": (Severity.MEDIUM, "Use of subprocess.run()", "Validate commands and avoid shell=True."),
            "pickle.load": (Severity.HIGH, "Use of pickle.load()", "Avoid pickle for untrusted data."),
            "pickle.loads": (Severity.HIGH, "Use of pickle.loads()", "Avoid pickle for untrusted data."),
            "yaml.load": (Severity.HIGH, "Use of yaml.load()", "Use yaml.safe_load instead."),
        }

        if call_name in dangerous_calls:
            severity, title, recommendation = dangerous_calls[call_name]
            findings.append(
                self._make_finding(
                    category=FindingCategory.DANGEROUS_IMPORT,
                    severity=severity,
                    title=title,
                    message=f"Detected risky call: {call_name}.",
                    file_path=file_path,
                    line_number=getattr(node, "lineno", None),
                    column=getattr(node, "col_offset", 0) + 1,
                    matched_text=call_name,
                    rule_id=f"AST_CALL_{call_name}",
                    recommendation=recommendation,
                    confidence=0.9,
                )
            )

        if call_name and call_name.startswith("subprocess."):
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    findings.append(
                        self._make_finding(
                            category=FindingCategory.INJECTION,
                            severity=Severity.HIGH,
                            title="subprocess shell=True detected",
                            message="shell=True increases command injection risk.",
                            file_path=file_path,
                            line_number=getattr(node, "lineno", None),
                            column=getattr(node, "col_offset", 0) + 1,
                            matched_text="shell=True",
                            rule_id="AST_SUBPROCESS_SHELL_TRUE",
                            recommendation="Use shell=False and pass arguments as a list.",
                            confidence=0.95,
                        )
                    )

        return findings

    def _scan_ast_assignment(self, node: ast.Assign, file_path: Optional[str]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        target_names = []
        for target in node.targets:
            target_names.extend(self._extract_assignment_target_names(target))

        if not target_names:
            return findings

        sensitive_name_pattern = re.compile(
            r"(password|passwd|secret|token|api_key|apikey|access_key|private_key)",
            re.IGNORECASE,
        )

        for target_name in target_names:
            if not sensitive_name_pattern.search(target_name):
                continue

            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                value = node.value.value.strip()

                if len(value) >= self.SECRET_VALUE_MIN_LENGTH and not self._looks_like_env_placeholder(value):
                    findings.append(
                        self._make_finding(
                            category=FindingCategory.SECRET,
                            severity=Severity.CRITICAL,
                            title="Hardcoded sensitive assignment",
                            message=f"Sensitive variable '{target_name}' appears to contain a hardcoded value.",
                            file_path=file_path,
                            line_number=getattr(node, "lineno", None),
                            column=getattr(node, "col_offset", 0) + 1,
                            matched_text=f"{target_name}=***",
                            rule_id="AST_SECRET_ASSIGNMENT",
                            recommendation="Load sensitive values from a secret manager or environment variable.",
                            confidence=0.9,
                        )
                    )

        return findings

    def _scan_ast_import(self, node: ast.Import, file_path: Optional[str]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        risky_imports = {
            "pickle": Severity.MEDIUM,
            "marshal": Severity.MEDIUM,
            "subprocess": Severity.LOW,
            "os": Severity.LOW,
            "pty": Severity.HIGH,
        }

        for alias in node.names:
            root = alias.name.split(".")[0]
            if root in risky_imports:
                findings.append(
                    self._make_finding(
                        category=FindingCategory.DANGEROUS_IMPORT,
                        severity=risky_imports[root],
                        title=f"Risky import: {root}",
                        message=f"Module '{root}' can be risky if used with untrusted input.",
                        file_path=file_path,
                        line_number=getattr(node, "lineno", None),
                        column=getattr(node, "col_offset", 0) + 1,
                        matched_text=root,
                        rule_id=f"AST_IMPORT_{root}",
                        recommendation="Review usage and route sensitive operations through Security Agent.",
                        confidence=0.55,
                    )
                )

        return findings

    def _scan_ast_import_from(self, node: ast.ImportFrom, file_path: Optional[str]) -> List[SecurityFinding]:
        if not node.module:
            return []

        fake_import = ast.Import(names=[ast.alias(name=node.module)])
        fake_import.lineno = getattr(node, "lineno", 0)
        fake_import.col_offset = getattr(node, "col_offset", 0)
        return self._scan_ast_import(fake_import, file_path)

    def _scan_saas_isolation(self, code: str, file_path: Optional[str]) -> List[SecurityFinding]:
        """
        Detect missing SaaS isolation hints in files that appear user/workspace scoped.
        """
        findings: List[SecurityFinding] = []

        lower_code = code.lower()
        user_scoped_keywords = [
            "task",
            "memory",
            "audit",
            "file",
            "workspace",
            "subscription",
            "agent permission",
            "analytics",
            "history",
        ]

        appears_user_scoped = any(keyword in lower_code for keyword in user_scoped_keywords)
        has_user_id = "user_id" in lower_code
        has_workspace_id = "workspace_id" in lower_code

        if appears_user_scoped and not has_user_id:
            findings.append(
                self._make_finding(
                    category=FindingCategory.SAAS_ISOLATION,
                    severity=Severity.HIGH,
                    title="Missing user_id isolation",
                    message="This code appears user-scoped but does not reference user_id.",
                    file_path=file_path,
                    rule_id="SAAS_USER_ID_MISSING",
                    recommendation="Add user_id to all user-specific reads, writes, logs, tasks, memory, and analytics.",
                    confidence=0.75,
                )
            )

        if appears_user_scoped and not has_workspace_id:
            findings.append(
                self._make_finding(
                    category=FindingCategory.SAAS_ISOLATION,
                    severity=Severity.HIGH,
                    title="Missing workspace_id isolation",
                    message="This code appears workspace-scoped but does not reference workspace_id.",
                    file_path=file_path,
                    rule_id="SAAS_WORKSPACE_ID_MISSING",
                    recommendation="Add workspace_id to all workspace-specific reads, writes, logs, tasks, memory, and analytics.",
                    confidence=0.75,
                )
            )

        cross_tenant_patterns = [
            r"\.all\(\)",
            r"select\s+\*\s+from\s+(users|tasks|files|memory|audit_logs)",
            r"delete\s+from\s+(users|tasks|files|memory|audit_logs)",
            r"update\s+(users|tasks|files|memory|audit_logs)\s+set",
        ]

        for pattern in cross_tenant_patterns:
            for match in re.finditer(pattern, code, flags=re.IGNORECASE):
                line = self._line_number_for_index(code, match.start())
                findings.append(
                    self._make_finding(
                        category=FindingCategory.SAAS_ISOLATION,
                        severity=Severity.HIGH,
                        title="Possible cross-tenant data access",
                        message="Broad query/access pattern may affect multiple users or workspaces.",
                        file_path=file_path,
                        line_number=line,
                        matched_text=self._mask_sensitive_match(match.group(0), FindingCategory.SAAS_ISOLATION),
                        rule_id="SAAS_CROSS_TENANT_PATTERN",
                        recommendation="Filter by user_id and workspace_id before reading, updating, or deleting data.",
                        confidence=0.8,
                    )
                )

        return findings

    def _scan_access_control(self, code: str, file_path: Optional[str]) -> List[SecurityFinding]:
        """
        Detect weak access control patterns.
        """
        findings: List[SecurityFinding] = []

        sensitive_words = [
            "delete",
            "deploy",
            "terminal",
            "subprocess",
            "send_email",
            "call",
            "payment",
            "subscription",
            "browser",
            "system",
            "financial",
            "credential",
        ]

        lower_code = code.lower()
        appears_sensitive = any(word in lower_code for word in sensitive_words)

        has_permission_check = any(
            token in lower_code
            for token in [
                "permission",
                "authorize",
                "authorization",
                "security_agent",
                "_request_security_approval",
                "_requires_security_check",
                "has_role",
                "can_",
            ]
        )

        if appears_sensitive and not has_permission_check:
            findings.append(
                self._make_finding(
                    category=FindingCategory.ACCESS_CONTROL,
                    severity=Severity.HIGH,
                    title="Sensitive action without clear permission check",
                    message="This code appears to perform sensitive actions but no permission/security approval check was detected.",
                    file_path=file_path,
                    rule_id="ACCESS_MISSING_PERMISSION_CHECK",
                    recommendation="Route sensitive actions through Security Agent and enforce user/workspace permissions.",
                    confidence=0.8,
                )
            )

        return findings

    def _scan_dependency_content(self, code: str, file_path: Optional[str]) -> List[SecurityFinding]:
        """
        Scan dependency/config files for risky packages or unsafe versioning.
        """
        if not self.scan_dependencies or not file_path:
            return []

        filename = Path(file_path).name.lower()
        if filename not in {
            "requirements.txt",
            "package.json",
            "pyproject.toml",
            "pipfile",
            "dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
        } and not filename.endswith((".yml", ".yaml", ".json")):
            return []

        findings: List[SecurityFinding] = []

        risky_dependency_patterns = [
            (
                r"\bflask\s*==\s*0\.",
                "Old Flask version",
                "Old Flask versions may contain known vulnerabilities.",
                "Upgrade Flask to a maintained version.",
            ),
            (
                r"\bdjango\s*==\s*1\.",
                "Old Django version",
                "Old Django versions are unsupported and may contain known vulnerabilities.",
                "Upgrade Django to an actively supported version.",
            ),
            (
                r"\brequests\s*==\s*2\.([0-9]|1[0-9])\.",
                "Old requests version",
                "Old requests versions may have security issues.",
                "Upgrade requests to a current stable version.",
            ),
            (
                r"latest",
                "Unpinned latest dependency/image",
                "Using latest can make builds unpredictable and unsafe.",
                "Pin dependencies/images to known safe versions.",
            ),
        ]

        for pattern, title, message, recommendation in risky_dependency_patterns:
            for match in re.finditer(pattern, code, flags=re.IGNORECASE):
                findings.append(
                    self._make_finding(
                        category=FindingCategory.DEPENDENCY,
                        severity=Severity.MEDIUM,
                        title=title,
                        message=message,
                        file_path=file_path,
                        line_number=self._line_number_for_index(code, match.start()),
                        matched_text=match.group(0),
                        rule_id="DEPENDENCY_RISK",
                        recommendation=recommendation,
                        confidence=0.7,
                    )
                )

        if filename == "dockerfile":
            docker_patterns = [
                (
                    r"USER\s+root",
                    Severity.MEDIUM,
                    "Container runs as root",
                    "Use a non-root user in production containers.",
                ),
                (
                    r"ADD\s+https?://",
                    Severity.MEDIUM,
                    "Remote ADD in Dockerfile",
                    "Prefer COPY or verified download steps.",
                ),
                (
                    r"--privileged",
                    Severity.HIGH,
                    "Privileged container detected",
                    "Avoid privileged containers unless absolutely required and approved.",
                ),
            ]

            for pattern, severity, title, recommendation in docker_patterns:
                for match in re.finditer(pattern, code, flags=re.IGNORECASE):
                    findings.append(
                        self._make_finding(
                            category=FindingCategory.CONFIG,
                            severity=severity,
                            title=title,
                            message=title,
                            file_path=file_path,
                            line_number=self._line_number_for_index(code, match.start()),
                            matched_text=match.group(0),
                            rule_id="DOCKER_SECURITY",
                            recommendation=recommendation,
                            confidence=0.8,
                        )
                    )

        return findings

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _make_finding(
        self,
        category: FindingCategory,
        severity: Severity,
        title: str,
        message: str,
        file_path: Optional[str] = None,
        line_number: Optional[int] = None,
        column: Optional[int] = None,
        matched_text: Optional[str] = None,
        rule_id: Optional[str] = None,
        recommendation: Optional[str] = None,
        confidence: float = 0.75,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SecurityFinding:
        raw_id = f"{category.value}:{severity.value}:{title}:{file_path}:{line_number}:{column}:{matched_text}:{rule_id}"
        finding_id = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:16]

        return SecurityFinding(
            finding_id=finding_id,
            category=category.value,
            severity=severity.value,
            title=title,
            message=message,
            file_path=file_path,
            line_number=line_number,
            column=column,
            matched_text=matched_text,
            rule_id=rule_id,
            recommendation=recommendation,
            confidence=confidence,
            metadata=metadata or {},
        )

    def _deduplicate_findings(self, findings: Sequence[SecurityFinding]) -> List[SecurityFinding]:
        seen: set[str] = set()
        deduped: List[SecurityFinding] = []

        for finding in findings:
            key = finding.finding_id
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)

        severity_order = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 1,
            Severity.MEDIUM.value: 2,
            Severity.LOW.value: 3,
            Severity.INFO.value: 4,
        }

        deduped.sort(
            key=lambda item: (
                severity_order.get(item.severity, 9),
                item.file_path or "",
                item.line_number or 0,
                item.title,
            )
        )
        return deduped

    def _should_block(self, summary: ScanSummary) -> bool:
        if self.block_on_critical and summary.critical > 0:
            return True
        if self.block_on_high and summary.high > 0:
            return True
        return False

    def _build_recommendations(self, findings: Sequence[SecurityFinding]) -> List[str]:
        recommendations: List[str] = []
        seen: set[str] = set()

        for finding in findings:
            if finding.recommendation and finding.recommendation not in seen:
                seen.add(finding.recommendation)
                recommendations.append(finding.recommendation)

        if not recommendations:
            recommendations.append("No immediate security remediation required based on current static scan.")

        return recommendations[:20]

    def _file_extension(self, file_path: Optional[str]) -> str:
        if not file_path:
            return ""
        name = Path(file_path).name
        if name == "Dockerfile":
            return "Dockerfile"
        return Path(file_path).suffix.lower()

    def _rule_applies_to_extension(self, rule: SecurityRule, extension: str) -> bool:
        if not extension:
            return True
        return extension in rule.file_extensions

    def _guess_language(self, file_path: Optional[str]) -> str:
        if not file_path:
            return "unknown"

        extension = self._file_extension(file_path)
        mapping = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript-react",
            ".jsx": "javascript-react",
            ".json": "json",
            ".env": "env",
            ".yml": "yaml",
            ".yaml": "yaml",
            ".php": "php",
            ".html": "html",
            ".css": "css",
            ".sh": "shell",
            ".md": "markdown",
            "Dockerfile": "dockerfile",
        }
        return mapping.get(extension, "unknown")

    def _sha256_text(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

    def _mask_sensitive_match(
        self,
        matched_text: str,
        category: Union[FindingCategory, str],
    ) -> str:
        """
        Mask potentially sensitive data before returning/storing findings.
        """
        category_value = category.value if isinstance(category, FindingCategory) else str(category)

        if category_value == FindingCategory.SECRET.value:
            if len(matched_text) <= 8:
                return "***"
            return f"{matched_text[:4]}***{matched_text[-4:]}"

        if len(matched_text) > 120:
            return matched_text[:117] + "..."

        return matched_text

    def _line_number_for_index(self, text: str, index: int) -> int:
        return text.count("\n", 0, index) + 1

    def _looks_like_env_placeholder(self, value: str) -> bool:
        normalized = value.strip()
        if normalized.startswith("${") and normalized.endswith("}"):
            return True
        if normalized.startswith("$"):
            return True
        if normalized.upper() in {
            "CHANGE_ME",
            "YOUR_API_KEY",
            "YOUR_SECRET",
            "REPLACE_ME",
            "ENV_VAR",
            "EXAMPLE_SECRET",
        }:
            return True
        return False

    def _ast_call_name(self, node: ast.Call) -> Optional[str]:
        func = node.func

        if isinstance(func, ast.Name):
            return func.id

        if isinstance(func, ast.Attribute):
            parts = [func.attr]
            value = func.value
            while isinstance(value, ast.Attribute):
                parts.append(value.attr)
                value = value.value
            if isinstance(value, ast.Name):
                parts.append(value.id)
            return ".".join(reversed(parts))

        return None

    def _extract_assignment_target_names(self, target: ast.AST) -> List[str]:
        if isinstance(target, ast.Name):
            return [target.id]

        if isinstance(target, ast.Attribute):
            return [target.attr]

        if isinstance(target, (ast.Tuple, ast.List)):
            names: List[str] = []
            for element in target.elts:
                names.extend(self._extract_assignment_target_names(element))
            return names

        return []

    def _iter_files(
        self,
        root: Path,
        recursive: bool,
        include_extensions: Sequence[str],
        exclude_dirs: set[str],
    ) -> Iterable[Path]:
        pattern = "**/*" if recursive else "*"

        for path in root.glob(pattern):
            if not path.is_file():
                continue

            if any(part in exclude_dirs for part in path.parts):
                continue

            name = path.name
            suffix = path.suffix.lower()

            if name in include_extensions or suffix in include_extensions:
                yield path

    # -----------------------------------------------------------------------
    # Registry / routing metadata
    # -----------------------------------------------------------------------

    @classmethod
    def get_agent_metadata(cls) -> Dict[str, Any]:
        """
        Metadata for Agent Registry, Agent Loader, and Master Agent routing.
        """
        return {
            "agent_module": "Code Agent",
            "file": "security_checker.py",
            "class_name": "SecurityChecker",
            "capabilities": [
                "scan_code_for_secrets",
                "scan_code_for_injection_risks",
                "scan_code_for_unsafe_commands",
                "scan_code_for_weak_access_control",
                "scan_code_for_saas_isolation",
                "pre_write_security_gate",
                "pre_execution_security_gate",
                "verification_payload_generation",
                "memory_payload_generation",
                "audit_event_logging",
            ],
            "safe_to_import": True,
            "requires_user_context": True,
            "requires_workspace_context": True,
            "routes": [
                "code.security.scan",
                "code.security.pre_write",
                "code.security.pre_execute",
                "code.security.scan_file",
                "code.security.scan_directory",
            ],
            "version": "1.0.0",
        }


# ---------------------------------------------------------------------------
# Convenience function for direct module use
# ---------------------------------------------------------------------------

def scan_code_security(
    code: str,
    file_path: Optional[str] = None,
    user_id: Optional[Union[str, int]] = None,
    workspace_id: Optional[Union[str, int]] = None,
) -> Dict[str, Any]:
    """
    Simple helper for tests, scripts, API routes, or future dashboards.
    """
    checker = SecurityChecker()
    return checker.scan_code(
        code=code,
        file_path=file_path,
        context={
            "user_id": user_id,
            "workspace_id": workspace_id,
        },
    )


__all__ = [
    "SecurityChecker",
    "SecurityFinding",
    "SecurityRule",
    "ScanSummary",
    "Severity",
    "FindingCategory",
    "scan_code_security",
]