"""
agents/code_agent/error_analyzer.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Production-ready error analysis helper for the Code Agent.

    This file analyzes:
    - Python tracebacks
    - Runtime logs
    - Build errors
    - Dependency errors
    - CORS errors
    - OAuth/auth errors
    - API/network errors
    - Frontend/backend framework errors

Architecture Compatibility:
    - Master Agent routing compatible
    - Agent Registry compatible
    - Agent Loader compatible
    - BaseAgent compatible
    - SaaS user/workspace isolation aware
    - Security Agent approval compatible
    - Verification Agent payload compatible
    - Memory Agent payload compatible
    - Dashboard/API structured result compatible

Important:
    This file is import-safe even if the rest of the William/Jarvis system
    has not been created yet.
"""

from __future__ import annotations

import json
import logging
import re
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore
        """
        Safe fallback BaseAgent.

        This fallback keeps this file import-safe until the real BaseAgent
        exists in the William/Jarvis system.
        """

        def __init__(
            self,
            agent_name: str = "error_analyzer",
            user_id: Optional[Union[str, int]] = None,
            workspace_id: Optional[Union[str, int]] = None,
            **kwargs: Any,
        ) -> None:
            self.agent_name = agent_name
            self.user_id = user_id
            self.workspace_id = workspace_id
            self.extra_config = kwargs

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            logging.getLogger(__name__).debug(
                "Fallback BaseAgent event emitted: %s | %s",
                event_name,
                payload,
            )


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Enums and Data Structures
# ---------------------------------------------------------------------------

class ErrorSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(str, Enum):
    PYTHON_TRACEBACK = "python_traceback"
    JAVASCRIPT_ERROR = "javascript_error"
    TYPESCRIPT_ERROR = "typescript_error"
    BUILD_ERROR = "build_error"
    DEPENDENCY_ERROR = "dependency_error"
    IMPORT_ERROR = "import_error"
    SYNTAX_ERROR = "syntax_error"
    RUNTIME_ERROR = "runtime_error"
    DATABASE_ERROR = "database_error"
    API_ERROR = "api_error"
    NETWORK_ERROR = "network_error"
    CORS_ERROR = "cors_error"
    OAUTH_ERROR = "oauth_error"
    AUTH_ERROR = "auth_error"
    PERMISSION_ERROR = "permission_error"
    DOCKER_ERROR = "docker_error"
    FLUTTER_ERROR = "flutter_error"
    FASTAPI_ERROR = "fastapi_error"
    FLASK_ERROR = "flask_error"
    DJANGO_ERROR = "django_error"
    REACT_ERROR = "react_error"
    NEXTJS_ERROR = "nextjs_error"
    NODE_ERROR = "node_error"
    UNKNOWN = "unknown"


class FixConfidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class ErrorSignal:
    """
    A detected signal inside logs or tracebacks.
    """

    name: str
    category: str
    severity: str
    confidence: str
    evidence: str
    explanation: str
    suggested_fix: str


@dataclass
class FileReference:
    """
    Parsed file reference from a traceback or build log.
    """

    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    function_name: Optional[str] = None
    raw: Optional[str] = None


@dataclass
class ErrorAnalysis:
    """
    Normalized internal error analysis payload.
    """

    category: str
    severity: str
    title: str
    summary: str
    likely_root_cause: str
    confidence: str
    detected_signals: List[ErrorSignal] = field(default_factory=list)
    file_references: List[FileReference] = field(default_factory=list)
    recommended_steps: List[str] = field(default_factory=list)
    safe_commands: List[str] = field(default_factory=list)
    unsafe_or_destructive_commands: List[str] = field(default_factory=list)
    raw_error_excerpt: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Main ErrorAnalyzer
# ---------------------------------------------------------------------------

class ErrorAnalyzer(BaseAgent):
    """
    ErrorAnalyzer for William/Jarvis Code Agent.

    Main responsibilities:
        - Analyze tracebacks, logs, build failures, CORS/OAuth/API errors.
        - Return structured dict results.
        - Keep per-user/per-workspace isolation.
        - Prepare payloads for Verification Agent and Memory Agent.
        - Emit audit/dashboard-compatible events.
        - Avoid destructive actions.
    """

    AGENT_NAME = "error_analyzer"
    AGENT_MODULE = "code_agent"
    VERSION = "1.0.0"

    PYTHON_TRACEBACK_RE = re.compile(
        r'Traceback \(most recent call last\):(?P<body>.*?)(?=\n\S|$)',
        re.DOTALL,
    )

    PYTHON_FILE_LINE_RE = re.compile(
        r'File\s+"(?P<file>[^"]+)",\s+line\s+(?P<line>\d+),\s+in\s+(?P<func>[^\n]+)'
    )

    JS_TS_FILE_LINE_RE = re.compile(
        r'(?P<file>[\w./\\-]+\.(?:js|jsx|ts|tsx|vue|mjs|cjs))'
        r'[:\(](?P<line>\d+)[: ,](?P<column>\d+)?'
    )

    GENERIC_FILE_LINE_RE = re.compile(
        r'(?P<file>[\w./\\-]+\.(?:py|js|jsx|ts|tsx|dart|php|java|go|rs|rb|cs|cpp|c|h|html|css|scss|json|yaml|yml))'
        r'[:\(](?P<line>\d+)(?:[: ,](?P<column>\d+))?'
    )

    def __init__(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        strict_context: bool = True,
        enable_audit_logs: bool = True,
        enable_memory_payload: bool = True,
        enable_verification_payload: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=self.AGENT_NAME,
            user_id=user_id,
            workspace_id=workspace_id,
            **kwargs,
        )

        self.user_id = user_id
        self.workspace_id = workspace_id
        self.strict_context = strict_context
        self.enable_audit_logs = enable_audit_logs
        self.enable_memory_payload = enable_memory_payload
        self.enable_verification_payload = enable_verification_payload

        self._pattern_rules = self._build_pattern_rules()

    # -----------------------------------------------------------------------
    # Public Methods
    # -----------------------------------------------------------------------

    def analyze(
        self,
        error_text: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Main public entrypoint.

        Args:
            error_text:
                Raw traceback, logs, build error, API error, or console output.
            user_id:
                SaaS user id.
            workspace_id:
                SaaS workspace id.
            context:
                Optional project/runtime context.

        Returns:
            Structured result:
            {
                "success": bool,
                "message": str,
                "data": {...},
                "error": None | {...},
                "metadata": {...}
            }
        """

        context = context or {}

        validation = self._validate_task_context(user_id, workspace_id, context)
        if not validation["success"]:
            return validation

        if not isinstance(error_text, str) or not error_text.strip():
            return self._error_result(
                message="No error text was provided for analysis.",
                code="EMPTY_ERROR_TEXT",
                metadata={
                    "user_id": user_id or self.user_id,
                    "workspace_id": workspace_id or self.workspace_id,
                },
            )

        cleaned_text = self._normalize_text(error_text)

        try:
            self._emit_agent_event(
                event_name="error_analysis_started",
                payload={
                    "user_id": user_id or self.user_id,
                    "workspace_id": workspace_id or self.workspace_id,
                    "input_length": len(cleaned_text),
                    "context_keys": sorted(list(context.keys())),
                },
            )

            analysis = self._analyze_text(cleaned_text, context=context)

            verification_payload = (
                self._prepare_verification_payload(analysis, context)
                if self.enable_verification_payload
                else None
            )

            memory_payload = (
                self._prepare_memory_payload(analysis, context)
                if self.enable_memory_payload
                else None
            )

            result_data = {
                "analysis": self._analysis_to_dict(analysis),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
                "dashboard_payload": self._prepare_dashboard_payload(analysis),
            }

            self._log_audit_event(
                action="analyze_error",
                status="success",
                user_id=user_id or self.user_id,
                workspace_id=workspace_id or self.workspace_id,
                details={
                    "category": analysis.category,
                    "severity": analysis.severity,
                    "confidence": analysis.confidence,
                },
            )

            self._emit_agent_event(
                event_name="error_analysis_completed",
                payload={
                    "user_id": user_id or self.user_id,
                    "workspace_id": workspace_id or self.workspace_id,
                    "category": analysis.category,
                    "severity": analysis.severity,
                    "confidence": analysis.confidence,
                },
            )

            return self._safe_result(
                message="Error analysis completed successfully.",
                data=result_data,
                metadata={
                    "agent": self.AGENT_NAME,
                    "module": self.AGENT_MODULE,
                    "version": self.VERSION,
                    "user_id": user_id or self.user_id,
                    "workspace_id": workspace_id or self.workspace_id,
                    "timestamp": self._utc_now(),
                },
            )

        except Exception as exc:
            logger.exception("ErrorAnalyzer failed.")
            self._log_audit_event(
                action="analyze_error",
                status="failed",
                user_id=user_id or self.user_id,
                workspace_id=workspace_id or self.workspace_id,
                details={"exception": str(exc)},
            )
            return self._error_result(
                message="ErrorAnalyzer failed while analyzing the provided error.",
                code="ERROR_ANALYZER_FAILURE",
                exception=exc,
                metadata={
                    "agent": self.AGENT_NAME,
                    "module": self.AGENT_MODULE,
                    "user_id": user_id or self.user_id,
                    "workspace_id": workspace_id or self.workspace_id,
                },
            )

    def analyze_traceback(
        self,
        traceback_text: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze a Python traceback or traceback-like runtime error.
        """
        merged_context = dict(context or {})
        merged_context["input_type"] = "traceback"
        return self.analyze(traceback_text, user_id, workspace_id, merged_context)

    def analyze_logs(
        self,
        logs: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze runtime logs.
        """
        merged_context = dict(context or {})
        merged_context["input_type"] = "logs"
        return self.analyze(logs, user_id, workspace_id, merged_context)

    def analyze_build_error(
        self,
        build_output: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze build output from npm, pip, Flutter, Docker, Vite, Webpack, etc.
        """
        merged_context = dict(context or {})
        merged_context["input_type"] = "build_error"
        return self.analyze(build_output, user_id, workspace_id, merged_context)

    def analyze_api_error(
        self,
        api_error_text: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze API, HTTP, CORS, OAuth, token, or network errors.
        """
        merged_context = dict(context or {})
        merged_context["input_type"] = "api_error"
        return self.analyze(api_error_text, user_id, workspace_id, merged_context)

    def summarize_for_dashboard(
        self,
        analysis_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Convert a full analysis result into a smaller dashboard card payload.
        """
        try:
            analysis = (
                analysis_result
                .get("data", {})
                .get("analysis", {})
            )

            return self._safe_result(
                message="Dashboard summary prepared.",
                data={
                    "title": analysis.get("title", "Unknown error"),
                    "category": analysis.get("category", ErrorCategory.UNKNOWN.value),
                    "severity": analysis.get("severity", ErrorSeverity.MEDIUM.value),
                    "confidence": analysis.get("confidence", FixConfidence.MEDIUM.value),
                    "summary": analysis.get("summary", ""),
                    "recommended_steps": analysis.get("recommended_steps", [])[:5],
                    "file_references": analysis.get("file_references", [])[:5],
                },
                metadata={
                    "agent": self.AGENT_NAME,
                    "module": self.AGENT_MODULE,
                    "timestamp": self._utc_now(),
                },
            )
        except Exception as exc:
            return self._error_result(
                message="Could not prepare dashboard summary.",
                code="DASHBOARD_SUMMARY_FAILED",
                exception=exc,
            )

    # -----------------------------------------------------------------------
    # Core Analysis
    # -----------------------------------------------------------------------

    def _analyze_text(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> ErrorAnalysis:
        context = context or {}

        detected_signals = self._detect_signals(text)
        file_references = self._extract_file_references(text)
        category = self._determine_category(text, detected_signals, context)
        severity = self._determine_severity(text, detected_signals, category)
        confidence = self._determine_confidence(detected_signals, file_references)
        title = self._build_title(category, detected_signals, text)
        summary = self._build_summary(category, detected_signals, text)
        likely_root_cause = self._build_root_cause(category, detected_signals, text)
        recommended_steps = self._build_recommended_steps(
            category=category,
            signals=detected_signals,
            file_references=file_references,
            text=text,
            context=context,
        )
        safe_commands, unsafe_commands = self._suggest_commands(
            category=category,
            signals=detected_signals,
            context=context,
        )

        return ErrorAnalysis(
            category=category.value,
            severity=severity.value,
            title=title,
            summary=summary,
            likely_root_cause=likely_root_cause,
            confidence=confidence.value,
            detected_signals=detected_signals,
            file_references=file_references,
            recommended_steps=recommended_steps,
            safe_commands=safe_commands,
            unsafe_or_destructive_commands=unsafe_commands,
            raw_error_excerpt=self._excerpt(text),
            metadata={
                "input_type": context.get("input_type"),
                "framework_hint": context.get("framework"),
                "language_hint": context.get("language"),
                "project_path": context.get("project_path"),
                "analyzed_at": self._utc_now(),
            },
        )

    def _detect_signals(self, text: str) -> List[ErrorSignal]:
        normalized = text.lower()
        signals: List[ErrorSignal] = []

        for rule in self._pattern_rules:
            pattern = rule["pattern"]
            match = re.search(pattern, normalized, flags=re.IGNORECASE | re.MULTILINE)
            if match:
                evidence = self._get_evidence_line(text, match.group(0))
                signals.append(
                    ErrorSignal(
                        name=rule["name"],
                        category=rule["category"].value,
                        severity=rule["severity"].value,
                        confidence=rule["confidence"].value,
                        evidence=evidence,
                        explanation=rule["explanation"],
                        suggested_fix=rule["suggested_fix"],
                    )
                )

        return self._deduplicate_signals(signals)

    def _extract_file_references(self, text: str) -> List[FileReference]:
        refs: List[FileReference] = []

        for match in self.PYTHON_FILE_LINE_RE.finditer(text):
            refs.append(
                FileReference(
                    file_path=match.group("file"),
                    line_number=self._safe_int(match.group("line")),
                    function_name=match.group("func").strip(),
                    raw=match.group(0),
                )
            )

        for match in self.JS_TS_FILE_LINE_RE.finditer(text):
            refs.append(
                FileReference(
                    file_path=match.group("file"),
                    line_number=self._safe_int(match.group("line")),
                    column_number=self._safe_int(match.group("column")),
                    raw=match.group(0),
                )
            )

        for match in self.GENERIC_FILE_LINE_RE.finditer(text):
            ref = FileReference(
                file_path=match.group("file"),
                line_number=self._safe_int(match.group("line")),
                column_number=self._safe_int(match.group("column")),
                raw=match.group(0),
            )
            refs.append(ref)

        return self._deduplicate_file_refs(refs)

    def _determine_category(
        self,
        text: str,
        signals: List[ErrorSignal],
        context: Dict[str, Any],
    ) -> ErrorCategory:
        input_type = str(context.get("input_type", "")).lower()
        framework = str(context.get("framework", "")).lower()
        language = str(context.get("language", "")).lower()

        if signals:
            priority = [
                ErrorCategory.CORS_ERROR,
                ErrorCategory.OAUTH_ERROR,
                ErrorCategory.AUTH_ERROR,
                ErrorCategory.PERMISSION_ERROR,
                ErrorCategory.DATABASE_ERROR,
                ErrorCategory.IMPORT_ERROR,
                ErrorCategory.SYNTAX_ERROR,
                ErrorCategory.DEPENDENCY_ERROR,
                ErrorCategory.API_ERROR,
                ErrorCategory.BUILD_ERROR,
                ErrorCategory.FLUTTER_ERROR,
                ErrorCategory.DOCKER_ERROR,
                ErrorCategory.NODE_ERROR,
                ErrorCategory.PYTHON_TRACEBACK,
            ]

            signal_categories = {signal.category for signal in signals}
            for cat in priority:
                if cat.value in signal_categories:
                    return cat

            return ErrorCategory(signals[0].category)

        lower = text.lower()

        if "traceback (most recent call last)" in lower:
            return ErrorCategory.PYTHON_TRACEBACK
        if input_type == "build_error":
            return ErrorCategory.BUILD_ERROR
        if input_type == "api_error":
            return ErrorCategory.API_ERROR
        if "flutter" in lower or framework == "flutter" or language == "dart":
            return ErrorCategory.FLUTTER_ERROR
        if "fastapi" in lower or framework == "fastapi":
            return ErrorCategory.FASTAPI_ERROR
        if "flask" in lower or framework == "flask":
            return ErrorCategory.FLASK_ERROR
        if "django" in lower or framework == "django":
            return ErrorCategory.DJANGO_ERROR
        if "react" in lower or framework == "react":
            return ErrorCategory.REACT_ERROR
        if "next" in lower or framework in {"next", "nextjs", "next.js"}:
            return ErrorCategory.NEXTJS_ERROR
        if "node" in lower or "npm" in lower:
            return ErrorCategory.NODE_ERROR

        return ErrorCategory.UNKNOWN

    def _determine_severity(
        self,
        text: str,
        signals: List[ErrorSignal],
        category: ErrorCategory,
    ) -> ErrorSeverity:
        lower = text.lower()

        if any(word in lower for word in [
            "production down",
            "data loss",
            "database locked",
            "security breach",
            "unauthorized access",
            "secret key exposed",
            "private key",
            "payment failed",
        ]):
            return ErrorSeverity.CRITICAL

        if category in {
            ErrorCategory.AUTH_ERROR,
            ErrorCategory.OAUTH_ERROR,
            ErrorCategory.PERMISSION_ERROR,
            ErrorCategory.DATABASE_ERROR,
        }:
            return ErrorSeverity.HIGH

        if category in {
            ErrorCategory.BUILD_ERROR,
            ErrorCategory.DEPENDENCY_ERROR,
            ErrorCategory.IMPORT_ERROR,
            ErrorCategory.API_ERROR,
            ErrorCategory.CORS_ERROR,
            ErrorCategory.PYTHON_TRACEBACK,
        }:
            return ErrorSeverity.MEDIUM

        if signals:
            severity_rank = {
                ErrorSeverity.CRITICAL.value: 5,
                ErrorSeverity.HIGH.value: 4,
                ErrorSeverity.MEDIUM.value: 3,
                ErrorSeverity.LOW.value: 2,
                ErrorSeverity.INFO.value: 1,
            }
            highest = max(signals, key=lambda s: severity_rank.get(s.severity, 0))
            return ErrorSeverity(highest.severity)

        return ErrorSeverity.LOW

    def _determine_confidence(
        self,
        signals: List[ErrorSignal],
        file_references: List[FileReference],
    ) -> FixConfidence:
        if len(signals) >= 2 and file_references:
            return FixConfidence.HIGH
        if signals:
            return FixConfidence.MEDIUM
        return FixConfidence.LOW

    def _build_title(
        self,
        category: ErrorCategory,
        signals: List[ErrorSignal],
        text: str,
    ) -> str:
        if signals:
            return signals[0].name

        last_line = self._last_meaningful_line(text)
        if last_line:
            return f"{category.value.replace('_', ' ').title()}: {last_line[:100]}"

        return category.value.replace("_", " ").title()

    def _build_summary(
        self,
        category: ErrorCategory,
        signals: List[ErrorSignal],
        text: str,
    ) -> str:
        if signals:
            primary = signals[0]
            return primary.explanation

        if category == ErrorCategory.PYTHON_TRACEBACK:
            return "The log contains a Python traceback. The failing file and final exception should be reviewed first."
        if category == ErrorCategory.BUILD_ERROR:
            return "The project build failed. The root cause is likely in dependencies, configuration, syntax, or framework setup."
        if category == ErrorCategory.API_ERROR:
            return "The error appears related to API communication, HTTP status handling, authentication, or network configuration."
        if category == ErrorCategory.UNKNOWN:
            return "The error type could not be confidently classified. Review the final error line and nearby file references."

        return f"The error appears related to {category.value.replace('_', ' ')}."

    def _build_root_cause(
        self,
        category: ErrorCategory,
        signals: List[ErrorSignal],
        text: str,
    ) -> str:
        if signals:
            return signals[0].suggested_fix

        final_error = self._last_meaningful_line(text)
        if final_error:
            return f"Likely root cause is near the final error message: {final_error}"

        return f"Likely root cause is inside the {category.value.replace('_', ' ')} area."

    def _build_recommended_steps(
        self,
        category: ErrorCategory,
        signals: List[ErrorSignal],
        file_references: List[FileReference],
        text: str,
        context: Dict[str, Any],
    ) -> List[str]:
        steps: List[str] = []

        if file_references:
            first_ref = file_references[0]
            location = first_ref.file_path or "the referenced file"
            if first_ref.line_number:
                location += f" around line {first_ref.line_number}"
            steps.append(f"Open {location} and inspect the exact failing statement.")

        for signal in signals[:5]:
            steps.append(signal.suggested_fix)

        if category == ErrorCategory.IMPORT_ERROR:
            steps.extend([
                "Confirm the module/package exists in the project or virtual environment.",
                "Check whether the import path matches the actual folder/file structure.",
                "Verify that `__init__.py` exists where package imports require it.",
            ])

        elif category == ErrorCategory.DEPENDENCY_ERROR:
            steps.extend([
                "Confirm dependencies are installed in the same environment used to run the app.",
                "Check version conflicts between framework, plugin, SDK, and lock files.",
                "Regenerate the lock file only after backing up the current working state.",
            ])

        elif category == ErrorCategory.CORS_ERROR:
            steps.extend([
                "Add the frontend origin to the backend CORS allowlist.",
                "Confirm protocol, domain, port, and trailing slash match exactly.",
                "For authenticated requests, enable credentials and avoid wildcard origins.",
            ])

        elif category == ErrorCategory.OAUTH_ERROR:
            steps.extend([
                "Verify OAuth redirect URI exactly matches the provider console configuration.",
                "Check client id, client secret, scopes, callback path, and environment variables.",
                "Confirm local, staging, and production OAuth apps are not mixed.",
            ])

        elif category == ErrorCategory.API_ERROR:
            steps.extend([
                "Check the request URL, HTTP method, request body, headers, and auth token.",
                "Log the server response body and status code before parsing JSON.",
                "Confirm backend route prefixes match the frontend API service paths.",
            ])

        elif category == ErrorCategory.DATABASE_ERROR:
            steps.extend([
                "Check database connection string, migrations, table names, and column names.",
                "Verify the current user/workspace query filters are applied correctly.",
                "Avoid destructive migration resets unless a backup exists.",
            ])

        elif category == ErrorCategory.FLUTTER_ERROR:
            steps.extend([
                "Run `flutter analyze` to identify static issues.",
                "Check widget constructor parameters and route names.",
                "Confirm generated imports match the actual file paths.",
            ])

        elif category == ErrorCategory.NODE_ERROR:
            steps.extend([
                "Check Node.js version compatibility with the project.",
                "Run dependency install in the project root where package.json exists.",
                "Review package-lock.json or pnpm-lock.yaml for dependency conflicts.",
            ])

        elif category == ErrorCategory.DOCKER_ERROR:
            steps.extend([
                "Check Dockerfile paths, build context, copied files, and environment variables.",
                "Confirm container ports match app ports.",
                "Review volume mounts that may overwrite files inside the container.",
            ])

        elif category == ErrorCategory.UNKNOWN:
            steps.extend([
                "Read the final 20 lines of the log first; most tools place the root cause near the end.",
                "Search for the first occurrence of words like Error, Exception, Failed, denied, missing, or invalid.",
                "Re-run the command with verbose/debug logging if available.",
            ])

        steps.append("After applying the fix, rerun the same command and compare the new error output.")
        steps.append("Prepare the result for Verification Agent so the fix can be validated safely.")

        return self._deduplicate_strings(steps)

    def _suggest_commands(
        self,
        category: ErrorCategory,
        signals: List[ErrorSignal],
        context: Dict[str, Any],
    ) -> Tuple[List[str], List[str]]:
        safe_commands: List[str] = []
        unsafe_commands: List[str] = []

        language = str(context.get("language", "")).lower()
        framework = str(context.get("framework", "")).lower()

        if category in {ErrorCategory.PYTHON_TRACEBACK, ErrorCategory.IMPORT_ERROR} or language == "python":
            safe_commands.extend([
                "python --version",
                "python -m pip --version",
                "python -m pip check",
            ])

        if category == ErrorCategory.BUILD_ERROR:
            safe_commands.extend([
                "python -m pip check",
                "npm --version",
                "node --version",
            ])

        if category == ErrorCategory.FLUTTER_ERROR or framework == "flutter" or language == "dart":
            safe_commands.extend([
                "flutter --version",
                "flutter doctor",
                "flutter analyze",
            ])

        if category == ErrorCategory.NODE_ERROR or framework in {"react", "nextjs", "next.js", "vite"}:
            safe_commands.extend([
                "node --version",
                "npm --version",
                "npm run lint",
            ])

        if category == ErrorCategory.DOCKER_ERROR:
            safe_commands.extend([
                "docker --version",
                "docker compose version",
                "docker ps",
            ])

        if category == ErrorCategory.DATABASE_ERROR:
            safe_commands.extend([
                "python -m pip check",
            ])
            unsafe_commands.extend([
                "DROP DATABASE",
                "flask db downgrade",
                "prisma migrate reset",
                "rm -rf migrations",
            ])

        unsafe_commands.extend([
            "rm -rf node_modules package-lock.json",
            "rm -rf .venv",
            "git reset --hard",
            "git clean -fdx",
            "docker system prune -a",
        ])

        return self._deduplicate_strings(safe_commands), self._deduplicate_strings(unsafe_commands)

    # -----------------------------------------------------------------------
    # Pattern Rules
    # -----------------------------------------------------------------------

    def _build_pattern_rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "Python Module Import Failure",
                "pattern": r"(modulenotfounderror|importerror|no module named)",
                "category": ErrorCategory.IMPORT_ERROR,
                "severity": ErrorSeverity.MEDIUM,
                "confidence": FixConfidence.HIGH,
                "explanation": "Python cannot find a required module. This usually means the dependency is missing, the import path is wrong, or the app is running from the wrong working directory.",
                "suggested_fix": "Install the missing package or correct the Python import path and run the app from the correct project root.",
            },
            {
                "name": "Python Syntax Error",
                "pattern": r"(syntaxerror|indentationerror|taberror)",
                "category": ErrorCategory.SYNTAX_ERROR,
                "severity": ErrorSeverity.MEDIUM,
                "confidence": FixConfidence.HIGH,
                "explanation": "The Python interpreter found invalid syntax or inconsistent indentation.",
                "suggested_fix": "Open the referenced file and fix the syntax or indentation at the reported line.",
            },
            {
                "name": "Python Name Error",
                "pattern": r"(nameerror|is not defined)",
                "category": ErrorCategory.RUNTIME_ERROR,
                "severity": ErrorSeverity.MEDIUM,
                "confidence": FixConfidence.HIGH,
                "explanation": "The code is using a variable, function, or class name that has not been defined in the current scope.",
                "suggested_fix": "Define the missing name, import it, or correct the spelling/scope.",
            },
            {
                "name": "Python Attribute Error",
                "pattern": r"(attributeerror|object has no attribute)",
                "category": ErrorCategory.RUNTIME_ERROR,
                "severity": ErrorSeverity.MEDIUM,
                "confidence": FixConfidence.HIGH,
                "explanation": "The code is trying to access a method or property that does not exist on the object.",
                "suggested_fix": "Check the object type and replace the invalid attribute with the correct method/property.",
            },
            {
                "name": "Python Type Error",
                "pattern": r"(typeerror|takes .* positional argument|unexpected keyword argument|missing .* required positional)",
                "category": ErrorCategory.RUNTIME_ERROR,
                "severity": ErrorSeverity.MEDIUM,
                "confidence": FixConfidence.HIGH,
                "explanation": "A function or method is being called with the wrong argument type, count, or keyword name.",
                "suggested_fix": "Compare the function definition with the call site and update the arguments.",
            },
            {
                "name": "Database Operational Error",
                "pattern": r"(operationalerror|database is locked|no such table|unknown column|relation .* does not exist)",
                "category": ErrorCategory.DATABASE_ERROR,
                "severity": ErrorSeverity.HIGH,
                "confidence": FixConfidence.HIGH,
                "explanation": "The application cannot complete a database operation because of a missing table/column, locked database, or connection/schema issue.",
                "suggested_fix": "Check migrations, database connection, table creation, and user/workspace query filters.",
            },
            {
                "name": "CORS Policy Block",
                "pattern": r"(cors|cross-origin|access-control-allow-origin|preflight|blocked by cors policy)",
                "category": ErrorCategory.CORS_ERROR,
                "severity": ErrorSeverity.MEDIUM,
                "confidence": FixConfidence.HIGH,
                "explanation": "The browser blocked the frontend request because the backend CORS policy does not allow this origin/request.",
                "suggested_fix": "Add the frontend origin to backend CORS settings and configure credentials/headers/methods correctly.",
            },
            {
                "name": "OAuth Redirect URI Mismatch",
                "pattern": r"(redirect_uri_mismatch|invalid redirect uri|redirect uri mismatch|oauth.*redirect)",
                "category": ErrorCategory.OAUTH_ERROR,
                "severity": ErrorSeverity.HIGH,
                "confidence": FixConfidence.HIGH,
                "explanation": "OAuth login failed because the callback/redirect URI does not match the provider configuration.",
                "suggested_fix": "Update the provider console redirect URI to exactly match the app callback URL.",
            },
            {
                "name": "Authentication Token Error",
                "pattern": r"(jwt|token expired|invalid token|unauthorized|401|forbidden|403)",
                "category": ErrorCategory.AUTH_ERROR,
                "severity": ErrorSeverity.HIGH,
                "confidence": FixConfidence.MEDIUM,
                "explanation": "The request is failing because authentication or authorization is invalid, missing, expired, or insufficient.",
                "suggested_fix": "Refresh/login again, verify Authorization headers, and check user/workspace permission checks.",
            },
            {
                "name": "HTTP API Error",
                "pattern": r"(http error|status code|404|500|502|503|504|failed to fetch|networkerror|connection refused)",
                "category": ErrorCategory.API_ERROR,
                "severity": ErrorSeverity.MEDIUM,
                "confidence": FixConfidence.MEDIUM,
                "explanation": "The frontend or client could not communicate successfully with the backend/API.",
                "suggested_fix": "Verify route path, method, server status, proxy/base URL, and request/response format.",
            },
            {
                "name": "NPM Dependency Error",
                "pattern": r"(npm err|eresolve|enoent.*package\.json|cannot find module|module not found)",
                "category": ErrorCategory.DEPENDENCY_ERROR,
                "severity": ErrorSeverity.MEDIUM,
                "confidence": FixConfidence.HIGH,
                "explanation": "The Node/NPM project has a missing dependency, version conflict, or package configuration issue.",
                "suggested_fix": "Install dependencies from the project root and resolve package version conflicts.",
            },
            {
                "name": "TypeScript Compile Error",
                "pattern": r"(ts\d{4}|typescript error|type .* is not assignable|property .* does not exist)",
                "category": ErrorCategory.TYPESCRIPT_ERROR,
                "severity": ErrorSeverity.MEDIUM,
                "confidence": FixConfidence.HIGH,
                "explanation": "TypeScript compilation failed because a type, property, or interface does not match the code.",
                "suggested_fix": "Update the type/interface or fix the call/property usage at the referenced file.",
            },
            {
                "name": "React Render/Hook Error",
                "pattern": r"(invalid hook call|hooks can only be called|react-dom|hydration failed|cannot update a component)",
                "category": ErrorCategory.REACT_ERROR,
                "severity": ErrorSeverity.MEDIUM,
                "confidence": FixConfidence.HIGH,
                "explanation": "React failed due to incorrect hook usage, hydration mismatch, or render lifecycle issue.",
                "suggested_fix": "Check hook placement, component rendering conditions, and server/client markup consistency.",
            },
            {
                "name": "Next.js Build Runtime Error",
                "pattern": r"(next\.js|next build|app router|pages router|server component|client component)",
                "category": ErrorCategory.NEXTJS_ERROR,
                "severity": ErrorSeverity.MEDIUM,
                "confidence": FixConfidence.MEDIUM,
                "explanation": "The error appears related to Next.js routing, build, server components, or client components.",
                "suggested_fix": "Check server/client component boundaries, route files, environment variables, and build logs.",
            },
            {
                "name": "Flutter/Dart Error",
                "pattern": r"(flutter|dart|pubspec|widget|renderflex|setstate|no named parameter|undefined class)",
                "category": ErrorCategory.FLUTTER_ERROR,
                "severity": ErrorSeverity.MEDIUM,
                "confidence": FixConfidence.MEDIUM,
                "explanation": "The error appears related to Flutter/Dart widget structure, dependencies, routing, or constructor parameters.",
                "suggested_fix": "Run flutter analyze and fix the referenced widget, import, route, or pubspec issue.",
            },
            {
                "name": "Docker Build/Runtime Error",
                "pattern": r"(dockerfile|docker compose|docker-compose|container exited|failed to solve|no such service)",
                "category": ErrorCategory.DOCKER_ERROR,
                "severity": ErrorSeverity.MEDIUM,
                "confidence": FixConfidence.MEDIUM,
                "explanation": "Docker failed during build, compose startup, service resolution, or container runtime.",
                "suggested_fix": "Check Dockerfile paths, build context, compose service names, environment variables, and port mappings.",
            },
            {
                "name": "Permission Denied Error",
                "pattern": r"(permission denied|access denied|eacces|eperm|operation not permitted)",
                "category": ErrorCategory.PERMISSION_ERROR,
                "severity": ErrorSeverity.HIGH,
                "confidence": FixConfidence.HIGH,
                "explanation": "The process does not have permission to access the file, port, folder, or operation.",
                "suggested_fix": "Check file ownership, OS permissions, port usage, and whether elevated permissions are required.",
            },
            {
                "name": "Environment Variable Missing",
                "pattern": r"(environment variable|env var|missing env|keyerror:.*env|undefined.*process\.env)",
                "category": ErrorCategory.RUNTIME_ERROR,
                "severity": ErrorSeverity.MEDIUM,
                "confidence": FixConfidence.MEDIUM,
                "explanation": "A required environment variable is missing or not loaded into the runtime.",
                "suggested_fix": "Add the missing environment variable to the correct .env/config source and restart the app.",
            },
            {
                "name": "JSON Parsing Error",
                "pattern": r"(jsondecodeerror|unexpected token .* in json|invalid json|failed to parse json)",
                "category": ErrorCategory.API_ERROR,
                "severity": ErrorSeverity.MEDIUM,
                "confidence": FixConfidence.HIGH,
                "explanation": "The app expected JSON but received invalid JSON, empty response, HTML, or malformed data.",
                "suggested_fix": "Log the raw response body before JSON parsing and ensure the API returns valid JSON.",
            },
        ]

    # -----------------------------------------------------------------------
    # Required Compatibility Hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation context.
        """

        effective_user_id = user_id or self.user_id
        effective_workspace_id = workspace_id or self.workspace_id

        if self.strict_context:
            if effective_user_id is None:
                return self._error_result(
                    message="Missing user_id. Error analysis must be scoped to a SaaS user.",
                    code="MISSING_USER_ID",
                )

            if effective_workspace_id is None:
                return self._error_result(
                    message="Missing workspace_id. Error analysis must be scoped to a workspace.",
                    code="MISSING_WORKSPACE_ID",
                )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": effective_user_id,
                "workspace_id": effective_workspace_id,
                "context": context or {},
            },
        )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Decide if a requested action needs Security Agent approval.

        Error analysis itself is read-only and usually does not require approval.
        Any destructive command recommendation does.
        """

        destructive_keywords = [
            "delete",
            "remove",
            "drop",
            "reset",
            "clean",
            "prune",
            "truncate",
            "overwrite",
            "execute_command",
            "run_fix",
        ]

        action_lower = action.lower()
        if any(keyword in action_lower for keyword in destructive_keywords):
            return True

        payload_text = json.dumps(payload or {}, default=str).lower()
        return any(keyword in payload_text for keyword in destructive_keywords)

    def _request_security_approval(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Security Agent approval request.

        This file does not directly execute actions. It only prepares
        structured approval payloads for the Security Agent.
        """

        return {
            "required": self._requires_security_check(action, payload),
            "agent": self.AGENT_NAME,
            "module": self.AGENT_MODULE,
            "action": action,
            "payload": payload or {},
            "reason": "Security approval is required before any destructive or sensitive remediation action.",
            "created_at": self._utc_now(),
        }

    def _prepare_verification_payload(
        self,
        analysis: ErrorAnalysis,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload after analysis.
        """

        return {
            "agent": self.AGENT_NAME,
            "module": self.AGENT_MODULE,
            "verification_type": "error_analysis_review",
            "status": "pending",
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "category": analysis.category,
            "severity": analysis.severity,
            "confidence": analysis.confidence,
            "checks": [
                "Confirm category matches the raw error.",
                "Confirm file references are accurate.",
                "Confirm recommended steps are safe and non-destructive.",
                "Confirm commands do not execute destructive operations.",
                "Confirm SaaS user/workspace context is preserved.",
            ],
            "analysis_excerpt": analysis.raw_error_excerpt,
            "context": context or {},
            "created_at": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        analysis: ErrorAnalysis,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Memory Agent can store useful debugging patterns per user/workspace
        without mixing data across SaaS tenants.
        """

        return {
            "agent": self.AGENT_NAME,
            "module": self.AGENT_MODULE,
            "memory_type": "code_error_pattern",
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "should_store": analysis.confidence in {
                FixConfidence.MEDIUM.value,
                FixConfidence.HIGH.value,
            },
            "title": analysis.title,
            "category": analysis.category,
            "severity": analysis.severity,
            "summary": analysis.summary,
            "likely_root_cause": analysis.likely_root_cause,
            "recommended_steps": analysis.recommended_steps[:5],
            "metadata": {
                "framework_hint": analysis.metadata.get("framework_hint"),
                "language_hint": analysis.metadata.get("language_hint"),
                "project_path": analysis.metadata.get("project_path"),
                "created_at": self._utc_now(),
            },
            "context": context or {},
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Emit event for dashboard/registry/router integrations.

        Safe no-op if real event bus does not exist yet.
        """

        try:
            event_payload = {
                "agent": self.AGENT_NAME,
                "module": self.AGENT_MODULE,
                "event_name": event_name,
                "payload": payload,
                "timestamp": self._utc_now(),
            }

            if hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_name, event_payload)  # type: ignore
                except Exception:
                    pass

            logger.debug("Agent event: %s", event_payload)

        except Exception:
            logger.exception("Failed to emit ErrorAnalyzer event.")

    def _log_audit_event(
        self,
        action: str,
        status: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Write audit log event.

        This implementation logs safely. Future system can replace this with
        database-backed AuditLog service.
        """

        if not self.enable_audit_logs:
            return

        try:
            audit_payload = {
                "agent": self.AGENT_NAME,
                "module": self.AGENT_MODULE,
                "action": action,
                "status": status,
                "user_id": user_id or self.user_id,
                "workspace_id": workspace_id or self.workspace_id,
                "details": details or {},
                "timestamp": self._utc_now(),
            }
            logger.info("AUDIT_EVENT %s", json.dumps(audit_payload, default=str))
        except Exception:
            logger.exception("Failed to write audit event.")

    def _safe_result(
        self,
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
            "metadata": metadata or {
                "agent": self.AGENT_NAME,
                "module": self.AGENT_MODULE,
                "timestamp": self._utc_now(),
            },
        }

    def _error_result(
        self,
        message: str,
        code: str = "ERROR",
        exception: Optional[BaseException] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result.
        """

        error_payload: Dict[str, Any] = {
            "code": code,
            "message": message,
        }

        if exception is not None:
            error_payload["exception_type"] = exception.__class__.__name__
            error_payload["exception_message"] = str(exception)
            error_payload["traceback"] = traceback.format_exc()

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": error_payload,
            "metadata": metadata or {
                "agent": self.AGENT_NAME,
                "module": self.AGENT_MODULE,
                "timestamp": self._utc_now(),
            },
        }

    # -----------------------------------------------------------------------
    # Dashboard Payload
    # -----------------------------------------------------------------------

    def _prepare_dashboard_payload(self, analysis: ErrorAnalysis) -> Dict[str, Any]:
        return {
            "card_type": "error_analysis",
            "title": analysis.title,
            "category": analysis.category,
            "severity": analysis.severity,
            "confidence": analysis.confidence,
            "summary": analysis.summary,
            "primary_fix": analysis.recommended_steps[0] if analysis.recommended_steps else None,
            "signals_count": len(analysis.detected_signals),
            "file_refs_count": len(analysis.file_references),
            "created_at": self._utc_now(),
        }

    # -----------------------------------------------------------------------
    # Utility Methods
    # -----------------------------------------------------------------------

    def _analysis_to_dict(self, analysis: ErrorAnalysis) -> Dict[str, Any]:
        payload = asdict(analysis)
        payload["detected_signals"] = [asdict(signal) for signal in analysis.detected_signals]
        payload["file_references"] = [asdict(ref) for ref in analysis.file_references]
        return payload

    def _normalize_text(self, text: str) -> str:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        text = re.sub(r"\n{4,}", "\n\n\n", text)
        return text.strip()

    def _excerpt(self, text: str, limit: int = 3000) -> str:
        if len(text) <= limit:
            return text
        return text[-limit:]

    def _last_meaningful_line(self, text: str) -> str:
        for line in reversed(text.splitlines()):
            cleaned = line.strip()
            if cleaned:
                return cleaned
        return ""

    def _get_evidence_line(self, text: str, matched_text: str) -> str:
        if not matched_text:
            return ""

        lower_match = matched_text.lower()
        for line in text.splitlines():
            if lower_match in line.lower():
                return line.strip()[:500]

        return matched_text[:500]

    def _safe_int(self, value: Optional[str]) -> Optional[int]:
        try:
            if value is None:
                return None
            return int(value)
        except Exception:
            return None

    def _deduplicate_strings(self, items: List[str]) -> List[str]:
        seen = set()
        output = []
        for item in items:
            key = item.strip().lower()
            if key and key not in seen:
                seen.add(key)
                output.append(item.strip())
        return output

    def _deduplicate_signals(self, signals: List[ErrorSignal]) -> List[ErrorSignal]:
        seen = set()
        output = []
        for signal in signals:
            key = (signal.name, signal.category, signal.evidence)
            if key not in seen:
                seen.add(key)
                output.append(signal)
        return output

    def _deduplicate_file_refs(self, refs: List[FileReference]) -> List[FileReference]:
        seen = set()
        output = []
        for ref in refs:
            key = (
                ref.file_path,
                ref.line_number,
                ref.column_number,
                ref.function_name,
            )
            if key not in seen:
                seen.add(key)
                output.append(ref)
        return output

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Convenience function for simple direct use
# ---------------------------------------------------------------------------

def analyze_error_text(
    error_text: str,
    user_id: Optional[Union[str, int]] = None,
    workspace_id: Optional[Union[str, int]] = None,
    context: Optional[Dict[str, Any]] = None,
    strict_context: bool = False,
) -> Dict[str, Any]:
    """
    Convenience wrapper for scripts/tests.

    Example:
        result = analyze_error_text(
            traceback_text,
            user_id=1,
            workspace_id=1,
            context={"language": "python", "framework": "flask"},
        )
    """

    analyzer = ErrorAnalyzer(
        user_id=user_id,
        workspace_id=workspace_id,
        strict_context=strict_context,
    )
    return analyzer.analyze(
        error_text=error_text,
        user_id=user_id,
        workspace_id=workspace_id,
        context=context or {},
    )


# ---------------------------------------------------------------------------
# Manual test block
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sample_error = """
Traceback (most recent call last):
  File "app.py", line 12, in <module>
    from services.auth_service import login_user
ModuleNotFoundError: No module named 'services'
"""

    result = analyze_error_text(
        sample_error,
        user_id="demo_user",
        workspace_id="demo_workspace",
        context={
            "language": "python",
            "framework": "flask",
            "project_path": "/demo/william",
        },
        strict_context=True,
    )

    print(json.dumps(result, indent=2, default=str))