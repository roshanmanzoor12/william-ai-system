"""
agents/code_agent/dependency_manager.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    DependencyManager manages Python package dependencies, requirements files,
    package version conflicts, package metadata, dependency analysis, and safe
    dependency planning for the Code Agent.

Architecture Compatibility:
    - BaseAgent compatible
    - Master Agent routing compatible
    - Agent Registry / Agent Loader safe
    - SaaS user_id / workspace_id isolation aware
    - Security Agent approval hooks included
    - Verification Agent payload hooks included
    - Memory Agent payload hooks included
    - Dashboard/API structured result compatible

Important:
    This file is import-safe. If other William/Jarvis modules do not exist yet,
    fallback stubs are used so the file can still be imported and tested.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import subprocess
import hashlib
import datetime
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------
# Safe optional imports for William/Jarvis architecture compatibility
# ---------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:
        """
        Fallback BaseAgent stub.

        This allows DependencyManager to be imported before the real BaseAgent
        exists. When the full William/Jarvis system is available, the real
        BaseAgent will be used automatically.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "code_agent")
            self.logger = logging.getLogger(self.agent_name)

        def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent run() called.",
                "data": {},
                "error": None,
                "metadata": {},
            }


try:
    from packaging.requirements import Requirement  # type: ignore
    from packaging.version import Version, InvalidVersion  # type: ignore
    from packaging.specifiers import SpecifierSet  # type: ignore
    PACKAGING_AVAILABLE = True
except Exception:
    Requirement = None  # type: ignore
    Version = None  # type: ignore
    InvalidVersion = Exception  # type: ignore
    SpecifierSet = None  # type: ignore
    PACKAGING_AVAILABLE = False


# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------

LOGGER = logging.getLogger("DependencyManager")
if not LOGGER.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

DEFAULT_REQUIREMENT_FILES = [
    "requirements.txt",
    "requirements-dev.txt",
    "dev-requirements.txt",
    "requirements/base.txt",
    "requirements/dev.txt",
    "requirements/prod.txt",
    "pyproject.toml",
    "Pipfile",
    "setup.py",
    "setup.cfg",
]

SENSITIVE_PACKAGE_PATTERNS = [
    "keylogger",
    "stealer",
    "rat",
    "malware",
    "backdoor",
    "ransom",
    "spyware",
    "trojan",
    "cryptominer",
]

DESTRUCTIVE_ACTIONS = {
    "install",
    "uninstall",
    "upgrade",
    "freeze_write",
    "sync_environment",
    "modify_requirements",
}

SAFE_ACTIONS = {
    "parse",
    "analyze",
    "compare",
    "detect_conflicts",
    "read_requirements",
    "generate_report",
    "plan_install",
    "plan_upgrade",
    "plan_uninstall",
}


# ---------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------

@dataclass
class DependencyRecord:
    """
    Represents a single dependency parsed from a dependency file or package list.
    """

    name: str
    raw: str
    specifier: Optional[str] = None
    version: Optional[str] = None
    extras: List[str] = field(default_factory=list)
    marker: Optional[str] = None
    source: Optional[str] = None
    line_number: Optional[int] = None
    editable: bool = False
    url: Optional[str] = None
    valid: bool = True
    error: Optional[str] = None

    def normalized_name(self) -> str:
        return normalize_package_name(self.name)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DependencyConflict:
    """
    Represents a detected version or duplicate package conflict.
    """

    package: str
    conflict_type: str
    message: str
    records: List[Dict[str, Any]] = field(default_factory=list)
    severity: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DependencyPlan:
    """
    Represents a safe dependency action plan.

    The DependencyManager creates plans first. Destructive actions should be
    gated by Security Agent approval before execution.
    """

    action: str
    packages: List[str]
    project_path: Optional[str] = None
    requirement_file: Optional[str] = None
    commands: List[List[str]] = field(default_factory=list)
    requires_security: bool = True
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------

def utc_now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def normalize_package_name(name: str) -> str:
    """
    Normalize package names according to Python packaging convention.
    """
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def safe_read_text(path: Union[str, Path]) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as file:
        return file.read()


def safe_write_text(path: Union[str, Path], content: str) -> None:
    with open(path, "w", encoding="utf-8") as file:
        file.write(content)


def sha256_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def is_probably_requirement_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if stripped.startswith("#"):
        return False
    if stripped.startswith(("-r ", "--requirement", "-c ", "--constraint")):
        return False
    if stripped.startswith(("--index-url", "--extra-index-url", "-i ")):
        return False
    return True


def strip_inline_comment(line: str) -> str:
    """
    Removes inline comments while preserving URL fragments where possible.
    """
    if "://" in line:
        return line.strip()

    parts = line.split("#", 1)
    return parts[0].strip()


# ---------------------------------------------------------------------
# DependencyManager
# ---------------------------------------------------------------------

class DependencyManager(BaseAgent):
    """
    Code Agent helper responsible for dependency management.

    Main responsibilities:
        - Parse requirements files
        - Analyze package lists
        - Detect duplicate dependencies
        - Detect version conflicts
        - Generate safe install / upgrade / uninstall plans
        - Inspect installed packages
        - Create/merge requirements content
        - Prepare Security, Verification, Memory, Audit, and Dashboard payloads

    This file does not automatically perform destructive dependency changes
    unless explicitly asked and security approval passes.
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        agent_name: str = "DependencyManager",
        agent_type: str = "code_agent",
        default_project_path: Optional[Union[str, Path]] = None,
        allow_subprocess_execution: bool = False,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=agent_name, agent_type=agent_type, **kwargs)

        self.agent_name = agent_name
        self.agent_type = agent_type
        self.default_project_path = Path(default_project_path).resolve() if default_project_path else None
        self.allow_subprocess_execution = allow_subprocess_execution
        self.logger = logger or LOGGER

    # -----------------------------------------------------------------
    # Standard result helpers
    # -----------------------------------------------------------------

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "timestamp": utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        error_text = str(error) if error else message
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error_text,
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "timestamp": utc_now_iso(),
                **(metadata or {}),
            },
        }

    # -----------------------------------------------------------------
    # William/Jarvis compatibility hooks
    # -----------------------------------------------------------------

    def _validate_task_context(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        action: str,
        project_path: Optional[Union[str, Path]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validates SaaS isolation and task context.

        user_id and workspace_id are required whenever user-specific dependency
        actions are requested.
        """
        if user_id is None or str(user_id).strip() == "":
            return False, "Missing user_id. Dependency actions require SaaS user isolation."

        if workspace_id is None or str(workspace_id).strip() == "":
            return False, "Missing workspace_id. Dependency actions require workspace isolation."

        if not action or not isinstance(action, str):
            return False, "Missing or invalid action."

        if project_path is not None:
            resolved = Path(project_path).expanduser().resolve()
            if not resolved.exists():
                return False, f"Project path does not exist: {resolved}"

        return True, None

    def _requires_security_check(self, action: str, packages: Optional[List[str]] = None) -> bool:
        """
        Returns True when action should be routed through Security Agent.
        """
        action = action.strip().lower()

        if action in DESTRUCTIVE_ACTIONS:
            return True

        for package in packages or []:
            lowered = package.lower()
            if any(pattern in lowered for pattern in SENSITIVE_PACKAGE_PATTERNS):
                return True

        return False

    def _request_security_approval(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        action: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Security Agent compatibility hook.

        In the full system, this should call Security Agent. For import-safe
        behavior, this returns a structured approval placeholder.

        Destructive execution still requires allow_subprocess_execution=True.
        """
        requires_security = self._requires_security_check(
            action=action,
            packages=payload.get("packages") or [],
        )

        return {
            "required": requires_security,
            "approved": not requires_security,
            "message": (
                "Security approval required before execution."
                if requires_security
                else "Security approval not required for this action."
            ),
            "security_payload": {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "agent": self.agent_name,
                "action": action,
                "payload": payload,
                "timestamp": utc_now_iso(),
            },
        }

    def _prepare_verification_payload(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        action: str,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepares payload for Verification Agent.
        """
        return {
            "verification_type": "dependency_management",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "agent": self.agent_name,
            "action": action,
            "success": result.get("success", False),
            "message": result.get("message"),
            "data_hash": sha256_text(json.dumps(result.get("data", {}), sort_keys=True, default=str)),
            "timestamp": utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        action: str,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepares useful context for Memory Agent.

        This should never include secrets. It stores dependency summary only.
        """
        data = result.get("data", {})
        summary = {
            "action": action,
            "dependency_count": data.get("dependency_count"),
            "conflict_count": data.get("conflict_count"),
            "files": data.get("files"),
            "packages": data.get("packages"),
        }

        return {
            "memory_type": "code_dependency_context",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "agent": self.agent_name,
            "summary": summary,
            "timestamp": utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Dashboard/API/Registry event compatibility hook.
        """
        event = {
            "event_name": event_name,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": payload or {},
            "timestamp": utc_now_iso(),
        }

        self.logger.info("Agent event emitted: %s", event_name)
        return event

    def _log_audit_event(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        action: str,
        status: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Audit log compatibility hook.

        In the full SaaS system, this should write to the audit log table.
        This import-safe version returns the structured audit payload.
        """
        audit = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "agent": self.agent_name,
            "action": action,
            "status": status,
            "details": details or {},
            "timestamp": utc_now_iso(),
        }

        self.logger.info("Audit event: action=%s status=%s", action, status)
        return audit

    # -----------------------------------------------------------------
    # Core public routing method
    # -----------------------------------------------------------------

    def run(
        self,
        action: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        project_path: Optional[Union[str, Path]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Master Agent / Router compatible entrypoint.

        Supported actions:
            - discover_files
            - parse_requirements
            - analyze_project
            - detect_conflicts
            - list_installed
            - plan_install
            - plan_upgrade
            - plan_uninstall
            - merge_requirements
            - freeze_environment
        """
        action = (action or "").strip().lower()
        project = self._resolve_project_path(project_path)

        valid, error = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            action=action,
            project_path=project if project else None,
        )
        if not valid:
            return self._error_result(error or "Invalid task context.")

        assert user_id is not None
        assert workspace_id is not None

        self._emit_agent_event(
            "dependency_manager.started",
            user_id=user_id,
            workspace_id=workspace_id,
            payload={"action": action, "project_path": str(project) if project else None},
        )

        try:
            if action == "discover_files":
                result = self.discover_dependency_files(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    project_path=project,
                )
            elif action == "parse_requirements":
                result = self.parse_requirements_file(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    file_path=kwargs.get("file_path"),
                    project_path=project,
                )
            elif action == "analyze_project":
                result = self.analyze_project_dependencies(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    project_path=project,
                )
            elif action == "detect_conflicts":
                result = self.detect_conflicts(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    dependencies=kwargs.get("dependencies"),
                    project_path=project,
                )
            elif action == "list_installed":
                result = self.list_installed_packages(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    python_executable=kwargs.get("python_executable"),
                )
            elif action == "plan_install":
                result = self.plan_install(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    packages=kwargs.get("packages") or [],
                    project_path=project,
                    requirement_file=kwargs.get("requirement_file"),
                )
            elif action == "plan_upgrade":
                result = self.plan_upgrade(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    packages=kwargs.get("packages") or [],
                    project_path=project,
                )
            elif action == "plan_uninstall":
                result = self.plan_uninstall(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    packages=kwargs.get("packages") or [],
                    project_path=project,
                )
            elif action == "merge_requirements":
                result = self.merge_requirements(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    input_files=kwargs.get("input_files") or [],
                    output_file=kwargs.get("output_file"),
                    project_path=project,
                    write_file=bool(kwargs.get("write_file", False)),
                )
            elif action == "freeze_environment":
                result = self.freeze_environment(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    python_executable=kwargs.get("python_executable"),
                    output_file=kwargs.get("output_file"),
                    write_file=bool(kwargs.get("write_file", False)),
                )
            else:
                result = self._error_result(
                    message=f"Unsupported dependency manager action: {action}",
                    data={"supported_actions": self.supported_actions()},
                )

            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                action=action,
                result=result,
            )
            memory_payload = self._prepare_memory_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                action=action,
                result=result,
            )

            result.setdefault("metadata", {})
            result["metadata"]["verification_payload"] = verification_payload
            result["metadata"]["memory_payload"] = memory_payload

            self._log_audit_event(
                user_id=user_id,
                workspace_id=workspace_id,
                action=action,
                status="success" if result.get("success") else "failed",
                details={"message": result.get("message")},
            )

            return result

        except Exception as exc:
            self.logger.exception("DependencyManager run failed.")
            return self._error_result(
                message="DependencyManager action failed.",
                error=exc,
                metadata={"action": action},
            )

    def supported_actions(self) -> List[str]:
        return [
            "discover_files",
            "parse_requirements",
            "analyze_project",
            "detect_conflicts",
            "list_installed",
            "plan_install",
            "plan_upgrade",
            "plan_uninstall",
            "merge_requirements",
            "freeze_environment",
        ]

    # -----------------------------------------------------------------
    # Project/file helpers
    # -----------------------------------------------------------------

    def _resolve_project_path(self, project_path: Optional[Union[str, Path]]) -> Optional[Path]:
        if project_path:
            return Path(project_path).expanduser().resolve()
        if self.default_project_path:
            return self.default_project_path
        return None

    def discover_dependency_files(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        project_path: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Finds common Python dependency files in a project.
        """
        project = self._resolve_project_path(project_path)
        if not project:
            return self._error_result("project_path is required.")

        if not project.exists() or not project.is_dir():
            return self._error_result(f"Invalid project directory: {project}")

        found_files: List[Dict[str, Any]] = []

        for relative in DEFAULT_REQUIREMENT_FILES:
            candidate = project / relative
            if candidate.exists() and candidate.is_file():
                try:
                    content = safe_read_text(candidate)
                    found_files.append(
                        {
                            "path": str(candidate),
                            "relative_path": str(candidate.relative_to(project)),
                            "size_bytes": candidate.stat().st_size,
                            "sha256": sha256_text(content),
                            "type": self._classify_dependency_file(candidate),
                        }
                    )
                except Exception as exc:
                    found_files.append(
                        {
                            "path": str(candidate),
                            "relative_path": str(candidate.relative_to(project)),
                            "error": str(exc),
                            "type": self._classify_dependency_file(candidate),
                        }
                    )

        return self._safe_result(
            "Dependency files discovered.",
            data={
                "project_path": str(project),
                "files": found_files,
                "file_count": len(found_files),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def _classify_dependency_file(self, path: Path) -> str:
        name = path.name.lower()
        if name == "pyproject.toml":
            return "pyproject"
        if name == "pipfile":
            return "pipfile"
        if name == "setup.py":
            return "setup_py"
        if name == "setup.cfg":
            return "setup_cfg"
        if name.endswith(".txt"):
            return "requirements"
        return "unknown"

    # -----------------------------------------------------------------
    # Parsing
    # -----------------------------------------------------------------

    def parse_requirements_file(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        file_path: Optional[Union[str, Path]] = None,
        project_path: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Parses a requirements-style file.

        Supports normal requirements lines:
            package
            package==1.2.3
            package>=1,<2
            package[extra]==1.0
            -e git+https://...
        """
        project = self._resolve_project_path(project_path)

        if file_path is None:
            if not project:
                return self._error_result("file_path or project_path is required.")
            file_path = project / "requirements.txt"

        path = Path(file_path).expanduser().resolve()
        if not path.exists():
            return self._error_result(f"Requirements file does not exist: {path}")

        try:
            content = safe_read_text(path)
            dependencies = self.parse_requirements_content(content, source=str(path))

            return self._safe_result(
                "Requirements file parsed.",
                data={
                    "file_path": str(path),
                    "dependency_count": len(dependencies),
                    "dependencies": [item.to_dict() for item in dependencies],
                    "content_sha256": sha256_text(content),
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to parse requirements file.",
                error=exc,
                data={"file_path": str(path)},
            )

    def parse_requirements_content(
        self,
        content: str,
        source: Optional[str] = None,
    ) -> List[DependencyRecord]:
        """
        Parses raw requirements.txt content into DependencyRecord objects.
        """
        records: List[DependencyRecord] = []

        for line_number, raw_line in enumerate(content.splitlines(), start=1):
            original = raw_line.rstrip("\n")
            cleaned = strip_inline_comment(original)

            if not is_probably_requirement_line(cleaned):
                continue

            record = self._parse_single_requirement_line(
                line=cleaned,
                source=source,
                line_number=line_number,
            )
            records.append(record)

        return records

    def _parse_single_requirement_line(
        self,
        line: str,
        source: Optional[str] = None,
        line_number: Optional[int] = None,
    ) -> DependencyRecord:
        editable = False
        raw = line.strip()

        if raw.startswith("-e "):
            editable = True
            raw = raw[3:].strip()
        elif raw.startswith("--editable "):
            editable = True
            raw = raw[len("--editable "):].strip()

        if raw.startswith(("git+", "http://", "https://", "file:")):
            name = self._extract_name_from_url_requirement(raw)
            return DependencyRecord(
                name=name,
                raw=line,
                source=source,
                line_number=line_number,
                editable=editable,
                url=raw,
                valid=bool(name and name != "unknown-url-package"),
            )

        if PACKAGING_AVAILABLE and Requirement is not None:
            try:
                req = Requirement(raw)
                return DependencyRecord(
                    name=req.name,
                    raw=line,
                    specifier=str(req.specifier) if req.specifier else None,
                    extras=sorted(list(req.extras)) if req.extras else [],
                    marker=str(req.marker) if req.marker else None,
                    source=source,
                    line_number=line_number,
                    editable=editable,
                    valid=True,
                )
            except Exception as exc:
                return self._fallback_parse_requirement(
                    line=line,
                    source=source,
                    line_number=line_number,
                    editable=editable,
                    error=str(exc),
                )

        return self._fallback_parse_requirement(
            line=line,
            source=source,
            line_number=line_number,
            editable=editable,
            error=None,
        )

    def _fallback_parse_requirement(
        self,
        line: str,
        source: Optional[str],
        line_number: Optional[int],
        editable: bool,
        error: Optional[str],
    ) -> DependencyRecord:
        pattern = r"^\s*([A-Za-z0-9_.\-]+)(.*)$"
        match = re.match(pattern, line)
        if not match:
            return DependencyRecord(
                name="unknown",
                raw=line,
                source=source,
                line_number=line_number,
                editable=editable,
                valid=False,
                error=error or "Unable to parse requirement line.",
            )

        name = match.group(1)
        specifier = match.group(2).strip() or None

        version = None
        if specifier:
            version_match = re.search(r"==\s*([A-Za-z0-9_.!\-+]+)", specifier)
            if version_match:
                version = version_match.group(1)

        return DependencyRecord(
            name=name,
            raw=line,
            specifier=specifier,
            version=version,
            source=source,
            line_number=line_number,
            editable=editable,
            valid=error is None,
            error=error,
        )

    def _extract_name_from_url_requirement(self, raw: str) -> str:
        egg_match = re.search(r"[#&]egg=([A-Za-z0-9_.\-]+)", raw)
        if egg_match:
            return egg_match.group(1)

        name_match = re.search(r"/([A-Za-z0-9_.\-]+?)(?:\.git)?(?:$|[@#?])", raw)
        if name_match:
            return name_match.group(1)

        return "unknown-url-package"

    # -----------------------------------------------------------------
    # Project analysis
    # -----------------------------------------------------------------

    def analyze_project_dependencies(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        project_path: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Discovers and analyzes project dependency files.
        """
        project = self._resolve_project_path(project_path)
        if not project:
            return self._error_result("project_path is required.")

        discovered = self.discover_dependency_files(
            user_id=user_id,
            workspace_id=workspace_id,
            project_path=project,
        )

        if not discovered.get("success"):
            return discovered

        files = discovered.get("data", {}).get("files", [])
        all_dependencies: List[DependencyRecord] = []
        parsed_files: List[Dict[str, Any]] = []

        for file_info in files:
            path = Path(file_info["path"])
            file_type = file_info.get("type")

            if file_type == "requirements":
                parsed = self.parse_requirements_file(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    file_path=path,
                    project_path=project,
                )
                dependencies = parsed.get("data", {}).get("dependencies", [])
                parsed_files.append(
                    {
                        "path": str(path),
                        "type": file_type,
                        "dependency_count": len(dependencies),
                    }
                )
                for item in dependencies:
                    all_dependencies.append(DependencyRecord(**item))
            else:
                parsed_files.append(
                    {
                        "path": str(path),
                        "type": file_type,
                        "dependency_count": None,
                        "note": "Detected but not deeply parsed by requirements parser.",
                    }
                )

        conflict_result = self.detect_conflicts(
            user_id=user_id,
            workspace_id=workspace_id,
            dependencies=[item.to_dict() for item in all_dependencies],
            project_path=project,
        )

        conflicts = conflict_result.get("data", {}).get("conflicts", [])

        packages = sorted({item.normalized_name() for item in all_dependencies if item.name})

        return self._safe_result(
            "Project dependencies analyzed.",
            data={
                "project_path": str(project),
                "files": parsed_files,
                "dependency_count": len(all_dependencies),
                "packages": packages,
                "package_count": len(packages),
                "conflict_count": len(conflicts),
                "conflicts": conflicts,
                "invalid_dependencies": [
                    item.to_dict() for item in all_dependencies if not item.valid
                ],
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    # -----------------------------------------------------------------
    # Conflict detection
    # -----------------------------------------------------------------

    def detect_conflicts(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        dependencies: Optional[List[Union[Dict[str, Any], DependencyRecord]]] = None,
        project_path: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Detects duplicate packages and likely version conflicts.
        """
        records: List[DependencyRecord] = []

        if dependencies is None:
            project = self._resolve_project_path(project_path)
            if not project:
                return self._error_result("dependencies or project_path is required.")

            analysis = self.analyze_project_dependencies(
                user_id=user_id,
                workspace_id=workspace_id,
                project_path=project,
            )
            deps = analysis.get("data", {}).get("dependencies", [])
            dependencies = deps

        for dep in dependencies or []:
            if isinstance(dep, DependencyRecord):
                records.append(dep)
            elif isinstance(dep, dict):
                try:
                    records.append(DependencyRecord(**dep))
                except TypeError:
                    records.append(
                        DependencyRecord(
                            name=str(dep.get("name", "unknown")),
                            raw=str(dep.get("raw", dep)),
                            valid=False,
                            error="Invalid dependency record format.",
                        )
                    )

        grouped: Dict[str, List[DependencyRecord]] = {}
        for record in records:
            grouped.setdefault(record.normalized_name(), []).append(record)

        conflicts: List[DependencyConflict] = []

        for package, package_records in grouped.items():
            if len(package_records) <= 1:
                continue

            raw_specifiers = {
                str(record.specifier or "").strip()
                for record in package_records
                if str(record.specifier or "").strip()
            }

            if len(raw_specifiers) > 1:
                conflicts.append(
                    DependencyConflict(
                        package=package,
                        conflict_type="specifier_mismatch",
                        message=f"Package '{package}' has multiple version specifiers: {sorted(raw_specifiers)}",
                        records=[item.to_dict() for item in package_records],
                        severity="high",
                    )
                )
            else:
                conflicts.append(
                    DependencyConflict(
                        package=package,
                        conflict_type="duplicate_dependency",
                        message=f"Package '{package}' is listed multiple times.",
                        records=[item.to_dict() for item in package_records],
                        severity="low",
                    )
                )

        invalid_records = [record for record in records if not record.valid]
        for record in invalid_records:
            conflicts.append(
                DependencyConflict(
                    package=record.normalized_name(),
                    conflict_type="invalid_requirement",
                    message=f"Invalid requirement line: {record.raw}",
                    records=[record.to_dict()],
                    severity="medium",
                )
            )

        return self._safe_result(
            "Dependency conflicts detected.",
            data={
                "dependency_count": len(records),
                "conflict_count": len(conflicts),
                "conflicts": [conflict.to_dict() for conflict in conflicts],
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    # -----------------------------------------------------------------
    # Installed packages
    # -----------------------------------------------------------------

    def list_installed_packages(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        python_executable: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Lists installed packages using `python -m pip list --format=json`.

        This is read-only, but still executed safely.
        """
        executable = python_executable or sys.executable

        command = [executable, "-m", "pip", "list", "--format=json"]

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )

            if completed.returncode != 0:
                return self._error_result(
                    message="Failed to list installed packages.",
                    error=completed.stderr.strip() or completed.stdout.strip(),
                    data={"command": command},
                )

            packages = json.loads(completed.stdout or "[]")
            normalized = [
                {
                    "name": package.get("name"),
                    "normalized_name": normalize_package_name(package.get("name", "")),
                    "version": package.get("version"),
                }
                for package in packages
            ]

            return self._safe_result(
                "Installed packages listed.",
                data={
                    "python_executable": executable,
                    "package_count": len(normalized),
                    "packages": normalized,
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to inspect installed packages.",
                error=exc,
                data={"command": command},
            )

    # -----------------------------------------------------------------
    # Planning methods
    # -----------------------------------------------------------------

    def plan_install(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        packages: List[str],
        project_path: Optional[Union[str, Path]] = None,
        requirement_file: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Creates a safe install plan. Does not install packages automatically.
        """
        cleaned = self._validate_package_names(packages)
        if cleaned["invalid"]:
            return self._error_result(
                "Invalid package names found.",
                data=cleaned,
            )

        project = self._resolve_project_path(project_path)

        commands = [
            [sys.executable, "-m", "pip", "install", package]
            for package in cleaned["valid"]
        ]

        plan = DependencyPlan(
            action="install",
            packages=cleaned["valid"],
            project_path=str(project) if project else None,
            requirement_file=str(requirement_file) if requirement_file else None,
            commands=commands,
            requires_security=True,
            notes=[
                "This is a plan only. Security approval is required before execution.",
                "Use a virtual environment before installing production dependencies.",
            ],
        )

        security = self._request_security_approval(
            user_id=user_id,
            workspace_id=workspace_id,
            action="install",
            payload=plan.to_dict(),
        )

        return self._safe_result(
            "Dependency install plan created.",
            data={
                "plan": plan.to_dict(),
                "security": security,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def plan_upgrade(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        packages: List[str],
        project_path: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Creates a safe upgrade plan. Does not upgrade packages automatically.
        """
        cleaned = self._validate_package_names(packages)
        if cleaned["invalid"]:
            return self._error_result(
                "Invalid package names found.",
                data=cleaned,
            )

        project = self._resolve_project_path(project_path)

        commands = [
            [sys.executable, "-m", "pip", "install", "--upgrade", package]
            for package in cleaned["valid"]
        ]

        plan = DependencyPlan(
            action="upgrade",
            packages=cleaned["valid"],
            project_path=str(project) if project else None,
            commands=commands,
            requires_security=True,
            notes=[
                "This is a plan only. Security approval is required before execution.",
                "Run tests after dependency upgrades.",
            ],
        )

        security = self._request_security_approval(
            user_id=user_id,
            workspace_id=workspace_id,
            action="upgrade",
            payload=plan.to_dict(),
        )

        return self._safe_result(
            "Dependency upgrade plan created.",
            data={
                "plan": plan.to_dict(),
                "security": security,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def plan_uninstall(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        packages: List[str],
        project_path: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Creates a safe uninstall plan. Does not uninstall packages automatically.
        """
        cleaned = self._validate_package_names(packages)
        if cleaned["invalid"]:
            return self._error_result(
                "Invalid package names found.",
                data=cleaned,
            )

        project = self._resolve_project_path(project_path)

        commands = [
            [sys.executable, "-m", "pip", "uninstall", "-y", package]
            for package in cleaned["valid"]
        ]

        plan = DependencyPlan(
            action="uninstall",
            packages=cleaned["valid"],
            project_path=str(project) if project else None,
            commands=commands,
            requires_security=True,
            notes=[
                "This is a plan only. Security approval is required before execution.",
                "Uninstalling packages can break existing agents or dashboard services.",
            ],
        )

        security = self._request_security_approval(
            user_id=user_id,
            workspace_id=workspace_id,
            action="uninstall",
            payload=plan.to_dict(),
        )

        return self._safe_result(
            "Dependency uninstall plan created.",
            data={
                "plan": plan.to_dict(),
                "security": security,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def _validate_package_names(self, packages: List[str]) -> Dict[str, List[str]]:
        valid: List[str] = []
        invalid: List[str] = []

        for package in packages:
            if not isinstance(package, str):
                invalid.append(str(package))
                continue

            cleaned = package.strip()
            if not cleaned:
                invalid.append(package)
                continue

            if re.search(r"[;&|`$<>]", cleaned):
                invalid.append(package)
                continue

            valid.append(cleaned)

        return {
            "valid": valid,
            "invalid": invalid,
        }

    # -----------------------------------------------------------------
    # Requirements merging/writing
    # -----------------------------------------------------------------

    def merge_requirements(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        input_files: List[Union[str, Path]],
        output_file: Optional[Union[str, Path]] = None,
        project_path: Optional[Union[str, Path]] = None,
        write_file: bool = False,
    ) -> Dict[str, Any]:
        """
        Merges multiple requirements files into one deduplicated list.

        If write_file=True, Security Agent approval is required.
        """
        project = self._resolve_project_path(project_path)

        if not input_files:
            return self._error_result("input_files is required.")

        all_records: List[DependencyRecord] = []

        for file_item in input_files:
            path = Path(file_item)
            if not path.is_absolute() and project:
                path = project / path
            path = path.expanduser().resolve()

            if not path.exists():
                return self._error_result(f"Input requirements file does not exist: {path}")

            parsed = self.parse_requirements_file(
                user_id=user_id,
                workspace_id=workspace_id,
                file_path=path,
                project_path=project,
            )
            if not parsed.get("success"):
                return parsed

            for item in parsed.get("data", {}).get("dependencies", []):
                all_records.append(DependencyRecord(**item))

        deduped = self._dedupe_dependency_records(all_records)
        merged_content = self._records_to_requirements_content(deduped)

        security = None
        if write_file:
            if not output_file:
                return self._error_result("output_file is required when write_file=True.")

            security = self._request_security_approval(
                user_id=user_id,
                workspace_id=workspace_id,
                action="modify_requirements",
                payload={
                    "input_files": [str(item) for item in input_files],
                    "output_file": str(output_file),
                    "dependency_count": len(deduped),
                },
            )

            if security.get("required") and not security.get("approved"):
                return self._safe_result(
                    "Merged requirements prepared but not written because security approval is required.",
                    data={
                        "merged_content": merged_content,
                        "dependency_count": len(deduped),
                        "dependencies": [item.to_dict() for item in deduped],
                        "security": security,
                    },
                )

            out_path = Path(output_file)
            if not out_path.is_absolute() and project:
                out_path = project / out_path
            out_path = out_path.expanduser().resolve()
            safe_write_text(out_path, merged_content)

        return self._safe_result(
            "Requirements merged successfully.",
            data={
                "dependency_count": len(deduped),
                "dependencies": [item.to_dict() for item in deduped],
                "merged_content": merged_content,
                "output_file": str(output_file) if output_file else None,
                "written": bool(write_file and output_file),
                "security": security,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def _dedupe_dependency_records(self, records: List[DependencyRecord]) -> List[DependencyRecord]:
        selected: Dict[str, DependencyRecord] = {}

        for record in records:
            key = record.normalized_name()

            if key not in selected:
                selected[key] = record
                continue

            existing = selected[key]

            existing_score = self._dependency_specificity_score(existing)
            new_score = self._dependency_specificity_score(record)

            if new_score >= existing_score:
                selected[key] = record

        return sorted(selected.values(), key=lambda item: item.normalized_name())

    def _dependency_specificity_score(self, record: DependencyRecord) -> int:
        score = 0

        if record.specifier:
            score += 10
        if "==" in str(record.specifier):
            score += 20
        if record.extras:
            score += 5
        if record.marker:
            score += 5
        if record.valid:
            score += 2

        return score

    def _records_to_requirements_content(self, records: List[DependencyRecord]) -> str:
        lines = [
            "# Generated by William/Jarvis DependencyManager",
            f"# Generated at: {utc_now_iso()}",
            "",
        ]

        for record in records:
            if record.url:
                prefix = "-e " if record.editable else ""
                lines.append(f"{prefix}{record.url}")
                continue

            name = record.name
            extras = f"[{','.join(record.extras)}]" if record.extras else ""
            specifier = record.specifier or ""
            marker = f"; {record.marker}" if record.marker else ""
            lines.append(f"{name}{extras}{specifier}{marker}")

        lines.append("")
        return "\n".join(lines)

    # -----------------------------------------------------------------
    # Freeze environment
    # -----------------------------------------------------------------

    def freeze_environment(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        python_executable: Optional[str] = None,
        output_file: Optional[Union[str, Path]] = None,
        write_file: bool = False,
    ) -> Dict[str, Any]:
        """
        Runs pip freeze and optionally writes to a requirements file.

        Writing requires security approval.
        """
        executable = python_executable or sys.executable
        command = [executable, "-m", "pip", "freeze"]

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )

            if completed.returncode != 0:
                return self._error_result(
                    "pip freeze failed.",
                    error=completed.stderr.strip() or completed.stdout.strip(),
                    data={"command": command},
                )

            content = completed.stdout.strip() + "\n"
            security = None
            written = False

            if write_file:
                if not output_file:
                    return self._error_result("output_file is required when write_file=True.")

                security = self._request_security_approval(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    action="freeze_write",
                    payload={
                        "output_file": str(output_file),
                        "command": command,
                    },
                )

                if security.get("required") and not security.get("approved"):
                    return self._safe_result(
                        "Environment freeze prepared but not written because security approval is required.",
                        data={
                            "content": content,
                            "content_sha256": sha256_text(content),
                            "output_file": str(output_file),
                            "written": False,
                            "security": security,
                        },
                    )

                out_path = Path(output_file).expanduser().resolve()
                safe_write_text(out_path, content)
                written = True

            dependencies = self.parse_requirements_content(content, source="pip freeze")

            return self._safe_result(
                "Environment frozen successfully.",
                data={
                    "python_executable": executable,
                    "dependency_count": len(dependencies),
                    "dependencies": [item.to_dict() for item in dependencies],
                    "content": content,
                    "content_sha256": sha256_text(content),
                    "output_file": str(output_file) if output_file else None,
                    "written": written,
                    "security": security,
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to freeze environment.",
                error=exc,
                data={"command": command},
            )

    # -----------------------------------------------------------------
    # Optional controlled execution
    # -----------------------------------------------------------------

    def execute_plan(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        plan: Union[DependencyPlan, Dict[str, Any]],
        security_approved: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes a dependency plan only when explicitly enabled.

        Safe default:
            allow_subprocess_execution=False

        This protects against accidental package installation/uninstallation.
        """
        if isinstance(plan, DependencyPlan):
            plan_data = plan.to_dict()
        else:
            plan_data = plan

        action = str(plan_data.get("action", "")).lower()
        commands = plan_data.get("commands", [])
        packages = plan_data.get("packages", [])

        security_required = self._requires_security_check(action, packages)

        if security_required and not security_approved:
            return self._error_result(
                "Security approval is required before executing this dependency plan.",
                data={
                    "action": action,
                    "packages": packages,
                    "security_required": True,
                },
            )

        if not self.allow_subprocess_execution:
            return self._error_result(
                "Subprocess execution is disabled for DependencyManager.",
                data={
                    "action": action,
                    "packages": packages,
                    "set_allow_subprocess_execution": True,
                },
            )

        outputs: List[Dict[str, Any]] = []

        for command in commands:
            if not isinstance(command, list) or not command:
                outputs.append(
                    {
                        "command": command,
                        "success": False,
                        "error": "Invalid command format.",
                    }
                )
                continue

            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=180,
                )
                outputs.append(
                    {
                        "command": command,
                        "success": completed.returncode == 0,
                        "returncode": completed.returncode,
                        "stdout": completed.stdout,
                        "stderr": completed.stderr,
                    }
                )
            except Exception as exc:
                outputs.append(
                    {
                        "command": command,
                        "success": False,
                        "error": str(exc),
                    }
                )

        success = all(item.get("success") for item in outputs)

        result = self._safe_result if success else self._error_result
        return result(
            "Dependency plan executed." if success else "Dependency plan execution completed with errors.",
            data={
                "action": action,
                "packages": packages,
                "outputs": outputs,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )


# ---------------------------------------------------------------------
# Public module helpers
# ---------------------------------------------------------------------

def create_dependency_manager(
    default_project_path: Optional[Union[str, Path]] = None,
    allow_subprocess_execution: bool = False,
) -> DependencyManager:
    """
    Factory helper for Agent Loader / Registry.
    """
    return DependencyManager(
        default_project_path=default_project_path,
        allow_subprocess_execution=allow_subprocess_execution,
    )


def get_agent_metadata() -> Dict[str, Any]:
    """
    Agent Registry compatible metadata.
    """
    return {
        "agent_name": "DependencyManager",
        "agent_type": "code_agent",
        "class_name": "DependencyManager",
        "version": DependencyManager.VERSION,
        "file_path": "agents/code_agent/dependency_manager.py",
        "description": "Manages Python packages, dependency conflicts, requirements files, and safe dependency plans.",
        "supports_user_workspace_isolation": True,
        "requires_security_for_destructive_actions": True,
        "compatible_with_master_agent": True,
        "compatible_with_registry": True,
        "compatible_with_dashboard": True,
        "supported_actions": DependencyManager().supported_actions(),
    }


__all__ = [
    "DependencyManager",
    "DependencyRecord",
    "DependencyConflict",
    "DependencyPlan",
    "create_dependency_manager",
    "get_agent_metadata",
    "normalize_package_name",
]