"""
agents/code_agent/project_analyzer.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix

Purpose:
    Reads a project structure, detects frameworks, dependencies, risks, and missing files.
    This module is designed for the Code Agent and is compatible with the larger
    William/Jarvis architecture: BaseAgent, Agent Registry, Agent Loader, Agent Router,
    Master Agent routing, Security Agent approval, Memory Agent context, Verification
    Agent payloads, Dashboard/API reporting, audit logs, and SaaS user/workspace isolation.

Design goals:
    - Import-safe even when the rest of the William/Jarvis project is not yet created.
    - No destructive actions.
    - No secret hardcoding.
    - User/workspace aware.
    - Structured dict/JSON-style results.
    - Production-ready helper methods with validation, logging, and safe defaults.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import platform
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallbacks
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        The real William/Jarvis system should provide agents.base_agent.BaseAgent.
        This fallback keeps this file import-safe during early module generation.
        """

        agent_name: str = "base_agent"
        agent_type: str = "generic"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.logger = logging.getLogger(self.__class__.__name__)

        def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent.run() called.",
                "data": {},
                "error": "BaseAgent is not installed.",
                "metadata": {},
            }


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
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("william.code_agent.project_analyzer")
if not LOGGER.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ---------------------------------------------------------------------------
# Constants and signatures
# ---------------------------------------------------------------------------

DEFAULT_EXCLUDED_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    "coverage",
    ".coverage",
    "htmlcov",
    "target",
    "vendor",
    "Pods",
    "DerivedData",
    ".gradle",
    ".dart_tool",
    "android/.gradle",
    "ios/Pods",
}

DEFAULT_EXCLUDED_FILES: Set[str] = {
    ".DS_Store",
    "Thumbs.db",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "composer.lock",
    "Cargo.lock",
}

DEFAULT_SECRET_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
    re.compile(r"(?i)\b(AKIA[0-9A-Z]{16})\b"),
    re.compile(r"(?i)\bAIza[0-9A-Za-z\-_]{20,}\b"),
    re.compile(r"(?i)\bsk-[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"(?i)\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    re.compile(r"(?i)\b-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----\b"),
]

FRAMEWORK_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "fastapi": {
        "files": ["main.py", "app.py"],
        "dependencies": ["fastapi", "uvicorn"],
        "content_patterns": [r"from\s+fastapi\s+import", r"FastAPI\s*\("],
        "category": "python_backend",
    },
    "flask": {
        "files": ["app.py", "wsgi.py", "run.py"],
        "dependencies": ["flask"],
        "content_patterns": [r"from\s+flask\s+import", r"Flask\s*\("],
        "category": "python_backend",
    },
    "django": {
        "files": ["manage.py", "settings.py"],
        "dependencies": ["django"],
        "content_patterns": [r"django\.conf", r"DJANGO_SETTINGS_MODULE"],
        "category": "python_backend",
    },
    "python_package": {
        "files": ["pyproject.toml", "setup.py", "setup.cfg"],
        "dependencies": [],
        "content_patterns": [],
        "category": "python",
    },
    "react": {
        "files": ["package.json"],
        "dependencies": ["react", "react-dom"],
        "content_patterns": [r"from\s+['\"]react['\"]", r"ReactDOM"],
        "category": "javascript_frontend",
    },
    "nextjs": {
        "files": ["next.config.js", "next.config.mjs", "next.config.ts", "app", "pages"],
        "dependencies": ["next", "react"],
        "content_patterns": [r"next\/", r"next\s+dev", r"next\s+build"],
        "category": "javascript_fullstack",
    },
    "vue": {
        "files": ["vue.config.js", "vite.config.js", "vite.config.ts", "package.json"],
        "dependencies": ["vue"],
        "content_patterns": [r"createApp\s*\(", r"from\s+['\"]vue['\"]"],
        "category": "javascript_frontend",
    },
    "nuxt": {
        "files": ["nuxt.config.js", "nuxt.config.ts"],
        "dependencies": ["nuxt"],
        "content_patterns": [r"defineNuxtConfig"],
        "category": "javascript_fullstack",
    },
    "svelte": {
        "files": ["svelte.config.js", "svelte.config.ts"],
        "dependencies": ["svelte", "@sveltejs/kit"],
        "content_patterns": [r"@sveltejs"],
        "category": "javascript_frontend",
    },
    "vite": {
        "files": ["vite.config.js", "vite.config.ts", "vite.config.mjs"],
        "dependencies": ["vite"],
        "content_patterns": [r"defineConfig\s*\("],
        "category": "javascript_tooling",
    },
    "express": {
        "files": ["package.json", "server.js", "index.js", "app.js"],
        "dependencies": ["express"],
        "content_patterns": [r"require\(['\"]express['\"]\)", r"from\s+['\"]express['\"]"],
        "category": "javascript_backend",
    },
    "laravel": {
        "files": ["artisan", "composer.json"],
        "dependencies": ["laravel/framework"],
        "content_patterns": [r"Illuminate\\", r"Laravel"],
        "category": "php_backend",
    },
    "wordpress": {
        "files": ["wp-config.php", "wp-content", "wp-admin", "wp-includes"],
        "dependencies": [],
        "content_patterns": [r"ABSPATH", r"WP_DEBUG"],
        "category": "php_cms",
    },
    "flutter": {
        "files": ["pubspec.yaml", "lib/main.dart"],
        "dependencies": ["flutter"],
        "content_patterns": [r"MaterialApp\s*\(", r"CupertinoApp\s*\("],
        "category": "mobile",
    },
    "android": {
        "files": ["build.gradle", "settings.gradle", "AndroidManifest.xml"],
        "dependencies": ["com.android.application", "com.android.library"],
        "content_patterns": [r"com\.android\.application", r"android\s*\{"],
        "category": "mobile",
    },
    "ios": {
        "files": ["Podfile", ".xcodeproj", ".xcworkspace"],
        "dependencies": [],
        "content_patterns": [r"platform\s+:ios"],
        "category": "mobile",
    },
    "docker": {
        "files": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore"],
        "dependencies": [],
        "content_patterns": [r"FROM\s+\S+", r"services:"],
        "category": "devops",
    },
    "github_actions": {
        "files": [".github/workflows"],
        "dependencies": [],
        "content_patterns": [r"runs-on:", r"uses:"],
        "category": "ci_cd",
    },
}


RECOMMENDED_FILES_BY_FRAMEWORK: Dict[str, List[str]] = {
    "fastapi": ["requirements.txt", ".env.example", "README.md", "tests", "Dockerfile"],
    "flask": ["requirements.txt", ".env.example", "README.md", "tests", "Dockerfile"],
    "django": ["requirements.txt", ".env.example", "README.md", "tests", "Dockerfile"],
    "python_package": ["pyproject.toml", "README.md", "tests", ".gitignore"],
    "react": ["package.json", "README.md", ".env.example", ".gitignore"],
    "nextjs": ["package.json", "next.config.js", "README.md", ".env.example", ".gitignore"],
    "vue": ["package.json", "README.md", ".env.example", ".gitignore"],
    "nuxt": ["package.json", "nuxt.config.ts", "README.md", ".env.example", ".gitignore"],
    "svelte": ["package.json", "svelte.config.js", "README.md", ".env.example", ".gitignore"],
    "vite": ["package.json", "vite.config.js", "README.md", ".env.example", ".gitignore"],
    "express": ["package.json", "README.md", ".env.example", ".gitignore", "tests"],
    "laravel": ["composer.json", ".env.example", "README.md", "tests"],
    "wordpress": ["wp-config-sample.php", "wp-content", ".htaccess", "README.md"],
    "flutter": ["pubspec.yaml", "lib/main.dart", "test", "README.md"],
    "docker": ["Dockerfile", ".dockerignore"],
    "github_actions": [".github/workflows"],
}

COMMON_RECOMMENDED_FILES: List[str] = [
    "README.md",
    ".gitignore",
    ".env.example",
]

DEPENDENCY_FILES: List[str] = [
    "requirements.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "environment.yml",
    "package.json",
    "composer.json",
    "Gemfile",
    "go.mod",
    "Cargo.toml",
    "pubspec.yaml",
    "build.gradle",
    "pom.xml",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class AnalysisRisk:
    """A normalized project risk item for dashboard/API reporting."""

    severity: str
    category: str
    message: str
    path: Optional[str] = None
    recommendation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FileSummary:
    """Safe summary of one scanned file."""

    path: str
    size_bytes: int
    extension: str
    modified_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProjectAnalysisConfig:
    """
    Analyzer configuration.

    This can be passed from the Master Agent, Dashboard/API, or Code Agent settings.
    """

    max_files: int = 5000
    max_depth: int = 20
    max_file_read_bytes: int = 200_000
    include_hidden: bool = False
    detect_secrets: bool = True
    collect_tree: bool = True
    collect_file_stats: bool = True
    excluded_dirs: Set[str] = field(default_factory=lambda: set(DEFAULT_EXCLUDED_DIRS))
    excluded_files: Set[str] = field(default_factory=lambda: set(DEFAULT_EXCLUDED_FILES))
    allowed_root: Optional[Union[str, Path]] = None

    def normalized_allowed_root(self) -> Optional[Path]:
        if self.allowed_root is None:
            return None
        return Path(self.allowed_root).expanduser().resolve()


@dataclass
class ProjectContext:
    """Required SaaS context for all user/workspace-specific analysis."""

    user_id: Union[str, int]
    workspace_id: Union[str, int]
    request_id: Optional[str] = None
    actor: Optional[str] = None
    permissions: Dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> Dict[str, Any]:
        return {
            "user_id": str(self.user_id),
            "workspace_id": str(self.workspace_id),
            "request_id": self.request_id,
            "actor": self.actor,
        }


# ---------------------------------------------------------------------------
# Project Analyzer
# ---------------------------------------------------------------------------

class ProjectAnalyzer(BaseAgent):
    """
    Production-level project analyzer for William/Jarvis Code Agent.

    Responsibilities:
        - Read project structure safely.
        - Detect frameworks.
        - Detect dependencies from common manifest files.
        - Detect security/quality/structure risks.
        - Detect missing recommended files.
        - Prepare Verification Agent and Memory Agent compatible payloads.
        - Emit structured events for dashboard/API integrations.

    This class does not execute code, install packages, modify files, or perform
    destructive actions. It only reads metadata and limited file content for analysis.
    """

    agent_name = "project_analyzer"
    agent_type = "code_agent"
    version = "1.0.0"

    def __init__(
        self,
        config: Optional[ProjectAnalysisConfig] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(**kwargs)
        except TypeError:
            super().__init__()

        self.config = config or ProjectAnalysisConfig()
        self.security_agent = security_agent or self._build_optional_agent(SecurityAgent)
        self.verification_agent = verification_agent or self._build_optional_agent(VerificationAgent)
        self.memory_agent = memory_agent or self._build_optional_agent(MemoryAgent)
        self.logger = logger or LOGGER

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def run(self, task: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
        """
        BaseAgent-compatible run entrypoint.

        Expected task:
            {
                "project_path": "/path/to/project",
                "user_id": "1",
                "workspace_id": "default",
                "config": {... optional overrides ...}
            }
        """
        task = task or {}
        merged = {**task, **kwargs}
        project_path = merged.get("project_path") or merged.get("path") or merged.get("root_path")

        context = ProjectContext(
            user_id=merged.get("user_id"),
            workspace_id=merged.get("workspace_id"),
            request_id=merged.get("request_id"),
            actor=merged.get("actor"),
            permissions=merged.get("permissions") or {},
        )

        config = self._config_from_task(merged.get("config") or {})

        return self.analyze_project(
            project_path=project_path,
            context=context,
            config=config,
        )

    def analyze_project(
        self,
        project_path: Union[str, Path, None],
        context: ProjectContext,
        config: Optional[ProjectAnalysisConfig] = None,
    ) -> Dict[str, Any]:
        """
        Analyze a project folder and return a structured William/Jarvis result.
        """
        started_at = self._utc_now()
        active_config = config or self.config

        try:
            valid_context = self._validate_task_context(context)
            if not valid_context["success"]:
                return valid_context

            if not project_path:
                return self._error_result(
                    message="Project path is required.",
                    error="missing_project_path",
                    metadata=self._metadata(context, started_at=started_at),
                )

            root = Path(project_path).expanduser().resolve()
            path_validation = self._validate_project_path(root, active_config, context)
            if not path_validation["success"]:
                return path_validation

            if self._requires_security_check(root, context):
                approval = self._request_security_approval(
                    action="analyze_project",
                    target=str(root),
                    context=context,
                    metadata={"agent": self.agent_name},
                )
                if not approval.get("approved", False):
                    return self._error_result(
                        message="Security approval denied for project analysis.",
                        error="security_denied",
                        data={"approval": approval},
                        metadata=self._metadata(context, started_at=started_at, root=str(root)),
                    )

            self._emit_agent_event(
                event_type="project_analysis_started",
                context=context,
                payload={"project_path": str(root)},
            )
            self._log_audit_event(
                action="project_analysis_started",
                context=context,
                payload={"project_path": str(root)},
            )

            scanned = self._scan_project(root, active_config)
            frameworks = self.detect_frameworks(root, scanned, active_config)
            dependencies = self.detect_dependencies(root, scanned, active_config)
            missing_files = self.detect_missing_files(root, frameworks)
            risks = self.detect_risks(root, scanned, frameworks, dependencies, missing_files, active_config)
            project_tree = self.build_project_tree(root, scanned, active_config) if active_config.collect_tree else []
            stats = self.calculate_project_stats(root, scanned, frameworks, dependencies, risks)

            data = {
                "project_path": str(root),
                "project_name": root.name,
                "frameworks": frameworks,
                "dependencies": dependencies,
                "missing_files": missing_files,
                "risks": [risk.to_dict() for risk in risks],
                "stats": stats,
                "tree": project_tree,
                "files": [file.to_dict() for file in scanned["files"]] if active_config.collect_file_stats else [],
                "recommendations": self._build_recommendations(frameworks, risks, missing_files, dependencies),
                "verification_payload": self._prepare_verification_payload(
                    action="analyze_project",
                    context=context,
                    success=True,
                    data_summary={
                        "project_name": root.name,
                        "framework_count": len(frameworks),
                        "dependency_file_count": len(dependencies.get("files", [])),
                        "risk_count": len(risks),
                        "missing_file_count": len(missing_files),
                    },
                ),
                "memory_payload": self._prepare_memory_payload(
                    context=context,
                    project_path=str(root),
                    frameworks=frameworks,
                    stats=stats,
                ),
            }

            result = self._safe_result(
                message="Project analysis completed successfully.",
                data=data,
                metadata=self._metadata(
                    context,
                    started_at=started_at,
                    completed_at=self._utc_now(),
                    root=str(root),
                    agent=self.agent_name,
                    version=self.version,
                ),
            )

            self._emit_agent_event(
                event_type="project_analysis_completed",
                context=context,
                payload={
                    "project_path": str(root),
                    "frameworks": [fw["name"] for fw in frameworks],
                    "risk_count": len(risks),
                },
            )
            self._log_audit_event(
                action="project_analysis_completed",
                context=context,
                payload={
                    "project_path": str(root),
                    "framework_count": len(frameworks),
                    "risk_count": len(risks),
                },
            )
            return result

        except Exception as exc:
            self.logger.exception("Project analysis failed.")
            return self._error_result(
                message="Project analysis failed.",
                error=str(exc),
                metadata=self._metadata(context, started_at=started_at, completed_at=self._utc_now()),
            )

    def detect_frameworks(
        self,
        root: Path,
        scanned: Dict[str, Any],
        config: Optional[ProjectAnalysisConfig] = None,
    ) -> List[Dict[str, Any]]:
        """
        Detect project frameworks using files, dependency manifests, and content signatures.
        """
        file_paths: Set[str] = set(scanned.get("relative_paths", []))
        file_names: Set[str] = set(scanned.get("file_names", []))
        dir_names: Set[str] = set(scanned.get("dir_names", []))
        dependency_names: Set[str] = set()

        raw_dependency_data = self.detect_dependencies(root, scanned, config or self.config)
        for group in raw_dependency_data.get("groups", {}).values():
            if isinstance(group, list):
                dependency_names.update(str(item).lower() for item in group)

        content_hits = scanned.get("content_hits", {})
        detected: List[Dict[str, Any]] = []

        for framework_name, signature in FRAMEWORK_SIGNATURES.items():
            score = 0
            evidence: List[str] = []

            for expected_file in signature.get("files", []):
                expected_file = str(expected_file)
                if expected_file in file_paths or expected_file in file_names or expected_file in dir_names:
                    score += 25
                    evidence.append(f"file_or_dir:{expected_file}")
                else:
                    matched = any(
                        path == expected_file
                        or path.endswith(f"/{expected_file}")
                        or fnmatch.fnmatch(path, expected_file)
                        for path in file_paths
                    )
                    if matched:
                        score += 20
                        evidence.append(f"path:{expected_file}")

            for dependency in signature.get("dependencies", []):
                dependency_lower = str(dependency).lower()
                if dependency_lower in dependency_names:
                    score += 35
                    evidence.append(f"dependency:{dependency}")

            for pattern in signature.get("content_patterns", []):
                if pattern in content_hits:
                    score += 20
                    evidence.append(f"content_pattern:{pattern}")

            if score > 0:
                detected.append(
                    {
                        "name": framework_name,
                        "category": signature.get("category", "unknown"),
                        "confidence": min(score, 100),
                        "evidence": sorted(set(evidence)),
                    }
                )

        detected.sort(key=lambda item: item["confidence"], reverse=True)
        return detected

    def detect_dependencies(
        self,
        root: Path,
        scanned: Optional[Dict[str, Any]] = None,
        config: Optional[ProjectAnalysisConfig] = None,
    ) -> Dict[str, Any]:
        """
        Detect dependencies from common dependency files.

        This method intentionally avoids installing or executing anything.
        """
        active_config = config or self.config
        scanned = scanned or {"relative_paths": []}
        relative_paths = set(scanned.get("relative_paths", []))

        dependency_files: List[Dict[str, Any]] = []
        groups: Dict[str, List[str]] = {
            "python": [],
            "node": [],
            "php": [],
            "ruby": [],
            "go": [],
            "rust": [],
            "dart": [],
            "java": [],
            "docker": [],
            "unknown": [],
        }

        for rel in sorted(relative_paths):
            name = Path(rel).name
            if name not in DEPENDENCY_FILES and rel not in DEPENDENCY_FILES:
                continue

            path = root / rel
            parsed = self._parse_dependency_file(path, rel, active_config)
            dependency_files.append(parsed)

            ecosystem = parsed.get("ecosystem", "unknown")
            dependencies = parsed.get("dependencies", [])
            if ecosystem not in groups:
                groups[ecosystem] = []
            groups[ecosystem].extend(dependencies)

        for key, value in groups.items():
            groups[key] = sorted(set(str(item) for item in value if item))

        return {
            "files": dependency_files,
            "groups": groups,
            "total_dependencies": sum(len(items) for items in groups.values()),
        }

    def detect_missing_files(
        self,
        root: Path,
        frameworks: Sequence[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Detect missing recommended files based on common production standards and frameworks.
        """
        existing_paths = self._existing_relative_paths(root)
        required: Set[str] = set(COMMON_RECOMMENDED_FILES)

        for framework in frameworks:
            framework_name = str(framework.get("name", ""))
            required.update(RECOMMENDED_FILES_BY_FRAMEWORK.get(framework_name, []))

        missing: List[Dict[str, Any]] = []
        for rel in sorted(required):
            if not self._path_exists_flexibly(rel, existing_paths):
                severity = "medium" if rel in {"README.md", ".env.example", ".gitignore"} else "low"
                missing.append(
                    {
                        "path": rel,
                        "severity": severity,
                        "reason": self._missing_file_reason(rel),
                    }
                )

        return missing

    def detect_risks(
        self,
        root: Path,
        scanned: Dict[str, Any],
        frameworks: Sequence[Dict[str, Any]],
        dependencies: Dict[str, Any],
        missing_files: Sequence[Dict[str, Any]],
        config: Optional[ProjectAnalysisConfig] = None,
    ) -> List[AnalysisRisk]:
        """
        Detect common project risks without executing code.
        """
        active_config = config or self.config
        risks: List[AnalysisRisk] = []

        total_files = len(scanned.get("files", []))
        truncated = scanned.get("truncated", False)

        if truncated:
            risks.append(
                AnalysisRisk(
                    severity="medium",
                    category="scan_limit",
                    message="Project scan reached configured file limit.",
                    recommendation="Increase max_files or narrow the project path for deeper analysis.",
                )
            )

        if total_files == 0:
            risks.append(
                AnalysisRisk(
                    severity="high",
                    category="empty_project",
                    message="No readable project files were found.",
                    recommendation="Confirm the project path and permissions.",
                )
            )

        if not frameworks:
            risks.append(
                AnalysisRisk(
                    severity="medium",
                    category="framework_detection",
                    message="No known framework was detected.",
                    recommendation="Add standard manifest files or verify project structure.",
                )
            )

        dependency_file_count = len(dependencies.get("files", []))
        if dependency_file_count == 0:
            risks.append(
                AnalysisRisk(
                    severity="medium",
                    category="dependencies",
                    message="No dependency manifest file was detected.",
                    recommendation="Add requirements.txt, pyproject.toml, package.json, composer.json, or equivalent.",
                )
            )

        for item in missing_files:
            if item.get("severity") in {"medium", "high"}:
                risks.append(
                    AnalysisRisk(
                        severity=item.get("severity", "medium"),
                        category="missing_file",
                        message=f"Recommended file is missing: {item.get('path')}",
                        path=item.get("path"),
                        recommendation=item.get("reason"),
                    )
                )

        if active_config.detect_secrets:
            for secret_hit in scanned.get("secret_hits", []):
                risks.append(
                    AnalysisRisk(
                        severity="high",
                        category="secrets",
                        message="Possible secret or credential found in project file.",
                        path=secret_hit.get("path"),
                        recommendation="Move secrets to environment variables and rotate exposed credentials.",
                    )
                )

        for env_file in [".env", ".env.local", ".env.production", ".env.development"]:
            if (root / env_file).exists():
                risks.append(
                    AnalysisRisk(
                        severity="high",
                        category="secrets",
                        message=f"Environment file exists in project: {env_file}",
                        path=env_file,
                        recommendation="Do not commit real .env files. Keep only .env.example in version control.",
                    )
                )

        if not (root / ".gitignore").exists():
            risks.append(
                AnalysisRisk(
                    severity="medium",
                    category="version_control",
                    message=".gitignore file is missing.",
                    recommendation="Add a .gitignore to avoid committing secrets, build files, caches, and dependencies.",
                )
            )

        if not (root / "README.md").exists() and not (root / "readme.md").exists():
            risks.append(
                AnalysisRisk(
                    severity="low",
                    category="documentation",
                    message="README.md file is missing.",
                    recommendation="Add setup, test, deployment, and architecture instructions.",
                )
            )

        if self._has_path(root, "node_modules") and not (root / "package.json").exists():
            risks.append(
                AnalysisRisk(
                    severity="medium",
                    category="node_project",
                    message="node_modules exists but package.json was not found.",
                    recommendation="Confirm this is the project root or restore package.json.",
                )
            )

        if self._has_path(root, "venv") or self._has_path(root, ".venv"):
            risks.append(
                AnalysisRisk(
                    severity="low",
                    category="environment",
                    message="Local Python virtual environment exists inside project folder.",
                    recommendation="Ensure virtual environment folders are ignored by version control.",
                )
            )

        large_files = [
            file for file in scanned.get("files", [])
            if isinstance(file, FileSummary) and file.size_bytes > 10 * 1024 * 1024
        ]
        for file in large_files[:20]:
            risks.append(
                AnalysisRisk(
                    severity="low",
                    category="large_file",
                    message="Large file detected.",
                    path=file.path,
                    recommendation="Consider using external storage or Git LFS if this file must be versioned.",
                )
            )

        return risks

    def build_project_tree(
        self,
        root: Path,
        scanned: Dict[str, Any],
        config: Optional[ProjectAnalysisConfig] = None,
    ) -> List[Dict[str, Any]]:
        """
        Build a simple tree-like list for dashboard/API display.
        """
        active_config = config or self.config
        items: List[Dict[str, Any]] = []

        for rel in sorted(scanned.get("relative_paths", [])):
            depth = rel.count("/")
            if depth > active_config.max_depth:
                continue
            path = root / rel
            items.append(
                {
                    "path": rel,
                    "name": path.name,
                    "type": "dir" if path.is_dir() else "file",
                    "depth": depth,
                    "size_bytes": path.stat().st_size if path.is_file() and path.exists() else 0,
                }
            )

        return items

    def calculate_project_stats(
        self,
        root: Path,
        scanned: Dict[str, Any],
        frameworks: Sequence[Dict[str, Any]],
        dependencies: Dict[str, Any],
        risks: Sequence[AnalysisRisk],
    ) -> Dict[str, Any]:
        """
        Calculate high-level project statistics.
        """
        extension_counts: Dict[str, int] = {}
        total_size = 0

        for file in scanned.get("files", []):
            if not isinstance(file, FileSummary):
                continue
            extension_counts[file.extension or "[no_extension]"] = extension_counts.get(file.extension or "[no_extension]", 0) + 1
            total_size += file.size_bytes

        risk_counts: Dict[str, int] = {}
        for risk in risks:
            risk_counts[risk.severity] = risk_counts.get(risk.severity, 0) + 1

        return {
            "file_count": len(scanned.get("files", [])),
            "directory_count": len(scanned.get("directories", [])),
            "total_size_bytes": total_size,
            "extension_counts": dict(sorted(extension_counts.items(), key=lambda item: item[1], reverse=True)),
            "framework_count": len(frameworks),
            "framework_names": [item.get("name") for item in frameworks],
            "dependency_count": dependencies.get("total_dependencies", 0),
            "dependency_file_count": len(dependencies.get("files", [])),
            "risk_counts": risk_counts,
            "platform": {
                "python_version": sys.version.split()[0],
                "system": platform.system(),
                "release": platform.release(),
            },
        }

    # ------------------------------------------------------------------
    # Required William/Jarvis compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: ProjectContext) -> Dict[str, Any]:
        """
        Validate user/workspace context to prevent SaaS data mixing.
        """
        if context is None:
            return self._error_result(
                message="Task context is required.",
                error="missing_context",
            )

        if context.user_id is None or str(context.user_id).strip() == "":
            return self._error_result(
                message="user_id is required for project analysis.",
                error="missing_user_id",
            )

        if context.workspace_id is None or str(context.workspace_id).strip() == "":
            return self._error_result(
                message="workspace_id is required for project analysis.",
                error="missing_workspace_id",
            )

        return self._safe_result(
            message="Task context is valid.",
            data={"context": context.to_metadata()},
        )

    def _requires_security_check(self, project_path: Union[str, Path], context: ProjectContext) -> bool:
        """
        Project analysis reads files, so route through Security Agent.

        The action is read-only, but it can expose sensitive project metadata or secrets.
        """
        permissions = context.permissions or {}
        if permissions.get("skip_security_check") is True:
            return False
        return True

    def _request_security_approval(
        self,
        action: str,
        target: str,
        context: ProjectContext,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval if available.

        Falls back to safe local approval for read-only analysis only.
        """
        payload = {
            "action": action,
            "target": target,
            "risk_level": "medium",
            "read_only": True,
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
            "metadata": metadata or {},
        }

        if self.security_agent is not None:
            for method_name in ("approve_action", "request_approval", "validate_action", "check_permission"):
                method = getattr(self.security_agent, method_name, None)
                if callable(method):
                    try:
                        response = method(payload)
                        if isinstance(response, dict):
                            approved = bool(
                                response.get("approved")
                                or response.get("success")
                                or response.get("allowed")
                            )
                            response.setdefault("approved", approved)
                            return response
                    except Exception as exc:
                        self.logger.warning("Security Agent method %s failed: %s", method_name, exc)

        return {
            "approved": True,
            "fallback": True,
            "message": "Security Agent unavailable; approved read-only project analysis by safe fallback.",
            "payload": payload,
        }

    def _prepare_verification_payload(
        self,
        action: str,
        context: ProjectContext,
        success: bool,
        data_summary: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent.

        The Verification Agent can later confirm analysis completeness,
        UI display correctness, or API response structure.
        """
        return {
            "agent": self.agent_name,
            "action": action,
            "success": success,
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
            "request_id": context.request_id,
            "data_summary": data_summary or {},
            "created_at": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        context: ProjectContext,
        project_path: str,
        frameworks: Sequence[Dict[str, Any]],
        stats: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible context.

        This does not store secrets or full code. It only stores useful project metadata.
        """
        return {
            "memory_type": "project_analysis_summary",
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
            "agent": self.agent_name,
            "content": {
                "project_path": project_path,
                "frameworks": [item.get("name") for item in frameworks],
                "stats": {
                    "file_count": stats.get("file_count"),
                    "directory_count": stats.get("directory_count"),
                    "dependency_count": stats.get("dependency_count"),
                    "risk_counts": stats.get("risk_counts"),
                },
            },
            "created_at": self._utc_now(),
        }

    def _emit_agent_event(
        self,
        event_type: str,
        context: ProjectContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit dashboard/API friendly event.

        In the full SaaS system this can be replaced by EventBus, WebSocket,
        analytics counter, or audit stream.
        """
        event = {
            "event_type": event_type,
            "agent": self.agent_name,
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
            "request_id": context.request_id,
            "payload": payload or {},
            "created_at": self._utc_now(),
        }
        self.logger.info("Agent event: %s", json.dumps(event, default=str))

    def _log_audit_event(
        self,
        action: str,
        context: ProjectContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit-friendly record.

        Full William/Jarvis deployments can persist this to audit_logs table.
        """
        audit = {
            "action": action,
            "agent": self.agent_name,
            "user_id": str(context.user_id),
            "workspace_id": str(context.workspace_id),
            "actor": context.actor,
            "payload": payload or {},
            "created_at": self._utc_now(),
        }
        self.logger.info("Audit event: %s", json.dumps(audit, default=str))

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard successful William/Jarvis result."""
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
        """Return standard failed William/Jarvis result."""
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error or message,
            "metadata": metadata or {},
        }

    # ------------------------------------------------------------------
    # Internal scan helpers
    # ------------------------------------------------------------------

    def _scan_project(self, root: Path, config: ProjectAnalysisConfig) -> Dict[str, Any]:
        files: List[FileSummary] = []
        directories: List[str] = []
        relative_paths: Set[str] = set()
        file_names: Set[str] = set()
        dir_names: Set[str] = set()
        content_hits: Dict[str, List[str]] = {}
        secret_hits: List[Dict[str, Any]] = []
        truncated = False

        for current_root, dirnames, filenames in os.walk(root):
            current_path = Path(current_root)
            rel_dir = self._safe_relative_path(current_path, root)
            depth = 0 if rel_dir == "." else rel_dir.count("/") + 1

            if depth > config.max_depth:
                dirnames[:] = []
                continue

            dirnames[:] = [
                d for d in dirnames
                if self._should_include_dir(d, config)
            ]

            for dirname in dirnames:
                dir_path = current_path / dirname
                rel = self._safe_relative_path(dir_path, root)
                directories.append(rel)
                relative_paths.add(rel)
                dir_names.add(dirname)

            for filename in filenames:
                if not self._should_include_file(filename, config):
                    continue

                path = current_path / filename
                if not path.exists() or not path.is_file():
                    continue

                rel = self._safe_relative_path(path, root)
                try:
                    stat = path.stat()
                    modified_at = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
                    summary = FileSummary(
                        path=rel,
                        size_bytes=stat.st_size,
                        extension=path.suffix.lower(),
                        modified_at=modified_at,
                    )
                    files.append(summary)
                    relative_paths.add(rel)
                    file_names.add(filename)

                    self._collect_content_signatures(
                        path=path,
                        rel=rel,
                        content_hits=content_hits,
                        secret_hits=secret_hits,
                        config=config,
                    )

                    if len(files) >= config.max_files:
                        truncated = True
                        break
                except OSError as exc:
                    self.logger.debug("Skipping unreadable file %s: %s", path, exc)

            if truncated:
                break

        return {
            "files": files,
            "directories": directories,
            "relative_paths": relative_paths,
            "file_names": file_names,
            "dir_names": dir_names,
            "content_hits": content_hits,
            "secret_hits": secret_hits,
            "truncated": truncated,
        }

    def _collect_content_signatures(
        self,
        path: Path,
        rel: str,
        content_hits: Dict[str, List[str]],
        secret_hits: List[Dict[str, Any]],
        config: ProjectAnalysisConfig,
    ) -> None:
        """
        Read a limited number of bytes from text-like files and collect framework/security hits.
        """
        if not self._is_probably_text_file(path):
            return

        try:
            raw = path.read_bytes()[: config.max_file_read_bytes]
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            return

        for signature in FRAMEWORK_SIGNATURES.values():
            for pattern in signature.get("content_patterns", []):
                try:
                    if re.search(pattern, text):
                        content_hits.setdefault(pattern, []).append(rel)
                except re.error:
                    continue

        if config.detect_secrets:
            for pattern in DEFAULT_SECRET_PATTERNS:
                if pattern.search(text):
                    secret_hits.append({"path": rel, "pattern": pattern.pattern})
                    break

    def _parse_dependency_file(
        self,
        path: Path,
        rel: str,
        config: ProjectAnalysisConfig,
    ) -> Dict[str, Any]:
        """
        Parse known dependency files safely.
        """
        name = path.name
        ecosystem = self._dependency_ecosystem(name, rel)
        dependencies: List[str] = []
        parse_error: Optional[str] = None

        try:
            if not path.exists() or not path.is_file():
                return {
                    "path": rel,
                    "ecosystem": ecosystem,
                    "dependencies": [],
                    "parse_error": "file_not_found",
                }

            content = path.read_text(encoding="utf-8", errors="ignore")[: config.max_file_read_bytes]

            if name == "requirements.txt":
                dependencies = self._parse_requirements_txt(content)
            elif name == "pyproject.toml":
                dependencies = self._parse_pyproject_toml(content)
            elif name == "package.json":
                dependencies = self._parse_package_json(content)
            elif name == "composer.json":
                dependencies = self._parse_composer_json(content)
            elif name == "Gemfile":
                dependencies = self._parse_gemfile(content)
            elif name == "go.mod":
                dependencies = self._parse_go_mod(content)
            elif name == "Cargo.toml":
                dependencies = self._parse_cargo_toml(content)
            elif name == "pubspec.yaml":
                dependencies = self._parse_pubspec_yaml(content)
            elif name in {"build.gradle", "pom.xml"}:
                dependencies = self._parse_generic_dependency_lines(content)
            elif name in {"Dockerfile", "docker-compose.yml", "docker-compose.yaml"}:
                dependencies = self._parse_docker_dependencies(content)
            else:
                dependencies = self._parse_generic_dependency_lines(content)

        except Exception as exc:
            parse_error = str(exc)

        return {
            "path": rel,
            "ecosystem": ecosystem,
            "dependencies": sorted(set(dependencies)),
            "parse_error": parse_error,
        }

    # ------------------------------------------------------------------
    # Dependency parsers
    # ------------------------------------------------------------------

    def _parse_requirements_txt(self, content: str) -> List[str]:
        deps: List[str] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            name = re.split(r"[<>=!~\[\];\s]", line, maxsplit=1)[0].strip()
            if name:
                deps.append(name.lower())
        return deps

    def _parse_pyproject_toml(self, content: str) -> List[str]:
        deps: List[str] = []
        for line in content.splitlines():
            stripped = line.strip().strip(",")
            match = re.match(r"['\"]([A-Za-z0-9_.\-]+)(?:[<>=!~\[].*)?['\"]", stripped)
            if match:
                deps.append(match.group(1).lower())
            key_match = re.match(r"([A-Za-z0-9_.\-]+)\s*=\s*['\"]", stripped)
            if key_match and key_match.group(1).lower() not in {"name", "version", "description"}:
                deps.append(key_match.group(1).lower())
        return deps

    def _parse_package_json(self, content: str) -> List[str]:
        data = json.loads(content)
        deps: List[str] = []
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            values = data.get(section, {})
            if isinstance(values, dict):
                deps.extend(values.keys())
        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            for script_value in scripts.values():
                if isinstance(script_value, str):
                    deps.extend(self._script_dependency_hints(script_value))
        return [dep.lower() for dep in deps]

    def _parse_composer_json(self, content: str) -> List[str]:
        data = json.loads(content)
        deps: List[str] = []
        for section in ("require", "require-dev"):
            values = data.get(section, {})
            if isinstance(values, dict):
                deps.extend(values.keys())
        return [dep.lower() for dep in deps]

    def _parse_gemfile(self, content: str) -> List[str]:
        deps: List[str] = []
        for match in re.finditer(r"gem\s+['\"]([^'\"]+)['\"]", content):
            deps.append(match.group(1).lower())
        return deps

    def _parse_go_mod(self, content: str) -> List[str]:
        deps: List[str] = []
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("module ") or stripped.startswith("go "):
                continue
            if stripped.startswith("require "):
                stripped = stripped.replace("require ", "", 1).strip()
            if stripped and not stripped.startswith("(") and not stripped.startswith(")"):
                deps.append(stripped.split()[0].lower())
        return deps

    def _parse_cargo_toml(self, content: str) -> List[str]:
        deps: List[str] = []
        in_dependency_section = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                in_dependency_section = stripped in {"[dependencies]", "[dev-dependencies]", "[build-dependencies]"}
                continue
            if in_dependency_section and "=" in stripped and not stripped.startswith("#"):
                deps.append(stripped.split("=", 1)[0].strip().lower())
        return deps

    def _parse_pubspec_yaml(self, content: str) -> List[str]:
        deps: List[str] = []
        in_deps = False
        for line in content.splitlines():
            if re.match(r"^(dependencies|dev_dependencies):\s*$", line):
                in_deps = True
                continue
            if in_deps:
                if line and not line.startswith(" ") and not line.startswith("\t"):
                    in_deps = False
                    continue
                match = re.match(r"\s{2,}([A-Za-z0-9_\-]+):", line)
                if match:
                    deps.append(match.group(1).lower())
        return deps

    def _parse_docker_dependencies(self, content: str) -> List[str]:
        deps: List[str] = []
        for line in content.splitlines():
            stripped = line.strip()
            from_match = re.match(r"FROM\s+([^\s]+)", stripped, re.IGNORECASE)
            if from_match:
                deps.append(from_match.group(1).lower())
            image_match = re.match(r"image:\s*([^\s]+)", stripped, re.IGNORECASE)
            if image_match:
                deps.append(image_match.group(1).lower())
        return deps

    def _parse_generic_dependency_lines(self, content: str) -> List[str]:
        deps: List[str] = []
        patterns = [
            r"implementation\s+['\"]([^:'\"]+:[^:'\"]+)",
            r"api\s+['\"]([^:'\"]+:[^:'\"]+)",
            r"<artifactId>([^<]+)</artifactId>",
            r"require\(['\"]([^'\"]+)['\"]\)",
            r"from\s+['\"]([^'\"]+)['\"]",
            r"import\s+([A-Za-z0-9_.\-]+)",
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                deps.append(match.group(1).lower())
        return deps

    def _script_dependency_hints(self, script: str) -> List[str]:
        hints: List[str] = []
        known = ["next", "vite", "nuxt", "svelte-kit", "react-scripts", "webpack", "rollup", "tsc", "eslint"]
        for item in known:
            if re.search(rf"\b{re.escape(item)}\b", script):
                hints.append(item)
        return hints

    # ------------------------------------------------------------------
    # Validation and utility helpers
    # ------------------------------------------------------------------

    def _validate_project_path(
        self,
        root: Path,
        config: ProjectAnalysisConfig,
        context: ProjectContext,
    ) -> Dict[str, Any]:
        if not root.exists():
            return self._error_result(
                message="Project path does not exist.",
                error="path_not_found",
                metadata=self._metadata(context, root=str(root)),
            )

        if not root.is_dir():
            return self._error_result(
                message="Project path must be a directory.",
                error="path_not_directory",
                metadata=self._metadata(context, root=str(root)),
            )

        allowed_root = config.normalized_allowed_root()
        if allowed_root is not None:
            try:
                root.relative_to(allowed_root)
            except ValueError:
                return self._error_result(
                    message="Project path is outside the allowed root.",
                    error="path_outside_allowed_root",
                    metadata=self._metadata(
                        context,
                        root=str(root),
                        allowed_root=str(allowed_root),
                    ),
                )

        return self._safe_result(
            message="Project path is valid.",
            data={"project_path": str(root)},
        )

    def _config_from_task(self, raw: Dict[str, Any]) -> ProjectAnalysisConfig:
        if not raw:
            return self.config

        config = ProjectAnalysisConfig(
            max_files=int(raw.get("max_files", self.config.max_files)),
            max_depth=int(raw.get("max_depth", self.config.max_depth)),
            max_file_read_bytes=int(raw.get("max_file_read_bytes", self.config.max_file_read_bytes)),
            include_hidden=bool(raw.get("include_hidden", self.config.include_hidden)),
            detect_secrets=bool(raw.get("detect_secrets", self.config.detect_secrets)),
            collect_tree=bool(raw.get("collect_tree", self.config.collect_tree)),
            collect_file_stats=bool(raw.get("collect_file_stats", self.config.collect_file_stats)),
            excluded_dirs=set(raw.get("excluded_dirs", self.config.excluded_dirs)),
            excluded_files=set(raw.get("excluded_files", self.config.excluded_files)),
            allowed_root=raw.get("allowed_root", self.config.allowed_root),
        )
        return config

    def _build_optional_agent(self, agent_cls: Optional[Any]) -> Optional[Any]:
        if agent_cls is None:
            return None
        try:
            return agent_cls()
        except Exception:
            return None

    def _safe_relative_path(self, path: Path, root: Path) -> str:
        try:
            rel = path.relative_to(root)
            rel_text = rel.as_posix()
            return rel_text if rel_text else "."
        except ValueError:
            return path.name

    def _should_include_dir(self, dirname: str, config: ProjectAnalysisConfig) -> bool:
        if not config.include_hidden and dirname.startswith(".") and dirname not in {".github"}:
            return False
        if dirname in config.excluded_dirs:
            return False
        return True

    def _should_include_file(self, filename: str, config: ProjectAnalysisConfig) -> bool:
        if not config.include_hidden and filename.startswith(".") and filename not in {
            ".env.example",
            ".gitignore",
            ".dockerignore",
            ".htaccess",
        }:
            return False
        if filename in config.excluded_files:
            return False
        return True

    def _is_probably_text_file(self, path: Path) -> bool:
        text_extensions = {
            ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".toml", ".yaml", ".yml",
            ".txt", ".md", ".html", ".css", ".scss", ".php", ".rb", ".go", ".rs",
            ".dart", ".java", ".kt", ".swift", ".xml", ".gradle", ".env", ".ini",
            ".cfg", ".sql", ".sh", ".bat", ".ps1", ".dockerfile",
        }
        if path.suffix.lower() in text_extensions:
            return True
        if path.name in {
            "Dockerfile", "Gemfile", "Pipfile", "Makefile", ".env", ".env.example",
            ".gitignore", ".dockerignore",
        }:
            return True
        return False

    def _dependency_ecosystem(self, name: str, rel: str) -> str:
        if name in {"requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "environment.yml"}:
            return "python"
        if name == "package.json":
            return "node"
        if name == "composer.json":
            return "php"
        if name == "Gemfile":
            return "ruby"
        if name == "go.mod":
            return "go"
        if name == "Cargo.toml":
            return "rust"
        if name == "pubspec.yaml":
            return "dart"
        if name in {"build.gradle", "pom.xml"}:
            return "java"
        if name in {"Dockerfile", "docker-compose.yml", "docker-compose.yaml"}:
            return "docker"
        return "unknown"

    def _existing_relative_paths(self, root: Path) -> Set[str]:
        paths: Set[str] = set()
        try:
            for current_root, dirnames, filenames in os.walk(root):
                current = Path(current_root)
                for dirname in dirnames:
                    paths.add(self._safe_relative_path(current / dirname, root))
                    paths.add(dirname)
                for filename in filenames:
                    paths.add(self._safe_relative_path(current / filename, root))
                    paths.add(filename)
        except Exception:
            pass
        return paths

    def _path_exists_flexibly(self, rel: str, existing_paths: Set[str]) -> bool:
        if rel in existing_paths:
            return True
        if "/" not in rel and rel.lower() in {item.lower() for item in existing_paths}:
            return True
        return any(path.endswith(f"/{rel}") for path in existing_paths)

    def _missing_file_reason(self, rel: str) -> str:
        reasons = {
            "README.md": "Documents setup, usage, deployment, and architecture.",
            ".gitignore": "Prevents secrets, dependencies, caches, and build outputs from being committed.",
            ".env.example": "Shows required environment variables without exposing secrets.",
            "requirements.txt": "Defines Python dependencies for reproducible installs.",
            "package.json": "Defines Node scripts and dependencies.",
            "Dockerfile": "Improves deployment consistency.",
            "tests": "Adds automated validation and protects future changes.",
            ".github/workflows": "Adds CI/CD automation for testing and deployment.",
        }
        return reasons.get(rel, "Recommended for production readiness and maintainability.")

    def _has_path(self, root: Path, name: str) -> bool:
        return (root / name).exists()

    def _build_recommendations(
        self,
        frameworks: Sequence[Dict[str, Any]],
        risks: Sequence[AnalysisRisk],
        missing_files: Sequence[Dict[str, Any]],
        dependencies: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        recommendations: List[Dict[str, Any]] = []

        if not frameworks:
            recommendations.append(
                {
                    "priority": "medium",
                    "title": "Add framework-identifying files",
                    "details": "Add standard manifests/configs so tools can detect and manage the project correctly.",
                }
            )

        high_risks = [risk for risk in risks if risk.severity == "high"]
        if high_risks:
            recommendations.append(
                {
                    "priority": "high",
                    "title": "Fix high-severity risks first",
                    "details": "Review possible secrets, missing permissions, and unsafe environment files before deployment.",
                }
            )

        if missing_files:
            recommendations.append(
                {
                    "priority": "medium",
                    "title": "Add missing production files",
                    "details": "Start with README.md, .gitignore, .env.example, dependency manifests, and tests.",
                    "missing_files": [item.get("path") for item in missing_files],
                }
            )

        if dependencies.get("total_dependencies", 0) > 80:
            recommendations.append(
                {
                    "priority": "low",
                    "title": "Review dependency footprint",
                    "details": "Large dependency sets increase maintenance and security update effort.",
                }
            )

        if not recommendations:
            recommendations.append(
                {
                    "priority": "low",
                    "title": "Project structure looks healthy",
                    "details": "Continue adding tests, documentation, CI/CD, and security scans as the project grows.",
                }
            )

        return recommendations

    def _metadata(self, context: ProjectContext, **extra: Any) -> Dict[str, Any]:
        metadata = {
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "version": self.version,
            "user_id": str(context.user_id) if context and context.user_id is not None else None,
            "workspace_id": str(context.workspace_id) if context and context.workspace_id is not None else None,
            "request_id": context.request_id if context else None,
        }
        metadata.update(extra)
        return metadata

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()


__all__ = [
    "ProjectAnalyzer",
    "ProjectAnalysisConfig",
    "ProjectContext",
    "AnalysisRisk",
    "FileSummary",
]


if __name__ == "__main__":
    # Safe local CLI usage for quick testing:
    # python agents/code_agent/project_analyzer.py /path/to/project
    import argparse

    parser = argparse.ArgumentParser(description="Analyze a project structure safely.")
    parser.add_argument("project_path", help="Path to the project directory.")
    parser.add_argument("--user-id", default="local_user", help="SaaS user id.")
    parser.add_argument("--workspace-id", default="local_workspace", help="SaaS workspace id.")
    parser.add_argument("--max-files", type=int, default=1000, help="Maximum files to scan.")
    parser.add_argument("--include-hidden", action="store_true", help="Include hidden files/directories.")
    args = parser.parse_args()

    analyzer = ProjectAnalyzer(
        config=ProjectAnalysisConfig(
            max_files=args.max_files,
            include_hidden=args.include_hidden,
        )
    )
    output = analyzer.analyze_project(
        project_path=args.project_path,
        context=ProjectContext(
            user_id=args.user_id,
            workspace_id=args.workspace_id,
            permissions={"skip_security_check": True},
        ),
    )
    print(json.dumps(output, indent=2, default=str))
