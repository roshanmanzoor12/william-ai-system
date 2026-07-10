"""
agents/code_agent/ci_cd_manager.py

William / Jarvis Multi-Agent AI SaaS System - Code Agent CI/CD Manager.

This module generates and validates production deployment assets for SaaS projects:
Dockerfile, docker-compose.yml, GitHub Actions workflow, Nginx reverse proxy,
Gunicorn systemd service, SSL/Certbot commands, and safe VPS deployment scripts.

It is intentionally import-safe:
- Optional William/Jarvis BaseAgent imports are protected with fallbacks.
- No real deployment command is executed by default.
- Sensitive actions are routed through security approval hooks.
- Every public task supports SaaS isolation via user_id and workspace_id.
"""

from __future__ import annotations

import datetime as _dt
import logging
import os
import re
import shlex
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Import-safe BaseAgent compatibility
# ---------------------------------------------------------------------------
try:  # pragma: no cover - depends on future William/Jarvis project layout
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Minimal fallback so this file remains import-safe before BaseAgent exists.
        The real William/Jarvis BaseAgent can replace this automatically.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "code_agent")
            self.logger = logging.getLogger(self.agent_name)


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass
class CICDConfig:
    """
    Configuration used to generate CI/CD and deployment assets.

    This config is deliberately secret-free. Values such as SSH keys, registry
    tokens, database passwords, and API keys must be stored in GitHub Secrets,
    environment managers, or the William/Jarvis secrets vault - never here.
    """

    project_name: str = "william-jarvis-app"
    app_module: str = "app:app"
    framework: str = "fastapi"
    python_version: str = "3.11"
    exposed_port: int = 8000
    docker_image_name: str = "william-jarvis-app"
    container_name: str = "william-jarvis-app"
    service_name: str = "william-jarvis"
    domain: str = "example.com"
    email: str = "admin@example.com"
    deploy_user: str = "deploy"
    deploy_path: str = "/var/www/william-jarvis"
    branch: str = "main"
    use_postgres: bool = False
    use_redis: bool = False
    use_celery: bool = False
    use_nginx: bool = True
    use_ssl: bool = True
    include_tests: bool = True
    include_lint: bool = True
    include_migrations: bool = False
    requirements_file: str = "requirements.txt"
    env_file: str = ".env"
    healthcheck_path: str = "/health"
    static_path: str = "/static/"
    media_path: str = "/media/"
    workers: int = 3
    timeout: int = 120
    extra_environment: Dict[str, str] = field(default_factory=dict)
    github_python_cache: bool = True

    def normalized(self) -> "CICDConfig":
        """Return a sanitized copy with safe defaults and normalized names."""
        project_name = _slugify(self.project_name or "william-jarvis-app")
        image_name = _docker_name(self.docker_image_name or project_name)
        container_name = _docker_name(self.container_name or project_name)
        service_name = _systemd_name(self.service_name or project_name)

        domain = _safe_domain(self.domain) or "example.com"
        email = self.email if _looks_like_email(self.email) else "admin@example.com"
        deploy_user = _safe_linux_name(self.deploy_user) or "deploy"
        deploy_path = self.deploy_path if self.deploy_path.startswith("/") else f"/var/www/{project_name}"

        return CICDConfig(
            project_name=project_name,
            app_module=_safe_app_module(self.app_module) or "app:app",
            framework=(self.framework or "fastapi").strip().lower(),
            python_version=_safe_python_version(self.python_version) or "3.11",
            exposed_port=int(self.exposed_port or 8000),
            docker_image_name=image_name,
            container_name=container_name,
            service_name=service_name,
            domain=domain,
            email=email,
            deploy_user=deploy_user,
            deploy_path=deploy_path.rstrip("/"),
            branch=_safe_branch(self.branch) or "main",
            use_postgres=bool(self.use_postgres),
            use_redis=bool(self.use_redis),
            use_celery=bool(self.use_celery),
            use_nginx=bool(self.use_nginx),
            use_ssl=bool(self.use_ssl),
            include_tests=bool(self.include_tests),
            include_lint=bool(self.include_lint),
            include_migrations=bool(self.include_migrations),
            requirements_file=self.requirements_file or "requirements.txt",
            env_file=self.env_file or ".env",
            healthcheck_path=_safe_url_path(self.healthcheck_path) or "/health",
            static_path=_safe_url_path(self.static_path) or "/static/",
            media_path=_safe_url_path(self.media_path) or "/media/",
            workers=max(1, int(self.workers or 3)),
            timeout=max(30, int(self.timeout or 120)),
            extra_environment=dict(self.extra_environment or {}),
            github_python_cache=bool(self.github_python_cache),
        )


@dataclass
class GeneratedArtifact:
    """Represents one generated CI/CD artifact."""

    name: str
    relative_path: str
    content: str
    category: str
    sensitive: bool = False
    executable: bool = False
    description: str = ""


@dataclass
class CICDRisk:
    """Risk detected while preparing CI/CD assets."""

    code: str
    severity: str
    message: str
    recommendation: str
    path: Optional[str] = None


@dataclass
class TaskContext:
    """SaaS-safe task context used by William/Jarvis agents."""

    user_id: Union[str, int]
    workspace_id: Union[str, int]
    request_id: Optional[str] = None
    role: Optional[str] = None
    permissions: Sequence[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def _utc_now() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).isoformat()


def _slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9._-]+", "-", value)
    value = re.sub(r"-{2,}", "-", value).strip("-._")
    return value or "william-jarvis-app"


def _docker_name(value: str) -> str:
    value = _slugify(value).replace("_", "-")
    return value[:128] or "william-jarvis-app"


def _systemd_name(value: str) -> str:
    value = _slugify(value).replace("_", "-")
    return value[:80] or "william-jarvis"


def _safe_linux_name(value: str) -> str:
    value = (value or "").strip()
    if re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", value):
        return value
    return ""


def _safe_domain(value: str) -> str:
    value = (value or "").strip().lower()
    value = value.replace("https://", "").replace("http://", "").split("/")[0]
    if re.fullmatch(r"([a-z0-9-]+\.)+[a-z]{2,63}", value):
        return value
    return ""


def _looks_like_email(value: str) -> bool:
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", (value or "").strip()))


def _safe_branch(value: str) -> str:
    value = (value or "").strip()
    if re.fullmatch(r"[A-Za-z0-9._/-]{1,120}", value) and ".." not in value:
        return value
    return ""


def _safe_python_version(value: str) -> str:
    value = (value or "").strip()
    if re.fullmatch(r"3\.(9|10|11|12|13)", value):
        return value
    return ""


def _safe_url_path(value: str) -> str:
    value = (value or "").strip()
    if not value.startswith("/"):
        value = "/" + value
    if re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*", value):
        return value
    return "/"


def _safe_app_module(value: str) -> str:
    value = (value or "").strip()
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*", value):
        return value
    return ""


def _quote(value: str) -> str:
    return shlex.quote(str(value))


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _contains_any(text: str, needles: Iterable[str]) -> bool:
    lower = text.lower()
    return any(n.lower() in lower for n in needles)


# ---------------------------------------------------------------------------
# Main CI/CD Manager
# ---------------------------------------------------------------------------
class CICDManager(BaseAgent):
    """
    Generates safe CI/CD and deployment assets for William/Jarvis projects.

    Master Agent / Router:
        Public methods return structured dictionaries so the Master Agent can
        route requests, display dashboard output, or hand off results.

    Security Agent:
        Deployment execution, remote shell scripts, and overwriting files are
        considered sensitive and pass through _requires_security_check() and
        _request_security_approval() hooks.

    Verification Agent:
        Every generation/write operation prepares a verification payload that
        lists generated files, checks performed, risks, and recommended tests.

    Memory Agent:
        Useful project configuration and generated artifact metadata can be
        sent to Memory Agent through _prepare_memory_payload().

    Dashboard/API:
        Results are JSON-style dictionaries with success, message, data, error,
        and metadata fields.
    """

    AGENT_NAME = "CICDManager"
    AGENT_TYPE = "code_agent"
    VERSION = "1.0.0"

    DEFAULT_REQUIRED_FILES = (
        "requirements.txt",
        ".env.example",
        ".gitignore",
        "README.md",
    )

    SENSITIVE_PATTERNS = (
        "PRIVATE KEY",
        "AWS_SECRET",
        "AWS_ACCESS_KEY",
        "SECRET_KEY=",
        "DATABASE_URL=",
        "TOKEN=",
        "PASSWORD=",
        "API_KEY=",
        "client_secret",
    )

    def __init__(
        self,
        base_dir: Optional[Union[str, Path]] = None,
        security_client: Optional[Any] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        memory_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        verification_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger_: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.AGENT_NAME, agent_type=self.AGENT_TYPE, **kwargs)
        self.base_dir = Path(base_dir or os.getcwd()).resolve()
        self.security_client = security_client
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.memory_callback = memory_callback
        self.verification_callback = verification_callback
        self.logger = logger_ or logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------
    def generate_all_artifacts(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        project_path: Optional[Union[str, Path]] = None,
        config: Optional[Union[CICDConfig, Mapping[str, Any]]] = None,
        write_files: bool = False,
        overwrite: bool = False,
        request_id: Optional[str] = None,
        permissions: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """
        Generate Docker, GitHub Actions, VPS, Nginx, Gunicorn, and SSL assets.

        By default this does not write files. Set write_files=True to write
        generated artifacts into project_path after security approval.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            request_id=request_id,
            permissions=permissions or (),
        )
        if not context_result["success"]:
            return context_result

        ctx: TaskContext = context_result["data"]["context"]
        project_root = self._resolve_project_path(project_path)
        cfg = self._coerce_config(config).normalized()

        risks = self.detect_deployment_risks(project_root=project_root, config=cfg)["data"]["risks"]
        artifacts = [
            self.generate_dockerfile(config=cfg)["data"]["artifact"],
            self.generate_dockerignore(config=cfg)["data"]["artifact"],
            self.generate_docker_compose(config=cfg)["data"]["artifact"],
            self.generate_github_actions(config=cfg)["data"]["artifact"],
            self.generate_env_example(config=cfg)["data"]["artifact"],
            self.generate_nginx_config(config=cfg)["data"]["artifact"],
            self.generate_gunicorn_service(config=cfg)["data"]["artifact"],
            self.generate_vps_deploy_script(config=cfg)["data"]["artifact"],
            self.generate_ssl_commands(config=cfg)["data"]["artifact"],
        ]

        write_result: Optional[Dict[str, Any]] = None
        if write_files:
            if self._requires_security_check("write_cicd_artifacts", artifacts=artifacts, project_root=project_root):
                approval = self._request_security_approval(
                    action="write_cicd_artifacts",
                    context=ctx,
                    payload={
                        "project_root": str(project_root),
                        "overwrite": overwrite,
                        "files": [a.relative_path for a in artifacts],
                    },
                )
                if not approval.get("approved"):
                    return self._error_result(
                        message="Security approval denied for writing CI/CD artifacts.",
                        error="security_denied",
                        metadata={"approval": approval, "user_id": user_id, "workspace_id": workspace_id},
                    )
            write_result = self.write_artifacts(
                artifacts=artifacts,
                project_path=project_root,
                overwrite=overwrite,
                user_id=user_id,
                workspace_id=workspace_id,
                request_id=request_id,
                permissions=permissions,
            )

        verification_payload = self._prepare_verification_payload(
            context=ctx,
            action="generate_all_artifacts",
            artifacts=artifacts,
            risks=risks,
            project_root=project_root,
            config=cfg,
            write_result=write_result,
        )
        memory_payload = self._prepare_memory_payload(
            context=ctx,
            action="generate_all_artifacts",
            config=cfg,
            artifacts=artifacts,
            risks=risks,
        )

        self._emit_agent_event("cicd.artifacts.generated", {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "artifact_count": len(artifacts),
            "written": bool(write_files),
            "project_root": str(project_root),
        })
        self._log_audit_event("cicd_generate_all_artifacts", ctx, {
            "project_root": str(project_root),
            "artifact_count": len(artifacts),
            "write_files": write_files,
            "overwrite": overwrite,
        })

        return self._safe_result(
            message="CI/CD artifacts generated successfully.",
            data={
                "project_root": str(project_root),
                "config": asdict(cfg),
                "artifacts": [asdict(a) for a in artifacts],
                "risks": [asdict(r) if isinstance(r, CICDRisk) else r for r in risks],
                "write_result": write_result,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent": self.AGENT_NAME,
                "version": self.VERSION,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "request_id": request_id,
            },
        )

    def generate_dockerfile(self, config: Optional[Union[CICDConfig, Mapping[str, Any]]] = None) -> Dict[str, Any]:
        """Generate a secure Python Dockerfile for FastAPI/Flask/Django apps."""
        cfg = self._coerce_config(config).normalized()
        command = self._container_start_command(cfg)

        content = f"""# Generated by William/Jarvis CICDManager
# Secret-free production Dockerfile for {cfg.project_name}

FROM python:{cfg.python_version}-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    PIP_NO_CACHE_DIR=1 \\
    PORT={cfg.exposed_port}

WORKDIR /app

RUN apt-get update \\
    && apt-get install -y --no-install-recommends \\
       build-essential \\
       curl \\
       ca-certificates \\
    && rm -rf /var/lib/apt/lists/*

COPY {cfg.requirements_file} /app/{cfg.requirements_file}
RUN python -m pip install --upgrade pip \\
    && pip install -r /app/{cfg.requirements_file}

COPY . /app

RUN adduser --disabled-password --gecos "" appuser \\
    && chown -R appuser:appuser /app

USER appuser

EXPOSE {cfg.exposed_port}

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \\
    CMD curl -fsS http://127.0.0.1:{cfg.exposed_port}{cfg.healthcheck_path} || exit 1

CMD {command}
"""
        artifact = GeneratedArtifact(
            name="Dockerfile",
            relative_path="Dockerfile",
            content=content,
            category="docker",
            description="Production Python Dockerfile with non-root user and healthcheck.",
        )
        return self._safe_result("Dockerfile generated.", {"artifact": artifact})

    def generate_dockerignore(self, config: Optional[Union[CICDConfig, Mapping[str, Any]]] = None) -> Dict[str, Any]:
        """Generate .dockerignore to keep images clean and secret-free."""
        _ = self._coerce_config(config).normalized()
        content = """# Generated by William/Jarvis CICDManager
.git
.github
.gitignore
__pycache__/
*.py[cod]
*.pyo
*.pyd
*.db
*.sqlite3
*.log
.env
.env.*
!.env.example
.venv/
venv/
env/
node_modules/
dist/
build/
coverage/
.pytest_cache/
.mypy_cache/
.ruff_cache/
.DS_Store
.idea/
.vscode/
user_uploads/
media/private/
*.pem
*.key
id_rsa
id_ed25519
"""
        artifact = GeneratedArtifact(
            name=".dockerignore",
            relative_path=".dockerignore",
            content=content,
            category="docker",
            description="Docker ignore rules that exclude cache, local env files, and private keys.",
        )
        return self._safe_result(".dockerignore generated.", {"artifact": artifact})

    def generate_docker_compose(self, config: Optional[Union[CICDConfig, Mapping[str, Any]]] = None) -> Dict[str, Any]:
        """Generate docker-compose.yml for app, optional Postgres, Redis, and Celery."""
        cfg = self._coerce_config(config).normalized()
        lines = [
            "# Generated by William/Jarvis CICDManager",
            "services:",
            "  app:",
            "    build: .",
            f"    image: {cfg.docker_image_name}:latest",
            f"    container_name: {cfg.container_name}",
            "    restart: unless-stopped",
            f"    env_file:",
            f"      - {cfg.env_file}",
            "    ports:",
            f'      - "127.0.0.1:{cfg.exposed_port}:{cfg.exposed_port}"',
            "    volumes:",
            "      - ./media:/app/media",
            "      - ./logs:/app/logs",
            "    healthcheck:",
            f'      test: ["CMD", "curl", "-fsS", "http://127.0.0.1:{cfg.exposed_port}{cfg.healthcheck_path}"]',
            "      interval: 30s",
            "      timeout: 5s",
            "      retries: 3",
            "      start_period: 20s",
        ]

        depends = []
        if cfg.use_postgres:
            depends.append("db")
        if cfg.use_redis:
            depends.append("redis")
        if depends:
            lines.extend(["    depends_on:"] + [f"      - {d}" for d in depends])

        if cfg.use_celery:
            lines.extend([
                "",
                "  worker:",
                "    build: .",
                f"    image: {cfg.docker_image_name}:latest",
                f"    container_name: {cfg.container_name}-worker",
                "    restart: unless-stopped",
                f"    env_file:",
                f"      - {cfg.env_file}",
                "    command: celery -A app.celery_app worker --loglevel=INFO",
                "    volumes:",
                "      - ./media:/app/media",
                "      - ./logs:/app/logs",
            ])
            celery_depends = ["app"]
            if cfg.use_redis:
                celery_depends.append("redis")
            if cfg.use_postgres:
                celery_depends.append("db")
            lines.extend(["    depends_on:"] + [f"      - {d}" for d in celery_depends])

        if cfg.use_postgres:
            lines.extend([
                "",
                "  db:",
                "    image: postgres:16-alpine",
                f"    container_name: {cfg.container_name}-db",
                "    restart: unless-stopped",
                "    environment:",
                "      POSTGRES_DB: ${POSTGRES_DB:-william}",
                "      POSTGRES_USER: ${POSTGRES_USER:-william}",
                "      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}",
                "    volumes:",
                "      - postgres_data:/var/lib/postgresql/data",
                "    healthcheck:",
                '      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-william} -d ${POSTGRES_DB:-william}"]',
                "      interval: 10s",
                "      timeout: 5s",
                "      retries: 5",
            ])

        if cfg.use_redis:
            lines.extend([
                "",
                "  redis:",
                "    image: redis:7-alpine",
                f"    container_name: {cfg.container_name}-redis",
                "    restart: unless-stopped",
                "    command: redis-server --appendonly yes",
                "    volumes:",
                "      - redis_data:/data",
                "    healthcheck:",
                '      test: ["CMD", "redis-cli", "ping"]',
                "      interval: 10s",
                "      timeout: 5s",
                "      retries: 5",
            ])

        volumes = []
        if cfg.use_postgres:
            volumes.append("postgres_data:")
        if cfg.use_redis:
            volumes.append("redis_data:")
        if volumes:
            lines.extend(["", "volumes:"] + [f"  {v}" for v in volumes])

        content = "\n".join(lines) + "\n"
        artifact = GeneratedArtifact(
            name="docker-compose.yml",
            relative_path="docker-compose.yml",
            content=content,
            category="docker",
            description="Docker Compose stack for app and optional backing services.",
        )
        return self._safe_result("docker-compose.yml generated.", {"artifact": artifact})

    def generate_github_actions(self, config: Optional[Union[CICDConfig, Mapping[str, Any]]] = None) -> Dict[str, Any]:
        """Generate GitHub Actions workflow for lint, tests, Docker build, and deploy hook."""
        cfg = self._coerce_config(config).normalized()
        test_step = ""
        if cfg.include_tests:
            test_step = """
      - name: Run tests
        run: |
          if [ -d tests ]; then
            pytest -q
          else
            echo "No tests directory found; skipping pytest."
          fi
"""
        lint_step = ""
        if cfg.include_lint:
            lint_step = """
      - name: Run basic syntax checks
        run: |
          python -m compileall .
"""

        migration_step = ""
        if cfg.include_migrations:
            migration_step = """
            if command -v alembic >/dev/null 2>&1; then
              alembic upgrade head
            elif python manage.py help migrate >/dev/null 2>&1; then
              python manage.py migrate --noinput
            else
              echo "No migration command detected."
            fi
"""

        cache_line = "          cache: 'pip'\n" if cfg.github_python_cache else ""

        content = f"""# Generated by William/Jarvis CICDManager
name: CI/CD

on:
  push:
    branches: [{cfg.branch}]
  pull_request:
    branches: [{cfg.branch}]
  workflow_dispatch:

permissions:
  contents: read
  packages: write

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '{cfg.python_version}'
{cache_line.rstrip() if cache_line else ''}

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          if [ -f {cfg.requirements_file} ]; then pip install -r {cfg.requirements_file}; fi
          pip install pytest
{lint_step.rstrip()}
{test_step.rstrip()}

  docker-build:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Validate Docker build
        run: docker build -t {cfg.docker_image_name}:ci .

  deploy:
    runs-on: ubuntu-latest
    needs: docker-build
    if: github.ref == 'refs/heads/{cfg.branch}' && github.event_name != 'pull_request'
    steps:
      - name: Deploy over SSH
        uses: appleboy/ssh-action@v1.0.3
        with:
          host: ${{{{ secrets.VPS_HOST }}}}
          username: ${{{{ secrets.VPS_USER }}}}
          key: ${{{{ secrets.VPS_SSH_KEY }}}}
          port: ${{{{ secrets.VPS_PORT || 22 }}}}
          script: |
            set -euo pipefail
            cd {_quote(cfg.deploy_path)}
            git fetch origin {_quote(cfg.branch)}
            git reset --hard origin/{_quote(cfg.branch)}
            if [ -f {cfg.env_file}.production ]; then cp {cfg.env_file}.production {cfg.env_file}; fi
{migration_step.rstrip() if migration_step else '            echo "Migration step disabled."'}
            docker compose build --pull
            docker compose up -d --remove-orphans
            docker image prune -f
"""
        artifact = GeneratedArtifact(
            name="deploy.yml",
            relative_path=".github/workflows/deploy.yml",
            content=content,
            category="github_actions",
            sensitive=False,
            description="GitHub Actions CI/CD workflow using GitHub Secrets for VPS deploy.",
        )
        return self._safe_result("GitHub Actions workflow generated.", {"artifact": artifact})

    def generate_nginx_config(self, config: Optional[Union[CICDConfig, Mapping[str, Any]]] = None) -> Dict[str, Any]:
        """Generate Nginx reverse proxy config for the app."""
        cfg = self._coerce_config(config).normalized()
        ssl_block = ""
        listen_block = "    listen 80;\n"
        redirect_block = ""
        if cfg.use_ssl:
            redirect_block = f"""
server {{
    listen 80;
    server_name {cfg.domain} www.{cfg.domain};
    return 301 https://$host$request_uri;
}}

"""
            listen_block = (
                "    listen 443 ssl http2;\n"
                f"    ssl_certificate /etc/letsencrypt/live/{cfg.domain}/fullchain.pem;\n"
                f"    ssl_certificate_key /etc/letsencrypt/live/{cfg.domain}/privkey.pem;\n"
            )
            ssl_block = """
    ssl_session_timeout 1d;
    ssl_session_cache shared:WilliamSSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
"""

        content = f"""# Generated by William/Jarvis CICDManager
# Place at: /etc/nginx/sites-available/{cfg.service_name}
# Enable with: sudo ln -s /etc/nginx/sites-available/{cfg.service_name} /etc/nginx/sites-enabled/{cfg.service_name}

{redirect_block}server {{
{listen_block}    server_name {cfg.domain} www.{cfg.domain};
    client_max_body_size 25m;
{ssl_block}
    access_log /var/log/nginx/{cfg.service_name}.access.log;
    error_log /var/log/nginx/{cfg.service_name}.error.log;

    location {cfg.static_path} {{
        alias {cfg.deploy_path}/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }}

    location {cfg.media_path} {{
        alias {cfg.deploy_path}/media/;
        expires 7d;
        add_header Cache-Control "private";
    }}

    location / {{
        proxy_pass http://127.0.0.1:{cfg.exposed_port};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout {cfg.timeout}s;
        proxy_send_timeout {cfg.timeout}s;
    }}

    location = {cfg.healthcheck_path} {{
        proxy_pass http://127.0.0.1:{cfg.exposed_port}{cfg.healthcheck_path};
        access_log off;
    }}
}}
"""
        artifact = GeneratedArtifact(
            name=f"{cfg.service_name}.nginx.conf",
            relative_path=f"deploy/nginx/{cfg.service_name}.conf",
            content=content,
            category="nginx",
            sensitive=False,
            description="Nginx reverse proxy config for HTTP/HTTPS traffic.",
        )
        return self._safe_result("Nginx config generated.", {"artifact": artifact})

    def generate_gunicorn_service(self, config: Optional[Union[CICDConfig, Mapping[str, Any]]] = None) -> Dict[str, Any]:
        """Generate systemd service for Gunicorn/Uvicorn deployment without Docker."""
        cfg = self._coerce_config(config).normalized()
        worker_class = "uvicorn.workers.UvicornWorker" if cfg.framework in {"fastapi", "starlette"} else "gthread"
        content = f"""# Generated by William/Jarvis CICDManager
# Place at: /etc/systemd/system/{cfg.service_name}.service

[Unit]
Description={cfg.project_name} Gunicorn service
After=network.target

[Service]
User={cfg.deploy_user}
Group=www-data
WorkingDirectory={cfg.deploy_path}
EnvironmentFile={cfg.deploy_path}/{cfg.env_file}
ExecStart={cfg.deploy_path}/.venv/bin/gunicorn {cfg.app_module} \\
  --bind 127.0.0.1:{cfg.exposed_port} \\
  --workers {cfg.workers} \\
  --worker-class {worker_class} \\
  --timeout {cfg.timeout} \\
  --access-logfile {cfg.deploy_path}/logs/gunicorn-access.log \\
  --error-logfile {cfg.deploy_path}/logs/gunicorn-error.log

Restart=always
RestartSec=5
KillSignal=SIGQUIT
TimeoutStopSec=30

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths={cfg.deploy_path}

[Install]
WantedBy=multi-user.target
"""
        artifact = GeneratedArtifact(
            name=f"{cfg.service_name}.service",
            relative_path=f"deploy/systemd/{cfg.service_name}.service",
            content=content,
            category="systemd",
            sensitive=False,
            description="Systemd service for non-Docker Gunicorn deployment.",
        )
        return self._safe_result("Gunicorn systemd service generated.", {"artifact": artifact})

    def generate_ssl_commands(self, config: Optional[Union[CICDConfig, Mapping[str, Any]]] = None) -> Dict[str, Any]:
        """Generate safe Certbot commands as a script; does not execute them."""
        cfg = self._coerce_config(config).normalized()
        content = f"""#!/usr/bin/env bash
# Generated by William/Jarvis CICDManager
# This script prepares Let's Encrypt SSL for {cfg.domain}.
# Review before running on your VPS.

set -euo pipefail

DOMAIN={_quote(cfg.domain)}
EMAIL={_quote(cfg.email)}
SERVICE={_quote(cfg.service_name)}

sudo apt-get update
sudo apt-get install -y certbot python3-certbot-nginx nginx

sudo nginx -t

sudo certbot --nginx \\
  -d "$DOMAIN" \\
  -d "www.$DOMAIN" \\
  --email "$EMAIL" \\
  --agree-tos \\
  --no-eff-email \\
  --redirect

sudo systemctl reload nginx
sudo certbot renew --dry-run

echo "SSL setup completed for $DOMAIN"
"""
        artifact = GeneratedArtifact(
            name="setup_ssl.sh",
            relative_path="deploy/scripts/setup_ssl.sh",
            content=content,
            category="ssl",
            sensitive=True,
            executable=True,
            description="Reviewable Certbot SSL setup script. Not executed by this manager.",
        )
        return self._safe_result("SSL commands generated.", {"artifact": artifact})

    def generate_vps_deploy_script(self, config: Optional[Union[CICDConfig, Mapping[str, Any]]] = None) -> Dict[str, Any]:
        """Generate a reviewable VPS deploy script for Docker Compose deployment."""
        cfg = self._coerce_config(config).normalized()
        migration = "echo 'Migrations disabled.'"
        if cfg.include_migrations:
            migration = (
                "if docker compose exec -T app alembic upgrade head; then\n"
                "  echo 'Alembic migrations applied.'\n"
                "elif docker compose exec -T app python manage.py migrate --noinput; then\n"
                "  echo 'Django migrations applied.'\n"
                "else\n"
                "  echo 'No supported migration command succeeded; review manually.'\n"
                "fi"
            )

        nginx = "echo 'Nginx setup disabled.'"
        if cfg.use_nginx:
            nginx = f"""sudo cp deploy/nginx/{cfg.service_name}.conf /etc/nginx/sites-available/{cfg.service_name}
sudo ln -sfn /etc/nginx/sites-available/{cfg.service_name} /etc/nginx/sites-enabled/{cfg.service_name}
sudo nginx -t
sudo systemctl reload nginx"""

        content = f"""#!/usr/bin/env bash
# Generated by William/Jarvis CICDManager
# Safe-by-default VPS deploy script for {cfg.project_name}.
# This script is meant to be reviewed and run manually or by CI over SSH.

set -euo pipefail

APP_NAME={_quote(cfg.project_name)}
DEPLOY_PATH={_quote(cfg.deploy_path)}
BRANCH={_quote(cfg.branch)}

echo "Deploying $APP_NAME into $DEPLOY_PATH from branch $BRANCH"

if [ ! -d "$DEPLOY_PATH/.git" ]; then
  echo "ERROR: $DEPLOY_PATH is not a git repository. Clone the repository first."
  exit 1
fi

cd "$DEPLOY_PATH"

git fetch origin "$BRANCH"
git reset --hard "origin/$BRANCH"

mkdir -p logs media static

if [ -f "{cfg.env_file}.production" ]; then
  cp "{cfg.env_file}.production" "{cfg.env_file}"
fi

docker compose build --pull
docker compose up -d --remove-orphans

{migration}

docker compose ps
docker image prune -f

{nginx}

echo "Deployment completed."
"""
        artifact = GeneratedArtifact(
            name="deploy_vps.sh",
            relative_path="deploy/scripts/deploy_vps.sh",
            content=content,
            category="vps_deploy",
            sensitive=True,
            executable=True,
            description="Reviewable VPS deployment script. It is generated only; not executed.",
        )
        return self._safe_result("VPS deployment script generated.", {"artifact": artifact})

    def generate_env_example(self, config: Optional[Union[CICDConfig, Mapping[str, Any]]] = None) -> Dict[str, Any]:
        """Generate .env.example without real secrets."""
        cfg = self._coerce_config(config).normalized()
        env_lines = [
            "# Generated by William/Jarvis CICDManager",
            "# Copy to .env and fill real values in your secure environment.",
            "ENVIRONMENT=production",
            "DEBUG=false",
            f"PORT={cfg.exposed_port}",
            "SECRET_KEY=change-me-with-a-secure-random-value",
            "ALLOWED_HOSTS=example.com,www.example.com",
            "CORS_ORIGINS=https://example.com",
        ]
        if cfg.use_postgres:
            env_lines.extend([
                "POSTGRES_DB=william",
                "POSTGRES_USER=william",
                "POSTGRES_PASSWORD=change-me",
                "DATABASE_URL=postgresql://william:change-me@db:5432/william",
            ])
        else:
            env_lines.append("DATABASE_URL=sqlite:///./data/app.db")
        if cfg.use_redis:
            env_lines.extend([
                "REDIS_URL=redis://redis:6379/0",
                "CELERY_BROKER_URL=redis://redis:6379/1",
                "CELERY_RESULT_BACKEND=redis://redis:6379/2",
            ])
        for key, value in sorted(cfg.extra_environment.items()):
            clean_key = re.sub(r"[^A-Z0-9_]", "_", key.upper()).strip("_")
            if clean_key:
                env_lines.append(f"{clean_key}={value}")
        content = "\n".join(env_lines) + "\n"
        artifact = GeneratedArtifact(
            name=".env.example",
            relative_path=".env.example",
            content=content,
            category="environment",
            sensitive=False,
            description="Secret-free environment template.",
        )
        return self._safe_result(".env.example generated.", {"artifact": artifact})

    def validate_cicd_config(
        self,
        config: Optional[Union[CICDConfig, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Validate config and return warnings/errors without throwing."""
        raw = self._coerce_config(config)
        cfg = raw.normalized()
        warnings: List[str] = []
        errors: List[str] = []

        if raw.domain == "example.com":
            warnings.append("Domain is still example.com. Replace it before production deployment.")
        if raw.email == "admin@example.com":
            warnings.append("Email is still admin@example.com. Replace it for Certbot notices.")
        if cfg.exposed_port < 1024 or cfg.exposed_port > 65535:
            errors.append("exposed_port must be between 1024 and 65535 for this deployment template.")
        if cfg.framework not in {"fastapi", "flask", "django", "starlette", "generic"}:
            warnings.append(f"Unknown framework '{cfg.framework}'. Generic Gunicorn/Uvicorn commands may need review.")
        if cfg.use_celery and not cfg.use_redis:
            warnings.append("Celery is enabled but Redis is disabled. Add a broker or enable Redis.")

        return self._safe_result(
            message="CI/CD config validated.",
            data={"valid": not errors, "config": asdict(cfg), "warnings": warnings, "errors": errors},
        )

    def detect_project_stack(
        self,
        project_path: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """Inspect a project and infer framework/deployment requirements."""
        root = self._resolve_project_path(project_path)
        files = {p.name.lower(): p for p in root.iterdir()} if root.exists() and root.is_dir() else {}
        requirements = _read_text(root / "requirements.txt")
        pyproject = _read_text(root / "pyproject.toml")
        package_json = _read_text(root / "package.json")

        text = "\n".join([requirements, pyproject, package_json]).lower()

        framework = "generic"
        if "fastapi" in text or (root / "main.py").exists():
            framework = "fastapi"
        if "flask" in text:
            framework = "flask"
        if "django" in text or (root / "manage.py").exists():
            framework = "django"

        use_postgres = _contains_any(text, ["psycopg", "postgres", "asyncpg"])
        use_redis = _contains_any(text, ["redis", "celery", "rq"])
        use_celery = "celery" in text

        app_module = self._guess_app_module(root, framework)

        return self._safe_result(
            "Project stack detected.",
            data={
                "project_root": str(root),
                "framework": framework,
                "app_module": app_module,
                "use_postgres": use_postgres,
                "use_redis": use_redis,
                "use_celery": use_celery,
                "has_requirements": "requirements.txt" in files,
                "has_pyproject": "pyproject.toml" in files,
                "has_package_json": "package.json" in files,
                "has_dockerfile": (root / "Dockerfile").exists(),
                "has_compose": (root / "docker-compose.yml").exists() or (root / "compose.yml").exists(),
                "has_github_actions": (root / ".github" / "workflows").exists(),
            },
        )

    def detect_deployment_risks(
        self,
        *,
        project_root: Optional[Union[str, Path]] = None,
        config: Optional[Union[CICDConfig, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Detect deployment risks and missing production files."""
        root = self._resolve_project_path(project_root)
        cfg = self._coerce_config(config).normalized()
        risks: List[CICDRisk] = []

        if not root.exists():
            risks.append(CICDRisk(
                code="project_root_missing",
                severity="high",
                message=f"Project path does not exist: {root}",
                recommendation="Create or mount the project path before writing artifacts.",
                path=str(root),
            ))
            return self._safe_result("Deployment risks detected.", {"risks": risks})

        for filename in self.DEFAULT_REQUIRED_FILES:
            if not (root / filename).exists():
                risks.append(CICDRisk(
                    code="missing_required_file",
                    severity="medium",
                    message=f"Missing recommended production file: {filename}",
                    recommendation=f"Create {filename} before production deployment.",
                    path=str(root / filename),
                ))

        if (root / ".env").exists():
            risks.append(CICDRisk(
                code="env_file_present",
                severity="high",
                message=".env exists in project root. Make sure it is never committed.",
                recommendation="Keep .env in .gitignore and use .env.example for templates.",
                path=str(root / ".env"),
            ))

        gitignore = _read_text(root / ".gitignore")
        if gitignore and ".env" not in gitignore:
            risks.append(CICDRisk(
                code="env_not_ignored",
                severity="high",
                message=".gitignore does not appear to ignore .env files.",
                recommendation="Add .env and .env.* to .gitignore while allowing .env.example.",
                path=str(root / ".gitignore"),
            ))

        requirements = _read_text(root / cfg.requirements_file)
        if requirements and not _contains_any(requirements, ["gunicorn", "uvicorn", "hypercorn"]):
            risks.append(CICDRisk(
                code="missing_server_dependency",
                severity="medium",
                message="No production ASGI/WSGI server dependency detected.",
                recommendation="Add gunicorn and uvicorn for FastAPI/Starlette, or gunicorn for Flask/Django.",
                path=str(root / cfg.requirements_file),
            ))

        for candidate in list(root.glob("*.pem")) + list(root.glob("*.key")):
            risks.append(CICDRisk(
                code="private_key_in_project",
                severity="critical",
                message=f"Private key-like file found: {candidate.name}",
                recommendation="Remove private keys from the project and rotate exposed credentials.",
                path=str(candidate),
            ))

        for path in self._iter_small_text_files(root):
            content = _read_text(path)
            if any(pattern.lower() in content.lower() for pattern in self.SENSITIVE_PATTERNS):
                risks.append(CICDRisk(
                    code="possible_secret_in_file",
                    severity="high",
                    message=f"Possible secret pattern found in {path.name}.",
                    recommendation="Move secrets to environment variables or a secrets manager.",
                    path=str(path),
                ))

        if cfg.domain == "example.com":
            risks.append(CICDRisk(
                code="placeholder_domain",
                severity="low",
                message="Deployment domain is still example.com.",
                recommendation="Set config.domain to your real production domain.",
            ))

        return self._safe_result("Deployment risks detected.", {"risks": risks})

    def write_artifacts(
        self,
        *,
        artifacts: Sequence[Union[GeneratedArtifact, Mapping[str, Any]]],
        project_path: Optional[Union[str, Path]] = None,
        overwrite: bool = False,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        request_id: Optional[str] = None,
        permissions: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """
        Write generated artifacts to project_path.

        This method does not execute scripts. Executable artifacts are only
        written and chmodded to 750 after security approval by caller.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            request_id=request_id,
            permissions=permissions or (),
        )
        if not context_result["success"]:
            return context_result
        ctx: TaskContext = context_result["data"]["context"]

        root = self._resolve_project_path(project_path)
        root.mkdir(parents=True, exist_ok=True)

        written: List[str] = []
        skipped: List[str] = []
        errors: List[Dict[str, str]] = []

        for item in artifacts:
            artifact = self._coerce_artifact(item)
            target = (root / artifact.relative_path).resolve()
            if not self._is_within_directory(target, root):
                errors.append({"path": artifact.relative_path, "error": "Path traversal blocked."})
                continue
            if target.exists() and not overwrite:
                skipped.append(str(target))
                continue
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(artifact.content, encoding="utf-8")
                if artifact.executable:
                    target.chmod(0o750)
                written.append(str(target))
            except Exception as exc:
                self.logger.exception("Failed to write artifact %s", artifact.relative_path)
                errors.append({"path": artifact.relative_path, "error": str(exc)})

        self._emit_agent_event("cicd.artifacts.written", {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "project_root": str(root),
            "written": len(written),
            "skipped": len(skipped),
            "errors": len(errors),
        })
        self._log_audit_event("cicd_write_artifacts", ctx, {
            "project_root": str(root),
            "written": written,
            "skipped": skipped,
            "errors": errors,
        })

        return self._safe_result(
            message="CI/CD artifacts write operation completed.",
            data={
                "project_root": str(root),
                "written": written,
                "skipped": skipped,
                "errors": errors,
                "success_count": len(written),
                "skipped_count": len(skipped),
                "error_count": len(errors),
            },
            metadata={"partial_success": bool(errors and written)},
        )

    def build_config_from_project(
        self,
        *,
        project_path: Optional[Union[str, Path]] = None,
        overrides: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Infer CICDConfig from project structure and optional overrides."""
        stack_result = self.detect_project_stack(project_path)
        stack = stack_result["data"]
        root = Path(stack["project_root"])
        data: Dict[str, Any] = {
            "project_name": root.name,
            "framework": stack["framework"],
            "app_module": stack["app_module"],
            "use_postgres": stack["use_postgres"],
            "use_redis": stack["use_redis"],
            "use_celery": stack["use_celery"],
        }
        if overrides:
            data.update(dict(overrides))
        cfg = CICDConfig(**{k: v for k, v in data.items() if k in CICDConfig.__dataclass_fields__}).normalized()
        return self._safe_result("CI/CD config built from project.", {"config": asdict(cfg), "stack": stack})

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------
    def _validate_task_context(
        self,
        *,
        user_id: Union[str, int, None],
        workspace_id: Union[str, int, None],
        request_id: Optional[str] = None,
        permissions: Sequence[str] = (),
        role: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Validate SaaS isolation context before user/workspace-specific work."""
        if user_id is None or str(user_id).strip() == "":
            return self._error_result("Missing user_id. SaaS isolation requires user_id.", "missing_user_id")
        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result("Missing workspace_id. SaaS isolation requires workspace_id.", "missing_workspace_id")

        ctx = TaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            request_id=request_id,
            role=role,
            permissions=tuple(permissions or ()),
            metadata=metadata or {},
        )
        return self._safe_result("Task context validated.", {"context": ctx})

    def _requires_security_check(self, action: str, **kwargs: Any) -> bool:
        """
        Decide whether an action needs Security Agent approval.

        Generating text is safe. Writing deployment files, producing executable
        scripts, or any future remote execution requires approval.
        """
        sensitive_actions = {
            "write_cicd_artifacts",
            "execute_deploy",
            "remote_ssh",
            "modify_nginx",
            "install_ssl",
            "systemd_update",
        }
        if action in sensitive_actions:
            return True

        artifacts = kwargs.get("artifacts") or []
        for artifact in artifacts:
            try:
                if self._coerce_artifact(artifact).sensitive:
                    return True
            except Exception:
                continue
        return False

    def _request_security_approval(
        self,
        *,
        action: str,
        context: TaskContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Ask Security Agent/client for approval.

        If no security client exists yet, approval is granted for file generation
        and local writes only, never for command execution. This keeps the file
        usable during early development while preserving safe behavior.
        """
        if self.security_client and hasattr(self.security_client, "approve"):
            try:
                response = self.security_client.approve(
                    action=action,
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    payload=dict(payload),
                )
                if isinstance(response, Mapping):
                    return dict(response)
                return {"approved": bool(response), "source": "security_client"}
            except Exception as exc:
                self.logger.exception("Security approval failed.")
                return {"approved": False, "source": "security_client", "error": str(exc)}

        if action in {"execute_deploy", "remote_ssh", "modify_nginx", "install_ssl", "systemd_update"}:
            return {
                "approved": False,
                "source": "fallback_security",
                "reason": "No Security Agent connected for execution-level action.",
            }

        return {
            "approved": True,
            "source": "fallback_security",
            "reason": "Local artifact generation/write approved; no commands executed.",
        }

    def _prepare_verification_payload(
        self,
        *,
        context: TaskContext,
        action: str,
        artifacts: Sequence[GeneratedArtifact],
        risks: Sequence[Union[CICDRisk, Mapping[str, Any]]],
        project_root: Path,
        config: CICDConfig,
        write_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create Verification Agent-compatible payload."""
        payload = {
            "type": "cicd_verification",
            "agent": self.AGENT_NAME,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "project_root": str(project_root),
            "generated_files": [a.relative_path for a in artifacts],
            "sensitive_files": [a.relative_path for a in artifacts if a.sensitive],
            "executable_files": [a.relative_path for a in artifacts if a.executable],
            "risk_count": len(risks),
            "risks": [asdict(r) if isinstance(r, CICDRisk) else dict(r) for r in risks],
            "config_summary": {
                "project_name": config.project_name,
                "framework": config.framework,
                "domain": config.domain,
                "use_postgres": config.use_postgres,
                "use_redis": config.use_redis,
                "use_celery": config.use_celery,
                "use_ssl": config.use_ssl,
            },
            "recommended_checks": [
                "python -m compileall agents/code_agent/ci_cd_manager.py",
                "docker build -t local-ci-check .",
                "docker compose config",
                "nginx -t after installing generated Nginx config",
                "Run deployment scripts only after Security Agent approval.",
            ],
            "write_result": write_result,
            "created_at": _utc_now(),
        }
        if self.verification_callback:
            try:
                self.verification_callback(payload)
            except Exception:
                self.logger.exception("Verification callback failed.")
        return payload

    def _prepare_memory_payload(
        self,
        *,
        context: TaskContext,
        action: str,
        config: CICDConfig,
        artifacts: Sequence[GeneratedArtifact],
        risks: Sequence[Union[CICDRisk, Mapping[str, Any]]],
    ) -> Dict[str, Any]:
        """Create Memory Agent-compatible payload without storing secrets."""
        payload = {
            "type": "code_agent_cicd_context",
            "agent": self.AGENT_NAME,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "project_name": config.project_name,
            "framework": config.framework,
            "domain": config.domain,
            "artifacts": [
                {"path": a.relative_path, "category": a.category, "sensitive": a.sensitive}
                for a in artifacts
            ],
            "risk_codes": [
                (r.code if isinstance(r, CICDRisk) else str(r.get("code", "unknown")))
                for r in risks
            ],
            "created_at": _utc_now(),
        }
        if self.memory_callback:
            try:
                self.memory_callback(payload)
            except Exception:
                self.logger.exception("Memory callback failed.")
        return payload

    def _emit_agent_event(self, event_name: str, payload: Mapping[str, Any]) -> None:
        """Emit Dashboard/API compatible event."""
        event = {
            "event": event_name,
            "agent": self.AGENT_NAME,
            "agent_type": self.AGENT_TYPE,
            "payload": dict(payload),
            "created_at": _utc_now(),
        }
        if self.event_callback:
            try:
                self.event_callback(event)
                return
            except Exception:
                self.logger.exception("Event callback failed.")
        self.logger.info("Agent event: %s", event)

    def _log_audit_event(self, action: str, context: TaskContext, payload: Mapping[str, Any]) -> None:
        """Log SaaS audit event without mixing user/workspace data."""
        event = {
            "action": action,
            "agent": self.AGENT_NAME,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "payload": dict(payload),
            "created_at": _utc_now(),
        }
        if self.audit_callback:
            try:
                self.audit_callback(event)
                return
            except Exception:
                self.logger.exception("Audit callback failed.")
        self.logger.info("Audit event: %s", event)

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis success result."""
        return {
            "success": True,
            "message": message,
            "data": dict(data or {}),
            "error": None,
            "metadata": {
                "agent": self.AGENT_NAME,
                "agent_type": self.AGENT_TYPE,
                "version": self.VERSION,
                "created_at": _utc_now(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Union[str, Exception],
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis error result."""
        return {
            "success": False,
            "message": message,
            "data": dict(data or {}),
            "error": str(error),
            "metadata": {
                "agent": self.AGENT_NAME,
                "agent_type": self.AGENT_TYPE,
                "version": self.VERSION,
                "created_at": _utc_now(),
                **dict(metadata or {}),
            },
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _coerce_config(self, config: Optional[Union[CICDConfig, Mapping[str, Any]]]) -> CICDConfig:
        if isinstance(config, CICDConfig):
            return config
        if isinstance(config, Mapping):
            allowed = CICDConfig.__dataclass_fields__.keys()
            return CICDConfig(**{k: v for k, v in config.items() if k in allowed})
        return CICDConfig()

    def _coerce_artifact(self, artifact: Union[GeneratedArtifact, Mapping[str, Any]]) -> GeneratedArtifact:
        if isinstance(artifact, GeneratedArtifact):
            return artifact
        data = dict(artifact)
        return GeneratedArtifact(
            name=str(data.get("name", "artifact")),
            relative_path=str(data.get("relative_path", data.get("path", "artifact.txt"))),
            content=str(data.get("content", "")),
            category=str(data.get("category", "general")),
            sensitive=bool(data.get("sensitive", False)),
            executable=bool(data.get("executable", False)),
            description=str(data.get("description", "")),
        )

    def _resolve_project_path(self, project_path: Optional[Union[str, Path]]) -> Path:
        if project_path is None:
            return self.base_dir
        path = Path(project_path)
        if not path.is_absolute():
            path = self.base_dir / path
        return path.resolve()

    def _is_within_directory(self, target: Path, root: Path) -> bool:
        try:
            target.relative_to(root.resolve())
            return True
        except ValueError:
            return False

    def _container_start_command(self, cfg: CICDConfig) -> str:
        if cfg.framework in {"fastapi", "starlette"}:
            return f'["gunicorn", "{cfg.app_module}", "--bind", "0.0.0.0:{cfg.exposed_port}", "--workers", "{cfg.workers}", "--worker-class", "uvicorn.workers.UvicornWorker", "--timeout", "{cfg.timeout}"]'
        if cfg.framework == "django":
            return f'["gunicorn", "{cfg.app_module}", "--bind", "0.0.0.0:{cfg.exposed_port}", "--workers", "{cfg.workers}", "--timeout", "{cfg.timeout}"]'
        if cfg.framework == "flask":
            return f'["gunicorn", "{cfg.app_module}", "--bind", "0.0.0.0:{cfg.exposed_port}", "--workers", "{cfg.workers}", "--timeout", "{cfg.timeout}"]'
        return f'["python", "-m", "gunicorn", "{cfg.app_module}", "--bind", "0.0.0.0:{cfg.exposed_port}"]'

    def _guess_app_module(self, root: Path, framework: str) -> str:
        if framework == "django":
            project_dirs = [
                p for p in root.iterdir()
                if p.is_dir() and (p / "settings.py").exists() and (p / "wsgi.py").exists()
            ] if root.exists() else []
            if project_dirs:
                return f"{project_dirs[0].name}.wsgi:application"
            return "config.wsgi:application"

        candidates = [
            ("main.py", "app"),
            ("app.py", "app"),
            ("server.py", "app"),
            ("run.py", "app"),
        ]
        for filename, obj in candidates:
            path = root / filename
            if path.exists():
                text = _read_text(path)
                if re.search(rf"\b{obj}\s*=", text):
                    return f"{Path(filename).stem}:{obj}"
        if (root / "app" / "main.py").exists():
            return "app.main:app"
        return "app:app"

    def _iter_small_text_files(self, root: Path, max_size: int = 250_000) -> Iterable[Path]:
        if not root.exists() or not root.is_dir():
            return []
        ignored_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache"}
        text_exts = {".py", ".env", ".txt", ".md", ".toml", ".yml", ".yaml", ".json", ".ini", ".cfg"}
        results: List[Path] = []
        for path in root.rglob("*"):
            if any(part in ignored_dirs for part in path.parts):
                continue
            if not path.is_file():
                continue
            if path.suffix.lower() not in text_exts and path.name not in {".env", ".gitignore"}:
                continue
            try:
                if path.stat().st_size <= max_size:
                    results.append(path)
            except OSError:
                continue
        return results


__all__ = [
    "CICDManager",
    "CICDConfig",
    "GeneratedArtifact",
    "CICDRisk",
    "TaskContext",
]


if __name__ == "__main__":  # Safe smoke test; generates text only, executes nothing.
    logging.basicConfig(level=logging.INFO)
    manager = CICDManager()
    result = manager.generate_all_artifacts(
        user_id="local-user",
        workspace_id="local-workspace",
        config={
            "project_name": "william-jarvis",
            "framework": "fastapi",
            "domain": "example.com",
            "use_postgres": True,
            "use_redis": True,
            "use_celery": False,
        },
        write_files=False,
    )
    print({
        "success": result["success"],
        "message": result["message"],
        "artifact_count": len(result["data"].get("artifacts", [])),
    })
