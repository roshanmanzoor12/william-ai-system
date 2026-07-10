#!/usr/bin/env python3
"""
William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
File: deploy/monitoring/healthchecks.py
Agent/Module: Deployment Prompt Bible
Component: Healthchecks
Purpose: Service health checks for deployment monitoring.

This module is intentionally standalone and import-safe:
- It does not require future William/Jarvis modules to exist.
- It reads configuration from environment variables.
- It avoids hardcoded secrets.
- It attaches user_id and workspace_id to every check result.
- It can emit audit, memory, and verification payloads to future agents.
- It can run as a CLI utility or be imported by deployment scripts/API workers.

Supported checks:
- HTTP/HTTPS endpoints
- PostgreSQL TCP/auth check
- Redis TCP/auth check
- Docker container status
- Disk space
- Required environment variables
- Optional custom shell health command
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import hashlib
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


# ==============================================================================
# Utility Functions
# ==============================================================================


def utc_now() -> str:
    """Return current UTC time in ISO-8601 format."""
    return _dt.datetime.now(tz=_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_bool(value: str | bool | None, default: bool = False) -> bool:
    """Parse common truthy/falsy environment values safely."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default

    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    return default


def safe_int(value: str | int | None, default: int) -> int:
    """Parse int safely and return default on bad input."""
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def split_csv(value: str | None) -> List[str]:
    """Split comma-separated values, removing blanks."""
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def redact_secret(value: str | None) -> str:
    """Redact secret-like values for structured output."""
    if not value:
        return ""
    if len(value) <= 4:
        return "***"
    return f"{value[:2]}***{value[-2:]}"


def sha256_text(value: str) -> str:
    """Hash text for stable non-sensitive fingerprints."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_identifier(value: str, fallback: str) -> str:
    """
    Keep identifiers safe for logs and artifact paths.

    Allows letters, numbers, dot, dash, underscore, colon, slash, and @.
    Unsafe characters are replaced rather than raising, because health checks
    should return safe structured errors instead of crashing during import/use.
    """
    value = value or fallback
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:@/-")
    cleaned = "".join(char if char in allowed else "_" for char in value)
    return cleaned or fallback


def json_dumps(payload: Mapping[str, Any]) -> str:
    """Compact JSON dump for logs."""
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


# ==============================================================================
# Data Models
# ==============================================================================


@dataclasses.dataclass(frozen=True)
class HealthcheckConfig:
    """Configuration for Healthchecks."""

    component: str
    version: str
    run_id: str
    user_id: str
    workspace_id: str
    requested_by_role: str
    request_source: str

    environment: str
    timeout_seconds: int
    retries: int
    retry_sleep_seconds: int

    api_health_url: str
    dashboard_health_url: str
    worker_health_url: str
    extra_health_urls: Tuple[str, ...]

    postgres_host: str
    postgres_port: int
    postgres_database: str
    postgres_user: str
    postgres_password: str
    postgres_enabled: bool

    redis_host: str
    redis_port: int
    redis_password: str
    redis_enabled: bool

    docker_enabled: bool
    docker_containers: Tuple[str, ...]

    disk_check_enabled: bool
    disk_path: str
    disk_min_free_percent: int

    required_env_vars: Tuple[str, ...]

    custom_command_enabled: bool
    custom_command: str

    audit_log_hook_url: str
    memory_agent_hook_url: str
    verification_agent_hook_url: str
    master_agent_hook_url: str

    log_jsonl_path: str
    emit_hooks: bool

    allowed_roles: Tuple[str, ...)
    require_active_subscription: bool
    subscription_status: str
    allowed_plans: Tuple[str, ...)
    current_plan: str

    @classmethod
    def from_env(cls) -> "HealthcheckConfig":
        """Build config from environment variables."""
        user_id = normalize_identifier(os.getenv("USER_ID", "system"), "system")
        workspace_id = normalize_identifier(os.getenv("WORKSPACE_ID", "system"), "system")
        requested_by_role = normalize_identifier(os.getenv("REQUESTED_BY_ROLE", "system"), "system")

        run_seed = f"{utc_now()}-{os.getpid()}-{workspace_id}-{user_id}"
        run_id = os.getenv("HEALTHCHECK_RUN_ID") or f"{utc_now().replace(':', '').replace('-', '')}-{os.getpid()}"

        default_log_path = f"./deploy/logs/workspace_{workspace_id}/healthchecks_{run_id}.jsonl"

        return cls(
            component="Healthchecks",
            version="1.0.0",
            run_id=normalize_identifier(run_id, sha256_text(run_seed)[:16]),
            user_id=user_id,
            workspace_id=workspace_id,
            requested_by_role=requested_by_role,
            request_source=normalize_identifier(os.getenv("REQUEST_SOURCE", "deployment_monitoring"), "deployment_monitoring"),
            environment=os.getenv("DEPLOY_ENV", os.getenv("APP_ENV", "production")),
            timeout_seconds=max(1, safe_int(os.getenv("HEALTHCHECK_TIMEOUT_SECONDS"), 5)),
            retries=max(0, safe_int(os.getenv("HEALTHCHECK_RETRIES"), 1)),
            retry_sleep_seconds=max(0, safe_int(os.getenv("HEALTHCHECK_RETRY_SLEEP_SECONDS"), 2)),
            api_health_url=os.getenv("API_HEALTH_URL", "http://localhost:8000/health"),
            dashboard_health_url=os.getenv("DASHBOARD_HEALTH_URL", "http://localhost:3000"),
            worker_health_url=os.getenv("WORKER_HEALTH_URL", ""),
            extra_health_urls=tuple(split_csv(os.getenv("EXTRA_HEALTH_URLS"))),
            postgres_host=os.getenv("PGHOST", "localhost"),
            postgres_port=safe_int(os.getenv("PGPORT"), 5432),
            postgres_database=os.getenv("PGDATABASE", "william_jarvis"),
            postgres_user=os.getenv("PGUSER", "postgres"),
            postgres_password=os.getenv("PGPASSWORD", ""),
            postgres_enabled=safe_bool(os.getenv("POSTGRES_HEALTHCHECK_ENABLED"), True),
            redis_host=os.getenv("REDIS_HOST", "localhost"),
            redis_port=safe_int(os.getenv("REDIS_PORT"), 6379),
            redis_password=os.getenv("REDIS_PASSWORD", ""),
            redis_enabled=safe_bool(os.getenv("REDIS_HEALTHCHECK_ENABLED"), True),
            docker_enabled=safe_bool(os.getenv("DOCKER_HEALTHCHECK_ENABLED"), True),
            docker_containers=tuple(split_csv(os.getenv("DOCKER_CONTAINERS", "postgres,redis"))),
            disk_check_enabled=safe_bool(os.getenv("DISK_HEALTHCHECK_ENABLED"), True),
            disk_path=os.getenv("DISK_HEALTHCHECK_PATH", "."),
            disk_min_free_percent=max(1, min(99, safe_int(os.getenv("DISK_MIN_FREE_PERCENT"), 10))),
            required_env_vars=tuple(split_csv(os.getenv("REQUIRED_ENV_VARS", "APP_ENV"))),
            custom_command_enabled=safe_bool(os.getenv("CUSTOM_HEALTH_COMMAND_ENABLED"), False),
            custom_command=os.getenv("CUSTOM_HEALTH_COMMAND", ""),
            audit_log_hook_url=os.getenv("AUDIT_LOG_HOOK_URL", ""),
            memory_agent_hook_url=os.getenv("MEMORY_AGENT_HOOK_URL", ""),
            verification_agent_hook_url=os.getenv("VERIFICATION_AGENT_HOOK_URL", ""),
            master_agent_hook_url=os.getenv("MASTER_AGENT_HOOK_URL", ""),
            log_jsonl_path=os.getenv("HEALTHCHECK_LOG_JSONL_PATH", default_log_path),
            emit_hooks=safe_bool(os.getenv("HEALTHCHECK_EMIT_HOOKS"), False),
            allowed_roles=tuple(split_csv(os.getenv("ALLOWED_HEALTHCHECK_ROLES", "owner,admin,system,security_agent,devops,viewer"))),
            require_active_subscription=safe_bool(os.getenv("REQUIRE_ACTIVE_SUBSCRIPTION"), False),
            subscription_status=os.getenv("SUBSCRIPTION_STATUS", "active"),
            allowed_plans=tuple(split_csv(os.getenv("ALLOWED_HEALTHCHECK_PLANS", "enterprise,pro,system"))),
            current_plan=os.getenv("CURRENT_PLAN", "system"),
        )


@dataclasses.dataclass
class CheckResult:
    """Single health check result."""

    name: str
    status: str
    message: str
    latency_ms: int
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "latency_ms": self.latency_ms,
            "details": self.details,
        }


# ==============================================================================
# Main Healthchecks Component
# ==============================================================================


class Healthchecks:
    """
    Service health check runner for deployment monitoring.

    Status values:
    - healthy
    - degraded
    - unhealthy
    - skipped

    The class is designed to be imported by future Master Agent, Security Agent,
    Verification Agent, deployment scripts, or dashboard API modules.
    """

    def __init__(self, config: Optional[HealthcheckConfig] = None) -> None:
        self.config = config or HealthcheckConfig.from_env()
        self.started_at = utc_now()

    # --------------------------------------------------------------------------
    # Logging / Payloads
    # --------------------------------------------------------------------------

    def _base_payload(self) -> Dict[str, Any]:
        return {
            "component": self.config.component,
            "script_version": self.config.version,
            "run_id": self.config.run_id,
            "user_id": self.config.user_id,
            "workspace_id": self.config.workspace_id,
            "requested_by_role": self.config.requested_by_role,
            "request_source": self.config.request_source,
            "environment": self.config.environment,
            "timestamp": utc_now(),
        }

    def log_event(self, level: str, event: str, message: str, **extra: Any) -> None:
        payload: Dict[str, Any] = {
            **self._base_payload(),
            "level": level,
            "event": event,
            "message": message,
            **extra,
        }

        line = json_dumps(payload)
        print(line)

        try:
            path = Path(self.config.log_jsonl_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as file:
                file.write(line + "\n")
        except OSError:
            # Logging to file should never break health check execution.
            print(json_dumps({**self._base_payload(), "level": "warning", "event": "file_log_failed", "message": "Could not write healthcheck log file."}))

    def _post_json_hook(self, url: str, payload: Mapping[str, Any], hook_name: str) -> None:
        if not self.config.emit_hooks:
            self.log_event("info", f"{hook_name}_hook_skipped", "Hook emission disabled.")
            return

        if not url:
            self.log_event("info", f"{hook_name}_hook_skipped", "Hook URL not configured.")
            return

        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            url=url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                self.log_event("info", f"{hook_name}_hook_sent", f"{hook_name} hook accepted.", http_status=response.status)
        except Exception as exc:
            self.log_event("warning", f"{hook_name}_hook_failed", f"{hook_name} hook failed: {exc.__class__.__name__}")

    def audit_payload(self, status: str, message: str, results: Sequence[CheckResult]) -> Dict[str, Any]:
        return {
            **self._base_payload(),
            "event_type": "service_healthchecks",
            "status": status,
            "message": message,
            "results_count": len(results),
            "results": [result.to_dict() for result in results],
        }

    def memory_payload(self, status: str, message: str, results: Sequence[CheckResult]) -> Dict[str, Any]:
        return {
            **self._base_payload(),
            "memory_type": "deployment_event",
            "importance": "high" if status != "healthy" else "medium",
            "event": f"healthchecks_{status}",
            "summary": f"Healthchecks finished with status {status} for workspace {self.config.workspace_id}.",
            "metadata": {
                "message": message,
                "total_checks": len(results),
                "healthy": sum(1 for result in results if result.status == "healthy"),
                "degraded": sum(1 for result in results if result.status == "degraded"),
                "unhealthy": sum(1 for result in results if result.status == "unhealthy"),
                "skipped": sum(1 for result in results if result.status == "skipped"),
            },
        }

    def verification_payload(self, status: str, message: str, results: Sequence[CheckResult]) -> Dict[str, Any]:
        return {
            **self._base_payload(),
            "verification_type": "deployment_service_healthchecks",
            "status": status,
            "message": message,
            "results": [result.to_dict() for result in results],
            "started_at": self.started_at,
            "finished_at": utc_now(),
        }

    # --------------------------------------------------------------------------
    # Access Controls
    # --------------------------------------------------------------------------

    def check_access_controls(self) -> CheckResult:
        started = time.perf_counter()
        errors: List[str] = []

        if not self.config.user_id:
            errors.append("USER_ID is required.")
        if not self.config.workspace_id:
            errors.append("WORKSPACE_ID is required.")
        if not self.config.requested_by_role:
            errors.append("REQUESTED_BY_ROLE is required.")

        if self.config.requested_by_role not in self.config.allowed_roles:
            errors.append(f"Role '{self.config.requested_by_role}' is not allowed to run health checks.")

        if self.config.require_active_subscription:
            if self.config.subscription_status != "active":
                errors.append(f"Subscription must be active. Current status: {self.config.subscription_status}.")
            if self.config.current_plan not in self.config.allowed_plans:
                errors.append(f"Plan '{self.config.current_plan}' is not allowed to run health checks.")

        latency = int((time.perf_counter() - started) * 1000)

        if errors:
            return CheckResult(
                name="access_controls",
                status="unhealthy",
                message="Access control validation failed.",
                latency_ms=latency,
                details={"errors": errors},
            )

        return CheckResult(
            name="access_controls",
            status="healthy",
            message="Access control validation passed.",
            latency_ms=latency,
            details={
                "user_id": self.config.user_id,
                "workspace_id": self.config.workspace_id,
                "requested_by_role": self.config.requested_by_role,
                "subscription_checked": self.config.require_active_subscription,
            },
        )

    # --------------------------------------------------------------------------
    # HTTP Checks
    # --------------------------------------------------------------------------

    def check_http_endpoint(self, name: str, url: str) -> CheckResult:
        started = time.perf_counter()

        if not url:
            return CheckResult(
                name=name,
                status="skipped",
                message="HTTP endpoint not configured.",
                latency_ms=0,
                details={},
            )

        last_error = ""
        last_status: Optional[int] = None

        for attempt in range(self.config.retries + 1):
            try:
                request = urllib.request.Request(url=url, method="GET", headers={"User-Agent": "William-Jarvis-Healthchecks/1.0"})
                context = ssl.create_default_context()

                if url.startswith("https://"):
                    response_obj = urllib.request.urlopen(request, timeout=self.config.timeout_seconds, context=context)
                else:
                    response_obj = urllib.request.urlopen(request, timeout=self.config.timeout_seconds)

                with response_obj as response:
                    last_status = response.status
                    body = response.read(512).decode("utf-8", errors="replace")

                latency = int((time.perf_counter() - started) * 1000)

                if 200 <= int(last_status) <= 399:
                    return CheckResult(
                        name=name,
                        status="healthy",
                        message=f"HTTP endpoint returned {last_status}.",
                        latency_ms=latency,
                        details={"url": url, "http_status": last_status, "attempt": attempt + 1, "body_preview": body[:160]},
                    )

                last_error = f"Unexpected HTTP status {last_status}."
            except urllib.error.HTTPError as exc:
                last_status = exc.code
                last_error = f"HTTP error {exc.code}."
            except urllib.error.URLError as exc:
                last_error = f"URL error: {exc.reason}"
            except Exception as exc:
                last_error = f"{exc.__class__.__name__}: {exc}"

            if attempt < self.config.retries:
                time.sleep(self.config.retry_sleep_seconds)

        latency = int((time.perf_counter() - started) * 1000)
        return CheckResult(
            name=name,
            status="unhealthy",
            message=last_error or "HTTP endpoint failed.",
            latency_ms=latency,
            details={"url": url, "http_status": last_status, "attempts": self.config.retries + 1},
        )

    # --------------------------------------------------------------------------
    # TCP / PostgreSQL / Redis Checks
    # --------------------------------------------------------------------------

    def _tcp_connect(self, host: str, port: int) -> Tuple[bool, str]:
        try:
            with socket.create_connection((host, port), timeout=self.config.timeout_seconds):
                return True, "TCP connection succeeded."
        except Exception as exc:
            return False, f"{exc.__class__.__name__}: {exc}"

    def check_postgres(self) -> CheckResult:
        started = time.perf_counter()

        if not self.config.postgres_enabled:
            return CheckResult("postgres", "skipped", "PostgreSQL check disabled.", 0, {})

        ok, message = self._tcp_connect(self.config.postgres_host, self.config.postgres_port)
        latency = int((time.perf_counter() - started) * 1000)

        if not ok:
            return CheckResult(
                name="postgres",
                status="unhealthy",
                message=message,
                latency_ms=latency,
                details={
                    "host": self.config.postgres_host,
                    "port": self.config.postgres_port,
                    "database": self.config.postgres_database,
                    "user": self.config.postgres_user,
                    "password": redact_secret(self.config.postgres_password),
                    "auth_query_executed": False,
                },
            )

        # Auth/query check using psql if available. This avoids requiring psycopg.
        psql_path = shutil.which("psql")
        if not psql_path:
            return CheckResult(
                name="postgres",
                status="degraded",
                message="TCP connection succeeded, but psql is not installed for query validation.",
                latency_ms=latency,
                details={
                    "host": self.config.postgres_host,
                    "port": self.config.postgres_port,
                    "database": self.config.postgres_database,
                    "user": self.config.postgres_user,
                    "auth_query_executed": False,
                },
            )

        command = [
            psql_path,
            "--host",
            self.config.postgres_host,
            "--port",
            str(self.config.postgres_port),
            "--username",
            self.config.postgres_user,
            "--dbname",
            self.config.postgres_database,
            "--set",
            "ON_ERROR_STOP=on",
            "--tuples-only",
            "--command",
            "SELECT 1;",
        ]

        env = os.environ.copy()
        if self.config.postgres_password:
            env["PGPASSWORD"] = self.config.postgres_password

        try:
            completed = subprocess.run(
                command,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.config.timeout_seconds,
                check=False,
            )
            latency = int((time.perf_counter() - started) * 1000)

            if completed.returncode == 0:
                return CheckResult(
                    name="postgres",
                    status="healthy",
                    message="PostgreSQL TCP and query check passed.",
                    latency_ms=latency,
                    details={
                        "host": self.config.postgres_host,
                        "port": self.config.postgres_port,
                        "database": self.config.postgres_database,
                        "user": self.config.postgres_user,
                        "auth_query_executed": True,
                    },
                )

            return CheckResult(
                name="postgres",
                status="unhealthy",
                message="PostgreSQL query check failed.",
                latency_ms=latency,
                details={
                    "host": self.config.postgres_host,
                    "port": self.config.postgres_port,
                    "database": self.config.postgres_database,
                    "user": self.config.postgres_user,
                    "stderr": completed.stderr[-500:],
                    "auth_query_executed": True,
                },
            )
        except subprocess.TimeoutExpired:
            latency = int((time.perf_counter() - started) * 1000)
            return CheckResult(
                name="postgres",
                status="unhealthy",
                message="PostgreSQL query check timed out.",
                latency_ms=latency,
                details={"host": self.config.postgres_host, "port": self.config.postgres_port, "auth_query_executed": True},
            )

    def check_redis(self) -> CheckResult:
        started = time.perf_counter()

        if not self.config.redis_enabled:
            return CheckResult("redis", "skipped", "Redis check disabled.", 0, {})

        ok, message = self._tcp_connect(self.config.redis_host, self.config.redis_port)
        latency = int((time.perf_counter() - started) * 1000)

        if not ok:
            return CheckResult(
                name="redis",
                status="unhealthy",
                message=message,
                latency_ms=latency,
                details={
                    "host": self.config.redis_host,
                    "port": self.config.redis_port,
                    "password": redact_secret(self.config.redis_password),
                    "ping_executed": False,
                },
            )

        redis_cli_path = shutil.which("redis-cli")
        if not redis_cli_path:
            return CheckResult(
                name="redis",
                status="degraded",
                message="TCP connection succeeded, but redis-cli is not installed for PING validation.",
                latency_ms=latency,
                details={"host": self.config.redis_host, "port": self.config.redis_port, "ping_executed": False},
            )

        command = [redis_cli_path, "-h", self.config.redis_host, "-p", str(self.config.redis_port)]
        if self.config.redis_password:
            command += ["-a", self.config.redis_password]
        command.append("PING")

        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.config.timeout_seconds,
                check=False,
            )
            latency = int((time.perf_counter() - started) * 1000)

            if completed.returncode == 0 and "PONG" in completed.stdout.upper():
                return CheckResult(
                    name="redis",
                    status="healthy",
                    message="Redis TCP and PING check passed.",
                    latency_ms=latency,
                    details={"host": self.config.redis_host, "port": self.config.redis_port, "ping_executed": True},
                )

            return CheckResult(
                name="redis",
                status="unhealthy",
                message="Redis PING check failed.",
                latency_ms=latency,
                details={
                    "host": self.config.redis_host,
                    "port": self.config.redis_port,
                    "stdout": completed.stdout[-200:],
                    "stderr": completed.stderr[-500:],
                    "ping_executed": True,
                },
            )
        except subprocess.TimeoutExpired:
            latency = int((time.perf_counter() - started) * 1000)
            return CheckResult(
                name="redis",
                status="unhealthy",
                message="Redis PING check timed out.",
                latency_ms=latency,
                details={"host": self.config.redis_host, "port": self.config.redis_port, "ping_executed": True},
            )

    # --------------------------------------------------------------------------
    # Docker Checks
    # --------------------------------------------------------------------------

    def check_docker_containers(self) -> CheckResult:
        started = time.perf_counter()

        if not self.config.docker_enabled:
            return CheckResult("docker_containers", "skipped", "Docker container check disabled.", 0, {})

        if not self.config.docker_containers:
            return CheckResult("docker_containers", "skipped", "No Docker containers configured.", 0, {})

        docker_path = shutil.which("docker")
        if not docker_path:
            return CheckResult(
                name="docker_containers",
                status="degraded",
                message="Docker command not found.",
                latency_ms=int((time.perf_counter() - started) * 1000),
                details={"containers": list(self.config.docker_containers)},
            )

        command = [docker_path, "ps", "--format", "{{.Names}}|{{.Status}}"]
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=self.config.timeout_seconds,
            check=False,
        )

        latency = int((time.perf_counter() - started) * 1000)

        if completed.returncode != 0:
            return CheckResult(
                name="docker_containers",
                status="unhealthy",
                message="docker ps failed.",
                latency_ms=latency,
                details={"stderr": completed.stderr[-500:]},
            )

        running: Dict[str, str] = {}
        for line in completed.stdout.splitlines():
            if "|" in line:
                name, status = line.split("|", 1)
                running[name.strip()] = status.strip()

        missing = [name for name in self.config.docker_containers if name not in running]
        unhealthy = [
            {"name": name, "status": running[name]}
            for name in self.config.docker_containers
            if name in running and "Up" not in running[name]
        ]

        if missing or unhealthy:
            return CheckResult(
                name="docker_containers",
                status="unhealthy",
                message="One or more Docker containers are missing or unhealthy.",
                latency_ms=latency,
                details={
                    "expected": list(self.config.docker_containers),
                    "missing": missing,
                    "unhealthy": unhealthy,
                    "found": running,
                },
            )

        return CheckResult(
            name="docker_containers",
            status="healthy",
            message="Expected Docker containers are running.",
            latency_ms=latency,
            details={"expected": list(self.config.docker_containers), "found": running},
        )

    # --------------------------------------------------------------------------
    # Disk / Environment / Custom Checks
    # --------------------------------------------------------------------------

    def check_disk_space(self) -> CheckResult:
        started = time.perf_counter()

        if not self.config.disk_check_enabled:
            return CheckResult("disk_space", "skipped", "Disk check disabled.", 0, {})

        disk_path = Path(self.config.disk_path)
        if not disk_path.exists():
            return CheckResult(
                name="disk_space",
                status="unhealthy",
                message="Disk check path does not exist.",
                latency_ms=int((time.perf_counter() - started) * 1000),
                details={"path": str(disk_path)},
            )

        usage = shutil.disk_usage(str(disk_path))
        free_percent = int((usage.free / usage.total) * 100) if usage.total else 0
        latency = int((time.perf_counter() - started) * 1000)

        status = "healthy" if free_percent >= self.config.disk_min_free_percent else "unhealthy"
        message = (
            f"Disk free space is {free_percent}%."
            if status == "healthy"
            else f"Disk free space is below minimum: {free_percent}% < {self.config.disk_min_free_percent}%."
        )

        return CheckResult(
            name="disk_space",
            status=status,
            message=message,
            latency_ms=latency,
            details={
                "path": str(disk_path),
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
                "free_percent": free_percent,
                "minimum_free_percent": self.config.disk_min_free_percent,
            },
        )

    def check_required_env(self) -> CheckResult:
        started = time.perf_counter()

        if not self.config.required_env_vars:
            return CheckResult("required_env", "skipped", "No required environment variables configured.", 0, {})

        missing = [name for name in self.config.required_env_vars if not os.getenv(name)]
        present = [name for name in self.config.required_env_vars if os.getenv(name)]

        latency = int((time.perf_counter() - started) * 1000)

        if missing:
            return CheckResult(
                name="required_env",
                status="unhealthy",
                message="Required environment variables are missing.",
                latency_ms=latency,
                details={"missing": missing, "present": present},
            )

        return CheckResult(
            name="required_env",
            status="healthy",
            message="Required environment variables are present.",
            latency_ms=latency,
            details={"present": present},
        )

    def check_custom_command(self) -> CheckResult:
        started = time.perf_counter()

        if not self.config.custom_command_enabled:
            return CheckResult("custom_command", "skipped", "Custom health command disabled.", 0, {})

        if not self.config.custom_command:
            return CheckResult("custom_command", "skipped", "Custom health command not configured.", 0, {})

        try:
            completed = subprocess.run(
                ["bash", "-lc", self.config.custom_command],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.config.timeout_seconds,
                check=False,
            )
            latency = int((time.perf_counter() - started) * 1000)

            if completed.returncode == 0:
                return CheckResult(
                    name="custom_command",
                    status="healthy",
                    message="Custom health command passed.",
                    latency_ms=latency,
                    details={"stdout": completed.stdout[-500:]},
                )

            return CheckResult(
                name="custom_command",
                status="unhealthy",
                message="Custom health command failed.",
                latency_ms=latency,
                details={
                    "returncode": completed.returncode,
                    "stdout": completed.stdout[-500:],
                    "stderr": completed.stderr[-500:],
                },
            )
        except subprocess.TimeoutExpired:
            latency = int((time.perf_counter() - started) * 1000)
            return CheckResult(
                name="custom_command",
                status="unhealthy",
                message="Custom health command timed out.",
                latency_ms=latency,
                details={"timeout_seconds": self.config.timeout_seconds},
            )

    # --------------------------------------------------------------------------
    # Orchestration
    # --------------------------------------------------------------------------

    def overall_status(self, results: Sequence[CheckResult]) -> str:
        statuses = {result.status for result in results}

        if "unhealthy" in statuses:
            return "unhealthy"
        if "degraded" in statuses:
            return "degraded"
        if results and all(result.status == "skipped" for result in results):
            return "skipped"
        return "healthy"

    def run_all(self) -> Dict[str, Any]:
        """Run all configured health checks and return structured response."""
        self.log_event("info", "healthchecks_started", "Service health checks started.")

        results: List[CheckResult] = []

        checks = [
            self.check_access_controls,
            self.check_required_env,
            lambda: self.check_http_endpoint("api_http", self.config.api_health_url),
            lambda: self.check_http_endpoint("dashboard_http", self.config.dashboard_health_url),
            lambda: self.check_http_endpoint("worker_http", self.config.worker_health_url),
            self.check_postgres,
            self.check_redis,
            self.check_docker_containers,
            self.check_disk_space,
            self.check_custom_command,
        ]

        for index, url in enumerate(self.config.extra_health_urls, start=1):
            checks.append(lambda endpoint=url, idx=index: self.check_http_endpoint(f"extra_http_{idx}", endpoint))

        for check in checks:
            try:
                result = check()
            except Exception as exc:
                result = CheckResult(
                    name=getattr(check, "__name__", "unknown_check"),
                    status="unhealthy",
                    message=f"Health check crashed safely: {exc.__class__.__name__}: {exc}",
                    latency_ms=0,
                    details={"traceback": traceback.format_exc(limit=4)},
                )
            results.append(result)
            self.log_event(result.status if result.status in {"healthy", "degraded", "unhealthy"} else "info", f"check_{result.name}", result.message, result=result.to_dict())

        status = self.overall_status(results)
        message = f"Healthchecks completed with status: {status}."

        audit = self.audit_payload(status, message, results)
        memory = self.memory_payload(status, message, results)
        verification = self.verification_payload(status, message, results)

        self._post_json_hook(self.config.audit_log_hook_url, audit, "audit_log")
        self._post_json_hook(self.config.memory_agent_hook_url, memory, "memory_agent")
        self._post_json_hook(self.config.verification_agent_hook_url, verification, "verification_agent")
        self._post_json_hook(self.config.master_agent_hook_url, verification, "master_agent")

        response = {
            **self._base_payload(),
            "status": status,
            "message": message,
            "started_at": self.started_at,
            "finished_at": utc_now(),
            "summary": {
                "total": len(results),
                "healthy": sum(1 for result in results if result.status == "healthy"),
                "degraded": sum(1 for result in results if result.status == "degraded"),
                "unhealthy": sum(1 for result in results if result.status == "unhealthy"),
                "skipped": sum(1 for result in results if result.status == "skipped"),
            },
            "results": [result.to_dict() for result in results],
            "verification_payload": verification,
        }

        self.log_event("info" if status == "healthy" else "warning", "healthchecks_completed", message, summary=response["summary"])
        return response


# ==============================================================================
# CLI
# ==============================================================================


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="healthchecks.py",
        description="Run William/Jarvis service health checks.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Print final structured JSON response.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print final JSON response, not progress logs.",
    )
    parser.add_argument(
        "--fail-on-degraded",
        action="store_true",
        help="Exit non-zero on degraded status as well as unhealthy.",
    )
    parser.add_argument(
        "--api-url",
        default=None,
        help="Override API_HEALTH_URL.",
    )
    parser.add_argument(
        "--dashboard-url",
        default=None,
        help="Override DASHBOARD_HEALTH_URL.",
    )
    parser.add_argument(
        "--workspace-id",
        default=None,
        help="Override WORKSPACE_ID.",
    )
    parser.add_argument(
        "--user-id",
        default=None,
        help="Override USER_ID.",
    )
    parser.add_argument(
        "--role",
        default=None,
        help="Override REQUESTED_BY_ROLE.",
    )

    return parser.parse_args(argv)


class QuietHealthchecks(Healthchecks):
    """Healthchecks variant that suppresses progress logs."""

    def log_event(self, level: str, event: str, message: str, **extra: Any) -> None:
        try:
            path = Path(self.config.log_jsonl_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                **self._base_payload(),
                "level": level,
                "event": event,
                "message": message,
                **extra,
            }
            with path.open("a", encoding="utf-8") as file:
                file.write(json_dumps(payload) + "\n")
        except OSError:
            return


def build_config_with_cli_overrides(args: argparse.Namespace) -> HealthcheckConfig:
    base = HealthcheckConfig.from_env()

    overrides = dataclasses.asdict(base)

    if args.api_url is not None:
        overrides["api_health_url"] = args.api_url
    if args.dashboard_url is not None:
        overrides["dashboard_health_url"] = args.dashboard_url
    if args.workspace_id is not None:
        overrides["workspace_id"] = normalize_identifier(args.workspace_id, "system")
    if args.user_id is not None:
        overrides["user_id"] = normalize_identifier(args.user_id, "system")
    if args.role is not None:
        overrides["requested_by_role"] = normalize_identifier(args.role, "system")

    return HealthcheckConfig(**overrides)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    config = build_config_with_cli_overrides(args)

    runner_cls = QuietHealthchecks if args.quiet else Healthchecks
    runner = runner_cls(config=config)

    response = runner.run_all()

    if args.json or args.quiet:
        print(json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True))

    status = response.get("status")

    if status == "unhealthy":
        return 2
    if status == "degraded" and args.fail_on_degraded:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())