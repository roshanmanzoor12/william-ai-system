# ============================================================
# William / Jarvis Multi-Agent AI SaaS System
# Digital Promotix
# File: Dockerfile
# Purpose: Production backend Dockerfile
# Agent/Module: Deployment Prompt Bible
# ============================================================

# ------------------------------------------------------------
# Stage 1: Base Python image
# ------------------------------------------------------------
# Using slim keeps the image smaller while still supporting
# production FastAPI, SQLAlchemy, async workers, and agent logic.
# ------------------------------------------------------------
FROM python:3.12-slim AS base

# ------------------------------------------------------------
# Environment safety defaults
# ------------------------------------------------------------
# PYTHONDONTWRITEBYTECODE:
#   Prevents Python from writing .pyc files.
#
# PYTHONUNBUFFERED:
#   Ensures logs are streamed immediately to Docker/Kubernetes.
#
# PIP_NO_CACHE_DIR:
#   Reduces image size by avoiding pip cache.
#
# APP_ENV:
#   Defaults to production, but can be overridden at runtime.
#
# PORT:
#   Backend app port. Should match docker-compose / cloud runtime.
# ------------------------------------------------------------
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    APP_ENV=production \
    PORT=8000

# ------------------------------------------------------------
# System dependencies
# ------------------------------------------------------------
# gcc/build-essential:
#   Needed for Python packages that compile native extensions.
#
# libpq-dev:
#   Needed for PostgreSQL clients such as psycopg/asyncpg setups.
#
# curl:
#   Used for container health checks.
#
# tini:
#   Handles process signals properly inside containers.
# ------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
    curl \
    tini \
    && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------
# Application working directory
# ------------------------------------------------------------
WORKDIR /app

# ------------------------------------------------------------
# Create a non-root application user
# ------------------------------------------------------------
# Running as root in production containers is risky.
# This user owns only the app directory and runtime folders.
# ------------------------------------------------------------
RUN groupadd --system william && \
    useradd --system --gid william --home-dir /app --shell /usr/sbin/nologin william && \
    mkdir -p /app/logs /app/tmp /app/storage && \
    chown -R william:william /app

# ------------------------------------------------------------
# Stage 2: Dependency installation
# ------------------------------------------------------------
FROM base AS dependencies

# ------------------------------------------------------------
# Copy dependency manifests first for better Docker layer caching.
# Supports common Python dependency layouts:
# - requirements.txt
# - requirements-prod.txt
# - pyproject.toml
# ------------------------------------------------------------
COPY requirements*.txt pyproject.toml* poetry.lock* /app/

# ------------------------------------------------------------
# Install Python dependencies
# ------------------------------------------------------------
# Priority:
# 1. requirements-prod.txt if available
# 2. requirements.txt if available
# 3. pyproject.toml fallback
#
# No secrets are baked into the image.
# Private package credentials must be passed securely at build/runtime
# through your CI/CD secret manager, not written here.
# ------------------------------------------------------------
RUN python -m pip install --upgrade pip setuptools wheel && \
    if [ -f requirements-prod.txt ]; then \
        pip install --no-cache-dir -r requirements-prod.txt; \
    elif [ -f requirements.txt ]; then \
        pip install --no-cache-dir -r requirements.txt; \
    elif [ -f pyproject.toml ]; then \
        pip install --no-cache-dir .; \
    else \
        echo "No dependency manifest found. Expected requirements.txt, requirements-prod.txt, or pyproject.toml." && exit 1; \
    fi

# ------------------------------------------------------------
# Stage 3: Production runtime
# ------------------------------------------------------------
FROM base AS production

# ------------------------------------------------------------
# Copy installed Python packages from dependency stage
# ------------------------------------------------------------
COPY --from=dependencies /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=dependencies /usr/local/bin /usr/local/bin

# ------------------------------------------------------------
# Copy application source
# ------------------------------------------------------------
# This assumes the Dockerfile lives at the project root.
# Recommended project layout examples:
#
# /apps/api/main.py
# /apps/api/routes/
# /agents/
# /database/
# /subscriptions/
# /security/
# /config/
# /main.py
#
# The startup command below supports both:
# - apps.api.main:app
# - main:app
# ------------------------------------------------------------
COPY . /app

# ------------------------------------------------------------
# Runtime folders and permissions
# ------------------------------------------------------------
RUN mkdir -p /app/logs /app/tmp /app/storage && \
    chown -R william:william /app && \
    chmod -R 755 /app

# ------------------------------------------------------------
# Switch to non-root user
# ------------------------------------------------------------
USER william

# ------------------------------------------------------------
# Expose backend port
# ------------------------------------------------------------
EXPOSE 8000

# ------------------------------------------------------------
# Runtime environment variables
# ------------------------------------------------------------
# These are safe defaults only.
# Real values must be injected by docker-compose, Kubernetes,
# ECS, Render, Railway, Fly.io, or your production secret manager.
#
# Required production examples:
# DATABASE_URL
# REDIS_URL
# SECRET_KEY
# JWT_SECRET
# ENCRYPTION_KEY
# MASTER_AGENT_URL
# SECURITY_AGENT_URL
# MEMORY_AGENT_URL
# VERIFICATION_AGENT_URL
# ------------------------------------------------------------
ENV HOST=0.0.0.0 \
    WORKERS=2 \
    LOG_LEVEL=info \
    WILLIAM_STORAGE_DIR=/app/storage \
    WILLIAM_LOG_DIR=/app/logs \
    WILLIAM_TMP_DIR=/app/tmp

# ------------------------------------------------------------
# Health check
# ------------------------------------------------------------
# The backend should expose one of these endpoints:
# - /health
# - /api/health
#
# Recommended response:
# {
#   "status": "ok",
#   "service": "william-api",
#   "environment": "production"
# }
#
# Health checks must not expose secrets, user data,
# workspace data, memory, logs, billing, or agent payloads.
# ------------------------------------------------------------
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" || curl -fsS "http://127.0.0.1:${PORT}/api/health" || exit 1

# ------------------------------------------------------------
# Production start command
# ------------------------------------------------------------
# Uses tini for correct signal handling.
#
# Startup logic:
# 1. Prefer apps.api.main:app for monorepo backend layout.
# 2. Fallback to main:app for simple backend layout.
#
# Notes:
# - Do not run --reload in production.
# - Gunicorn with Uvicorn workers is production-safe.
# - Worker count can be overridden using WORKERS env.
# - Logs go to stdout/stderr for Docker/Kubernetes collection.
# ------------------------------------------------------------
ENTRYPOINT ["/usr/bin/tini", "--"]

CMD sh -c '\
    if python -c "import apps.api.main" >/dev/null 2>&1; then \
        exec gunicorn apps.api.main:app \
            --worker-class uvicorn.workers.UvicornWorker \
            --workers ${WORKERS:-2} \
            --bind ${HOST:-0.0.0.0}:${PORT:-8000} \
            --log-level ${LOG_LEVEL:-info} \
            --access-logfile - \
            --error-logfile - \
            --timeout 120; \
    elif python -c "import main" >/dev/null 2>&1; then \
        exec gunicorn main:app \
            --worker-class uvicorn.workers.UvicornWorker \
            --workers ${WORKERS:-2} \
            --bind ${HOST:-0.0.0.0}:${PORT:-8000} \
            --log-level ${LOG_LEVEL:-info} \
            --access-logfile - \
            --error-logfile - \
            --timeout 120; \
    else \
        echo "No FastAPI app found. Expected apps.api.main:app or main:app." >&2; \
        exit 1; \
    fi \
'