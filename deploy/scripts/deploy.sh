#!/usr/bin/env bash
# ==============================================================================
# William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
# File: deploy/scripts/deploy.sh
# Agent/Module: Deployment Prompt Bible
# Component: Deploy
# Purpose: Safe deployment script for the William / Jarvis SaaS platform.
#
# Responsibilities:
# - Validate safe deployment context.
# - Enforce role/plan/subscription gates for dashboard/API-triggered deploys.
# - Route sensitive deployment action through Security Agent when configured.
# - Optionally create a database backup before deployment.
# - Deploy using Docker Compose by default.
# - Optionally run migrations.
# - Run health checks after deployment.
# - Emit audit, memory, and verification payloads.
#
# Production Rules:
# - Never hardcode secrets.
# - Read all environment values from env/config.
# - Every deployment must carry user_id and workspace_id metadata.
# - Never mix deployment artifacts, logs, backups, or audit events across workspaces.
# - Every sensitive action should route to Security Agent.
# - Every completed action should prepare a Verification Agent payload.
# - Safe shell execution: strict mode, validated inputs, structured errors.
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# ------------------------------------------------------------------------------
# Deploy Constants
# ------------------------------------------------------------------------------

SCRIPT_NAME="Deploy"
SCRIPT_VERSION="1.0.0"
RUN_ID="$(date -u +"%Y%m%dT%H%M%SZ")-$$"
STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# ------------------------------------------------------------------------------
# Safe Defaults
# ------------------------------------------------------------------------------

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
DEPLOY_ROOT="${DEPLOY_ROOT:-./deploy}"
DEPLOY_LOG_ROOT="${DEPLOY_LOG_ROOT:-./deploy/logs}"
DEPLOY_ARTIFACT_ROOT="${DEPLOY_ARTIFACT_ROOT:-./deploy/artifacts}"
DEPLOY_LOCK_FILE="${DEPLOY_LOCK_FILE:-/tmp/william_jarvis_deploy.lock}"

DEPLOY_ENV="${DEPLOY_ENV:-production}" # production | staging | development
DEPLOY_STRATEGY="${DEPLOY_STRATEGY:-docker_compose}" # docker_compose | command_only
DEPLOY_CONFIRMATION="${DEPLOY_CONFIRMATION:-}"
DRY_RUN="${DRY_RUN:-false}"

# Docker Compose settings.
DOCKER_COMPOSE_FILE="${DOCKER_COMPOSE_FILE:-docker-compose.yml}"
DOCKER_COMPOSE_PROJECT_NAME="${DOCKER_COMPOSE_PROJECT_NAME:-william_jarvis}"
DOCKER_COMPOSE_PROFILE="${DOCKER_COMPOSE_PROFILE:-}"
COMPOSE_PULL_IMAGES="${COMPOSE_PULL_IMAGES:-true}"
COMPOSE_BUILD_IMAGES="${COMPOSE_BUILD_IMAGES:-true}"
COMPOSE_REMOVE_ORPHANS="${COMPOSE_REMOVE_ORPHANS:-true}"

# Optional custom commands.
PRE_DEPLOY_COMMAND="${PRE_DEPLOY_COMMAND:-}"
BUILD_COMMAND="${BUILD_COMMAND:-}"
MIGRATION_COMMAND="${MIGRATION_COMMAND:-}"
POST_DEPLOY_COMMAND="${POST_DEPLOY_COMMAND:-}"

# Backup settings.
CREATE_DB_BACKUP_BEFORE_DEPLOY="${CREATE_DB_BACKUP_BEFORE_DEPLOY:-true}"
BACKUP_SCRIPT_PATH="${BACKUP_SCRIPT_PATH:-./deploy/scripts/backup_db.sh}"

# Health check settings.
RUN_HEALTH_CHECKS="${RUN_HEALTH_CHECKS:-true}"
HEALTHCHECK_URL="${HEALTHCHECK_URL:-http://localhost:8000/health}"
HEALTHCHECK_ATTEMPTS="${HEALTHCHECK_ATTEMPTS:-30}"
HEALTHCHECK_SLEEP_SECONDS="${HEALTHCHECK_SLEEP_SECONDS:-5}"
HEALTHCHECK_EXPECTED_STATUS="${HEALTHCHECK_EXPECTED_STATUS:-200}"

# SaaS metadata. Required for auditability and future Master Agent orchestration.
USER_ID="${USER_ID:-system}"
WORKSPACE_ID="${WORKSPACE_ID:-system}"
REQUESTED_BY_ROLE="${REQUESTED_BY_ROLE:-system}"
REQUEST_SOURCE="${REQUEST_SOURCE:-deployment_script}"

# Role/plan/subscription gates.
REQUIRE_ACTIVE_SUBSCRIPTION="${REQUIRE_ACTIVE_SUBSCRIPTION:-false}"
SUBSCRIPTION_STATUS="${SUBSCRIPTION_STATUS:-active}"
ALLOWED_DEPLOY_PLANS="${ALLOWED_DEPLOY_PLANS:-enterprise,pro,system}"
CURRENT_PLAN="${CURRENT_PLAN:-system}"
ALLOWED_DEPLOY_ROLES="${ALLOWED_DEPLOY_ROLES:-owner,admin,system,security_agent,devops}"

# Deployment is sensitive. Default approval is true for production.
REQUIRE_SECURITY_APPROVAL="${REQUIRE_SECURITY_APPROVAL:-true}"

# Future agent integration hooks.
MASTER_AGENT_HOOK_URL="${MASTER_AGENT_HOOK_URL:-}"
SECURITY_AGENT_HOOK_URL="${SECURITY_AGENT_HOOK_URL:-}"
AUDIT_LOG_HOOK_URL="${AUDIT_LOG_HOOK_URL:-}"
MEMORY_AGENT_HOOK_URL="${MEMORY_AGENT_HOOK_URL:-}"
VERIFICATION_AGENT_HOOK_URL="${VERIFICATION_AGENT_HOOK_URL:-}"

# Rollback hint only. This script avoids destructive automatic rollback unless
# explicitly configured in future deploy pipeline.
ROLLBACK_COMMAND="${ROLLBACK_COMMAND:-}"

# ------------------------------------------------------------------------------
# Logging Helpers
# ------------------------------------------------------------------------------

json_escape() {
  local input="${1:-}"
  input="${input//\\/\\\\}"
  input="${input//\"/\\\"}"
  input="${input//$'\n'/\\n}"
  input="${input//$'\r'/\\r}"
  input="${input//$'\t'/\\t}"
  printf '%s' "$input"
}

log_json() {
  local level="$1"
  local event="$2"
  local message="$3"
  local timestamp
  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  mkdir -p "$DEPLOY_LOG_ROOT/workspace_${WORKSPACE_ID}" 2>/dev/null || true

  local line
  line="$(printf '{"timestamp":"%s","level":"%s","component":"%s","run_id":"%s","event":"%s","user_id":"%s","workspace_id":"%s","environment":"%s","message":"%s"}' \
    "$timestamp" \
    "$(json_escape "$level")" \
    "$SCRIPT_NAME" \
    "$(json_escape "$RUN_ID")" \
    "$(json_escape "$event")" \
    "$(json_escape "$USER_ID")" \
    "$(json_escape "$WORKSPACE_ID")" \
    "$(json_escape "$DEPLOY_ENV")" \
    "$(json_escape "$message")")"

  printf '%s\n' "$line"
  printf '%s\n' "$line" >> "$DEPLOY_LOG_ROOT/workspace_${WORKSPACE_ID}/deploy_${RUN_ID}.jsonl" 2>/dev/null || true
}

fail() {
  local event="$1"
  local message="$2"
  local code="${3:-1}"

  log_json "error" "$event" "$message"
  emit_verification_payload "failed" "$message" "" ""
  suggest_rollback "$message"
  exit "$code"
}

# ------------------------------------------------------------------------------
# Cleanup / Error Trap
# ------------------------------------------------------------------------------

cleanup_lock() {
  if [[ -f "$DEPLOY_LOCK_FILE" ]]; then
    local existing_pid
    existing_pid="$(cat "$DEPLOY_LOCK_FILE" 2>/dev/null || true)"
    if [[ "$existing_pid" == "$$" ]]; then
      rm -f "$DEPLOY_LOCK_FILE"
    fi
  fi
}

on_error() {
  local exit_code=$?
  local line_no="${1:-unknown}"

  cleanup_lock
  log_json "error" "script_error" "Deployment failed at line ${line_no} with exit code ${exit_code}."
  emit_verification_payload "failed" "Deployment failed at line ${line_no} with exit code ${exit_code}." "" ""
  suggest_rollback "Deployment failed at line ${line_no}."
  exit "$exit_code"
}

trap 'on_error $LINENO' ERR
trap cleanup_lock EXIT

# ------------------------------------------------------------------------------
# Validation Helpers
# ------------------------------------------------------------------------------

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    fail "missing_dependency" "Required command not found: ${command_name}" 127
  fi
}

validate_integer() {
  local value="$1"
  local name="$2"

  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    fail "invalid_config" "${name} must be a positive integer. Current value: ${value}" 2
  fi
}

validate_identifier() {
  local value="$1"
  local name="$2"

  if [[ -z "$value" ]]; then
    fail "invalid_identity" "${name} cannot be empty." 2
  fi

  if ! [[ "$value" =~ ^[a-zA-Z0-9._:@/-]+$ ]]; then
    fail "invalid_identity" "${name} contains unsafe characters. Use letters, numbers, dot, dash, underscore, colon, slash, or @ only." 2
  fi
}

csv_contains() {
  local needle="$1"
  local haystack_csv="$2"
  local item

  IFS=',' read -ra values <<< "$haystack_csv"
  for item in "${values[@]}"; do
    item="$(echo "$item" | xargs)"
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done

  return 1
}

acquire_lock() {
  if [[ -f "$DEPLOY_LOCK_FILE" ]]; then
    local old_pid
    old_pid="$(cat "$DEPLOY_LOCK_FILE" 2>/dev/null || true)"

    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" >/dev/null 2>&1; then
      fail "deploy_already_running" "Another deployment is already running with PID ${old_pid}." 75
    fi

    log_json "warning" "stale_lock_removed" "Removing stale lock file at ${DEPLOY_LOCK_FILE}."
    rm -f "$DEPLOY_LOCK_FILE"
  fi

  echo "$$" > "$DEPLOY_LOCK_FILE"
}

validate_access_controls() {
  validate_identifier "$USER_ID" "USER_ID"
  validate_identifier "$WORKSPACE_ID" "WORKSPACE_ID"
  validate_identifier "$REQUESTED_BY_ROLE" "REQUESTED_BY_ROLE"

  if ! csv_contains "$REQUESTED_BY_ROLE" "$ALLOWED_DEPLOY_ROLES"; then
    fail "role_not_allowed" "Role '${REQUESTED_BY_ROLE}' is not allowed to run deployments." 78
  fi

  if [[ "$REQUIRE_ACTIVE_SUBSCRIPTION" == "true" ]]; then
    if [[ "$SUBSCRIPTION_STATUS" != "active" ]]; then
      fail "subscription_inactive" "Deployment requires an active subscription. Current status: ${SUBSCRIPTION_STATUS}" 79
    fi

    if ! csv_contains "$CURRENT_PLAN" "$ALLOWED_DEPLOY_PLANS"; then
      fail "plan_not_allowed" "Plan '${CURRENT_PLAN}' is not allowed to run deployments." 79
    fi
  fi
}

validate_deploy_confirmation() {
  if [[ "$DRY_RUN" == "true" ]]; then
    log_json "info" "dry_run_enabled" "Dry run enabled. No deployment changes will be made."
    return 0
  fi

  if [[ "$DEPLOY_ENV" == "production" && "$DEPLOY_CONFIRMATION" != "DEPLOY_PRODUCTION_NOW" ]]; then
    fail "deploy_not_confirmed" "Production deployment requires DEPLOY_CONFIRMATION=DEPLOY_PRODUCTION_NOW." 76
  fi
}

validate_environment() {
  case "$DEPLOY_ENV" in
    production|staging|development)
      ;;
    *)
      fail "invalid_config" "DEPLOY_ENV must be production, staging, or development. Current value: ${DEPLOY_ENV}" 2
      ;;
  esac

  case "$DEPLOY_STRATEGY" in
    docker_compose|command_only)
      ;;
    *)
      fail "invalid_config" "DEPLOY_STRATEGY must be docker_compose or command_only. Current value: ${DEPLOY_STRATEGY}" 2
      ;;
  esac

  validate_integer "$HEALTHCHECK_ATTEMPTS" "HEALTHCHECK_ATTEMPTS"
  validate_integer "$HEALTHCHECK_SLEEP_SECONDS" "HEALTHCHECK_SLEEP_SECONDS"
}

prepare_workspace_dirs() {
  mkdir -p "$DEPLOY_LOG_ROOT/workspace_${WORKSPACE_ID}"
  mkdir -p "$DEPLOY_ARTIFACT_ROOT/workspace_${WORKSPACE_ID}"

  chmod 700 "$DEPLOY_LOG_ROOT/workspace_${WORKSPACE_ID}" 2>/dev/null || true
  chmod 700 "$DEPLOY_ARTIFACT_ROOT/workspace_${WORKSPACE_ID}" 2>/dev/null || true
}

# ------------------------------------------------------------------------------
# Agent Hook Helpers
# ------------------------------------------------------------------------------

post_hook_json() {
  local hook_url="$1"
  local payload="$2"
  local hook_name="$3"

  if [[ -z "$hook_url" ]]; then
    log_json "info" "${hook_name}_skipped" "${hook_name} hook URL not configured."
    return 0
  fi

  if ! command -v curl >/dev/null 2>&1; then
    log_json "warning" "${hook_name}_skipped" "curl is not available, so ${hook_name} hook was skipped."
    return 0
  fi

  local response_file="/tmp/${SCRIPT_NAME}_${hook_name}_${RUN_ID}.response"
  local response_code
  response_code="$(
    curl -sS -o "$response_file" \
      -w "%{http_code}" \
      -X POST "$hook_url" \
      -H "Content-Type: application/json" \
      --data "$payload" || true
  )"

  if [[ "$response_code" =~ ^2[0-9][0-9]$ ]]; then
    log_json "info" "${hook_name}_sent" "${hook_name} hook accepted with HTTP ${response_code}."
  else
    log_json "warning" "${hook_name}_failed" "${hook_name} hook returned HTTP ${response_code}."
  fi
}

deployment_payload() {
  local action="$1"
  local status="$2"
  local message="$3"

  cat <<JSON
{
  "component": "$(json_escape "$SCRIPT_NAME")",
  "script_version": "$(json_escape "$SCRIPT_VERSION")",
  "run_id": "$(json_escape "$RUN_ID")",
  "action": "$(json_escape "$action")",
  "status": "$(json_escape "$status")",
  "risk_level": "high",
  "user_id": "$(json_escape "$USER_ID")",
  "workspace_id": "$(json_escape "$WORKSPACE_ID")",
  "requested_by_role": "$(json_escape "$REQUESTED_BY_ROLE")",
  "request_source": "$(json_escape "$REQUEST_SOURCE")",
  "environment": "$(json_escape "$DEPLOY_ENV")",
  "strategy": "$(json_escape "$DEPLOY_STRATEGY")",
  "project_root": "$(json_escape "$PROJECT_ROOT")",
  "compose_file": "$(json_escape "$DOCKER_COMPOSE_FILE")",
  "message": "$(json_escape "$message")",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
JSON
}

audit_payload() {
  local status="$1"
  local message="$2"
  local artifact_path="${3:-}"

  cat <<JSON
{
  "component": "$(json_escape "$SCRIPT_NAME")",
  "script_version": "$(json_escape "$SCRIPT_VERSION")",
  "run_id": "$(json_escape "$RUN_ID")",
  "event_type": "deployment",
  "status": "$(json_escape "$status")",
  "user_id": "$(json_escape "$USER_ID")",
  "workspace_id": "$(json_escape "$WORKSPACE_ID")",
  "requested_by_role": "$(json_escape "$REQUESTED_BY_ROLE")",
  "request_source": "$(json_escape "$REQUEST_SOURCE")",
  "environment": "$(json_escape "$DEPLOY_ENV")",
  "strategy": "$(json_escape "$DEPLOY_STRATEGY")",
  "artifact_path": "$(json_escape "$artifact_path")",
  "message": "$(json_escape "$message")",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
JSON
}

memory_payload() {
  local status="$1"
  local message="$2"
  local artifact_path="${3:-}"

  cat <<JSON
{
  "component": "$(json_escape "$SCRIPT_NAME")",
  "memory_type": "deployment_event",
  "importance": "high",
  "user_id": "$(json_escape "$USER_ID")",
  "workspace_id": "$(json_escape "$WORKSPACE_ID")",
  "event": "deployment_${status}",
  "summary": "Deployment ${status} for workspace $(json_escape "$WORKSPACE_ID") in $(json_escape "$DEPLOY_ENV").",
  "metadata": {
    "run_id": "$(json_escape "$RUN_ID")",
    "environment": "$(json_escape "$DEPLOY_ENV")",
    "strategy": "$(json_escape "$DEPLOY_STRATEGY")",
    "artifact_path": "$(json_escape "$artifact_path")",
    "message": "$(json_escape "$message")",
    "created_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  }
}
JSON
}

verification_payload() {
  local status="$1"
  local message="$2"
  local artifact_path="${3:-}"
  local health_status="${4:-}"

  cat <<JSON
{
  "component": "$(json_escape "$SCRIPT_NAME")",
  "script_version": "$(json_escape "$SCRIPT_VERSION")",
  "run_id": "$(json_escape "$RUN_ID")",
  "verification_type": "deployment",
  "status": "$(json_escape "$status")",
  "user_id": "$(json_escape "$USER_ID")",
  "workspace_id": "$(json_escape "$WORKSPACE_ID")",
  "environment": "$(json_escape "$DEPLOY_ENV")",
  "strategy": "$(json_escape "$DEPLOY_STRATEGY")",
  "artifact_path": "$(json_escape "$artifact_path")",
  "health_status": "$(json_escape "$health_status")",
  "message": "$(json_escape "$message")",
  "started_at": "$(json_escape "$STARTED_AT")",
  "finished_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
JSON
}

emit_verification_payload() {
  local status="$1"
  local message="$2"
  local artifact_path="${3:-}"
  local health_status="${4:-}"
  local payload
  payload="$(verification_payload "$status" "$message" "$artifact_path" "$health_status")"

  log_json "info" "verification_payload_prepared" "$payload"
  post_hook_json "$VERIFICATION_AGENT_HOOK_URL" "$payload" "verification_agent"
}

notify_master_agent() {
  local action="$1"
  local status="$2"
  local message="$3"
  local payload
  payload="$(deployment_payload "$action" "$status" "$message")"

  post_hook_json "$MASTER_AGENT_HOOK_URL" "$payload" "master_agent"
}

request_security_approval() {
  local payload
  payload="$(deployment_payload "deploy_approval_request" "pending" "Deployment approval requested.")"

  log_json "info" "security_payload_prepared" "$payload"

  if [[ "$DRY_RUN" == "true" ]]; then
    post_hook_json "$SECURITY_AGENT_HOOK_URL" "$payload" "security_agent"
    return 0
  fi

  if [[ "$REQUIRE_SECURITY_APPROVAL" != "true" ]]; then
    post_hook_json "$SECURITY_AGENT_HOOK_URL" "$payload" "security_agent"
    return 0
  fi

  if [[ -z "$SECURITY_AGENT_HOOK_URL" ]]; then
    fail "security_approval_required" "Security approval is required, but SECURITY_AGENT_HOOK_URL is not configured." 77
  fi

  require_command "curl"

  local response_file="/tmp/${SCRIPT_NAME}_security_${RUN_ID}.response"
  local response_code
  response_code="$(
    curl -sS -o "$response_file" \
      -w "%{http_code}" \
      -X POST "$SECURITY_AGENT_HOOK_URL" \
      -H "Content-Type: application/json" \
      --data "$payload" || true
  )"

  if [[ ! "$response_code" =~ ^2[0-9][0-9]$ ]]; then
    fail "security_approval_denied" "Security Agent did not approve deployment request. HTTP ${response_code}." 77
  fi

  if grep -Eiq '"approved"[[:space:]]*:[[:space:]]*false' "$response_file"; then
    fail "security_approval_denied" "Security Agent explicitly denied deployment request." 77
  fi

  log_json "info" "security_approval_granted" "Security Agent approval accepted."
}

# ------------------------------------------------------------------------------
# Command Runner
# ------------------------------------------------------------------------------

run_shell_command() {
  local command_name="$1"
  local command_value="$2"

  if [[ -z "$command_value" ]]; then
    log_json "info" "${command_name}_skipped" "${command_name} not configured."
    return 0
  fi

  log_json "info" "${command_name}_started" "Running ${command_name}."

  if [[ "$DRY_RUN" == "true" ]]; then
    log_json "info" "${command_name}_dry_run" "Dry run command: ${command_value}"
    return 0
  fi

  bash -lc "$command_value"

  log_json "info" "${command_name}_completed" "${command_name} completed."
}

# ------------------------------------------------------------------------------
# Deployment Steps
# ------------------------------------------------------------------------------

preflight_checks() {
  log_json "info" "preflight_started" "Running deployment preflight checks."

  if [[ ! -d "$PROJECT_ROOT" ]]; then
    fail "project_root_missing" "PROJECT_ROOT does not exist: ${PROJECT_ROOT}" 66
  fi

  cd "$PROJECT_ROOT"

  if [[ "$DEPLOY_STRATEGY" == "docker_compose" ]]; then
    require_command "docker"

    if ! docker compose version >/dev/null 2>&1; then
      fail "docker_compose_missing" "Docker Compose plugin is not available. Install Docker Compose v2." 127
    fi

    if [[ ! -f "$DOCKER_COMPOSE_FILE" ]]; then
      fail "compose_file_missing" "Docker Compose file not found: ${DOCKER_COMPOSE_FILE}" 66
    fi
  fi

  if [[ "$RUN_HEALTH_CHECKS" == "true" ]]; then
    require_command "curl"
  fi

  if [[ "$CREATE_DB_BACKUP_BEFORE_DEPLOY" == "true" ]]; then
    if [[ ! -x "$BACKUP_SCRIPT_PATH" ]]; then
      fail "backup_script_missing" "Backup script is missing or not executable: ${BACKUP_SCRIPT_PATH}" 66
    fi
  fi

  log_json "info" "preflight_completed" "Deployment preflight checks passed."
}

create_deployment_artifact() {
  local artifact_path
  artifact_path="${DEPLOY_ARTIFACT_ROOT}/workspace_${WORKSPACE_ID}/deploy_${RUN_ID}.metadata.json"

  mkdir -p "$(dirname "$artifact_path")"

  cat > "$artifact_path" <<JSON
{
  "component": "$SCRIPT_NAME",
  "script_version": "$SCRIPT_VERSION",
  "run_id": "$(json_escape "$RUN_ID")",
  "user_id": "$(json_escape "$USER_ID")",
  "workspace_id": "$(json_escape "$WORKSPACE_ID")",
  "requested_by_role": "$(json_escape "$REQUESTED_BY_ROLE")",
  "request_source": "$(json_escape "$REQUEST_SOURCE")",
  "environment": "$(json_escape "$DEPLOY_ENV")",
  "strategy": "$(json_escape "$DEPLOY_STRATEGY")",
  "project_root": "$(json_escape "$PROJECT_ROOT")",
  "compose_file": "$(json_escape "$DOCKER_COMPOSE_FILE")",
  "started_at": "$(json_escape "$STARTED_AT")"
}
JSON

  chmod 600 "$artifact_path" 2>/dev/null || true
  echo "$artifact_path"
}

run_database_backup() {
  if [[ "$CREATE_DB_BACKUP_BEFORE_DEPLOY" != "true" ]]; then
    log_json "warning" "pre_deploy_backup_skipped" "CREATE_DB_BACKUP_BEFORE_DEPLOY is false. No database backup will be created."
    return 0
  fi

  log_json "info" "pre_deploy_backup_started" "Running database backup before deployment."

  if [[ "$DRY_RUN" == "true" ]]; then
    log_json "info" "pre_deploy_backup_dry_run" "Dry run enabled. Database backup skipped."
    return 0
  fi

  USER_ID="$USER_ID" \
  WORKSPACE_ID="$WORKSPACE_ID" \
  REQUESTED_BY_ROLE="$REQUESTED_BY_ROLE" \
  REQUEST_SOURCE="deploy_pre_backup" \
  "$BACKUP_SCRIPT_PATH"

  log_json "info" "pre_deploy_backup_completed" "Database backup completed before deployment."
}

docker_compose_base_args() {
  local args=()

  args+=("-f" "$DOCKER_COMPOSE_FILE")
  args+=("-p" "$DOCKER_COMPOSE_PROJECT_NAME")

  if [[ -n "$DOCKER_COMPOSE_PROFILE" ]]; then
    args+=("--profile" "$DOCKER_COMPOSE_PROFILE")
  fi

  printf '%s\n' "${args[@]}"
}

deploy_with_docker_compose() {
  require_command "docker"

  local compose_args=()
  mapfile -t compose_args < <(docker_compose_base_args)

  if [[ "$COMPOSE_PULL_IMAGES" == "true" ]]; then
    log_json "info" "compose_pull_started" "Pulling Docker images."
    if [[ "$DRY_RUN" == "true" ]]; then
      log_json "info" "compose_pull_dry_run" "Dry run: docker compose ${compose_args[*]} pull"
    else
      docker compose "${compose_args[@]}" pull
    fi
    log_json "info" "compose_pull_completed" "Docker image pull completed."
  fi

  local up_args=("up" "-d")

  if [[ "$COMPOSE_BUILD_IMAGES" == "true" ]]; then
    up_args+=("--build")
  fi

  if [[ "$COMPOSE_REMOVE_ORPHANS" == "true" ]]; then
    up_args+=("--remove-orphans")
  fi

  log_json "info" "compose_deploy_started" "Deploying Docker Compose services."

  if [[ "$DRY_RUN" == "true" ]]; then
    log_json "info" "compose_deploy_dry_run" "Dry run: docker compose ${compose_args[*]} ${up_args[*]}"
  else
    docker compose "${compose_args[@]}" "${up_args[@]}"
  fi

  log_json "info" "compose_deploy_completed" "Docker Compose deployment completed."
}

run_deployment() {
  log_json "info" "deployment_started" "Deployment execution started."

  run_shell_command "pre_deploy_command" "$PRE_DEPLOY_COMMAND"
  run_shell_command "build_command" "$BUILD_COMMAND"

  case "$DEPLOY_STRATEGY" in
    docker_compose)
      deploy_with_docker_compose
      ;;
    command_only)
      log_json "info" "command_only_strategy" "Using command_only strategy. Docker Compose deployment skipped."
      ;;
    *)
      fail "invalid_strategy" "Unsupported DEPLOY_STRATEGY: ${DEPLOY_STRATEGY}" 2
      ;;
  esac

  run_shell_command "migration_command" "$MIGRATION_COMMAND"
  run_shell_command "post_deploy_command" "$POST_DEPLOY_COMMAND"

  log_json "info" "deployment_finished" "Deployment execution finished."
}

# ------------------------------------------------------------------------------
# Health Checks
# ------------------------------------------------------------------------------

run_health_checks() {
  if [[ "$RUN_HEALTH_CHECKS" != "true" ]]; then
    log_json "warning" "healthchecks_skipped" "RUN_HEALTH_CHECKS is false. Health checks skipped."
    echo "skipped"
    return 0
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    log_json "info" "healthchecks_dry_run" "Dry run enabled. Health checks skipped."
    echo "dry_run"
    return 0
  fi

  require_command "curl"

  log_json "info" "healthchecks_started" "Checking health endpoint: ${HEALTHCHECK_URL}"

  local attempt
  local status_code="000"

  for attempt in $(seq 1 "$HEALTHCHECK_ATTEMPTS"); do
    status_code="$(
      curl -sS -o /tmp/"${SCRIPT_NAME}_health_${RUN_ID}.response" \
        -w "%{http_code}" \
        "$HEALTHCHECK_URL" || true
    )"

    if [[ "$status_code" == "$HEALTHCHECK_EXPECTED_STATUS" ]]; then
      log_json "info" "healthcheck_passed" "Health check passed on attempt ${attempt} with HTTP ${status_code}."
      echo "passed"
      return 0
    fi

    log_json "warning" "healthcheck_retry" "Attempt ${attempt}/${HEALTHCHECK_ATTEMPTS} returned HTTP ${status_code}. Retrying."
    sleep "$HEALTHCHECK_SLEEP_SECONDS"
  done

  fail "healthcheck_failed" "Health check failed after ${HEALTHCHECK_ATTEMPTS} attempts. Last HTTP status: ${status_code}" 70
}

# ------------------------------------------------------------------------------
# Rollback Guidance
# ------------------------------------------------------------------------------

suggest_rollback() {
  local reason="$1"

  if [[ -z "$ROLLBACK_COMMAND" ]]; then
    log_json "warning" "rollback_not_configured" "No ROLLBACK_COMMAND configured. Manual rollback may be required. Reason: ${reason}"
    return 0
  fi

  log_json "warning" "rollback_available" "Rollback command is configured but not automatically executed. Reason: ${reason}"
  log_json "warning" "rollback_command" "$ROLLBACK_COMMAND"
}

# ------------------------------------------------------------------------------
# Main Flow
# ------------------------------------------------------------------------------

main() {
  prepare_workspace_dirs

  log_json "info" "script_started" "Starting ${SCRIPT_NAME} v${SCRIPT_VERSION}."

  validate_access_controls
  validate_environment
  validate_deploy_confirmation
  acquire_lock

  notify_master_agent "deployment_started" "started" "Deployment process started."

  local artifact_path
  artifact_path="$(create_deployment_artifact)"

  local audit_start
  audit_start="$(audit_payload "started" "Deployment started." "$artifact_path")"
  post_hook_json "$AUDIT_LOG_HOOK_URL" "$audit_start" "audit_log"

  preflight_checks
  request_security_approval
  run_database_backup
  run_deployment

  local health_status
  health_status="$(run_health_checks)"

  local audit_success
  audit_success="$(audit_payload "completed" "Deployment completed successfully." "$artifact_path")"
  post_hook_json "$AUDIT_LOG_HOOK_URL" "$audit_success" "audit_log"

  local memory_event
  memory_event="$(memory_payload "completed" "Deployment completed successfully." "$artifact_path")"
  post_hook_json "$MEMORY_AGENT_HOOK_URL" "$memory_event" "memory_agent"

  notify_master_agent "deployment_completed" "completed" "Deployment completed successfully."

  emit_verification_payload "completed" "Deployment completed successfully." "$artifact_path" "$health_status"

  log_json "info" "deployment_completed" "Deployment completed successfully."

  cat <<JSON
{
  "status": "success",
  "component": "$SCRIPT_NAME",
  "run_id": "$(json_escape "$RUN_ID")",
  "user_id": "$(json_escape "$USER_ID")",
  "workspace_id": "$(json_escape "$WORKSPACE_ID")",
  "environment": "$(json_escape "$DEPLOY_ENV")",
  "strategy": "$(json_escape "$DEPLOY_STRATEGY")",
  "artifact_path": "$(json_escape "$artifact_path")",
  "health_status": "$(json_escape "$health_status")",
  "started_at": "$(json_escape "$STARTED_AT")",
  "finished_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
JSON
}

main "$@"