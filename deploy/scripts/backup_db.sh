#!/usr/bin/env bash
# ==============================================================================
# William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
# File: deploy/scripts/backup_db.sh
# Agent/Module: Deployment Prompt Bible
# Component: BackupDb
# Purpose: PostgreSQL database backup script with safe defaults, audit hooks,
#          workspace/user metadata, checksum, compression, and retention cleanup.
#
# Production Rules:
# - Never hardcode secrets.
# - Read DB connection values from environment/config.
# - Support user_id/workspace_id metadata for SaaS isolation and auditability.
# - Route sensitive actions through Security Agent hook when configured.
# - Emit Verification Agent payload after completion.
# - Prepare useful metadata for Memory Agent compatibility.
# - Safe shell execution: strict mode, validated inputs, structured errors.
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# ------------------------------------------------------------------------------
# BackupDb Constants
# ------------------------------------------------------------------------------

SCRIPT_NAME="BackupDb"
SCRIPT_VERSION="1.0.0"
RUN_ID="$(date -u +"%Y%m%dT%H%M%SZ")-$$"
STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# ------------------------------------------------------------------------------
# Safe Defaults
# ------------------------------------------------------------------------------

BACKUP_ROOT="${BACKUP_ROOT:-./backups/database}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"
BACKUP_COMPRESS="${BACKUP_COMPRESS:-true}"
BACKUP_FORMAT="${BACKUP_FORMAT:-custom}" # custom | plain
BACKUP_LOCK_FILE="${BACKUP_LOCK_FILE:-/tmp/william_jarvis_backup_db.lock}"

# PostgreSQL connection values.
# Recommended production usage:
# export DATABASE_URL="postgresql://user:password@host:5432/dbname"
# OR export PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD
DATABASE_URL="${DATABASE_URL:-}"
PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5432}"
PGDATABASE="${PGDATABASE:-william_jarvis}"
PGUSER="${PGUSER:-postgres}"
PGPASSWORD="${PGPASSWORD:-}"

# Docker mode.
# Set DB_BACKUP_MODE=docker if Postgres runs inside a Docker Compose container.
DB_BACKUP_MODE="${DB_BACKUP_MODE:-auto}" # auto | local | docker
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-postgres}"
DOCKER_COMPOSE_FILE="${DOCKER_COMPOSE_FILE:-docker-compose.yml}"

# SaaS metadata. Optional but strongly recommended when a backup is triggered
# by a user/workspace task from the dashboard, API, or Master Agent.
USER_ID="${USER_ID:-system}"
WORKSPACE_ID="${WORKSPACE_ID:-system}"
REQUESTED_BY_ROLE="${REQUESTED_BY_ROLE:-system}"
REQUEST_SOURCE="${REQUEST_SOURCE:-deployment_script}"

# Optional policy controls.
REQUIRE_SECURITY_APPROVAL="${REQUIRE_SECURITY_APPROVAL:-false}"
ALLOWED_BACKUP_ROLES="${ALLOWED_BACKUP_ROLES:-owner,admin,system,security_agent}"

# Future agent integration hooks.
SECURITY_AGENT_HOOK_URL="${SECURITY_AGENT_HOOK_URL:-}"
AUDIT_LOG_HOOK_URL="${AUDIT_LOG_HOOK_URL:-}"
MEMORY_AGENT_HOOK_URL="${MEMORY_AGENT_HOOK_URL:-}"
VERIFICATION_AGENT_HOOK_URL="${VERIFICATION_AGENT_HOOK_URL:-}"

# Optional encryption command.
# Example:
# export BACKUP_ENCRYPT_COMMAND='openssl enc -aes-256-cbc -salt -pbkdf2 -pass env:BACKUP_ENCRYPTION_PASSWORD'
# The script avoids hardcoding encryption secrets.
BACKUP_ENCRYPT_COMMAND="${BACKUP_ENCRYPT_COMMAND:-}"

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

  printf '{"timestamp":"%s","level":"%s","component":"%s","run_id":"%s","event":"%s","user_id":"%s","workspace_id":"%s","message":"%s"}\n' \
    "$timestamp" \
    "$(json_escape "$level")" \
    "$SCRIPT_NAME" \
    "$(json_escape "$RUN_ID")" \
    "$(json_escape "$event")" \
    "$(json_escape "$USER_ID")" \
    "$(json_escape "$WORKSPACE_ID")" \
    "$(json_escape "$message")"
}

fail() {
  local event="$1"
  local message="$2"
  local code="${3:-1}"
  log_json "error" "$event" "$message"
  emit_verification_payload "failed" "$message" ""
  exit "$code"
}

# ------------------------------------------------------------------------------
# Cleanup / Error Trap
# ------------------------------------------------------------------------------

cleanup_lock() {
  if [[ -f "$BACKUP_LOCK_FILE" ]]; then
    local existing_pid
    existing_pid="$(cat "$BACKUP_LOCK_FILE" 2>/dev/null || true)"
    if [[ "$existing_pid" == "$$" ]]; then
      rm -f "$BACKUP_LOCK_FILE"
    fi
  fi
}

on_error() {
  local exit_code=$?
  local line_no="${1:-unknown}"
  cleanup_lock
  log_json "error" "script_error" "Backup failed at line ${line_no} with exit code ${exit_code}."
  emit_verification_payload "failed" "Backup failed at line ${line_no} with exit code ${exit_code}." ""
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

role_is_allowed() {
  local role="$1"
  local allowed_csv="$2"
  local item

  IFS=',' read -ra roles <<< "$allowed_csv"
  for item in "${roles[@]}"; do
    item="$(echo "$item" | xargs)"
    if [[ "$item" == "$role" ]]; then
      return 0
    fi
  done

  return 1
}

acquire_lock() {
  if [[ -f "$BACKUP_LOCK_FILE" ]]; then
    local old_pid
    old_pid="$(cat "$BACKUP_LOCK_FILE" 2>/dev/null || true)"

    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" >/dev/null 2>&1; then
      fail "backup_already_running" "Another database backup is already running with PID ${old_pid}." 75
    fi

    log_json "warning" "stale_lock_removed" "Removing stale lock file at ${BACKUP_LOCK_FILE}."
    rm -f "$BACKUP_LOCK_FILE"
  fi

  echo "$$" > "$BACKUP_LOCK_FILE"
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

  local response_code
  response_code="$(
    curl -sS -o /tmp/"${SCRIPT_NAME}_${hook_name}_${RUN_ID}.response" \
      -w "%{http_code}" \
      -X POST "$hook_url" \
      -H "Content-Type: application/json" \
      --data "$payload" || true
  )"

  if [[ "$response_code" =~ ^2[0-9][0-9]$ ]]; then
    log_json "info" "${hook_name}_sent" "${hook_name} hook accepted with HTTP ${response_code}."
  else
    log_json "warning" "${hook_name}_failed" "${hook_name} hook returned HTTP ${response_code}. Backup continues because hooks are non-blocking unless security approval is required."
  fi
}

security_approval_payload() {
  cat <<JSON
{
  "component": "$(json_escape "$SCRIPT_NAME")",
  "script_version": "$(json_escape "$SCRIPT_VERSION")",
  "run_id": "$(json_escape "$RUN_ID")",
  "action": "database_backup",
  "risk_level": "high",
  "requires_approval": ${REQUIRE_SECURITY_APPROVAL},
  "user_id": "$(json_escape "$USER_ID")",
  "workspace_id": "$(json_escape "$WORKSPACE_ID")",
  "requested_by_role": "$(json_escape "$REQUESTED_BY_ROLE")",
  "request_source": "$(json_escape "$REQUEST_SOURCE")",
  "database": "$(json_escape "$PGDATABASE")",
  "host": "$(json_escape "$PGHOST")",
  "started_at": "$(json_escape "$STARTED_AT")"
}
JSON
}

audit_payload() {
  local status="$1"
  local artifact_path="${2:-}"
  local message="${3:-}"

  cat <<JSON
{
  "component": "$(json_escape "$SCRIPT_NAME")",
  "script_version": "$(json_escape "$SCRIPT_VERSION")",
  "run_id": "$(json_escape "$RUN_ID")",
  "event_type": "database_backup",
  "status": "$(json_escape "$status")",
  "user_id": "$(json_escape "$USER_ID")",
  "workspace_id": "$(json_escape "$WORKSPACE_ID")",
  "requested_by_role": "$(json_escape "$REQUESTED_BY_ROLE")",
  "request_source": "$(json_escape "$REQUEST_SOURCE")",
  "database": "$(json_escape "$PGDATABASE")",
  "backup_path": "$(json_escape "$artifact_path")",
  "message": "$(json_escape "$message")",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
JSON
}

memory_payload() {
  local artifact_path="$1"
  local checksum="$2"

  cat <<JSON
{
  "component": "$(json_escape "$SCRIPT_NAME")",
  "memory_type": "deployment_event",
  "importance": "high",
  "user_id": "$(json_escape "$USER_ID")",
  "workspace_id": "$(json_escape "$WORKSPACE_ID")",
  "event": "database_backup_completed",
  "summary": "Database backup completed for workspace $(json_escape "$WORKSPACE_ID").",
  "metadata": {
    "run_id": "$(json_escape "$RUN_ID")",
    "backup_path": "$(json_escape "$artifact_path")",
    "checksum_sha256": "$(json_escape "$checksum")",
    "database": "$(json_escape "$PGDATABASE")",
    "created_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  }
}
JSON
}

verification_payload() {
  local status="$1"
  local message="$2"
  local artifact_path="${3:-}"
  local checksum="${4:-}"

  cat <<JSON
{
  "component": "$(json_escape "$SCRIPT_NAME")",
  "script_version": "$(json_escape "$SCRIPT_VERSION")",
  "run_id": "$(json_escape "$RUN_ID")",
  "verification_type": "deployment_database_backup",
  "status": "$(json_escape "$status")",
  "user_id": "$(json_escape "$USER_ID")",
  "workspace_id": "$(json_escape "$WORKSPACE_ID")",
  "artifact_path": "$(json_escape "$artifact_path")",
  "checksum_sha256": "$(json_escape "$checksum")",
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
  local checksum="${4:-}"
  local payload
  payload="$(verification_payload "$status" "$message" "$artifact_path" "$checksum")"

  log_json "info" "verification_payload_prepared" "$payload"
  post_hook_json "$VERIFICATION_AGENT_HOOK_URL" "$payload" "verification_agent"
}

request_security_approval() {
  local payload
  payload="$(security_approval_payload)"

  log_json "info" "security_payload_prepared" "$payload"

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
    fail "security_approval_denied" "Security Agent did not approve backup request. HTTP ${response_code}." 77
  fi

  if grep -Eiq '"approved"[[:space:]]*:[[:space:]]*false' "$response_file"; then
    fail "security_approval_denied" "Security Agent explicitly denied backup request." 77
  fi

  log_json "info" "security_approval_granted" "Security Agent approval accepted."
}

# ------------------------------------------------------------------------------
# Database Backup Mode Detection
# ------------------------------------------------------------------------------

docker_container_running() {
  if ! command -v docker >/dev/null 2>&1; then
    return 1
  fi

  docker ps --format '{{.Names}}' | grep -Fxq "$POSTGRES_CONTAINER"
}

resolve_backup_mode() {
  case "$DB_BACKUP_MODE" in
    local)
      echo "local"
      ;;
    docker)
      echo "docker"
      ;;
    auto)
      if docker_container_running; then
        echo "docker"
      else
        echo "local"
      fi
      ;;
    *)
      fail "invalid_config" "DB_BACKUP_MODE must be one of: auto, local, docker. Current value: ${DB_BACKUP_MODE}" 2
      ;;
  esac
}

# ------------------------------------------------------------------------------
# Backup Execution
# ------------------------------------------------------------------------------

prepare_directories() {
  local workspace_dir="$1"
  mkdir -p "$workspace_dir"
  chmod 700 "$BACKUP_ROOT" 2>/dev/null || true
  chmod 700 "$workspace_dir" 2>/dev/null || true
}

backup_extension() {
  if [[ "$BACKUP_FORMAT" == "plain" ]]; then
    echo "sql"
  else
    echo "dump"
  fi
}

pg_dump_format_flag() {
  if [[ "$BACKUP_FORMAT" == "plain" ]]; then
    echo "p"
  elif [[ "$BACKUP_FORMAT" == "custom" ]]; then
    echo "c"
  else
    fail "invalid_config" "BACKUP_FORMAT must be custom or plain. Current value: ${BACKUP_FORMAT}" 2
  fi
}

run_pg_dump_local() {
  local output_path="$1"
  local format_flag
  format_flag="$(pg_dump_format_flag)"

  require_command "pg_dump"

  log_json "info" "backup_started" "Starting local pg_dump backup."

  if [[ -n "$DATABASE_URL" ]]; then
    pg_dump "$DATABASE_URL" \
      --format="$format_flag" \
      --no-owner \
      --no-privileges \
      --file="$output_path"
  else
    if [[ -z "$PGPASSWORD" ]]; then
      log_json "warning" "pgpassword_missing" "PGPASSWORD is empty. pg_dump may prompt or fail depending on local authentication."
    fi

    PGPASSWORD="$PGPASSWORD" pg_dump \
      --host="$PGHOST" \
      --port="$PGPORT" \
      --username="$PGUSER" \
      --dbname="$PGDATABASE" \
      --format="$format_flag" \
      --no-owner \
      --no-privileges \
      --file="$output_path"
  fi
}

run_pg_dump_docker() {
  local output_path="$1"
  local format_flag
  format_flag="$(pg_dump_format_flag)"

  require_command "docker"

  if ! docker_container_running; then
    fail "docker_container_not_running" "Docker container '${POSTGRES_CONTAINER}' is not running." 69
  fi

  log_json "info" "backup_started" "Starting Docker pg_dump backup from container ${POSTGRES_CONTAINER}."

  if [[ -n "$DATABASE_URL" ]]; then
    docker exec "$POSTGRES_CONTAINER" sh -c \
      "pg_dump \"\$DATABASE_URL\" --format='${format_flag}' --no-owner --no-privileges" > "$output_path"
  else
    docker exec \
      -e PGPASSWORD="$PGPASSWORD" \
      "$POSTGRES_CONTAINER" \
      pg_dump \
        --host="${PGHOST}" \
        --port="${PGPORT}" \
        --username="${PGUSER}" \
        --dbname="${PGDATABASE}" \
        --format="${format_flag}" \
        --no-owner \
        --no-privileges > "$output_path"
  fi
}

compress_backup() {
  local source_path="$1"

  if [[ "$BACKUP_COMPRESS" != "true" ]]; then
    echo "$source_path"
    return 0
  fi

  require_command "gzip"

  local compressed_path="${source_path}.gz"
  gzip -c "$source_path" > "$compressed_path"
  rm -f "$source_path"

  echo "$compressed_path"
}

encrypt_backup_if_configured() {
  local source_path="$1"

  if [[ -z "$BACKUP_ENCRYPT_COMMAND" ]]; then
    echo "$source_path"
    return 0
  fi

  local encrypted_path="${source_path}.enc"

  log_json "info" "backup_encryption_started" "Encrypting backup using configured BACKUP_ENCRYPT_COMMAND."

  # shellcheck disable=SC2086
  $BACKUP_ENCRYPT_COMMAND < "$source_path" > "$encrypted_path"

  rm -f "$source_path"
  chmod 600 "$encrypted_path" 2>/dev/null || true

  echo "$encrypted_path"
}

calculate_checksum() {
  local file_path="$1"

  require_command "sha256sum"

  sha256sum "$file_path" | awk '{print $1}'
}

write_metadata_file() {
  local backup_path="$1"
  local checksum="$2"
  local metadata_path="${backup_path}.metadata.json"

  cat > "$metadata_path" <<JSON
{
  "component": "$SCRIPT_NAME",
  "script_version": "$SCRIPT_VERSION",
  "run_id": "$(json_escape "$RUN_ID")",
  "user_id": "$(json_escape "$USER_ID")",
  "workspace_id": "$(json_escape "$WORKSPACE_ID")",
  "requested_by_role": "$(json_escape "$REQUESTED_BY_ROLE")",
  "request_source": "$(json_escape "$REQUEST_SOURCE")",
  "database": "$(json_escape "$PGDATABASE")",
  "host": "$(json_escape "$PGHOST")",
  "port": "$(json_escape "$PGPORT")",
  "backup_format": "$(json_escape "$BACKUP_FORMAT")",
  "compressed": "$(json_escape "$BACKUP_COMPRESS")",
  "encrypted": "$([[ -n "$BACKUP_ENCRYPT_COMMAND" ]] && echo "true" || echo "false")",
  "backup_path": "$(json_escape "$backup_path")",
  "checksum_sha256": "$(json_escape "$checksum")",
  "created_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
JSON

  chmod 600 "$metadata_path" 2>/dev/null || true
  echo "$metadata_path"
}

cleanup_old_backups() {
  validate_integer "$BACKUP_RETENTION_DAYS" "BACKUP_RETENTION_DAYS"

  if [[ "$BACKUP_RETENTION_DAYS" -eq 0 ]]; then
    log_json "info" "retention_skipped" "BACKUP_RETENTION_DAYS is 0, retention cleanup skipped."
    return 0
  fi

  if [[ ! -d "$BACKUP_ROOT" ]]; then
    return 0
  fi

  log_json "info" "retention_cleanup_started" "Removing backups older than ${BACKUP_RETENTION_DAYS} days from ${BACKUP_ROOT}."

  find "$BACKUP_ROOT" \
    -type f \
    \( -name "*.dump" -o -name "*.dump.gz" -o -name "*.dump.gz.enc" -o -name "*.sql" -o -name "*.sql.gz" -o -name "*.sql.gz.enc" -o -name "*.metadata.json" \) \
    -mtime +"$BACKUP_RETENTION_DAYS" \
    -print \
    -delete | while read -r deleted_file; do
      log_json "info" "old_backup_deleted" "Deleted old backup artifact: ${deleted_file}"
    done
}

# ------------------------------------------------------------------------------
# Main Flow
# ------------------------------------------------------------------------------

main() {
  log_json "info" "script_started" "Starting ${SCRIPT_NAME} v${SCRIPT_VERSION}."

  validate_identifier "$USER_ID" "USER_ID"
  validate_identifier "$WORKSPACE_ID" "WORKSPACE_ID"
  validate_identifier "$REQUESTED_BY_ROLE" "REQUESTED_BY_ROLE"

  validate_integer "$BACKUP_RETENTION_DAYS" "BACKUP_RETENTION_DAYS"

  if ! role_is_allowed "$REQUESTED_BY_ROLE" "$ALLOWED_BACKUP_ROLES"; then
    fail "role_not_allowed" "Role '${REQUESTED_BY_ROLE}' is not allowed to run database backups." 78
  fi

  acquire_lock

  local mode
  mode="$(resolve_backup_mode)"
  log_json "info" "backup_mode_resolved" "Database backup mode resolved as '${mode}'."

  local workspace_dir
  workspace_dir="${BACKUP_ROOT}/workspace_${WORKSPACE_ID}"
  prepare_directories "$workspace_dir"

  request_security_approval

  local extension
  extension="$(backup_extension)"

  local raw_backup_path
  raw_backup_path="${workspace_dir}/${PGDATABASE}_${WORKSPACE_ID}_${RUN_ID}.${extension}"

  local audit_start
  audit_start="$(audit_payload "started" "$raw_backup_path" "Database backup started.")"
  post_hook_json "$AUDIT_LOG_HOOK_URL" "$audit_start" "audit_log"

  if [[ "$mode" == "docker" ]]; then
    run_pg_dump_docker "$raw_backup_path"
  else
    run_pg_dump_local "$raw_backup_path"
  fi

  if [[ ! -s "$raw_backup_path" ]]; then
    fail "empty_backup" "Backup file was created but is empty: ${raw_backup_path}" 70
  fi

  chmod 600 "$raw_backup_path" 2>/dev/null || true

  local final_backup_path
  final_backup_path="$(compress_backup "$raw_backup_path")"
  final_backup_path="$(encrypt_backup_if_configured "$final_backup_path")"

  if [[ ! -s "$final_backup_path" ]]; then
    fail "invalid_backup_artifact" "Final backup artifact is missing or empty: ${final_backup_path}" 70
  fi

  local checksum
  checksum="$(calculate_checksum "$final_backup_path")"

  local checksum_path="${final_backup_path}.sha256"
  printf '%s  %s\n' "$checksum" "$(basename "$final_backup_path")" > "$checksum_path"
  chmod 600 "$checksum_path" 2>/dev/null || true

  local metadata_path
  metadata_path="$(write_metadata_file "$final_backup_path" "$checksum")"

  cleanup_old_backups

  local audit_success
  audit_success="$(audit_payload "completed" "$final_backup_path" "Database backup completed successfully.")"
  post_hook_json "$AUDIT_LOG_HOOK_URL" "$audit_success" "audit_log"

  local memory_event
  memory_event="$(memory_payload "$final_backup_path" "$checksum")"
  post_hook_json "$MEMORY_AGENT_HOOK_URL" "$memory_event" "memory_agent"

  emit_verification_payload "completed" "Database backup completed successfully." "$final_backup_path" "$checksum"

  log_json "info" "backup_completed" "Backup completed: ${final_backup_path}"
  log_json "info" "checksum_created" "Checksum created: ${checksum_path}"
  log_json "info" "metadata_created" "Metadata created: ${metadata_path}"

  cat <<JSON
{
  "status": "success",
  "component": "$SCRIPT_NAME",
  "run_id": "$(json_escape "$RUN_ID")",
  "user_id": "$(json_escape "$USER_ID")",
  "workspace_id": "$(json_escape "$WORKSPACE_ID")",
  "backup_path": "$(json_escape "$final_backup_path")",
  "checksum_path": "$(json_escape "$checksum_path")",
  "metadata_path": "$(json_escape "$metadata_path")",
  "checksum_sha256": "$(json_escape "$checksum")",
  "started_at": "$(json_escape "$STARTED_AT")",
  "finished_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
JSON
}

main "$@"