#!/usr/bin/env bash
# ==============================================================================
# William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
# File: deploy/scripts/restore_db.sh
# Agent/Module: Deployment Prompt Bible
# Component: RestoreDb
# Purpose: PostgreSQL database restore script with safe defaults, explicit
#          confirmation, checksum validation, pre-restore backup, audit hooks,
#          workspace/user metadata, and future agent integration payloads.
#
# Production Rules:
# - Never hardcode secrets.
# - Read DB connection values from environment/config.
# - Restores are destructive and must be treated as sensitive actions.
# - Support user_id/workspace_id metadata for SaaS isolation and auditability.
# - Route sensitive restore actions through Security Agent hook when configured.
# - Emit Verification Agent payload after completion/failure.
# - Prepare useful metadata for Memory Agent compatibility.
# - Safe shell execution: strict mode, validated inputs, structured errors.
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# ------------------------------------------------------------------------------
# RestoreDb Constants
# ------------------------------------------------------------------------------

SCRIPT_NAME="RestoreDb"
SCRIPT_VERSION="1.0.0"
RUN_ID="$(date -u +"%Y%m%dT%H%M%SZ")-$$"
STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# ------------------------------------------------------------------------------
# Safe Defaults
# ------------------------------------------------------------------------------

BACKUP_ROOT="${BACKUP_ROOT:-./backups/database}"
RESTORE_LOCK_FILE="${RESTORE_LOCK_FILE:-/tmp/william_jarvis_restore_db.lock}"

# Required input:
# export RESTORE_BACKUP_PATH="./backups/database/workspace_system/file.dump.gz"
RESTORE_BACKUP_PATH="${RESTORE_BACKUP_PATH:-}"

# Restore confirmation:
# Must be explicitly set to RESTORE_DATABASE_NOW unless --dry-run is used.
RESTORE_CONFIRMATION="${RESTORE_CONFIRMATION:-}"
DRY_RUN="${DRY_RUN:-false}"

# Restore options.
DROP_EXISTING_DB_OBJECTS="${DROP_EXISTING_DB_OBJECTS:-false}"
CLEAN_RESTORE="${CLEAN_RESTORE:-true}"
NO_OWNER="${NO_OWNER:-true}"
NO_PRIVILEGES="${NO_PRIVILEGES:-true}"
CREATE_PRE_RESTORE_BACKUP="${CREATE_PRE_RESTORE_BACKUP:-true}"
RESTORE_FORMAT="${RESTORE_FORMAT:-auto}" # auto | custom | plain

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
# Set DB_RESTORE_MODE=docker if Postgres runs inside a Docker Compose container.
DB_RESTORE_MODE="${DB_RESTORE_MODE:-auto}" # auto | local | docker
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-postgres}"

# SaaS metadata. Strongly recommended when triggered by dashboard/API/Master Agent.
USER_ID="${USER_ID:-system}"
WORKSPACE_ID="${WORKSPACE_ID:-system}"
REQUESTED_BY_ROLE="${REQUESTED_BY_ROLE:-system}"
REQUEST_SOURCE="${REQUEST_SOURCE:-deployment_script}"

# Restore is destructive. Security approval defaults to true.
REQUIRE_SECURITY_APPROVAL="${REQUIRE_SECURITY_APPROVAL:-true}"
ALLOWED_RESTORE_ROLES="${ALLOWED_RESTORE_ROLES:-owner,admin,system,security_agent}"

# Optional plan/subscription gate. Deployment scripts usually run system-side,
# but this allows dashboard/API-triggered restore workflows to enforce access.
REQUIRE_ACTIVE_SUBSCRIPTION="${REQUIRE_ACTIVE_SUBSCRIPTION:-false}"
SUBSCRIPTION_STATUS="${SUBSCRIPTION_STATUS:-active}"
ALLOWED_RESTORE_PLANS="${ALLOWED_RESTORE_PLANS:-enterprise,pro,system}"
CURRENT_PLAN="${CURRENT_PLAN:-system}"

# Future agent integration hooks.
SECURITY_AGENT_HOOK_URL="${SECURITY_AGENT_HOOK_URL:-}"
AUDIT_LOG_HOOK_URL="${AUDIT_LOG_HOOK_URL:-}"
MEMORY_AGENT_HOOK_URL="${MEMORY_AGENT_HOOK_URL:-}"
VERIFICATION_AGENT_HOOK_URL="${VERIFICATION_AGENT_HOOK_URL:-}"

# Optional decryption command.
# Example:
# export BACKUP_DECRYPT_COMMAND='openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_ENCRYPTION_PASSWORD'
# The script avoids hardcoding encryption secrets.
BACKUP_DECRYPT_COMMAND="${BACKUP_DECRYPT_COMMAND:-}"

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
  emit_verification_payload "failed" "$message" "" ""
  exit "$code"
}

# ------------------------------------------------------------------------------
# Cleanup / Error Trap
# ------------------------------------------------------------------------------

TEMP_FILES=()

register_temp_file() {
  TEMP_FILES+=("$1")
}

cleanup_temp_files() {
  local file_path
  for file_path in "${TEMP_FILES[@]:-}"; do
    if [[ -n "$file_path" && -f "$file_path" ]]; then
      rm -f "$file_path"
    fi
  done
}

cleanup_lock() {
  if [[ -f "$RESTORE_LOCK_FILE" ]]; then
    local existing_pid
    existing_pid="$(cat "$RESTORE_LOCK_FILE" 2>/dev/null || true)"
    if [[ "$existing_pid" == "$$" ]]; then
      rm -f "$RESTORE_LOCK_FILE"
    fi
  fi
}

on_error() {
  local exit_code=$?
  local line_no="${1:-unknown}"
  cleanup_temp_files
  cleanup_lock
  log_json "error" "script_error" "Restore failed at line ${line_no} with exit code ${exit_code}."
  emit_verification_payload "failed" "Restore failed at line ${line_no} with exit code ${exit_code}." "" ""
  exit "$exit_code"
}

trap 'on_error $LINENO' ERR
trap 'cleanup_temp_files; cleanup_lock' EXIT

# ------------------------------------------------------------------------------
# Validation Helpers
# ------------------------------------------------------------------------------

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    fail "missing_dependency" "Required command not found: ${command_name}" 127
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
  if [[ -f "$RESTORE_LOCK_FILE" ]]; then
    local old_pid
    old_pid="$(cat "$RESTORE_LOCK_FILE" 2>/dev/null || true)"

    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" >/dev/null 2>&1; then
      fail "restore_already_running" "Another database restore is already running with PID ${old_pid}." 75
    fi

    log_json "warning" "stale_lock_removed" "Removing stale lock file at ${RESTORE_LOCK_FILE}."
    rm -f "$RESTORE_LOCK_FILE"
  fi

  echo "$$" > "$RESTORE_LOCK_FILE"
}

validate_access_controls() {
  validate_identifier "$USER_ID" "USER_ID"
  validate_identifier "$WORKSPACE_ID" "WORKSPACE_ID"
  validate_identifier "$REQUESTED_BY_ROLE" "REQUESTED_BY_ROLE"

  if ! csv_contains "$REQUESTED_BY_ROLE" "$ALLOWED_RESTORE_ROLES"; then
    fail "role_not_allowed" "Role '${REQUESTED_BY_ROLE}' is not allowed to restore databases." 78
  fi

  if [[ "$REQUIRE_ACTIVE_SUBSCRIPTION" == "true" ]]; then
    if [[ "$SUBSCRIPTION_STATUS" != "active" ]]; then
      fail "subscription_inactive" "Restore requires an active subscription. Current status: ${SUBSCRIPTION_STATUS}" 79
    fi

    if ! csv_contains "$CURRENT_PLAN" "$ALLOWED_RESTORE_PLANS"; then
      fail "plan_not_allowed" "Plan '${CURRENT_PLAN}' is not allowed to restore databases." 79
    fi
  fi
}

validate_restore_confirmation() {
  if [[ "$DRY_RUN" == "true" ]]; then
    log_json "info" "dry_run_enabled" "Dry run enabled. No database changes will be made."
    return 0
  fi

  if [[ "$RESTORE_CONFIRMATION" != "RESTORE_DATABASE_NOW" ]]; then
    fail "restore_not_confirmed" "Database restore is destructive. Set RESTORE_CONFIRMATION=RESTORE_DATABASE_NOW to continue." 76
  fi
}

validate_restore_path() {
  if [[ -z "$RESTORE_BACKUP_PATH" ]]; then
    fail "missing_restore_backup_path" "RESTORE_BACKUP_PATH is required." 2
  fi

  if [[ "$RESTORE_BACKUP_PATH" == *".."* ]]; then
    fail "unsafe_restore_path" "RESTORE_BACKUP_PATH cannot contain '..'." 2
  fi

  if [[ ! -f "$RESTORE_BACKUP_PATH" ]]; then
    fail "restore_file_not_found" "Restore backup file not found: ${RESTORE_BACKUP_PATH}" 66
  fi

  if [[ ! -s "$RESTORE_BACKUP_PATH" ]]; then
    fail "restore_file_empty" "Restore backup file is empty: ${RESTORE_BACKUP_PATH}" 66
  fi

  local expected_workspace_dir
  expected_workspace_dir="${BACKUP_ROOT}/workspace_${WORKSPACE_ID}"

  case "$RESTORE_BACKUP_PATH" in
    "$expected_workspace_dir"/*)
      log_json "info" "workspace_path_validated" "Restore file is inside expected workspace directory."
      ;;
    *)
      if [[ "$WORKSPACE_ID" != "system" ]]; then
        fail "workspace_isolation_violation" "Restore file must be inside ${expected_workspace_dir} for workspace isolation." 73
      fi
      log_json "warning" "system_workspace_path_override" "WORKSPACE_ID=system allows restore file outside workspace directory."
      ;;
  esac
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
    log_json "warning" "${hook_name}_failed" "${hook_name} hook returned HTTP ${response_code}."
  fi
}

security_approval_payload() {
  cat <<JSON
{
  "component": "$(json_escape "$SCRIPT_NAME")",
  "script_version": "$(json_escape "$SCRIPT_VERSION")",
  "run_id": "$(json_escape "$RUN_ID")",
  "action": "database_restore",
  "risk_level": "critical",
  "requires_approval": ${REQUIRE_SECURITY_APPROVAL},
  "user_id": "$(json_escape "$USER_ID")",
  "workspace_id": "$(json_escape "$WORKSPACE_ID")",
  "requested_by_role": "$(json_escape "$REQUESTED_BY_ROLE")",
  "request_source": "$(json_escape "$REQUEST_SOURCE")",
  "database": "$(json_escape "$PGDATABASE")",
  "host": "$(json_escape "$PGHOST")",
  "restore_backup_path": "$(json_escape "$RESTORE_BACKUP_PATH")",
  "dry_run": ${DRY_RUN},
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
  "event_type": "database_restore",
  "status": "$(json_escape "$status")",
  "user_id": "$(json_escape "$USER_ID")",
  "workspace_id": "$(json_escape "$WORKSPACE_ID")",
  "requested_by_role": "$(json_escape "$REQUESTED_BY_ROLE")",
  "request_source": "$(json_escape "$REQUEST_SOURCE")",
  "database": "$(json_escape "$PGDATABASE")",
  "restore_backup_path": "$(json_escape "$artifact_path")",
  "message": "$(json_escape "$message")",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
JSON
}

memory_payload() {
  local artifact_path="$1"
  local checksum="$2"
  local status="$3"

  cat <<JSON
{
  "component": "$(json_escape "$SCRIPT_NAME")",
  "memory_type": "deployment_event",
  "importance": "critical",
  "user_id": "$(json_escape "$USER_ID")",
  "workspace_id": "$(json_escape "$WORKSPACE_ID")",
  "event": "database_restore_${status}",
  "summary": "Database restore ${status} for workspace $(json_escape "$WORKSPACE_ID").",
  "metadata": {
    "run_id": "$(json_escape "$RUN_ID")",
    "restore_backup_path": "$(json_escape "$artifact_path")",
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
  "verification_type": "deployment_database_restore",
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

  if [[ "$DRY_RUN" == "true" ]]; then
    post_hook_json "$SECURITY_AGENT_HOOK_URL" "$payload" "security_agent"
    return 0
  fi

  if [[ "$REQUIRE_SECURITY_APPROVAL" != "true" ]]; then
    post_hook_json "$SECURITY_AGENT_HOOK_URL" "$payload" "security_agent"
    return 0
  fi

  if [[ -z "$SECURITY_AGENT_HOOK_URL" ]]; then
    fail "security_approval_required" "Security approval is required for restore, but SECURITY_AGENT_HOOK_URL is not configured." 77
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
    fail "security_approval_denied" "Security Agent did not approve restore request. HTTP ${response_code}." 77
  fi

  if grep -Eiq '"approved"[[:space:]]*:[[:space:]]*false' "$response_file"; then
    fail "security_approval_denied" "Security Agent explicitly denied restore request." 77
  fi

  log_json "info" "security_approval_granted" "Security Agent approval accepted."
}

# ------------------------------------------------------------------------------
# Backup Inspection / Checksum
# ------------------------------------------------------------------------------

calculate_checksum() {
  local file_path="$1"

  require_command "sha256sum"

  sha256sum "$file_path" | awk '{print $1}'
}

verify_checksum_if_available() {
  local file_path="$1"
  local checksum_path="${file_path}.sha256"

  if [[ ! -f "$checksum_path" ]]; then
    log_json "warning" "checksum_missing" "Checksum file not found: ${checksum_path}. Restore will continue after logging warning."
    calculate_checksum "$file_path"
    return 0
  fi

  require_command "sha256sum"

  local checksum_dir
  checksum_dir="$(dirname "$file_path")"

  log_json "info" "checksum_verification_started" "Verifying checksum: ${checksum_path}"

  (
    cd "$checksum_dir"
    sha256sum -c "$(basename "$checksum_path")" >/dev/null
  )

  local checksum
  checksum="$(calculate_checksum "$file_path")"
  log_json "info" "checksum_verified" "Backup checksum verified successfully."

  echo "$checksum"
}

detect_restore_format() {
  local file_path="$1"

  if [[ "$RESTORE_FORMAT" == "custom" || "$RESTORE_FORMAT" == "plain" ]]; then
    echo "$RESTORE_FORMAT"
    return 0
  fi

  if [[ "$RESTORE_FORMAT" != "auto" ]]; then
    fail "invalid_config" "RESTORE_FORMAT must be auto, custom, or plain. Current value: ${RESTORE_FORMAT}" 2
  fi

  case "$file_path" in
    *.sql|*.sql.gz|*.sql.enc|*.sql.gz.enc)
      echo "plain"
      ;;
    *.dump|*.dump.gz|*.dump.enc|*.dump.gz.enc)
      echo "custom"
      ;;
    *)
      log_json "warning" "restore_format_unknown" "Could not detect restore format from extension. Defaulting to custom."
      echo "custom"
      ;;
  esac
}

prepare_restore_input() {
  local source_path="$1"
  local prepared_path="$source_path"

  if [[ "$source_path" == *.enc ]]; then
    if [[ -z "$BACKUP_DECRYPT_COMMAND" ]]; then
      fail "decrypt_command_missing" "Backup file appears encrypted but BACKUP_DECRYPT_COMMAND is not configured." 65
    fi

    local decrypted_path="/tmp/${SCRIPT_NAME}_${RUN_ID}_decrypted"
    register_temp_file "$decrypted_path"

    log_json "info" "backup_decryption_started" "Decrypting backup into temporary restore input."

    # shellcheck disable=SC2086
    $BACKUP_DECRYPT_COMMAND < "$source_path" > "$decrypted_path"

    if [[ ! -s "$decrypted_path" ]]; then
      fail "decryption_failed" "Decrypted restore file is empty." 65
    fi

    prepared_path="$decrypted_path"
  fi

  if [[ "$prepared_path" == *.gz ]]; then
    require_command "gzip"

    local decompressed_path="/tmp/${SCRIPT_NAME}_${RUN_ID}_decompressed"
    register_temp_file "$decompressed_path"

    log_json "info" "backup_decompression_started" "Decompressing backup into temporary restore input."

    gzip -dc "$prepared_path" > "$decompressed_path"

    if [[ ! -s "$decompressed_path" ]]; then
      fail "decompression_failed" "Decompressed restore file is empty." 65
    fi

    prepared_path="$decompressed_path"
  fi

  echo "$prepared_path"
}

# ------------------------------------------------------------------------------
# Database Mode Detection
# ------------------------------------------------------------------------------

docker_container_running() {
  if ! command -v docker >/dev/null 2>&1; then
    return 1
  fi

  docker ps --format '{{.Names}}' | grep -Fxq "$POSTGRES_CONTAINER"
}

resolve_restore_mode() {
  case "$DB_RESTORE_MODE" in
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
      fail "invalid_config" "DB_RESTORE_MODE must be one of: auto, local, docker. Current value: ${DB_RESTORE_MODE}" 2
      ;;
  esac
}

# ------------------------------------------------------------------------------
# Pre-Restore Backup
# ------------------------------------------------------------------------------

create_pre_restore_backup_local() {
  local output_path="$1"

  require_command "pg_dump"

  if [[ -n "$DATABASE_URL" ]]; then
    pg_dump "$DATABASE_URL" \
      --format="c" \
      --no-owner \
      --no-privileges \
      --file="$output_path"
  else
    PGPASSWORD="$PGPASSWORD" pg_dump \
      --host="$PGHOST" \
      --port="$PGPORT" \
      --username="$PGUSER" \
      --dbname="$PGDATABASE" \
      --format="c" \
      --no-owner \
      --no-privileges \
      --file="$output_path"
  fi
}

create_pre_restore_backup_docker() {
  local output_path="$1"

  require_command "docker"

  if ! docker_container_running; then
    fail "docker_container_not_running" "Docker container '${POSTGRES_CONTAINER}' is not running." 69
  fi

  if [[ -n "$DATABASE_URL" ]]; then
    docker exec "$POSTGRES_CONTAINER" sh -c \
      "pg_dump \"\$DATABASE_URL\" --format='c' --no-owner --no-privileges" > "$output_path"
  else
    docker exec \
      -e PGPASSWORD="$PGPASSWORD" \
      "$POSTGRES_CONTAINER" \
      pg_dump \
        --host="${PGHOST}" \
        --port="${PGPORT}" \
        --username="${PGUSER}" \
        --dbname="${PGDATABASE}" \
        --format="c" \
        --no-owner \
        --no-privileges > "$output_path"
  fi
}

create_pre_restore_backup() {
  local mode="$1"

  if [[ "$CREATE_PRE_RESTORE_BACKUP" != "true" ]]; then
    log_json "warning" "pre_restore_backup_skipped" "CREATE_PRE_RESTORE_BACKUP is false. No safety backup will be created."
    echo ""
    return 0
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    log_json "info" "pre_restore_backup_dry_run" "Dry run enabled. Pre-restore backup skipped."
    echo ""
    return 0
  fi

  local workspace_dir
  workspace_dir="${BACKUP_ROOT}/workspace_${WORKSPACE_ID}"
  mkdir -p "$workspace_dir"
  chmod 700 "$workspace_dir" 2>/dev/null || true

  local output_path
  output_path="${workspace_dir}/${PGDATABASE}_${WORKSPACE_ID}_${RUN_ID}_pre_restore.dump"

  log_json "info" "pre_restore_backup_started" "Creating pre-restore safety backup: ${output_path}"

  if [[ "$mode" == "docker" ]]; then
    create_pre_restore_backup_docker "$output_path"
  else
    create_pre_restore_backup_local "$output_path"
  fi

  if [[ ! -s "$output_path" ]]; then
    fail "pre_restore_backup_failed" "Pre-restore backup was created but is empty: ${output_path}" 70
  fi

  gzip -c "$output_path" > "${output_path}.gz"
  rm -f "$output_path"
  chmod 600 "${output_path}.gz" 2>/dev/null || true

  log_json "info" "pre_restore_backup_completed" "Pre-restore safety backup created: ${output_path}.gz"

  echo "${output_path}.gz"
}

# ------------------------------------------------------------------------------
# Restore Commands
# ------------------------------------------------------------------------------

pg_restore_common_args() {
  local args=()

  if [[ "$CLEAN_RESTORE" == "true" || "$DROP_EXISTING_DB_OBJECTS" == "true" ]]; then
    args+=("--clean" "--if-exists")
  fi

  if [[ "$NO_OWNER" == "true" ]]; then
    args+=("--no-owner")
  fi

  if [[ "$NO_PRIVILEGES" == "true" ]]; then
    args+=("--no-privileges")
  fi

  printf '%s\n' "${args[@]}"
}

run_restore_local_custom() {
  local input_path="$1"

  require_command "pg_restore"

  local args=()
  mapfile -t args < <(pg_restore_common_args)

  if [[ -n "$DATABASE_URL" ]]; then
    pg_restore "${args[@]}" \
      --dbname="$DATABASE_URL" \
      "$input_path"
  else
    PGPASSWORD="$PGPASSWORD" pg_restore "${args[@]}" \
      --host="$PGHOST" \
      --port="$PGPORT" \
      --username="$PGUSER" \
      --dbname="$PGDATABASE" \
      "$input_path"
  fi
}

run_restore_local_plain() {
  local input_path="$1"

  require_command "psql"

  if [[ -n "$DATABASE_URL" ]]; then
    psql "$DATABASE_URL" \
      --set ON_ERROR_STOP=on \
      --file="$input_path"
  else
    PGPASSWORD="$PGPASSWORD" psql \
      --host="$PGHOST" \
      --port="$PGPORT" \
      --username="$PGUSER" \
      --dbname="$PGDATABASE" \
      --set ON_ERROR_STOP=on \
      --file="$input_path"
  fi
}

run_restore_docker_custom() {
  local input_path="$1"

  require_command "docker"

  if ! docker_container_running; then
    fail "docker_container_not_running" "Docker container '${POSTGRES_CONTAINER}' is not running." 69
  fi

  local args=()
  mapfile -t args < <(pg_restore_common_args)

  if [[ -n "$DATABASE_URL" ]]; then
    cat "$input_path" | docker exec -i "$POSTGRES_CONTAINER" \
      pg_restore "${args[@]}" \
      --dbname="$DATABASE_URL"
  else
    cat "$input_path" | docker exec -i \
      -e PGPASSWORD="$PGPASSWORD" \
      "$POSTGRES_CONTAINER" \
      pg_restore "${args[@]}" \
        --host="${PGHOST}" \
        --port="${PGPORT}" \
        --username="${PGUSER}" \
        --dbname="${PGDATABASE}"
  fi
}

run_restore_docker_plain() {
  local input_path="$1"

  require_command "docker"

  if ! docker_container_running; then
    fail "docker_container_not_running" "Docker container '${POSTGRES_CONTAINER}' is not running." 69
  fi

  if [[ -n "$DATABASE_URL" ]]; then
    cat "$input_path" | docker exec -i "$POSTGRES_CONTAINER" \
      psql "$DATABASE_URL" \
        --set ON_ERROR_STOP=on
  else
    cat "$input_path" | docker exec -i \
      -e PGPASSWORD="$PGPASSWORD" \
      "$POSTGRES_CONTAINER" \
      psql \
        --host="${PGHOST}" \
        --port="${PGPORT}" \
        --username="${PGUSER}" \
        --dbname="${PGDATABASE}" \
        --set ON_ERROR_STOP=on
  fi
}

run_restore() {
  local mode="$1"
  local restore_format="$2"
  local input_path="$3"

  if [[ "$DRY_RUN" == "true" ]]; then
    log_json "info" "restore_dry_run_success" "Dry run completed. Restore input validated. No database changes made."
    return 0
  fi

  log_json "info" "restore_started" "Starting ${restore_format} restore using ${mode} mode."

  if [[ "$mode" == "docker" && "$restore_format" == "custom" ]]; then
    run_restore_docker_custom "$input_path"
  elif [[ "$mode" == "docker" && "$restore_format" == "plain" ]]; then
    run_restore_docker_plain "$input_path"
  elif [[ "$mode" == "local" && "$restore_format" == "custom" ]]; then
    run_restore_local_custom "$input_path"
  elif [[ "$mode" == "local" && "$restore_format" == "plain" ]]; then
    run_restore_local_plain "$input_path"
  else
    fail "invalid_restore_combination" "Invalid restore mode/format combination: mode=${mode}, format=${restore_format}" 2
  fi

  log_json "info" "restore_finished" "Database restore command completed."
}

# ------------------------------------------------------------------------------
# Post-Restore Health Check
# ------------------------------------------------------------------------------

run_health_check_local() {
  require_command "psql"

  if [[ -n "$DATABASE_URL" ]]; then
    psql "$DATABASE_URL" \
      --set ON_ERROR_STOP=on \
      --tuples-only \
      --command="SELECT 1;" >/dev/null
  else
    PGPASSWORD="$PGPASSWORD" psql \
      --host="$PGHOST" \
      --port="$PGPORT" \
      --username="$PGUSER" \
      --dbname="$PGDATABASE" \
      --set ON_ERROR_STOP=on \
      --tuples-only \
      --command="SELECT 1;" >/dev/null
  fi
}

run_health_check_docker() {
  require_command "docker"

  if [[ -n "$DATABASE_URL" ]]; then
    docker exec "$POSTGRES_CONTAINER" \
      psql "$DATABASE_URL" \
        --set ON_ERROR_STOP=on \
        --tuples-only \
        --command="SELECT 1;" >/dev/null
  else
    docker exec \
      -e PGPASSWORD="$PGPASSWORD" \
      "$POSTGRES_CONTAINER" \
      psql \
        --host="${PGHOST}" \
        --port="${PGPORT}" \
        --username="${PGUSER}" \
        --dbname="${PGDATABASE}" \
        --set ON_ERROR_STOP=on \
        --tuples-only \
        --command="SELECT 1;" >/dev/null
  fi
}

run_health_check() {
  local mode="$1"

  if [[ "$DRY_RUN" == "true" ]]; then
    log_json "info" "health_check_skipped" "Dry run enabled. Post-restore database health check skipped."
    return 0
  fi

  log_json "info" "health_check_started" "Running post-restore database health check."

  if [[ "$mode" == "docker" ]]; then
    run_health_check_docker
  else
    run_health_check_local
  fi

  log_json "info" "health_check_passed" "Post-restore database health check passed."
}

# ------------------------------------------------------------------------------
# Main Flow
# ------------------------------------------------------------------------------

main() {
  log_json "info" "script_started" "Starting ${SCRIPT_NAME} v${SCRIPT_VERSION}."

  validate_access_controls
  validate_restore_confirmation
  validate_restore_path
  acquire_lock

  local mode
  mode="$(resolve_restore_mode)"
  log_json "info" "restore_mode_resolved" "Database restore mode resolved as '${mode}'."

  local checksum
  checksum="$(verify_checksum_if_available "$RESTORE_BACKUP_PATH")"

  local restore_format
  restore_format="$(detect_restore_format "$RESTORE_BACKUP_PATH")"
  log_json "info" "restore_format_resolved" "Restore format resolved as '${restore_format}'."

  local audit_start
  audit_start="$(audit_payload "started" "$RESTORE_BACKUP_PATH" "Database restore started.")"
  post_hook_json "$AUDIT_LOG_HOOK_URL" "$audit_start" "audit_log"

  request_security_approval

  local prepared_input_path
  prepared_input_path="$(prepare_restore_input "$RESTORE_BACKUP_PATH")"

  local pre_restore_backup_path
  pre_restore_backup_path="$(create_pre_restore_backup "$mode")"

  run_restore "$mode" "$restore_format" "$prepared_input_path"
  run_health_check "$mode"

  local audit_success
  audit_success="$(audit_payload "completed" "$RESTORE_BACKUP_PATH" "Database restore completed successfully.")"
  post_hook_json "$AUDIT_LOG_HOOK_URL" "$audit_success" "audit_log"

  local memory_event
  memory_event="$(memory_payload "$RESTORE_BACKUP_PATH" "$checksum" "completed")"
  post_hook_json "$MEMORY_AGENT_HOOK_URL" "$memory_event" "memory_agent"

  emit_verification_payload "completed" "Database restore completed successfully." "$RESTORE_BACKUP_PATH" "$checksum"

  log_json "info" "restore_completed" "Restore completed from: ${RESTORE_BACKUP_PATH}"

  cat <<JSON
{
  "status": "success",
  "component": "$SCRIPT_NAME",
  "run_id": "$(json_escape "$RUN_ID")",
  "user_id": "$(json_escape "$USER_ID")",
  "workspace_id": "$(json_escape "$WORKSPACE_ID")",
  "database": "$(json_escape "$PGDATABASE")",
  "restore_backup_path": "$(json_escape "$RESTORE_BACKUP_PATH")",
  "pre_restore_backup_path": "$(json_escape "$pre_restore_backup_path")",
  "checksum_sha256": "$(json_escape "$checksum")",
  "restore_mode": "$(json_escape "$mode")",
  "restore_format": "$(json_escape "$restore_format")",
  "dry_run": ${DRY_RUN},
  "started_at": "$(json_escape "$STARTED_AT")",
  "finished_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
JSON
}

main "$@"