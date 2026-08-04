#!/bin/sh
set -eu

usage() {
  echo "usage: $0 OUTPUT_DIR [CORE_IMAGE] [RUNNER_IMAGE] [POSTGRES_IMAGE] [TLS_SERVER_NAME]" >&2
  exit 2
}

die() {
  echo "bootstrap-local: $*" >&2
  exit 1
}

out_input=${1:-}
[ -n "$out_input" ] || usage
core_image=${2:-dirextalk-agent-core:local}
runner_image=${3:-dirextalk-extension-runner:local}
postgres_image=${4:-docker.io/library/postgres:18@sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a}
core_runner_image=${DIREXTALK_CORE_RUNNER_IMAGE_IMMUTABLE:-dirextalk-core-runner:local}
tls_server_name=${5:-localhost}
case "$tls_server_name" in
  *[!A-Za-z0-9.-]*|""|.*|*-|.*-*) echo "invalid TLS server name" >&2; exit 2 ;;
esac

parse_bool() {
  name=$1
  value=$2
  case "$value" in
    true|false) printf '%s' "$value" ;;
    *) die "${name} must be exactly true or false" ;;
  esac
}

validate_uid() {
  name=$1
  value=$2
  case "$value" in
    ''|*[!0-9]*) die "${name} must be a positive decimal UID" ;;
    0*) die "${name} must be a positive decimal UID" ;;
  esac
  [ "$value" != "65532" ] || die "${name} must differ from the Agent UID 65532"
}

validate_socket() {
  name=$1
  value=$2
  case "$value" in
    /*) ;;
    *) die "${name} must be an absolute Unix socket path" ;;
  esac
  case "$value" in
    *'//'*) die "${name} must be a clean Unix socket path" ;;
    *'..'*) die "${name} must be a clean Unix socket path" ;;
    */) die "${name} must be a clean Unix socket path" ;;
  esac
}

validate_cgroup_parent() {
  name=$1
  value=$2
  [ -n "$value" ] || return 0
  control_bytes=$(printf '%s' "$value" | od -An -v -t x1)
  if printf '%s\n' "$control_bytes" | grep -Eq '(^|[[:space:]])(0[0-9a-f]|1[0-9a-f]|7f)([[:space:]]|$)'; then
    die "${name} must not contain control bytes"
  fi
  printf '%s\n' "$value" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?\.slice$' || die "${name} must be a safe systemd slice name"
}

validate_stack_name() {
  name=$1
  value=$2
  case "$value" in
    [a-z0-9]*) ;;
    *) die "${name} must start with a lowercase letter or digit" ;;
  esac
  case "$value" in
    *[!a-z0-9_-]*) die "${name} may contain only lowercase letters, digits, '_' or '-'" ;;
  esac
  # The longest derived Docker resource is <stack>-postgres-secret-material;
  # keep every generated name within Docker's 63-character limit.
  [ "${#value}" -le 38 ] || die "${name} is too long"
}

core_extension_enabled=$(parse_bool DIREXTALK_CORE_EXTENSION_ENABLED "${DIREXTALK_CORE_EXTENSION_ENABLED:-false}")
core_workload_enabled=$(parse_bool DIREXTALK_CORE_WORKLOAD_ENABLED "${DIREXTALK_CORE_WORKLOAD_ENABLED:-false}")
extension_runner_socket=${DIREXTALK_CORE_EXTENSION_RUNNER_SOCKET:-/run/dirextalk-agent/extension-runner.sock}
workload_runner_socket=${DIREXTALK_CORE_WORKLOAD_RUNNER_SOCKET:-/run/dirextalk-core-runner/runner.sock}
extension_runner_dir=${extension_runner_socket%/*}
workload_runner_dir=${workload_runner_socket%/*}
extension_runner_uid=${DIREXTALK_CORE_EXTENSION_RUNNER_UID:-65531}
workload_runner_uid=${DIREXTALK_CORE_WORKLOAD_RUNNER_UID:-65530}
extension_cgroup_parent=${DIREXTALK_EXTENSION_CGROUP_PARENT:-}
workload_cgroup_parent=${DIREXTALK_CORE_RUNNER_CGROUP_PARENT:-}
validate_socket DIREXTALK_CORE_EXTENSION_RUNNER_SOCKET "$extension_runner_socket"
validate_socket DIREXTALK_CORE_WORKLOAD_RUNNER_SOCKET "$workload_runner_socket"
validate_uid DIREXTALK_CORE_EXTENSION_RUNNER_UID "$extension_runner_uid"
validate_uid DIREXTALK_CORE_WORKLOAD_RUNNER_UID "$workload_runner_uid"
validate_cgroup_parent DIREXTALK_EXTENSION_CGROUP_PARENT "$extension_cgroup_parent"
validate_cgroup_parent DIREXTALK_CORE_RUNNER_CGROUP_PARENT "$workload_cgroup_parent"

umask 077
case "$out_input" in
  /*) out=$out_input ;;
  *) out=$(pwd -P)/$out_input ;;
esac
out_parent=$(dirname "$out")
out_base=$(basename "$out")
mkdir -p "$out_parent"
out_parent=$(cd "$out_parent" && pwd -P)
out=$out_parent/$out_base

required_files="postgres-password database-url service-token core-secret-master-key instance-id tls-key tls-cert tls-ca config.yaml .env"
lock=$out.lock

is_expected_name() {
  case "$1" in
    postgres-password|database-url|service-token|core-secret-master-key|instance-id|tls-key|tls-cert|tls-ca|config.yaml|.env|.manifest) return 0 ;;
    *) return 1 ;;
  esac
}

is_regular_protected_file() {
  file=$1
  [ -f "$file" ] && [ ! -L "$file" ] && [ "$(stat -c '%a' "$file" 2>/dev/null || echo 0)" = 400 ]
}

is_migration_artifact_name() {
  case "$1" in
    .cgroup-parent-migration|.cgroup-parent-migration.tmp|.env.migrate-backup|.env.migrate.tmp|.manifest.migrate-backup|.manifest.migrate.tmp|.core-secret-master-key.migrate.tmp|config.yaml.migrate.tmp) return 0 ;;
    *) return 1 ;;
  esac
}

sync_path() {
  path=$1
  if command -v sync >/dev/null 2>&1; then
    sync -f "$path" 2>/dev/null || true
  fi
}

sync_directory() {
  dir=$1
  if command -v sync >/dev/null 2>&1; then
    sync -f "$dir" 2>/dev/null || true
  fi
}

migration_failpoint() {
  [ "${DIREXTALK_BOOTSTRAP_MIGRATION_FAILPOINT:-}" = "$1" ] || return 0
  exit 86
}

validate_manifest() {
  dir=$1
  manifest=$dir/.manifest
  is_regular_protected_file "$manifest" || return 1
  [ "$(sed -n '1p' "$manifest")" = "# dirextalk-bootstrap-manifest-v1" ] || return 1
  expected_count=$(printf '%s\n' $required_files | wc -l)
  actual_count=$(tail -n +2 "$manifest" | wc -l)
  [ "$actual_count" -eq "$expected_count" ] || return 1
  for name in $required_files; do
    tail -n +2 "$manifest" | grep -Eq "^[0-9a-f]{64}  ${name}$" || return 1
  done
  (cd "$dir" && tail -n +2 .manifest | sha256sum -c --status -) || return 1
}

validate_complete() {
  dir=$1
  expected_root=${2:-$dir}
  [ -d "$dir" ] && [ ! -L "$dir" ] || return 1
  [ "$(stat -c '%a' "$dir" 2>/dev/null || echo 0)" = 700 ] || return 1
  for entry in "$dir"/* "$dir"/.[!.]* "$dir"/..?*; do
    [ -e "$entry" ] || continue
    is_expected_name "$(basename "$entry")" || is_migration_artifact_name "$(basename "$entry")" || return 1
  done
  for name in $required_files; do
    is_regular_protected_file "$dir/$name" || return 1
  done
  validate_manifest "$dir" || return 1

  sh "$(dirname "$0")/validate-token.sh" "$dir/service-token" || return 1

  instance_id=$(cat "$dir/instance-id")
  printf '%s\n' "$instance_id" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$' || return 1
  password=$(sed -n '1{/^$/d;p;}' "$dir/postgres-password")
  [ "$(printf '%s\n' "$password" | wc -l)" -eq 1 ] || return 1
  printf '%s' "$password" | grep -Eq '^[0-9a-f]{48}$' || return 1
  [ "$(wc -c < "$dir/core-secret-master-key")" -eq 32 ] || return 1
  expected_url="postgresql://dirextalk_agent:${password}@postgres:5432/dirextalk_agent?sslmode=disable"
  printf '%s\n' "$expected_url" | cmp -s - "$dir/database-url" || return 1

  openssl x509 -in "$dir/tls-cert" -noout >/dev/null 2>&1 || return 1
  openssl pkey -in "$dir/tls-key" -noout >/dev/null 2>&1 || return 1
  openssl x509 -in "$dir/tls-ca" -noout >/dev/null 2>&1 || return 1
  cert_pub=$(openssl x509 -in "$dir/tls-cert" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum) || return 1
  key_pub=$(openssl pkey -in "$dir/tls-key" -pubout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum) || return 1
  [ "$cert_pub" = "$key_pub" ] || return 1
  cmp -s "$dir/tls-cert" "$dir/tls-ca" || return 1

  grep -Fqx "instance_id: $instance_id" "$dir/config.yaml" || return 1
  grep -Fqx "database_url_file: /run/secrets/database_url" "$dir/config.yaml" || return 1
  grep -Fqx "tls_cert_file: /run/secrets/tls_cert" "$dir/config.yaml" || return 1
  grep -Fqx "tls_key_file: /run/secrets/tls_key" "$dir/config.yaml" || return 1
  grep -Fqx "service_token_file: /run/secrets/service_token" "$dir/config.yaml" || return 1
  grep -Fqx "core_secret_master_key_file: /run/secrets/core_secret_master_key" "$dir/config.yaml" || return 1
  grep -Fqx "core_secret_master_key_version: 1" "$dir/config.yaml" || return 1
  grep -Fqx "DIREXTALK_AGENT_CONFIG_FILE=$expected_root/config.yaml" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_POSTGRES_PASSWORD_FILE=$expected_root/postgres-password" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_DATABASE_URL_FILE=$expected_root/database-url" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_TLS_CERT_FILE=$expected_root/tls-cert" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_TLS_KEY_FILE=$expected_root/tls-key" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_TLS_CA_FILE=$expected_root/tls-ca" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_SERVICE_TOKEN_FILE=$expected_root/service-token" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_CORE_SECRET_MASTER_KEY_FILE=$expected_root/core-secret-master-key" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_AGENT_INSTANCE_ID_FILE=$expected_root/instance-id" "$dir/.env" || return 1
  grep -Eq '^DIREXTALK_AGENT_EXPECTED_INSTANCE_ID=[0-9a-f-]+$' "$dir/.env" || return 1
  grep -Eq '^DIREXTALK_CORE_RUNNER_IMAGE_IMMUTABLE=.+$' "$dir/.env" || return 1
  stack_name=$(sed -n 's/^DIREXTALK_AGENT_STACK_NAME=//p' "$dir/.env" | tail -n 1)
  validate_stack_name DIREXTALK_AGENT_STACK_NAME "$stack_name" >/dev/null 2>&1 || return 1
  for name in \
    DIREXTALK_AGENT_NETWORK_NAME DIREXTALK_AGENT_EGRESS_NETWORK_NAME DIREXTALK_AGENT_CALLER_NETWORK_NAME \
    DIREXTALK_AGENT_POSTGRES_VOLUME DIREXTALK_AGENT_SOCKET_VOLUME DIREXTALK_AGENT_INSTALL_VOLUME \
    DIREXTALK_AGENT_STAGING_VOLUME DIREXTALK_AGENT_WORKSPACE_VOLUME DIREXTALK_AGENT_RUNNER_WORKSPACE_VOLUME \
    DIREXTALK_AGENT_RUNNER_STATE_VOLUME DIREXTALK_AGENT_SECRET_VOLUME DIREXTALK_AGENT_POSTGRES_SECRET_VOLUME \
    DIREXTALK_AGENT_CONFIG_VOLUME DIREXTALK_CORE_RUNNER_SOCKET_VOLUME DIREXTALK_CORE_RUNNER_INSTALL_VOLUME \
    DIREXTALK_CORE_RUNNER_WORKSPACE_VOLUME DIREXTALK_CORE_RUNNER_STATE_VOLUME \
    DIREXTALK_EXTENSION_CGROUP_ROOT DIREXTALK_CORE_RUNNER_CGROUP_ROOT \
    DIREXTALK_CORE_EXTENSION_ENABLED DIREXTALK_CORE_WORKLOAD_ENABLED \
    DIREXTALK_CORE_EXTENSION_RUNNER_SOCKET DIREXTALK_CORE_WORKLOAD_RUNNER_SOCKET \
    DIREXTALK_CORE_EXTENSION_RUNNER_DIR DIREXTALK_CORE_WORKLOAD_RUNNER_DIR \
    DIREXTALK_CORE_EXTENSION_RUNNER_UID DIREXTALK_CORE_WORKLOAD_RUNNER_UID; do
    grep -Eq "^${name}=.+$" "$dir/.env" || return 1
  done
  for name in DIREXTALK_EXTENSION_CGROUP_PARENT DIREXTALK_CORE_RUNNER_CGROUP_PARENT; do
    value=$(sed -n "s/^${name}=//p" "$dir/.env" | tail -n 1)
    [ -z "$value" ] || validate_cgroup_parent "$name" "$value" >/dev/null 2>&1 || return 1
  done
  grep -Eq '^core_extension_enabled: (true|false)$' "$dir/config.yaml" || return 1
  grep -Eq '^core_workload_enabled: (true|false)$' "$dir/config.yaml" || return 1
  grep -Eq '^core_extension_runner_uid: [1-9][0-9]*$' "$dir/config.yaml" || return 1
  grep -Eq '^core_workload_runner_uid: [1-9][0-9]*$' "$dir/config.yaml" || return 1
}

write_migration_marker() {
  dir=$1
  phase=$2
  marker_tmp=$dir/.cgroup-parent-migration.tmp
  rm -f "$marker_tmp"
  {
    printf '%s\n' '# dirextalk-cgroup-parent-migration-v1'
    printf 'phase=%s\n' "$phase"
  } > "$marker_tmp" || { rm -f "$marker_tmp"; return 1; }
  chmod 0400 "$marker_tmp" || { rm -f "$marker_tmp"; return 1; }
  sync_path "$marker_tmp"
  mv -f "$marker_tmp" "$dir/.cgroup-parent-migration" || { rm -f "$marker_tmp"; return 1; }
  sync_directory "$dir"
}

validate_migration_marker() {
  marker=$1
  is_regular_protected_file "$marker" || return 1
  [ "$(sed -n '1p' "$marker")" = "# dirextalk-cgroup-parent-migration-v1" ] || return 1
  phase=$(sed -n 's/^phase=//p' "$marker" | tail -n 1)
  case "$phase" in
    prepared|env-replaced) return 0 ;;
    *) return 1 ;;
  esac
}

copy_protected_atomic() {
  source=$1
  target=$2
  target_tmp=$3
  rm -f "$target_tmp"
  cp "$source" "$target_tmp" || { rm -f "$target_tmp"; return 1; }
  chmod 0400 "$target_tmp" || { rm -f "$target_tmp"; return 1; }
  sync_path "$target_tmp"
  mv -f "$target_tmp" "$target" || { rm -f "$target_tmp"; return 1; }
  sync_directory "$(dirname "$target")"
}

write_manifest_atomic() {
  dir=$1
  manifest_tmp=$dir/.manifest.migrate.tmp
  if [ "${2:-failpoint}" = failpoint ]; then
    migration_failpoint before-manifest-mktemp
  fi
  rm -f "$manifest_tmp"
  (
    cd "$dir" || exit 1
    { printf '%s\n' '# dirextalk-bootstrap-manifest-v1'; sha256sum $required_files; } > "$manifest_tmp"
  ) || { rm -f "$manifest_tmp"; return 1; }
  if [ "${2:-failpoint}" = failpoint ]; then
    migration_failpoint after-manifest-hash
  fi
  chmod 0400 "$manifest_tmp" || { rm -f "$manifest_tmp"; return 1; }
  sync_path "$manifest_tmp"
  mv -f "$manifest_tmp" "$dir/.manifest" || { rm -f "$manifest_tmp"; return 1; }
  sync_directory "$dir"
}

# Older protected bundles predate the encrypted Core AWS credential boundary.
# Preserve their identity/volumes while adding one fresh, strict master-key
# artifact and its non-secret path references. This is an additive bootstrap
# migration; an existing malformed key is never replaced automatically.
migrate_legacy_master_key() {
  dir=$1
  key=$dir/core-secret-master-key
  legacy_files="postgres-password database-url service-token instance-id tls-key tls-cert tls-ca config.yaml .env"
  [ -f "$dir/.manifest" ] && [ "$(stat -c '%a' "$dir/.manifest" 2>/dev/null || echo 0)" = 400 ] || return 0
  [ "$(sed -n '1p' "$dir/.manifest")" = "# dirextalk-bootstrap-manifest-v1" ] || return 0
  [ "$(tail -n +2 "$dir/.manifest" | wc -l)" -eq 9 ] || return 0
  for name in $legacy_files; do
    is_regular_protected_file "$dir/$name" || return 0
    tail -n +2 "$dir/.manifest" | grep -Eq "^[0-9a-f]{64}  ${name}$" || return 0
  done
  (cd "$dir" && tail -n +2 .manifest | sha256sum -c --status -) || return 0
  if [ -e "$key" ] || [ -L "$key" ]; then
    is_regular_protected_file "$key" || return 1
    [ "$(wc -c < "$key")" -eq 32 ] || return 1
  else
    key_tmp=$dir/.core-secret-master-key.migrate.tmp
    openssl rand 32 > "$key_tmp" || { rm -f "$key_tmp"; return 1; }
    chmod 0400 "$key_tmp" || { rm -f "$key_tmp"; return 1; }
    sync_path "$key_tmp"
    mv -f "$key_tmp" "$key" || { rm -f "$key_tmp"; return 1; }
    sync_directory "$dir"
  fi
  for target in "$dir/config.yaml" "$dir/.env"; do
      target_tmp=$target.migrate.tmp
      cp "$target" "$target_tmp" || { rm -f "$target_tmp"; return 1; }
      if [ "$target" = "$dir/config.yaml" ]; then
        grep -Fqx "core_secret_master_key_file: /run/secrets/core_secret_master_key" "$target" || printf '%s\n' 'core_secret_master_key_file: /run/secrets/core_secret_master_key' >> "$target_tmp"
        grep -Fqx "core_secret_master_key_version: 1" "$target" || printf '%s\n' 'core_secret_master_key_version: 1' >> "$target_tmp"
      else
        grep -Fqx "DIREXTALK_CORE_SECRET_MASTER_KEY_FILE=$dir/core-secret-master-key" "$target" || printf '%s\n' "DIREXTALK_CORE_SECRET_MASTER_KEY_FILE=$dir/core-secret-master-key" >> "$target_tmp"
      fi
      chmod 0400 "$target_tmp" || { rm -f "$target_tmp"; return 1; }
      sync_path "$target_tmp"
      mv -f "$target_tmp" "$target"
      sync_directory "$dir"
  done
  write_manifest_atomic "$dir" nofail || return 1
  return 0
}

clear_migration_artifacts() {
  dir=$1
  rm -f "$dir/.cgroup-parent-migration" "$dir/.cgroup-parent-migration.tmp" \
    "$dir/.env.migrate-backup" "$dir/.env.migrate.tmp" \
    "$dir/.manifest.migrate-backup" "$dir/.manifest.migrate.tmp" \
    "$dir/.core-secret-master-key.migrate.tmp" "$dir/config.yaml.migrate.tmp"
  sync_directory "$dir"
}

recover_cgroup_parent_migration() {
  dir=$1
  marker=$dir/.cgroup-parent-migration
  env_backup=$dir/.env.migrate-backup
  manifest_backup=$dir/.manifest.migrate-backup
  marker_tmp=$dir/.cgroup-parent-migration.tmp
  env_tmp=$dir/.env.migrate.tmp
  manifest_tmp=$dir/.manifest.migrate.tmp
  [ -e "$marker" ] || [ -e "$env_backup" ] || [ -e "$manifest_backup" ] || [ -e "$marker_tmp" ] || [ -e "$env_tmp" ] || [ -e "$manifest_tmp" ] || return 0
  [ -d "$dir" ] && [ ! -L "$dir" ] || return 1
  owner_uid=$(id -u)
  [ "$(stat -c '%u' "$dir" 2>/dev/null || echo -1)" = "$owner_uid" ] || return 1
  if [ -e "$marker" ]; then
    validate_migration_marker "$marker" || return 1
    [ "$(stat -c '%u' "$marker" 2>/dev/null || echo -1)" = "$owner_uid" ] || return 1
  fi
  if [ -e "$env_backup" ] || [ -e "$manifest_backup" ]; then
    if [ ! -e "$env_backup" ] || [ ! -e "$manifest_backup" ]; then
      if validate_manifest "$dir"; then
        clear_migration_artifacts "$dir"
        return 0
      fi
      return 1
    fi
    is_regular_protected_file "$env_backup" || return 1
    is_regular_protected_file "$manifest_backup" || return 1
    [ "$(stat -c '%u' "$env_backup" 2>/dev/null || echo -1)" = "$owner_uid" ] || return 1
    [ "$(stat -c '%u' "$manifest_backup" 2>/dev/null || echo -1)" = "$owner_uid" ] || return 1
    [ -f "$dir/.env" ] && [ ! -L "$dir/.env" ] || return 1
    current_env_hash=$(sha256sum "$dir/.env" | awk '{print $1}') || return 1
    backup_env_hash=$(sha256sum "$env_backup" | awk '{print $1}') || return 1
    if [ "$current_env_hash" = "$backup_env_hash" ]; then
      if validate_manifest "$dir"; then
        clear_migration_artifacts "$dir"
        return 0
      fi
      copy_protected_atomic "$manifest_backup" "$dir/.manifest" "$manifest_tmp" || return 1
      validate_manifest "$dir" || return 1
      clear_migration_artifacts "$dir"
      return 0
    fi
    if write_manifest_atomic "$dir" && validate_manifest "$dir" && (validate_complete "$dir"); then
      clear_migration_artifacts "$dir"
      return 0
    fi
    copy_protected_atomic "$env_backup" "$dir/.env" "$env_tmp" || return 1
    migration_failpoint after-env-restore
    copy_protected_atomic "$manifest_backup" "$dir/.manifest" "$manifest_tmp" || return 1
    validate_manifest "$dir" || return 1
    clear_migration_artifacts "$dir"
    return 0
  fi
  if [ -e "$marker" ]; then
    return 1
  fi
  if validate_manifest "$dir"; then
    rm -f "$marker_tmp" "$env_tmp" "$manifest_tmp"
    sync_directory "$dir"
    return 0
  fi
  return 1
}

migrate_cgroup_parents() {
  dir=$1
  validate_complete "$dir" || return 1
  owner_uid=$(id -u)
  [ "$(stat -c '%u' "$dir" 2>/dev/null || echo -1)" = "$owner_uid" ] || return 1
  for name in $required_files .manifest; do
    [ "$(stat -c '%u' "$dir/$name" 2>/dev/null || echo -1)" = "$owner_uid" ] || return 1
  done
  stack_name=$(sed -n 's/^DIREXTALK_AGENT_STACK_NAME=//p' "$dir/.env" | tail -n 1)
  validate_stack_name DIREXTALK_AGENT_STACK_NAME "$stack_name" >/dev/null 2>&1 || return 1
  extension_parent=$(sed -n 's/^DIREXTALK_EXTENSION_CGROUP_PARENT=//p' "$dir/.env" | tail -n 1)
  workload_parent=$(sed -n 's/^DIREXTALK_CORE_RUNNER_CGROUP_PARENT=//p' "$dir/.env" | tail -n 1)
  [ -n "$extension_parent" ] || extension_parent=${stack_name}-extension.slice
  [ -n "$workload_parent" ] || workload_parent=${stack_name}-core-runner.slice
  validate_cgroup_parent DIREXTALK_EXTENSION_CGROUP_PARENT "$extension_parent"
  validate_cgroup_parent DIREXTALK_CORE_RUNNER_CGROUP_PARENT "$workload_parent"
  [ -n "$(sed -n 's/^DIREXTALK_EXTENSION_CGROUP_PARENT=//p' "$dir/.env" | tail -n 1)" ] && have_extension=1 || have_extension=0
  [ -n "$(sed -n 's/^DIREXTALK_CORE_RUNNER_CGROUP_PARENT=//p' "$dir/.env" | tail -n 1)" ] && have_workload=1 || have_workload=0
  [ "$have_extension$have_workload" = 11 ] && return 0
  [ "$(stat -c '%a' "$dir/.env" 2>/dev/null || echo 0)" = 400 ] || return 1
  [ "$(stat -c '%a' "$dir/.manifest" 2>/dev/null || echo 0)" = 400 ] || return 1
  copy_protected_atomic "$dir/.env" "$dir/.env.migrate-backup" "$dir/.env.migrate.tmp" || return 1
  copy_protected_atomic "$dir/.manifest" "$dir/.manifest.migrate-backup" "$dir/.manifest.migrate.tmp" || return 1
  write_migration_marker "$dir" prepared || return 1
  env_tmp=$dir/.env.migrate.tmp
  rm -f "$env_tmp"
  awk -v extension_parent="$extension_parent" -v workload_parent="$workload_parent" '
    BEGIN { extension_seen = 0; workload_seen = 0 }
    /^DIREXTALK_EXTENSION_CGROUP_PARENT=/ { print "DIREXTALK_EXTENSION_CGROUP_PARENT=" extension_parent; extension_seen = 1; next }
    /^DIREXTALK_CORE_RUNNER_CGROUP_PARENT=/ { print "DIREXTALK_CORE_RUNNER_CGROUP_PARENT=" workload_parent; workload_seen = 1; next }
    { print }
    END {
      if (!extension_seen) print "DIREXTALK_EXTENSION_CGROUP_PARENT=" extension_parent
      if (!workload_seen) print "DIREXTALK_CORE_RUNNER_CGROUP_PARENT=" workload_parent
    }
  ' "$dir/.env" > "$env_tmp" || { rm -f "$env_tmp"; return 1; }
  chmod 0400 "$env_tmp" || { rm -f "$env_tmp"; return 1; }
  sync_path "$env_tmp"
  mv -f "$env_tmp" "$dir/.env" || { rm -f "$env_tmp"; return 1; }
  sync_directory "$dir"
  migration_failpoint after-env-replace
  write_migration_marker "$dir" env-replaced || return 1
  write_manifest_atomic "$dir" || return 1
  validate_manifest "$dir" && validate_complete "$dir" || return 1
  clear_migration_artifacts "$dir"
}

if ! mkdir "$lock" 2>/dev/null; then
  die "bootstrap lock is held; refusing concurrent generation: $lock"
fi
stage=""
cleanup() {
  if [ -n "$stage" ] && [ -d "$stage" ]; then
    rm -rf "$stage"
  fi
  rmdir "$lock" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

if [ -e "$out" ] || [ -L "$out" ]; then
  migrate_legacy_master_key "$out" || die "legacy Core AWS master-key migration failed; refusing in-place regeneration: $out"
  recover_cgroup_parent_migration "$out" || die "protected Compose migration recovery failed; refusing in-place regeneration: $out"
  if ! validate_complete "$out"; then
    migrate_cgroup_parents "$out" || die "output target exists but is incomplete or inconsistent; refusing in-place regeneration: $out"
    validate_complete "$out" || die "migrated protected Compose environment failed validation: $out"
    echo "migrated existing protected Compose environment with per-runner cgroup parents in $out" >&2
    exit 0
  fi
  migrate_cgroup_parents "$out" || die "failed to validate existing protected Compose environment: $out"
  echo "reused complete local protected files and Compose environment in $out" >&2
  exit 0
fi

stage=$(mktemp -d "$out_parent/.${out_base}.staging.XXXXXX")

instance_id=$(openssl rand -hex 16)
instance_id=$(printf '%s' "$instance_id" | awk '{printf "%.8s-%.4s-4%.3s-8%.3s-%.12s", $0, substr($0,9), substr($0,13), substr($0,16), substr($0,20)}')
instance_short=${instance_id%%-*}
stack_name=${DIREXTALK_AGENT_STACK_NAME:-dirextalk-agent-$instance_short}
validate_stack_name DIREXTALK_AGENT_STACK_NAME "$stack_name"
extension_cgroup_root=${DIREXTALK_EXTENSION_CGROUP_ROOT:-/sys/fs/cgroup/$stack_name-extension}
core_runner_cgroup_root=${DIREXTALK_CORE_RUNNER_CGROUP_ROOT:-/sys/fs/cgroup/$stack_name-core-runner}
extension_cgroup_parent=${extension_cgroup_parent:-${stack_name}-extension.slice}
workload_cgroup_parent=${workload_cgroup_parent:-${stack_name}-core-runner.slice}
validate_socket DIREXTALK_EXTENSION_CGROUP_ROOT "$extension_cgroup_root"
validate_socket DIREXTALK_CORE_RUNNER_CGROUP_ROOT "$core_runner_cgroup_root"
validate_cgroup_parent DIREXTALK_EXTENSION_CGROUP_PARENT "$extension_cgroup_parent"
validate_cgroup_parent DIREXTALK_CORE_RUNNER_CGROUP_PARENT "$workload_cgroup_parent"
[ "$core_extension_enabled" = false ] || [ -n "$extension_cgroup_parent" ] || die "DIREXTALK_EXTENSION_CGROUP_PARENT is required when extensions are enabled"
[ "$core_workload_enabled" = false ] || [ -n "$workload_cgroup_parent" ] || die "DIREXTALK_CORE_RUNNER_CGROUP_PARENT is required when Core Runner is enabled"
password=$(openssl rand -hex 24)
token=""
while [ "$(printf '%s' "$token" | wc -c)" -ne 43 ]; do
  token=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')
done

printf '%s\n' "$password" > "$stage/postgres-password"
printf 'postgresql://dirextalk_agent:%s@postgres:5432/dirextalk_agent?sslmode=disable\n' "$password" > "$stage/database-url"
printf '%s' "$token" > "$stage/service-token"
openssl rand 32 > "$stage/core-secret-master-key"
printf '%s\n' "$instance_id" > "$stage/instance-id"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$stage/tls-key" -out "$stage/tls-cert" -days 365 \
  -subj "/CN=$tls_server_name" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "subjectAltName=DNS:$tls_server_name,IP:127.0.0.1" >/dev/null 2>&1
cp "$stage/tls-cert" "$stage/tls-ca"

cat > "$stage/config.yaml" <<EOF
instance_id: $instance_id
database_url_file: /run/secrets/database_url
grpc_listen: ":9443"
tls_cert_file: /run/secrets/tls_cert
tls_key_file: /run/secrets/tls_key
service_token_file: /run/secrets/service_token
core_aws_enabled: false
core_secret_master_key_file: /run/secrets/core_secret_master_key
core_secret_master_key_version: 1
enable_health_service: true
enable_reflection: false
core_extension_staging_root: /var/lib/dirextalk-agent/extension-staging
core_extension_workspace_root: /var/lib/dirextalk-agent/extension-workspaces
core_extension_enabled: $core_extension_enabled
core_extension_runner_socket: $extension_runner_socket
core_extension_runner_uid: $extension_runner_uid
core_workload_enabled: $core_workload_enabled
core_workload_runner_socket: $workload_runner_socket
core_workload_runner_uid: $workload_runner_uid
EOF

cat > "$stage/.env" <<EOF
DIREXTALK_AGENT_IMAGE_IMMUTABLE=$core_image
DIREXTALK_EXTENSION_RUNNER_IMAGE_IMMUTABLE=$runner_image
DIREXTALK_CORE_RUNNER_IMAGE_IMMUTABLE=$core_runner_image
DIREXTALK_POSTGRES_IMAGE_IMMUTABLE=$postgres_image
DIREXTALK_AGENT_CONFIG_FILE=$out/config.yaml
DIREXTALK_POSTGRES_PASSWORD_FILE=$out/postgres-password
DIREXTALK_DATABASE_URL_FILE=$out/database-url
DIREXTALK_TLS_CERT_FILE=$out/tls-cert
DIREXTALK_TLS_KEY_FILE=$out/tls-key
DIREXTALK_TLS_CA_FILE=$out/tls-ca
DIREXTALK_SERVICE_TOKEN_FILE=$out/service-token
DIREXTALK_CORE_SECRET_MASTER_KEY_FILE=$out/core-secret-master-key
DIREXTALK_HEALTHCHECK_SERVER_NAME=$tls_server_name
DIREXTALK_AGENT_INSTANCE_ID_FILE=$out/instance-id
DIREXTALK_AGENT_EXPECTED_INSTANCE_ID=$instance_id
DIREXTALK_AGENT_STACK_NAME=$stack_name
DIREXTALK_AGENT_NETWORK_NAME=${stack_name}-private
DIREXTALK_AGENT_EGRESS_NETWORK_NAME=${stack_name}-egress
DIREXTALK_AGENT_CALLER_NETWORK_NAME=${stack_name}-caller
DIREXTALK_AGENT_POSTGRES_VOLUME=${stack_name}-postgres-data
DIREXTALK_AGENT_SOCKET_VOLUME=${stack_name}-extension-socket
DIREXTALK_AGENT_INSTALL_VOLUME=${stack_name}-extension-install
DIREXTALK_AGENT_STAGING_VOLUME=${stack_name}-extension-staging
DIREXTALK_AGENT_WORKSPACE_VOLUME=${stack_name}-extension-workspaces
DIREXTALK_AGENT_RUNNER_WORKSPACE_VOLUME=${stack_name}-extension-runner-workspaces
DIREXTALK_AGENT_RUNNER_STATE_VOLUME=${stack_name}-extension-runner-state
DIREXTALK_AGENT_SECRET_VOLUME=${stack_name}-secret-material
DIREXTALK_AGENT_POSTGRES_SECRET_VOLUME=${stack_name}-postgres-secret-material
DIREXTALK_AGENT_CONFIG_VOLUME=${stack_name}-config-material
DIREXTALK_CORE_RUNNER_SOCKET_VOLUME=${stack_name}-core-runner-socket
DIREXTALK_CORE_RUNNER_INSTALL_VOLUME=${stack_name}-core-runner-installs
DIREXTALK_CORE_RUNNER_WORKSPACE_VOLUME=${stack_name}-core-runner-workspaces
DIREXTALK_CORE_RUNNER_STATE_VOLUME=${stack_name}-core-runner-state
DIREXTALK_EXTENSION_CGROUP_ROOT=$extension_cgroup_root
DIREXTALK_CORE_RUNNER_CGROUP_ROOT=$core_runner_cgroup_root
DIREXTALK_EXTENSION_CGROUP_PARENT=$extension_cgroup_parent
DIREXTALK_CORE_RUNNER_CGROUP_PARENT=$workload_cgroup_parent
DIREXTALK_CORE_EXTENSION_ENABLED=$core_extension_enabled
DIREXTALK_CORE_WORKLOAD_ENABLED=$core_workload_enabled
DIREXTALK_CORE_EXTENSION_RUNNER_SOCKET=$extension_runner_socket
DIREXTALK_CORE_WORKLOAD_RUNNER_SOCKET=$workload_runner_socket
DIREXTALK_CORE_EXTENSION_RUNNER_DIR=$extension_runner_dir
DIREXTALK_CORE_WORKLOAD_RUNNER_DIR=$workload_runner_dir
DIREXTALK_CORE_EXTENSION_RUNNER_UID=$extension_runner_uid
DIREXTALK_CORE_WORKLOAD_RUNNER_UID=$workload_runner_uid
EOF

for name in $required_files; do
  chmod 0400 "$stage/$name"
done
(
  cd "$stage"
  {
    printf '%s\n' '# dirextalk-bootstrap-manifest-v1'
    sha256sum $required_files
  } > .manifest
)
chmod 0400 "$stage/.manifest"

validate_complete "$stage" "$out" || die "generated bootstrap set failed validation"
if [ -e "$out" ] || [ -L "$out" ]; then
  die "output target appeared during bootstrap; refusing replacement: $out"
fi
mv "$stage" "$out"
cleanup
trap - EXIT HUP INT TERM
echo "created local protected files and Compose environment in $out" >&2
