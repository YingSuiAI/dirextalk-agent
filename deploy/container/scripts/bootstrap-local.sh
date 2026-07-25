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
tls_server_name=${5:-localhost}
case "$tls_server_name" in
  *[!A-Za-z0-9.-]*|""|.*|*-|.*-*) echo "invalid TLS server name" >&2; exit 2 ;;
esac

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

required_files="postgres-password database-url service-token instance-id tls-key tls-cert tls-ca config.yaml .env"
lock=$out.lock

is_expected_name() {
  case "$1" in
    postgres-password|database-url|service-token|instance-id|tls-key|tls-cert|tls-ca|config.yaml|.env|.manifest) return 0 ;;
    *) return 1 ;;
  esac
}

is_regular_protected_file() {
  file=$1
  [ -f "$file" ] && [ ! -L "$file" ] && [ "$(stat -c '%a' "$file" 2>/dev/null || echo 0)" = 400 ]
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
    is_expected_name "$(basename "$entry")" || return 1
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
  grep -Fqx "DIREXTALK_AGENT_CONFIG_FILE=$expected_root/config.yaml" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_POSTGRES_PASSWORD_FILE=$expected_root/postgres-password" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_DATABASE_URL_FILE=$expected_root/database-url" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_TLS_CERT_FILE=$expected_root/tls-cert" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_TLS_KEY_FILE=$expected_root/tls-key" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_TLS_CA_FILE=$expected_root/tls-ca" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_SERVICE_TOKEN_FILE=$expected_root/service-token" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_AGENT_INSTANCE_ID_FILE=$expected_root/instance-id" "$dir/.env" || return 1
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
  if validate_complete "$out"; then
    echo "reused complete local protected files and Compose environment in $out" >&2
    exit 0
  fi
  die "output target exists but is incomplete or inconsistent; refusing in-place regeneration: $out"
fi

stage=$(mktemp -d "$out_parent/.${out_base}.staging.XXXXXX")

instance_id=$(openssl rand -hex 16)
instance_id=$(printf '%s' "$instance_id" | awk '{printf "%.8s-%.4s-4%.3s-8%.3s-%.12s", $0, substr($0,9), substr($0,13), substr($0,16), substr($0,20)}')
password=$(openssl rand -hex 24)
token=""
while [ "$(printf '%s' "$token" | wc -c)" -ne 43 ]; do
  token=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')
done

printf '%s\n' "$password" > "$stage/postgres-password"
printf 'postgresql://dirextalk_agent:%s@postgres:5432/dirextalk_agent?sslmode=disable\n' "$password" > "$stage/database-url"
printf '%s' "$token" > "$stage/service-token"
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
enable_health_service: true
enable_reflection: false
core_extension_enabled: false
core_extension_staging_root: /var/lib/dirextalk-agent/extension-staging
core_extension_workspace_root: /var/lib/dirextalk-agent/extension-workspaces
core_extension_runner_socket: /run/dirextalk-agent/extension-runner.sock
core_extension_runner_uid: 65531
EOF

cat > "$stage/.env" <<EOF
DIREXTALK_AGENT_IMAGE_IMMUTABLE=$core_image
DIREXTALK_EXTENSION_RUNNER_IMAGE_IMMUTABLE=$runner_image
DIREXTALK_POSTGRES_IMAGE_IMMUTABLE=$postgres_image
DIREXTALK_AGENT_CONFIG_FILE=$out/config.yaml
DIREXTALK_POSTGRES_PASSWORD_FILE=$out/postgres-password
DIREXTALK_DATABASE_URL_FILE=$out/database-url
DIREXTALK_TLS_CERT_FILE=$out/tls-cert
DIREXTALK_TLS_KEY_FILE=$out/tls-key
DIREXTALK_TLS_CA_FILE=$out/tls-ca
DIREXTALK_SERVICE_TOKEN_FILE=$out/service-token
DIREXTALK_EXTENSION_CGROUP_ROOT=/sys/fs/cgroup/dirextalk-agent
DIREXTALK_HEALTHCHECK_SERVER_NAME=$tls_server_name
DIREXTALK_AGENT_CALLER_NETWORK_NAME=dirextalk-agent-caller
DIREXTALK_AGENT_INSTANCE_ID_FILE=$out/instance-id
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
