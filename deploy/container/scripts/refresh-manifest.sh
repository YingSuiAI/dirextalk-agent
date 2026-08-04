#!/bin/sh
set -eu

usage() {
  echo "usage: $0 [--locked] ARTIFACT_DIR" >&2
  exit 2
}

die() {
  echo "refresh-manifest: $*" >&2
  exit 1
}

locked=0
if [ "${1:-}" = "--locked" ]; then
  locked=1
  shift
fi
dir=${1:-}
[ -n "$dir" ] || usage
case "$dir" in
  /*) ;;
  *) dir=$(pwd -P)/$dir ;;
esac
dir_parent=$(dirname "$dir")
dir_base=$(basename "$dir")
dir_parent=$(cd "$dir_parent" && pwd -P)
dir=$dir_parent/$dir_base
lock=$dir.lock
tmp_manifest=""

cleanup() {
  if [ -n "$tmp_manifest" ] && [ -e "$tmp_manifest" ]; then
    rm -f "$tmp_manifest"
  fi
  if [ "$locked" -eq 0 ]; then
    rmdir "$lock" 2>/dev/null || true
  fi
}

if [ "$locked" -eq 0 ]; then
  mkdir "$lock" 2>/dev/null || die "artifact lock is held; refusing concurrent rotation: $lock"
else
  [ -d "$lock" ] || die "--locked requires the adjacent artifact lock: $lock"
fi
trap cleanup EXIT HUP INT TERM

all_files="postgres-password database-url service-token core-secret-master-key instance-id tls-key tls-cert tls-ca config.yaml .env"
immutable_files="postgres-password database-url core-secret-master-key instance-id config.yaml .env"

is_expected_name() {
  case "$1" in
    postgres-password|database-url|service-token|core-secret-master-key|instance-id|tls-key|tls-cert|tls-ca|config.yaml|.env|.manifest) return 0 ;;
    *) return 1 ;;
  esac
}

protected_file() {
  file=$1
  [ -f "$file" ] && [ ! -L "$file" ] && [ "$(stat -c '%a' "$file" 2>/dev/null || echo 0)" = 400 ]
}

validate_manifest_shape() {
  manifest=$1
  protected_file "$manifest" || return 1
  [ "$(sed -n '1p' "$manifest")" = "# dirextalk-bootstrap-manifest-v1" ] || return 1
  [ "$(tail -n +2 "$manifest" | wc -l)" -eq 10 ] || return 1
  for name in $all_files; do
    tail -n +2 "$manifest" | grep -Eq "^[0-9a-f]{64}  ${name}$" || return 1
  done
}

check_manifest_hash() {
  manifest=$1
  name=$2
  line=$(grep -E "^[0-9a-f]{64}  ${name}$" "$manifest") || return 1
  (cd "$dir" && printf '%s\n' "$line" | sha256sum -c --status -)
}

validate_artifacts() {
  [ -d "$dir" ] && [ ! -L "$dir" ] || return 1
  [ "$(stat -c '%a' "$dir" 2>/dev/null || echo 0)" = 700 ] || return 1
  for entry in "$dir"/* "$dir"/.[!.]* "$dir"/..?*; do
    [ -e "$entry" ] || continue
    is_expected_name "$(basename "$entry")" || return 1
  done
  for name in $all_files; do
    protected_file "$dir/$name" || return 1
  done

  sh "$(dirname "$0")/validate-token.sh" "$dir/service-token" || return 1
  instance_id=$(cat "$dir/instance-id")
  printf '%s\n' "$instance_id" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$' || return 1
  password=$(sed -n '1{/^$/d;p;}' "$dir/postgres-password")
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
  server_name=$(sed -n 's/^DIREXTALK_HEALTHCHECK_SERVER_NAME=//p' "$dir/.env" | tail -n 1)
  [ -n "$server_name" ] || return 1
  openssl x509 -in "$dir/tls-cert" -noout -ext subjectAltName 2>/dev/null | grep -Fq "DNS:$server_name" || return 1
  grep -Fqx "instance_id: $instance_id" "$dir/config.yaml" || return 1
  grep -Fqx "DIREXTALK_AGENT_CONFIG_FILE=$dir/config.yaml" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_POSTGRES_PASSWORD_FILE=$dir/postgres-password" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_DATABASE_URL_FILE=$dir/database-url" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_TLS_CERT_FILE=$dir/tls-cert" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_TLS_KEY_FILE=$dir/tls-key" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_TLS_CA_FILE=$dir/tls-ca" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_SERVICE_TOKEN_FILE=$dir/service-token" "$dir/.env" || return 1
  grep -Fqx "DIREXTALK_CORE_SECRET_MASTER_KEY_FILE=$dir/core-secret-master-key" "$dir/.env" || return 1
  grep -Fqx "core_secret_master_key_file: /run/secrets/core_secret_master_key" "$dir/config.yaml" || return 1
  grep -Fqx "core_secret_master_key_version: 1" "$dir/config.yaml" || return 1
  grep -Fqx "DIREXTALK_AGENT_INSTANCE_ID_FILE=$dir/instance-id" "$dir/.env" || return 1
}

manifest=$dir/.manifest
validate_artifacts || die "artifact set is incomplete or invalid"
validate_manifest_shape "$manifest" || die "existing manifest is incomplete or invalid"
for name in $immutable_files; do
  check_manifest_hash "$manifest" "$name" || die "immutable artifact changed; refusing rotation: $name"
done

tmp_manifest=$(mktemp "$dir/.manifest.tmp.XXXXXX")
(
  cd "$dir"
  {
    printf '%s\n' '# dirextalk-bootstrap-manifest-v1'
    sha256sum $all_files
  } > "$tmp_manifest"
)
chmod 0400 "$tmp_manifest"
validate_manifest_shape "$tmp_manifest" || die "new manifest failed validation"
(cd "$dir" && tail -n +2 "$tmp_manifest" | sha256sum -c --status -) || die "new manifest hash validation failed"
manifest=$dir/.manifest
mv "$tmp_manifest" "$manifest"
tmp_manifest=""
echo "refreshed bootstrap manifest after validated TLS/token rotation" >&2
