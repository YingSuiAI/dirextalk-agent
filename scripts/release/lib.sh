#!/usr/bin/env bash
set -euo pipefail

release_die() {
  printf 'Agent release gate failed: %s\n' "$*" >&2
  exit 1
}

release_init() {
  [[ $# -eq 1 ]] || release_die 'usage: <script> vX.Y.Z'
  RELEASE_VERSION=$1
  [[ "$RELEASE_VERSION" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || \
    release_die 'version must be canonical vX.Y.Z'

  local discovered_root configured_root expected_output configured_output
  discovered_root=$(cd "$(dirname "${BASH_SOURCE[1]}")/../.." && pwd -P)
  configured_root=${AGENT_RELEASE_REPO_ROOT:-$discovered_root}
  if [[ "$configured_root" != "$discovered_root" && "${AGENT_RELEASE_CONTRACT_TEST:-0}" != 1 ]]; then
    release_die 'repository override is allowed only in contract tests'
  fi
  RELEASE_REPO_ROOT=$(cd "$configured_root" && pwd -P)
  expected_output=$RELEASE_REPO_ROOT/.release/$RELEASE_VERSION
  configured_output=${AGENT_RELEASE_OUTPUT_DIR:-$expected_output}
  if [[ "$configured_output" != "$expected_output" && "${AGENT_RELEASE_CONTRACT_TEST:-0}" != 1 ]]; then
    release_die 'release output must be the repository .release/version directory'
  fi

  RELEASE_OUTPUT_DIR=$configured_output
  RELEASE_CONFIG=$RELEASE_REPO_ROOT/release/$RELEASE_VERSION.json
  RELEASE_CONTEXT=$RELEASE_OUTPUT_DIR/release-context.json
  RELEASE_VERIFIED=$RELEASE_OUTPUT_DIR/verified.json
  RELEASE_IMAGE=dirextalk/agent:$RELEASE_VERSION
  RELEASE_EXPECTED_BRANCH=${AGENT_RELEASE_EXPECTED_BRANCH:-main}
  export RELEASE_VERSION RELEASE_REPO_ROOT RELEASE_OUTPUT_DIR RELEASE_CONFIG
  export RELEASE_CONTEXT RELEASE_VERIFIED RELEASE_IMAGE RELEASE_EXPECTED_BRANCH
}

release_require_tools() {
  local tool
  for tool in "$@"; do
    command -v "$tool" >/dev/null 2>&1 || release_die "required tool is unavailable: $tool"
  done
}

release_remote_main() {
  local root=$1 line
  line=$(git -C "$root" ls-remote --exit-code origin refs/heads/main)
  [[ "$line" =~ ^([0-9a-f]{40})[[:space:]]refs/heads/main$ ]] || release_die 'remote main response is invalid'
  printf '%s\n' "${BASH_REMATCH[1]}"
}

release_validate_config() {
  [[ -f "$RELEASE_CONFIG" ]] || release_die "missing release config release/$RELEASE_VERSION.json"
  python3 - "$RELEASE_CONFIG" "$RELEASE_VERSION" \
    "$RELEASE_REPO_ROOT/internal/buildinfo/version.go" "$RELEASE_REPO_ROOT/migrations/embed.go" <<'PY'
import json, pathlib, re, sys

config_path, expected, buildinfo_path, migrations_path = sys.argv[1:]
try:
    config = json.loads(pathlib.Path(config_path).read_bytes())
except Exception as exc:
    raise SystemExit(f"invalid release config: {exc}")
required = {"version", "schema_version", "schema_compat_version"}
if not isinstance(config, dict) or set(config) != required:
    raise SystemExit("release config fields do not match the fixed contract")
version_re = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
if config["version"] != expected or not version_re.fullmatch(expected):
    raise SystemExit("release config version mismatch")
for field in ("schema_version", "schema_compat_version"):
    value = config[field]
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise SystemExit(f"{field} must be a positive integer")
if config["schema_compat_version"] > config["schema_version"]:
    raise SystemExit("schema compatibility is invalid")

buildinfo = pathlib.Path(buildinfo_path).read_text(encoding="utf-8")
migrations = pathlib.Path(migrations_path).read_text(encoding="utf-8")
source_version = re.search(r'(?m)^\s*CurrentReleaseVersion\s*=\s*"([^"]+)"\s*$', buildinfo)
source_compat = re.search(r'(?m)^\s*SchemaCompatVersion\s*=\s*([0-9]+)\s*$', buildinfo)
source_schema = re.search(r'(?m)^\s*CurrentVersion\s*=\s*int64\(([0-9]+)\)\s*$', migrations)
if not source_version or not source_compat or not source_schema:
    raise SystemExit("source release identity is incomplete")
if source_version.group(1) != expected:
    raise SystemExit("checked-in current version does not match requested release")
if int(source_compat.group(1)) != config["schema_compat_version"] or int(source_schema.group(1)) != config["schema_version"]:
    raise SystemExit("release config schema metadata does not match source")
PY
}

release_preflight() {
  release_require_tools git python3
  cd "$RELEASE_REPO_ROOT"
  [[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || release_die 'working tree must be clean'
  [[ "$(git branch --show-current)" == "$RELEASE_EXPECTED_BRANCH" ]] || \
    release_die "release branch must be $RELEASE_EXPECTED_BRANCH"
  RELEASE_COMMIT=$(git rev-parse HEAD)
  [[ "$RELEASE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || release_die 'release commit is invalid'
  [[ "$RELEASE_COMMIT" == "$(release_remote_main "$RELEASE_REPO_ROOT")" ]] || \
    release_die 'HEAD must exactly match origin/main'
  grep -Eq "^##[[:space:]]+$RELEASE_VERSION([[:space:]]|$)" release/RELEASE_NOTES.md || \
    release_die 'matching release notes section is required'
  release_validate_config
  RELEASE_BUILD_TIME=$(git show -s --format=%cI HEAD)
  [[ "$RELEASE_BUILD_TIME" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]] || release_die 'commit build time is invalid'
  export RELEASE_COMMIT RELEASE_BUILD_TIME
}

release_write_json() {
  local path=$1 kind=$2
  mkdir -p "$RELEASE_OUTPUT_DIR"
  python3 - "$path" "$kind" "$RELEASE_VERSION" "$RELEASE_COMMIT" "$RELEASE_BUILD_TIME" "$RELEASE_IMAGE" <<'PY'
import json, os, pathlib, sys, tempfile
path = pathlib.Path(sys.argv[1])
keys = ("kind", "version", "commit", "build_time", "image")
value = dict(zip(keys, sys.argv[2:]))
data = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary): os.unlink(temporary)
PY
}

release_require_json() {
  local path=$1 kind=$2 values current_head
  [[ -f "$path" ]] || release_die "missing $(basename "$path") evidence"
  values=$(python3 - "$path" "$kind" <<'PY'
import json, pathlib, re, sys
path, expected_kind = sys.argv[1:]
raw = pathlib.Path(path).read_bytes()
value = json.loads(raw)
required = {"kind", "version", "commit", "build_time", "image"}
if set(value) != required or raw != json.dumps(value, separators=(",", ":"), sort_keys=True).encode():
    raise SystemExit("evidence is not canonical")
patterns = {
    "version": r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$",
    "commit": r"^[0-9a-f]{40}$",
    "build_time": r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[^\r\n]+$",
    "image": r"^dirextalk/agent:v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$",
}
if value.get("kind") != expected_kind or any(not isinstance(value.get(k), str) or not re.fullmatch(p, value[k]) for k, p in patterns.items()):
    raise SystemExit("evidence value is invalid")
for key in ("version", "commit", "build_time", "image"):
    print(value.get(key, ""))
PY
) || release_die "invalid $(basename "$path") evidence"
  mapfile -t RELEASE_EVIDENCE <<<"$values"
  current_head=$(git -C "$RELEASE_REPO_ROOT" rev-parse HEAD)
  [[ "${RELEASE_EVIDENCE[0]}" == "$RELEASE_VERSION" && \
     "${RELEASE_EVIDENCE[1]}" == "$RELEASE_COMMIT" && \
     "${RELEASE_EVIDENCE[1]}" == "$current_head" && \
     "${RELEASE_EVIDENCE[2]}" == "$RELEASE_BUILD_TIME" && \
     "${RELEASE_EVIDENCE[3]}" == "$RELEASE_IMAGE" ]] || release_die 'evidence does not match current release source'
}

release_write_notes() {
  local destination=$1
  python3 - "$RELEASE_REPO_ROOT/release/RELEASE_NOTES.md" "$RELEASE_VERSION" "$destination" <<'PY'
import pathlib, re, sys
source, version, destination = sys.argv[1:]
text = pathlib.Path(source).read_text(encoding="utf-8")
match = re.search(rf"(?ms)^##[ \t]+{re.escape(version)}[ \t]*\n.*?(?=^##[ \t]+v|\Z)", text)
if not match:
    raise SystemExit("release notes section is missing")
pathlib.Path(destination).write_text(match.group(0).rstrip() + "\n", encoding="utf-8", newline="\n")
PY
}

release_verify_image() {
  local ref=$1 identity binary output
  identity=$(docker image inspect "$ref" --format '{{index .Config.Labels "org.opencontainers.image.version"}}|{{index .Config.Labels "org.opencontainers.image.revision"}}|{{index .Config.Labels "org.opencontainers.image.created"}}') || \
    release_die 'Agent image inspection failed'
  [[ "$identity" == "$RELEASE_VERSION|$RELEASE_COMMIT|$RELEASE_BUILD_TIME" ]] || \
    release_die 'Agent image labels do not match the release source'
  for binary in dirextalk-agent dirextalk-extension-runner dirextalk-core-runner; do
    output=$(docker run --rm --entrypoint "/usr/local/bin/$binary" "$ref" --version) || \
      release_die "$binary version probe failed"
    [[ "$output" == "$RELEASE_VERSION" ]] || release_die "$binary reports a different version"
  done
  release_verify_http_version "$ref"
}

release_verify_http_version() (
  set -euo pipefail
  local ref=$1 probe_dir probe_id network postgres_name agent_name response status
  local postgres_image='pgvector/pgvector:pg18@sha256:691673308c99d2161ba298736f3147f1f22d79de2fb7ec93ae9b4afcab870b62'
  local probe_client_image='docker.io/library/alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40'
  release_require_tools openssl
  probe_dir=$(mktemp -d "$RELEASE_OUTPUT_DIR/http-version-probe.XXXXXX")
  probe_id="agent-release-${BASHPID}-${RANDOM}"
  network="$probe_id"
  postgres_name="$probe_id-postgres"
  agent_name="$probe_id-agent"
  # shellcheck disable=SC2329 # Invoked by the EXIT trap below.
  cleanup() {
    docker rm -f "$agent_name" "$postgres_name" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
    rm -rf "$probe_dir"
  }
  trap cleanup EXIT

  umask 077
  printf '%s' 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' >"$probe_dir/service-token"
  head -c 32 /dev/zero >"$probe_dir/core-secret-master-key"
  chmod 0400 "$probe_dir/core-secret-master-key"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$probe_dir/tls-key" -out "$probe_dir/tls-cert" -days 1 \
    -subj '/CN=localhost' >/dev/null 2>&1
  openssl genpkey -algorithm ED25519 -out "$probe_dir/grant-private-key" >/dev/null 2>&1
  openssl pkey -in "$probe_dir/grant-private-key" -pubout \
    -out "$probe_dir/grant-public-key" >/dev/null 2>&1
  rm -f "$probe_dir/grant-private-key"
  printf '%s\n' 'postgresql://postgres:agent-release-probe@postgres:5432/postgres?sslmode=disable' \
    >"$probe_dir/database-url"
  mkdir "$probe_dir/extension-staging"
  chmod 0700 "$probe_dir/extension-staging"
  cat >"$probe_dir/config.yaml" <<'EOF'
instance_id: 00000000-0000-4000-8000-000000000001
database_url_file: /probe/database-url
grpc_listen: ":9443"
tls_cert_file: /probe/tls-cert
tls_key_file: /probe/tls-key
service_token_file: /probe/service-token
core_secret_master_key_file: /probe/core-secret-master-key
core_secret_master_key_version: 1
core_extension_staging_root: /probe/extension-staging
agent_http_enabled: true
agent_http_listen: "0.0.0.0:8082"
capability_grant_public_key_file: /probe/grant-public-key
capability_account_generation: 1
enable_health_service: true
enable_reflection: false
EOF

  docker network create "$network" >/dev/null
  docker run --detach --name "$postgres_name" --network "$network" --network-alias postgres \
    --env POSTGRES_PASSWORD=agent-release-probe \
    --health-cmd 'pg_isready -U postgres' --health-interval 1s --health-timeout 3s --health-retries 30 \
    "$postgres_image" >/dev/null
  status=
  for _ in {1..30}; do
    status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$postgres_name") || \
      release_die 'release probe PostgreSQL inspection failed'
    [[ "$status" != healthy ]] || break
    [[ "$status" != unhealthy ]] || release_die 'release probe PostgreSQL is unhealthy'
    sleep 1
  done
  [[ "$status" == healthy ]] || release_die 'release probe PostgreSQL did not become healthy'

  docker run --rm --network "$network" --user "$(id -u):$(id -g)" \
    --volume "$probe_dir:/probe" "$ref" --config /probe/config.yaml migrate >/dev/null || \
    release_die 'Agent release HTTP probe migration failed'
  docker run --detach --name "$agent_name" --network "$network" --network-alias agent \
    --user "$(id -u):$(id -g)" --volume "$probe_dir:/probe" \
    "$ref" --config /probe/config.yaml serve >/dev/null || \
    release_die 'Agent release HTTP probe failed to start'

  response=
  for _ in {1..30}; do
    if response=$(docker run --rm --network "$network" "$probe_client_image" \
        wget -qO- http://agent:8082/agent/v1/health 2>/dev/null); then
      break
    fi
    status=$(docker inspect --format '{{.State.Running}}' "$agent_name") || \
      release_die 'running Agent HTTP probe inspection failed'
    if [[ "$status" != true ]]; then
      docker logs "$agent_name" >&2 || true
      release_die 'running Agent stopped before its HTTP probe'
    fi
    sleep 1
  done
  if [[ -z "$response" ]]; then
    docker logs "$agent_name" >&2 || true
    release_die 'running Agent HTTP probe did not become available'
  fi
  python3 - "$response" "$RELEASE_VERSION" <<'PY' || release_die 'running Agent HTTP release version does not match'
import json, sys

try:
    value = json.loads(sys.argv[1])
except Exception as exc:
    raise SystemExit(f"invalid Agent HTTP health response: {exc}")
if value != {"status": "ok", "release_version": sys.argv[2]}:
    raise SystemExit("Agent HTTP health response does not match the release")
PY
)
