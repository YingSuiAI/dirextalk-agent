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
  RELEASE_MESSAGE_SERVER_ROOT=${DIREXTALK_MESSAGE_SERVER_ROOT:-$RELEASE_REPO_ROOT/../dirextalk-message-server}
  export RELEASE_VERSION RELEASE_REPO_ROOT RELEASE_OUTPUT_DIR RELEASE_CONFIG
  export RELEASE_CONTEXT RELEASE_VERIFIED RELEASE_IMAGE RELEASE_EXPECTED_BRANCH
  export RELEASE_MESSAGE_SERVER_ROOT
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

release_require_message_server() {
  local root head
  root=$(cd "$RELEASE_MESSAGE_SERVER_ROOT" && pwd -P) || release_die 'Message Server checkout is unavailable'
  for path in p2p/native_agent_catalog.go internal/agentgateway/runner.go internal/agentgateway/catalog_requirements.go; do
    [[ -f "$root/$path" ]] || release_die "Message Server release input is missing: $path"
  done
  [[ -z "$(git -C "$root" status --porcelain=v1 --untracked-files=all)" ]] || \
    release_die 'Message Server release input must be clean'
  head=$(git -C "$root" rev-parse HEAD)
  [[ "$head" =~ ^[0-9a-f]{40}$ && "$head" == "$(release_remote_main "$root")" ]] || \
    release_die 'Message Server release input must exactly match origin/main'
  RELEASE_MESSAGE_SERVER_ROOT=$root
  export RELEASE_MESSAGE_SERVER_ROOT
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
}
