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
  local path=$1 kind=$2 image_id=${3:-}
  mkdir -p "$RELEASE_OUTPUT_DIR"
  python3 - "$path" "$kind" "$RELEASE_VERSION" "$RELEASE_COMMIT" "$RELEASE_BUILD_TIME" "$RELEASE_IMAGE" "$image_id" <<'PY'
import json, os, pathlib, sys, tempfile
path = pathlib.Path(sys.argv[1])
keys = ("kind", "version", "commit", "build_time", "image", "image_id")
value = dict(zip(keys, sys.argv[2:]))
if not value["image_id"]:
    value.pop("image_id")
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
  local path=$1 kind=$2 require_id=$3 values current_head
  [[ -f "$path" ]] || release_die "missing $(basename "$path") evidence"
  values=$(python3 - "$path" "$kind" "$require_id" <<'PY'
import json, pathlib, re, sys
path, expected_kind, require_id = sys.argv[1:]
raw = pathlib.Path(path).read_bytes()
value = json.loads(raw)
required = {"kind", "version", "commit", "build_time", "image"}
if require_id == "yes": required.add("image_id")
if set(value) != required or raw != json.dumps(value, separators=(",", ":"), sort_keys=True).encode():
    raise SystemExit("evidence is not canonical")
patterns = {
    "version": r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$",
    "commit": r"^[0-9a-f]{40}$",
    "build_time": r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[^\r\n]+$",
    "image": r"^dirextalk/agent:v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$",
}
if require_id == "yes": patterns["image_id"] = r"^sha256:[0-9a-f]{64}$"
if value.get("kind") != expected_kind or any(not isinstance(value.get(k), str) or not re.fullmatch(p, value[k]) for k, p in patterns.items()):
    raise SystemExit("evidence value is invalid")
for key in ("version", "commit", "build_time", "image", "image_id"):
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

release_probe_remote_index() {
  [[ $# -eq 1 ]] || release_die 'internal error: remote index verification requires one image reference'
  local ref=$1 inspection_file error_file digest status
  RELEASE_REMOTE_INDEX_EXISTS=0
  RELEASE_REMOTE_INDEX_DIGEST=
  inspection_file=$(mktemp "${TMPDIR:-/tmp}/dirextalk-agent-oci-inspect.XXXXXX")
  error_file=$(mktemp "${TMPDIR:-/tmp}/dirextalk-agent-oci-error.XXXXXX")
  if docker buildx imagetools inspect "$ref" --format '{{json .}}' >"$inspection_file" 2>"$error_file"; then
    status=0
  else
    status=$?
  fi
  if [[ "$status" -ne 0 ]]; then
    if grep -Fqx "ERROR: docker.io/$ref: not found" "$error_file" || \
       grep -Fqx "ERROR: $ref: not found" "$error_file"; then
      rm -f "$inspection_file" "$error_file"
      return
    fi
    rm -f "$inspection_file" "$error_file"
    release_die "could not inspect remote OCI index: $ref"
  fi

  if digest=$(python3 - "$inspection_file" "$ref" <<'PY'
import json, pathlib, re, sys

path, ref = sys.argv[1:]
try:
    value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
except Exception as exc:
    raise SystemExit(f"invalid imagetools response for {ref}: {exc}")

manifest = value.get("manifest") if isinstance(value, dict) else None
if not isinstance(manifest, dict):
    raise SystemExit(f"imagetools response for {ref} has no manifest")
if manifest.get("mediaType") != "application/vnd.oci.image.index.v1+json":
    raise SystemExit(f"remote image is not an OCI index: {ref}")

digest = manifest.get("digest")
if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    raise SystemExit(f"remote OCI index has an invalid digest: {ref}")

descriptors = manifest.get("manifests")
if not isinstance(descriptors, list):
    raise SystemExit(f"remote OCI index has no platform manifests: {ref}")

platforms = []
platform_digests = []
attestation_subjects = []
for descriptor in descriptors:
    if not isinstance(descriptor, dict):
        raise SystemExit(f"remote OCI index has an invalid descriptor: {ref}")
    if descriptor.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
        raise SystemExit(f"remote OCI index has a non-OCI manifest descriptor: {ref}")
    descriptor_digest = descriptor.get("digest")
    if not isinstance(descriptor_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", descriptor_digest):
        raise SystemExit(f"remote OCI index has an invalid descriptor digest: {ref}")
    platform = descriptor.get("platform")
    if not isinstance(platform, dict):
        raise SystemExit(f"remote OCI index descriptor has no platform: {ref}")
    os_name = platform.get("os")
    architecture = platform.get("architecture")
    if os_name == "unknown" and architecture == "unknown":
        annotations = descriptor.get("annotations")
        if not isinstance(annotations, dict) or annotations.get("vnd.docker.reference.type") != "attestation-manifest":
            raise SystemExit(f"remote OCI index has an unexpected unknown platform descriptor: {ref}")
        subject = annotations.get("vnd.docker.reference.digest")
        if not isinstance(subject, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", subject):
            raise SystemExit(f"remote OCI index has an unbound attestation descriptor: {ref}")
        attestation_subjects.append(subject)
        continue
    platforms.append((os_name, architecture, platform.get("variant")))
    platform_digests.append(descriptor_digest)

if platforms != [("linux", "amd64", None)]:
    raise SystemExit(f"remote OCI index must contain exactly linux/amd64: {ref}")
if attestation_subjects != [platform_digests[0]]:
    raise SystemExit(f"remote OCI index attestations are not bound to linux/amd64: {ref}")
print(digest)
print(platform_digests[0])
PY
  ); then
    status=0
  else
    status=$?
  fi
  rm -f "$inspection_file" "$error_file"
  [[ "$status" -eq 0 ]] || release_die "remote OCI index verification failed: $ref"
  mapfile -t remote_index_fields <<<"$digest"
  [[ "${#remote_index_fields[@]}" == 2 ]] || release_die "remote OCI index identity is incomplete: $ref"
  RELEASE_REMOTE_INDEX_EXISTS=1
  RELEASE_REMOTE_INDEX_DIGEST=${remote_index_fields[0]}
  RELEASE_REMOTE_PLATFORM_DIGEST=${remote_index_fields[1]}
  export RELEASE_REMOTE_INDEX_EXISTS RELEASE_REMOTE_INDEX_DIGEST RELEASE_REMOTE_PLATFORM_DIGEST
}

release_remote_index_digest() {
  [[ $# -eq 1 ]] || release_die 'internal error: remote index verification requires one image reference'
  release_probe_remote_index "$1"
  [[ "$RELEASE_REMOTE_INDEX_EXISTS" == 1 ]] || release_die "remote OCI index is unavailable: $1"
  printf '%s\n' "$RELEASE_REMOTE_INDEX_DIGEST"
}

release_remote_platform_config_digest() {
  [[ $# -eq 1 && "$1" =~ ^sha256:[0-9a-f]{64}$ ]] || \
    release_die 'remote platform manifest digest is invalid'
  local manifest_ref="dirextalk/agent@$1" raw_file config_digest status
  raw_file=$(mktemp "${TMPDIR:-/tmp}/dirextalk-agent-manifest.XXXXXX")
  if docker buildx imagetools inspect "$manifest_ref" --raw >"$raw_file"; then
    status=0
  else
    status=$?
  fi
  [[ "$status" -eq 0 ]] || {
    rm -f "$raw_file"
    release_die "could not inspect remote platform manifest: $manifest_ref"
  }
  if config_digest=$(python3 - "$raw_file" <<'PY'
import json, pathlib, re, sys

try:
    value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
except Exception as exc:
    raise SystemExit(f"invalid remote platform manifest: {exc}")
if value.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
    raise SystemExit("remote platform image is not an OCI manifest")
config = value.get("config")
digest = config.get("digest") if isinstance(config, dict) else None
if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    raise SystemExit("remote platform manifest has an invalid config digest")
print(digest)
PY
  ); then
    status=0
  else
    status=$?
  fi
  rm -f "$raw_file"
  [[ "$status" -eq 0 ]] || release_die "remote platform manifest verification failed: $manifest_ref"
  printf '%s\n' "$config_digest"
}

release_verify_remote_attestations() {
  [[ $# -eq 2 && "$2" =~ ^sha256:[0-9a-f]{64}$ ]] || \
    release_die 'remote attestation verification input is invalid'
  local ref=$1 platform_digest=$2 kind output_file status
  for kind in Provenance SBOM; do
    output_file=$(mktemp "${TMPDIR:-/tmp}/dirextalk-agent-${kind,,}.XXXXXX")
    if docker buildx imagetools inspect "$ref" --format "{{json .$kind}}" >"$output_file"; then
      status=0
    else
      status=$?
    fi
    [[ "$status" -eq 0 ]] || {
      rm -f "$output_file"
      release_die "could not inspect remote $kind attestation: $ref"
    }
    if python3 - "$output_file" "$kind" "$platform_digest" <<'PY'
import json, pathlib, sys

path, kind, platform_digest = sys.argv[1:]
try:
    value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
except Exception as exc:
    raise SystemExit(f"invalid {kind} attestation: {exc}")
if not isinstance(value, dict) or not value:
    raise SystemExit(f"remote {kind} attestation is empty")
expected_key = "SLSA" if kind == "Provenance" else "SPDX"
if expected_key not in value or not isinstance(value[expected_key], dict) or not value[expected_key]:
    raise SystemExit(f"remote {kind} attestation lacks {expected_key}")
subject = value.get("_subjectDigest")
if subject is not None and subject != platform_digest:
    raise SystemExit(f"remote {kind} attestation is bound to another manifest")
PY
    then
      status=0
    else
      status=$?
    fi
    rm -f "$output_file"
    [[ "$status" -eq 0 ]] || release_die "remote $kind attestation verification failed: $ref"
  done
}

release_buildx_metadata_digest() {
  [[ $# -eq 1 && -f "$1" ]] || release_die 'buildx metadata is unavailable'
  python3 - "$1" <<'PY'
import json, pathlib, re, sys

path = pathlib.Path(sys.argv[1])
try:
    value = json.loads(path.read_text(encoding="utf-8"))
except Exception as exc:
    raise SystemExit(f"invalid buildx metadata: {exc}")
digest = value.get("containerimage.digest") if isinstance(value, dict) else None
if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    raise SystemExit("buildx metadata has no canonical image digest")
print(digest)
PY
}
