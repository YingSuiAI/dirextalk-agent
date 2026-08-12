#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
prepare="$repo_root/scripts/release/prepare.sh"
verify="$repo_root/scripts/release/verify.sh"
publish="$repo_root/scripts/release/publish.sh"
lib="$repo_root/scripts/release/lib.sh"
version=v1.0.69
head_commit=1111111111111111111111111111111111111111
other_commit=2222222222222222222222222222222222222222

fail() {
  printf 'Agent release contract test failed: %s\n' "$*" >&2
  exit 1
}

for script in "$lib" "$prepare" "$verify" "$publish"; do
  [[ -f "$script" ]] || fail "missing ${script#"$repo_root"/}"
done
grep -F 'uses: docker/setup-buildx-action@v3' "$repo_root/.github/workflows/release.yml" >/dev/null || \
  fail 'release workflow does not install Docker Buildx'
if grep -Eq 'docker (push|tag)([[:space:]]|$)' "$publish"; then
  fail 'publish still uses mutable local docker push/tag publication'
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

make_fixture() {
  local name=$1 requested_version=${2:-$version}
  local fixture=$tmp/$name
  mkdir -p "$fixture/bin" "$fixture/repo/scripts/release" \
    "$fixture/repo/release" "$fixture/repo/internal/buildinfo" \
    "$fixture/repo/migrations" "$fixture/message-server/p2p" \
    "$fixture/message-server/internal/agentgateway"
  cp "$lib" "$prepare" "$verify" "$publish" "$fixture/repo/scripts/release/"
  printf '# Agent releases\n\n## %s\n\nStable Agent release.\n' "$requested_version" \
    >"$fixture/repo/release/RELEASE_NOTES.md"
  python3 - "$fixture/repo/release/$requested_version.json" "$requested_version" <<'PY'
import json, pathlib, sys

path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({
    "version": sys.argv[2],
    "schema_version": 12,
    "schema_compat_version": 1,
}, separators=(",", ":")) + "\n", encoding="utf-8")
PY
  cp "$repo_root/internal/buildinfo/version.go" "$fixture/repo/internal/buildinfo/version.go"
  cp "$repo_root/migrations/embed.go" "$fixture/repo/migrations/embed.go"
  touch "$fixture/message-server/p2p/native_agent_catalog.go"
  touch "$fixture/message-server/internal/agentgateway/runner.go"
  touch "$fixture/message-server/internal/agentgateway/catalog_requirements.go"
  : >"$fixture/commands.log"

  install_fake_tools "$fixture"
  printf '%s\n' "$fixture"
}

install_fake_tools() {
  local fixture=$1
  cat >"$fixture/bin/git" <<EOF
#!/usr/bin/env bash
set -euo pipefail

printf 'git %s\n' "\$*" >>"\$AGENT_RELEASE_TEST_LOG"
root=\$(pwd -P)
if [[ "\${1:-}" == -C ]]; then
  root=\$(cd "\$2" && pwd -P)
  shift 2
fi

case "\${1:-}" in
  status)
    if [[ "\$root" == "\$AGENT_RELEASE_TEST_MESSAGE_SERVER_ROOT" ]]; then
      printf '%s' "\${FAKE_MESSAGE_SERVER_DIRTY:-}"
    else
      printf '%s' "\${FAKE_AGENT_DIRTY:-}"
    fi
    ;;
  branch)
    [[ "\${2:-}" == --show-current ]] || exit 2
    printf '%s\n' "\${FAKE_AGENT_BRANCH:-main}"
    ;;
  rev-parse)
    case "\${2:-}" in
      HEAD)
        if [[ "\$root" == "\$AGENT_RELEASE_TEST_MESSAGE_SERVER_ROOT" ]]; then
          printf '%s\n' "\${FAKE_MESSAGE_SERVER_HEAD:-$head_commit}"
        else
          printf '%s\n' "\${FAKE_AGENT_HEAD:-$head_commit}"
        fi
        ;;
      refs/tags/*'^{}') printf '%s\n' "\${FAKE_LOCAL_TAG_COMMIT:-\${FAKE_AGENT_HEAD:-$head_commit}}" ;;
      refs/tags/*) printf '%s\n' "\${FAKE_LOCAL_TAG_OBJECT:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}" ;;
      *) exit 2 ;;
    esac
    ;;
  ls-remote)
    if [[ "\${2:-}" == --exit-code ]]; then
      if [[ "\$root" == "\$AGENT_RELEASE_TEST_MESSAGE_SERVER_ROOT" ]]; then
        printf '%s\trefs/heads/main\n' "\${FAKE_MESSAGE_SERVER_REMOTE_HEAD:-\${FAKE_MESSAGE_SERVER_HEAD:-$head_commit}}"
      else
        printf '%s\trefs/heads/main\n' "\${FAKE_AGENT_REMOTE_HEAD:-\${FAKE_AGENT_HEAD:-$head_commit}}"
      fi
    elif [[ "\${2:-}" == --tags ]]; then
      requested_ref=\${4:-}
      if [[ -f "\$AGENT_RELEASE_TEST_GIT_STATE.remote-tag" || -n "\${FAKE_REMOTE_TAG_COMMIT:-}" ]]; then
        printf '%s\t%s\n' "\${FAKE_REMOTE_TAG_OBJECT:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}" "\$requested_ref"
        if [[ "\${FAKE_REMOTE_TAG_LIGHTWEIGHT:-0}" != 1 ]]; then
          printf '%s\t%s^{}\n' "\${FAKE_REMOTE_TAG_COMMIT:-\${FAKE_AGENT_HEAD:-$head_commit}}" "\$requested_ref"
        fi
      fi
    else
      exit 2
    fi
    ;;
  show)
    printf '%s\n' '2026-08-12T08:00:00+08:00'
    ;;
  tag)
    if [[ "\${2:-}" == --list ]]; then
      if [[ -f "\$AGENT_RELEASE_TEST_GIT_STATE.local-tag" || -n "\${FAKE_LOCAL_TAG:-}" ]]; then
        printf '%s\n' "\${FAKE_LOCAL_TAG:-\${3:-$version}}"
      fi
    elif [[ "\${2:-}" == -a ]]; then
      : >"\$AGENT_RELEASE_TEST_GIT_STATE.local-tag"
    else
      exit 2
    fi
    ;;
  cat-file)
    printf '%s\n' "\${FAKE_LOCAL_TAG_TYPE:-tag}"
    ;;
  var)
    [[ "\${FAKE_GIT_IDENTITY_VALID:-1}" == 1 ]] || exit 1
    printf '%s\n' 'Release Bot <release@example.invalid> 1786492800 +0800'
    ;;
  push)
    if [[ "\$*" == *refs/tags/* ]]; then
      : >"\$AGENT_RELEASE_TEST_GIT_STATE.remote-tag"
    fi
    ;;
  *)
    exit 2
    ;;
esac
EOF
  cat >"$fixture/bin/go" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'go message_server_root=%s %s\n' "\${DIREXTALK_MESSAGE_SERVER_ROOT:-}" "\$*" >>"\$AGENT_RELEASE_TEST_LOG"
if [[ -n "\${FAKE_GO_FAIL_PATTERN:-}" && "\$*" == *"\$FAKE_GO_FAIL_PATTERN"* ]]; then
  exit 1
fi
EOF
  cat >"$fixture/bin/buf" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'buf %s\n' "\$*" >>"\$AGENT_RELEASE_TEST_LOG"
[[ "\${FAKE_BUF_FAIL:-0}" != 1 ]]
EOF
  cat >"$fixture/bin/docker" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'docker %s\n' "\$*" >>"\$AGENT_RELEASE_TEST_LOG"
if [[ -n "\${FAKE_DOCKER_FAIL_PATTERN:-}" && "\$*" == *"\$FAKE_DOCKER_FAIL_PATTERN"* ]]; then
  exit 1
fi

if [[ "\${1:-} \${2:-}" == 'image inspect' ]]; then
  ref=\${3:-}
  if [[ "\$*" == *'{{.Id}}'* ]]; then
    if [[ "\$ref" == *@sha256:* ]]; then
      printf '%s\n' "\${FAKE_REMOTE_IMAGE_ID:-sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}"
    else
      printf '%s\n' "\${FAKE_IMAGE_ID:-sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}"
    fi
  elif [[ "\$ref" == *@sha256:* && "\${FAKE_REMOTE_LABEL_DRIFT:-0}" == 1 ]]; then
    printf '%s\n' "\$RELEASE_VERSION|$other_commit|\$RELEASE_BUILD_TIME"
  else
    printf '%s\n' "\$RELEASE_VERSION|\${FAKE_IMAGE_REVISION:-\$RELEASE_COMMIT}|\$RELEASE_BUILD_TIME"
  fi
elif [[ "\${1:-}" == run ]]; then
  binary=
  immutable=0
  while (( \$# )); do
    if [[ "\$1" == --entrypoint ]]; then
      binary=\$2
    fi
    [[ "\$1" == *@sha256:* ]] && immutable=1
    shift
  done
  if [[ -n "\${FAKE_VERSION_PROBE_FAIL_BINARY:-}" && "\$binary" == */"\$FAKE_VERSION_PROBE_FAIL_BINARY" ]] || \
     [[ "\$immutable" == 1 && -n "\${FAKE_REMOTE_PROBE_FAIL_BINARY:-}" && \
        "\$binary" == */"\$FAKE_REMOTE_PROBE_FAIL_BINARY" ]]; then
    exit 1
  fi
  printf '%s\n' "\${FAKE_BINARY_VERSION:-\$RELEASE_VERSION}"
elif [[ "\${1:-} \${2:-} \${3:-}" == 'buildx imagetools inspect' ]]; then
  ref=\${4:-}
  if [[ "\$*" == *'--raw'* ]]; then
    printf '%s\n' '{"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}'
    exit 0
  fi
  if [[ "\$*" == *'.Provenance'* ]]; then
    printf '%s\n' '{"SLSA":{"buildDefinition":{"buildType":"https://mobyproject.org/buildkit@v1"}}}'
    exit 0
  fi
  if [[ "\$*" == *'.SBOM'* ]]; then
    printf '%s\n' '{"SPDX":{"spdxVersion":"SPDX-2.3"}}'
    exit 0
  fi
  if [[ "\$*" == *'org.opencontainers.image.version'* ]]; then
    printf '%s\n' "\${FAKE_LATEST_VERSION:-v1.0.68}"
    exit 0
  fi
  if [[ "\$ref" == 'dirextalk/agent:latest' && \
        ! -f "\$AGENT_RELEASE_TEST_DOCKER_STATE.latest-exists" && \
        ! -f "\$AGENT_RELEASE_TEST_DOCKER_STATE.latest-promoted" ]]; then
    printf '%s\n' 'ERROR: docker.io/dirextalk/agent:latest: not found' >&2
    exit 1
  fi
  if [[ "\$ref" == "dirextalk/agent:$version" && \
        ! -f "\$AGENT_RELEASE_TEST_DOCKER_STATE.version-index" ]]; then
    if [[ "\${FAKE_REMOTE_INDEX_INITIAL_STATE:-absent}" == infra ]]; then
      printf '%s\n' 'registry authorization timeout' >&2
      exit 1
    elif [[ "\${FAKE_REMOTE_INDEX_INITIAL_STATE:-absent}" == dns ]]; then
      printf '%s\n' 'dial tcp: lookup registry-1.docker.io: object not found' >&2
      exit 1
    elif [[ "\${FAKE_REMOTE_INDEX_INITIAL_STATE:-absent}" == absent ]]; then
      printf '%s\n' 'ERROR: docker.io/dirextalk/agent:$version: not found' >&2
      exit 1
    fi
  fi
  FAKE_INDEX_REF="\$ref" python3 - <<'PY'
import json, os

oci_index = "application/vnd.oci.image.index.v1+json"
oci_manifest = "application/vnd.oci.image.manifest.v1+json"
digest = "sha256:" + "d" * 64
if os.environ.get("FAKE_LATEST_DIGEST_MISMATCH") == "1" and os.environ["FAKE_INDEX_REF"] == "dirextalk/agent:latest":
    digest = "sha256:" + "e" * 64
if os.environ.get("FAKE_INVALID_INDEX_DIGEST") == "1":
    digest = "not-a-digest"

mode = os.environ.get("FAKE_INDEX_PLATFORM_MODE", "valid")
amd64 = {
    "mediaType": oci_manifest,
    "digest": "sha256:" + "c" * 64,
    "platform": {"os": "linux", "architecture": "amd64"},
}
attestation = {
    "mediaType": oci_manifest,
    "digest": "sha256:" + "a" * 64,
    "platform": {"os": "unknown", "architecture": "unknown"},
    "annotations": {
        "vnd.docker.reference.type": "attestation-manifest",
        "vnd.docker.reference.digest": amd64["digest"],
    },
}
if mode == "missing-amd64":
    descriptors = [attestation]
elif mode == "extra-platform":
    arm64 = dict(amd64, digest="sha256:" + "9" * 64,
                 platform={"os": "linux", "architecture": "arm64"})
    descriptors = [amd64, arm64, attestation]
elif mode == "invalid-descriptor":
    descriptors = [amd64, "invalid"]
elif mode == "invalid-descriptor-digest":
    descriptors = [dict(amd64, digest="invalid")]
elif mode == "missing-attestation":
    descriptors = [amd64]
elif mode == "unbound-attestation":
    unbound = dict(attestation, annotations=dict(attestation["annotations"],
                   **{"vnd.docker.reference.digest": "sha256:" + "8" * 64}))
    descriptors = [amd64, unbound]
else:
    descriptors = [amd64, attestation]
print(json.dumps({"manifest": {
    "mediaType": os.environ.get("FAKE_INDEX_MEDIA_TYPE", oci_index),
    "digest": digest,
    "manifests": descriptors,
}}, separators=(",", ":")))
PY
elif [[ "\${1:-} \${2:-}" == 'buildx build' ]]; then
  : >"\$AGENT_RELEASE_TEST_DOCKER_STATE.version-index"
  metadata_file=
  while (( \$# )); do
    if [[ "\$1" == --metadata-file ]]; then
      metadata_file=\$2
      break
    fi
    shift
  done
  [[ -n "\$metadata_file" ]] || exit 3
  if [[ "\${FAKE_BUILDX_METADATA_MISMATCH:-0}" == 1 ]]; then
    printf '%s\n' '{"containerimage.digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}' >"\$metadata_file"
  else
    printf '%s\n' '{"containerimage.digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}' >"\$metadata_file"
  fi
elif [[ "\${1:-} \${2:-} \${3:-}" == 'buildx imagetools create' ]]; then
  : >"\$AGENT_RELEASE_TEST_DOCKER_STATE.latest-promoted"
  : >"\$AGENT_RELEASE_TEST_DOCKER_STATE.latest-exists"
fi
EOF
  cat >"$fixture/bin/gh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'gh %s\n' "\$*" >>"\$AGENT_RELEASE_TEST_LOG"

if [[ "\${1:-}" == api ]]; then
  if [[ -f "\$AGENT_RELEASE_TEST_GH_STATE.release" ]]; then
    printf '%s\n' 'HTTP/1.1 200 OK'
    exit 0
  fi
  printf '%s\n' 'HTTP/1.1 404 Not Found' >&2
  exit 1
fi

if [[ "\${1:-} \${2:-}" == 'release view' ]]; then
  [[ -f "\$AGENT_RELEASE_TEST_GH_STATE.release" ]] || exit 1
  FAKE_GH_REQUESTED_TAG=\${3:-} python3 - <<'PY'
import json, os, pathlib

tag = os.environ["FAKE_GH_REQUESTED_TAG"]
notes = pathlib.Path(os.environ["RELEASE_OUTPUT_DIR"], "release-notes.md").read_text(encoding="utf-8")
print(json.dumps({
    "tagName": os.environ.get("FAKE_GH_TAG", tag),
    "name": os.environ.get("FAKE_GH_TITLE", f"Dirextalk Agent {tag}"),
    "body": os.environ.get("FAKE_GH_BODY", notes),
    "isDraft": os.environ.get("FAKE_GH_DRAFT", "false") == "true",
    "isPrerelease": os.environ.get("FAKE_GH_PRERELEASE", "false") == "true",
    "assets": [{"name": "stale.txt"}] if os.environ.get("FAKE_GH_ASSETS", "0") == "1" else [],
}, separators=(",", ":")))
PY
  exit 0
fi

if [[ "\${1:-} \${2:-}" == 'release create' ]]; then
  [[ "\${FAKE_GH_CREATE_FAIL:-0}" != 1 ]] || exit 1
  : >"\$AGENT_RELEASE_TEST_GH_STATE.release"
  exit 0
fi
exit 2
EOF
  chmod +x "$fixture/bin/"*
}

run_script() {
  local fixture=$1 script=$2 requested_version=${3:-$version}
  shift 3 || true
  (
    cd "$fixture/repo"
    PATH="$fixture/bin:$PATH" \
      AGENT_RELEASE_REPO_ROOT="$fixture/repo" \
      AGENT_RELEASE_CONTRACT_TEST=1 \
      DIREXTALK_MESSAGE_SERVER_ROOT="$fixture/message-server" \
      AGENT_TEST_POSTGRES_DSN='postgres://fixture.invalid/agent' \
      AGENT_RELEASE_TEST_LOG="$fixture/commands.log" \
      AGENT_RELEASE_TEST_GIT_STATE="$fixture/git-state" \
      AGENT_RELEASE_TEST_GH_STATE="$fixture/gh-state" \
      AGENT_RELEASE_TEST_DOCKER_STATE="$fixture/docker-state" \
      AGENT_RELEASE_TEST_MESSAGE_SERVER_ROOT="$fixture/message-server" \
      "$@" bash "$fixture/repo/scripts/release/$script" "$requested_version"
  )
}

prepare_and_verify() {
  local fixture=$1
  run_script "$fixture" prepare.sh "$version" env
  run_script "$fixture" verify.sh "$version" env
}

clear_log() {
  : >"$1/commands.log"
}

assert_no_version_publication() {
  local fixture=$1 reason=$2
  if grep -F 'docker buildx build ' "$fixture/commands.log" >/dev/null; then
    fail "$reason published the version OCI index"
  fi
}

assert_latest_not_promoted() {
  local fixture=$1 reason=$2
  if grep -F 'docker buildx imagetools create --tag dirextalk/agent:latest' "$fixture/commands.log" >/dev/null; then
    fail "$reason promoted latest"
  fi
}

# Source and metadata gates.
fixture=$(make_fixture noncanonical)
if run_script "$fixture" prepare.sh v1.0.069 env; then
  fail 'prepare accepted a non-canonical version'
fi

fixture=$(make_fixture dirty)
if run_script "$fixture" prepare.sh "$version" env FAKE_AGENT_DIRTY=' M tracked.go'; then
  fail 'prepare accepted a dirty Agent checkout'
fi

fixture=$(make_fixture branch)
if run_script "$fixture" prepare.sh "$version" env FAKE_AGENT_BRANCH=feature; then
  fail 'prepare accepted a non-main branch'
fi

fixture=$(make_fixture agent-remote-drift)
if run_script "$fixture" prepare.sh "$version" env FAKE_AGENT_REMOTE_HEAD="$other_commit"; then
  fail 'prepare accepted Agent HEAD drift from origin/main'
fi

fixture=$(make_fixture notes)
printf '# no matching notes\n' >"$fixture/repo/release/RELEASE_NOTES.md"
if run_script "$fixture" prepare.sh "$version" env; then
  fail 'prepare accepted missing version release notes'
fi

fixture=$(make_fixture source-version)
sed -i 's/v1\.0\.69/v9.9.9/' "$fixture/repo/internal/buildinfo/version.go"
if run_script "$fixture" prepare.sh "$version" env; then
  fail 'prepare accepted source version drift'
fi

fixture=$(make_fixture schema-version)
sed -i 's/int64(12)/int64(13)/' "$fixture/repo/migrations/embed.go"
if run_script "$fixture" prepare.sh "$version" env; then
  fail 'prepare accepted schema version drift'
fi

fixture=$(make_fixture schema-compat)
sed -i 's/SchemaCompatVersion   = 1/SchemaCompatVersion   = 2/' "$fixture/repo/internal/buildinfo/version.go"
if run_script "$fixture" prepare.sh "$version" env; then
  fail 'prepare accepted schema compatibility drift'
fi

fixture=$(make_fixture extra-metadata)
python3 - "$fixture/repo/release/$version.json" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["minimum_message_server_version"] = "v1.0.0"
path.write_text(json.dumps(value) + "\n", encoding="utf-8")
PY
if run_script "$fixture" prepare.sh "$version" env; then
  fail 'prepare accepted a non-contract metadata field'
fi

# The sibling Message Server is a mandatory, immutable verification input.
fixture=$(make_fixture dirty-message-server)
run_script "$fixture" prepare.sh "$version" env
if run_script "$fixture" verify.sh "$version" env FAKE_MESSAGE_SERVER_DIRTY=' M p2p/native_agent_catalog.go'; then
  fail 'verify accepted a dirty Message Server checkout'
fi

fixture=$(make_fixture message-server-remote-drift)
run_script "$fixture" prepare.sh "$version" env
if run_script "$fixture" verify.sh "$version" env FAKE_MESSAGE_SERVER_REMOTE_HEAD="$other_commit"; then
  fail 'verify accepted Message Server HEAD drift from origin/main'
fi

# Verify must exercise the full build and bind canonical evidence to one image.
fixture=$(make_fixture verify-contract)
run_script "$fixture" prepare.sh "$version" env
run_script "$fixture" verify.sh "$version" env
grep -F "go message_server_root=$fixture/message-server test ./... -count=1" "$fixture/commands.log" >/dev/null || \
  fail 'verify did not run the Agent suite with the Message Server catalog input'
grep -F "go message_server_root=$fixture/message-server build ./cmd/..." "$fixture/commands.log" >/dev/null || \
  fail 'verify did not build all Agent commands'
grep -F 'buf lint' "$fixture/commands.log" >/dev/null || fail 'verify did not lint Protobuf'
build_line=$(grep -F 'docker build ' "$fixture/commands.log" | tail -1)
[[ "$build_line" == *"--build-arg VERSION=$version"* && \
   "$build_line" == *"--build-arg REVISION=$head_commit"* && \
   "$build_line" == *'--build-arg BUILD_TIME=2026-08-12T08:00:00+08:00'* ]] || \
  fail 'verify omitted a canonical image build argument'
for binary in dirextalk-agent dirextalk-extension-runner dirextalk-core-runner; do
  grep -F -- "--entrypoint /usr/local/bin/$binary" "$fixture/commands.log" >/dev/null || \
    fail "verify omitted the $binary version probe"
done
python3 - "$fixture/repo/.release/$version/release-context.json" \
  "$fixture/repo/.release/$version/verified.json" "$version" "$head_commit" <<'PY' || \
  fail 'prepare/verify evidence is not canonical and commit-bound'
import json, pathlib, sys

context_path, verified_path, version, commit = sys.argv[1:]
for path, kind, has_image_id in (
    (pathlib.Path(context_path), "prepared", False),
    (pathlib.Path(verified_path), "verified", True),
):
    raw = path.read_bytes()
    value = json.loads(raw)
    expected = {"kind", "version", "commit", "build_time", "image"}
    if has_image_id:
        expected.add("image_id")
    assert set(value) == expected
    assert raw == json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    assert value["kind"] == kind
    assert value["version"] == version
    assert value["commit"] == commit
    assert value["image"] == f"dirextalk/agent:{version}"
    if has_image_id:
        assert value["image_id"] == "sha256:" + "b" * 64
PY

fixture=$(make_fixture failed-binary-probe)
run_script "$fixture" prepare.sh "$version" env
if run_script "$fixture" verify.sh "$version" env FAKE_VERSION_PROBE_FAIL_BINARY=dirextalk-core-runner; then
  fail 'verify ignored a failing runner version probe'
fi
[[ ! -e "$fixture/repo/.release/$version/verified.json" ]] || \
  fail 'verify wrote successful evidence after a failed version probe'

fixture=$(make_fixture tampered-context)
run_script "$fixture" prepare.sh "$version" env
printf '\nnot canonical\n' >>"$fixture/repo/.release/$version/release-context.json"
if run_script "$fixture" verify.sh "$version" env; then
  fail 'verify accepted tampered prepare evidence'
fi

# Existing tag and formal Release conflicts must fail before the version image moves.
fixture=$(make_fixture local-tag-mismatch)
prepare_and_verify "$fixture"
clear_log "$fixture"
if run_script "$fixture" publish.sh "$version" env FAKE_LOCAL_TAG="$version" FAKE_LOCAL_TAG_COMMIT="$other_commit"; then
  fail 'publish accepted a local tag on another commit'
fi
assert_no_version_publication "$fixture" 'local tag mismatch'

fixture=$(make_fixture remote-tag-mismatch)
prepare_and_verify "$fixture"
clear_log "$fixture"
if run_script "$fixture" publish.sh "$version" env FAKE_REMOTE_TAG_COMMIT="$other_commit"; then
  fail 'publish accepted a remote tag on another commit'
fi
assert_no_version_publication "$fixture" 'remote tag mismatch'

fixture=$(make_fixture lightweight-remote-tag)
prepare_and_verify "$fixture"
clear_log "$fixture"
if run_script "$fixture" publish.sh "$version" env \
    FAKE_REMOTE_TAG_COMMIT="$head_commit" FAKE_REMOTE_TAG_LIGHTWEIGHT=1; then
  fail 'publish accepted a lightweight remote tag'
fi
assert_no_version_publication "$fixture" 'lightweight remote tag'

for stale_case in title body assets draft prerelease; do
  fixture=$(make_fixture "stale-release-$stale_case")
  prepare_and_verify "$fixture"
  : >"$fixture/gh-state.release"
  clear_log "$fixture"
  case "$stale_case" in
    title) stale_env=(FAKE_GH_TITLE='stale title') ;;
    body) stale_env=(FAKE_GH_BODY='stale body') ;;
    assets) stale_env=(FAKE_GH_ASSETS=1) ;;
    draft) stale_env=(FAKE_GH_DRAFT=true) ;;
    prerelease) stale_env=(FAKE_GH_PRERELEASE=true) ;;
  esac
  if run_script "$fixture" publish.sh "$version" env \
      FAKE_REMOTE_TAG_COMMIT="$head_commit" "${stale_env[@]}"; then
    fail "publish accepted stale GitHub Release $stale_case"
  fi
  assert_no_version_publication "$fixture" "stale GitHub Release $stale_case"
done

fixture=$(make_fixture tampered-verified)
prepare_and_verify "$fixture"
printf '\nnot canonical\n' >>"$fixture/repo/.release/$version/verified.json"
clear_log "$fixture"
if run_script "$fixture" publish.sh "$version" env; then
  fail 'publish accepted tampered verification evidence'
fi
assert_no_version_publication "$fixture" 'tampered verification evidence'

fixture=$(make_fixture changed-image)
prepare_and_verify "$fixture"
clear_log "$fixture"
if run_script "$fixture" publish.sh "$version" env \
    FAKE_IMAGE_ID=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc; then
  fail 'publish accepted a changed verified image ID'
fi
assert_no_version_publication "$fixture" 'changed verified image ID'

# Any OCI-index, immutable-image, or formal-Release failure must leave latest untouched.
fixture=$(make_fixture version-index-build-failure)
prepare_and_verify "$fixture"
clear_log "$fixture"
if run_script "$fixture" publish.sh "$version" env FAKE_DOCKER_FAIL_PATTERN='buildx build'; then
  fail 'publish succeeded after the version OCI index build failed'
fi
assert_latest_not_promoted "$fixture" 'version OCI index build failure'

fixture=$(make_fixture version-index-inspect-infrastructure-failure)
prepare_and_verify "$fixture"
clear_log "$fixture"
if run_script "$fixture" publish.sh "$version" env FAKE_REMOTE_INDEX_INITIAL_STATE=infra; then
  fail 'publish treated an OCI index inspection infrastructure failure as absence'
fi
assert_no_version_publication "$fixture" 'OCI index inspection infrastructure failure'
assert_latest_not_promoted "$fixture" 'OCI index inspection infrastructure failure'

fixture=$(make_fixture version-index-inspect-dns-not-found)
prepare_and_verify "$fixture"
clear_log "$fixture"
if run_script "$fixture" publish.sh "$version" env FAKE_REMOTE_INDEX_INITIAL_STATE=dns; then
  fail 'publish treated a DNS not-found infrastructure failure as version absence'
fi
assert_no_version_publication "$fixture" 'DNS not-found infrastructure failure'
assert_latest_not_promoted "$fixture" 'DNS not-found infrastructure failure'

for index_case in docker-v2 missing-amd64 extra-platform invalid-descriptor \
    invalid-descriptor-digest invalid-index-digest missing-attestation unbound-attestation; do
  fixture=$(make_fixture "invalid-index-$index_case")
  prepare_and_verify "$fixture"
  clear_log "$fixture"
  case "$index_case" in
    docker-v2)
      index_env=(FAKE_INDEX_MEDIA_TYPE=application/vnd.docker.distribution.manifest.list.v2+json)
      ;;
    missing-amd64) index_env=(FAKE_INDEX_PLATFORM_MODE=missing-amd64) ;;
    extra-platform) index_env=(FAKE_INDEX_PLATFORM_MODE=extra-platform) ;;
    invalid-descriptor) index_env=(FAKE_INDEX_PLATFORM_MODE=invalid-descriptor) ;;
    invalid-descriptor-digest) index_env=(FAKE_INDEX_PLATFORM_MODE=invalid-descriptor-digest) ;;
    invalid-index-digest) index_env=(FAKE_INVALID_INDEX_DIGEST=1) ;;
    missing-attestation) index_env=(FAKE_INDEX_PLATFORM_MODE=missing-attestation) ;;
    unbound-attestation) index_env=(FAKE_INDEX_PLATFORM_MODE=unbound-attestation) ;;
  esac
  if run_script "$fixture" publish.sh "$version" env "${index_env[@]}"; then
    fail "publish accepted invalid OCI index $index_case"
  fi
  assert_latest_not_promoted "$fixture" "invalid OCI index $index_case"
done

fixture=$(make_fixture buildx-metadata-mismatch)
prepare_and_verify "$fixture"
clear_log "$fixture"
if run_script "$fixture" publish.sh "$version" env FAKE_BUILDX_METADATA_MISMATCH=1; then
  fail 'publish accepted Buildx metadata digest drift from the registry index'
fi
assert_latest_not_promoted "$fixture" 'Buildx metadata digest mismatch'

fixture=$(make_fixture immutable-pull-failure)
prepare_and_verify "$fixture"
clear_log "$fixture"
if run_script "$fixture" publish.sh "$version" env \
    FAKE_DOCKER_FAIL_PATTERN='pull --platform linux/amd64 dirextalk/agent@sha256:'; then
  fail 'publish succeeded when the immutable linux/amd64 pull failed'
fi
assert_latest_not_promoted "$fixture" 'immutable linux/amd64 pull failure'

fixture=$(make_fixture immutable-label-drift)
prepare_and_verify "$fixture"
clear_log "$fixture"
if run_script "$fixture" publish.sh "$version" env FAKE_REMOTE_LABEL_DRIFT=1; then
  fail 'publish accepted immutable image label drift'
fi
assert_latest_not_promoted "$fixture" 'immutable image label drift'

for binary in dirextalk-agent dirextalk-extension-runner dirextalk-core-runner; do
  fixture=$(make_fixture "immutable-probe-$binary")
  prepare_and_verify "$fixture"
  clear_log "$fixture"
  if run_script "$fixture" publish.sh "$version" env FAKE_REMOTE_PROBE_FAIL_BINARY="$binary"; then
    fail "publish ignored immutable $binary version probe failure"
  fi
  assert_latest_not_promoted "$fixture" "immutable $binary version probe failure"
done

fixture=$(make_fixture release-create-failure)
prepare_and_verify "$fixture"
clear_log "$fixture"
if run_script "$fixture" publish.sh "$version" env FAKE_GH_CREATE_FAIL=1; then
  fail 'publish succeeded after GitHub Release creation failure'
fi
assert_latest_not_promoted "$fixture" 'GitHub Release creation failure'

# The only successful order is version index -> immutable probes -> formal Release -> digest promotion.
fixture=$(make_fixture publish-order)
prepare_and_verify "$fixture"
clear_log "$fixture"
run_script "$fixture" publish.sh "$version" env
version_line=$(grep -nF 'docker buildx build ' "$fixture/commands.log" | tail -1 | cut -d: -f1)
immutable_pull_line=$(grep -nF 'docker pull --platform linux/amd64 dirextalk/agent@sha256:' "$fixture/commands.log" | head -1 | cut -d: -f1)
release_line=$(grep -nF "gh release create $version" "$fixture/commands.log" | tail -1 | cut -d: -f1)
latest_line=$(grep -nF 'docker buildx imagetools create --tag dirextalk/agent:latest' "$fixture/commands.log" | tail -1 | cut -d: -f1)
[[ -n "$version_line" && -n "$immutable_pull_line" && \
   -n "$release_line" && -n "$latest_line" ]] || \
  fail 'successful publish omitted an OCI index publication or verification phase'
(( version_line < immutable_pull_line && immutable_pull_line < release_line && release_line < latest_line )) || \
  fail 'publish order is not version index -> immutable probes -> Release -> latest promotion'
publish_build_line=$(grep -F 'docker buildx build ' "$fixture/commands.log" | tail -1)
[[ "$publish_build_line" == *'--platform linux/amd64'* && \
   "$publish_build_line" == *'--provenance=mode=max'* && \
   "$publish_build_line" == *'--sbom=true'* && \
   "$publish_build_line" == *'--push'* && \
   "$publish_build_line" == *'--metadata-file '* && \
   "$publish_build_line" == *"--build-arg VERSION=$version"* && \
   "$publish_build_line" == *"--build-arg REVISION=$head_commit"* ]] || \
  fail 'publish omitted an immutable OCI index build requirement'
for binary in dirextalk-agent dirextalk-extension-runner dirextalk-core-runner; do
  probe_line=$(grep -nF -- "--entrypoint /usr/local/bin/$binary dirextalk/agent@sha256:" \
    "$fixture/commands.log" | head -1 | cut -d: -f1)
  [[ -n "$probe_line" && "$probe_line" -lt "$release_line" ]] || \
    fail "publish did not probe immutable $binary before the formal Release"
done
if grep -Eq '^docker (push|tag)([[:space:]]|$)' "$fixture/commands.log"; then
  fail 'successful publish used forbidden docker push/tag mutation'
fi

fixture=$(make_fixture digest-mismatch)
prepare_and_verify "$fixture"
clear_log "$fixture"
if run_script "$fixture" publish.sh "$version" env FAKE_LATEST_DIGEST_MISMATCH=1; then
  fail 'publish accepted different version and latest repository digests'
fi

# Repeating the exact publication is safe and must not recreate tag or Release.
fixture=$(make_fixture idempotent)
prepare_and_verify "$fixture"
run_script "$fixture" publish.sh "$version" env
clear_log "$fixture"
run_script "$fixture" publish.sh "$version" env
if grep -F "git tag -a $version" "$fixture/commands.log" >/dev/null; then
  fail 'exact retry recreated the annotated tag'
fi
if grep -F "git push origin refs/tags/$version" "$fixture/commands.log" >/dev/null; then
  fail 'exact retry pushed the existing annotated tag again'
fi
if grep -F "gh release create $version" "$fixture/commands.log" >/dev/null; then
  fail 'exact retry recreated the formal GitHub Release'
fi
if grep -F 'docker buildx build ' "$fixture/commands.log" >/dev/null; then
  fail 'exact retry rebuilt an existing exact OCI index'
fi
grep -F "docker buildx imagetools inspect dirextalk/agent:$version" "$fixture/commands.log" >/dev/null || \
  fail 'exact retry did not revalidate the existing version OCI index'
if grep -F 'docker buildx imagetools create --tag dirextalk/agent:latest' "$fixture/commands.log" >/dev/null; then
  fail 'exact retry repeated an already exact latest promotion'
fi
grep -F 'docker buildx imagetools inspect dirextalk/agent:latest' "$fixture/commands.log" >/dev/null || \
  fail 'exact retry did not revalidate the existing latest OCI index'

fixture=$(make_fixture newer-latest)
prepare_and_verify "$fixture"
: >"$fixture/docker-state.latest-exists"
clear_log "$fixture"
if run_script "$fixture" publish.sh "$version" env \
    FAKE_REMOTE_INDEX_INITIAL_STATE=existing FAKE_LATEST_VERSION=v1.0.70 \
    FAKE_LATEST_DIGEST_MISMATCH=1; then
  fail 'publish allowed an older release to replace newer latest'
fi
assert_latest_not_promoted "$fixture" 'newer latest rollback refusal'

printf 'Agent release contract tests passed\n'
