#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
version=v1.0.69
head_commit=1111111111111111111111111111111111111111
other_commit=2222222222222222222222222222222222222222

fail() {
  printf 'Agent release contract test failed: %s\n' "$*" >&2
  exit 1
}

for script in lib.sh prepare.sh verify.sh publish.sh; do
  [[ -f "$repo_root/scripts/release/$script" ]] || fail "missing scripts/release/$script"
done
grep -F 'uses: docker/setup-buildx-action@v3' "$repo_root/.github/workflows/release.yml" >/dev/null || \
  fail 'release workflow does not install Docker Buildx'
if grep -En 'attestation|remote_index|metadata.digest|image ID changed|latest.*newer|compare-and-swap' \
    "$repo_root/scripts/release/lib.sh" "$repo_root/scripts/release/prepare.sh" \
    "$repo_root/scripts/release/verify.sh" "$repo_root/scripts/release/publish.sh" >/dev/null; then
  fail 'release scripts still contain superseded digest, attestation, image-ID, or latest-history gates'
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

install_fake_tools() {
  local fixture=$1
  mkdir -p "$fixture/bin"

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
      *) exit 2 ;;
    esac
    ;;
  ls-remote)
    if [[ "\$*" == *'refs/heads/main'* ]]; then
      if [[ "\$root" == "\$AGENT_RELEASE_TEST_MESSAGE_SERVER_ROOT" ]]; then
        printf '%s\trefs/heads/main\n' "\${FAKE_MESSAGE_SERVER_REMOTE_HEAD:-\${FAKE_MESSAGE_SERVER_HEAD:-$head_commit}}"
      else
        printf '%s\trefs/heads/main\n' "\${FAKE_AGENT_REMOTE_HEAD:-\${FAKE_AGENT_HEAD:-$head_commit}}"
      fi
    elif [[ "\$*" == *'refs/tags/'* ]]; then
      if [[ -f "\$AGENT_RELEASE_TEST_GIT_STATE.remote-tag" || -n "\${FAKE_REMOTE_TAG_COMMIT:-}" ]]; then
        requested_ref=\${*: -1}
        printf '%s\t%s\n' "\${FAKE_REMOTE_TAG_COMMIT:-\${FAKE_AGENT_HEAD:-$head_commit}}" "\$requested_ref"
      else
        exit 2
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
      if [[ -f "\$AGENT_RELEASE_TEST_GIT_STATE.local-tag" || -n "\${FAKE_LOCAL_TAG_COMMIT:-}" ]]; then
        printf '%s\n' "\${3:-$version}"
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
  push)
    : >"\$AGENT_RELEASE_TEST_GIT_STATE.remote-tag"
    ;;
  *) exit 2 ;;
esac
EOF

  cat >"$fixture/bin/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'go message_server_root=%s %s\n' "${DIREXTALK_MESSAGE_SERVER_ROOT:-}" "$*" >>"$AGENT_RELEASE_TEST_LOG"
[[ -z "${FAKE_GO_FAIL_PATTERN:-}" || "$*" != *"$FAKE_GO_FAIL_PATTERN"* ]]
EOF

  cat >"$fixture/bin/buf" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'buf %s\n' "$*" >>"$AGENT_RELEASE_TEST_LOG"
[[ "${FAKE_BUF_FAIL:-0}" != 1 ]]
EOF

  cat >"$fixture/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'docker %s\n' "$*" >>"$AGENT_RELEASE_TEST_LOG"
if [[ -n "${FAKE_DOCKER_FAIL_PATTERN:-}" && "$*" == *"$FAKE_DOCKER_FAIL_PATTERN"* ]]; then
  exit 1
fi
if [[ "${1:-} ${2:-}" == 'image inspect' ]]; then
  ref=${3:-}
  if [[ "$ref" == 'dirextalk/agent:latest' && "${FAKE_LATEST_LABEL_DRIFT:-0}" == 1 ]]; then
    printf '%s\n' "$RELEASE_VERSION|2222222222222222222222222222222222222222|$RELEASE_BUILD_TIME"
  else
    printf '%s\n' "$RELEASE_VERSION|${FAKE_IMAGE_REVISION:-$RELEASE_COMMIT}|$RELEASE_BUILD_TIME"
  fi
elif [[ "${1:-}" == run ]]; then
  binary=
  ref=
  while (( $# )); do
    if [[ "$1" == --entrypoint ]]; then binary=$2; shift; fi
    if [[ "$1" == dirextalk/agent:* ]]; then ref=$1; fi
    shift
  done
  if [[ -n "${FAKE_VERSION_PROBE_FAIL_BINARY:-}" && "$binary" == */"$FAKE_VERSION_PROBE_FAIL_BINARY" ]]; then
    exit 1
  fi
  if [[ "$ref" == 'dirextalk/agent:latest' && -n "${FAKE_LATEST_PROBE_FAIL_BINARY:-}" && \
        "$binary" == */"$FAKE_LATEST_PROBE_FAIL_BINARY" ]]; then
    exit 1
  fi
  printf '%s\n' "${FAKE_BINARY_VERSION:-$RELEASE_VERSION}"
elif [[ "${1:-} ${2:-} ${3:-}" == 'buildx imagetools create' ]]; then
  : >"$AGENT_RELEASE_TEST_DOCKER_STATE.latest"
fi
EOF

  cat >"$fixture/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'gh %s\n' "$*" >>"$AGENT_RELEASE_TEST_LOG"
if [[ "${1:-} ${2:-}" == 'release view' ]]; then
  [[ -f "$AGENT_RELEASE_TEST_GH_STATE.release" ]] || exit 1
  FAKE_GH_REQUESTED_TAG=${3:-} python3 - <<'PY'
import json, os, pathlib
version = os.environ["FAKE_GH_REQUESTED_TAG"]
notes = pathlib.Path(os.environ["RELEASE_OUTPUT_DIR"], "release-notes.md").read_text(encoding="utf-8")
print(json.dumps({
    "tagName": os.environ.get("FAKE_GH_TAG", version),
    "name": os.environ.get("FAKE_GH_TITLE", f"Dirextalk Agent {version}"),
    "body": os.environ.get("FAKE_GH_BODY", notes),
    "isDraft": False,
    "isPrerelease": False,
}, separators=(",", ":")))
PY
elif [[ "${1:-} ${2:-}" == 'release create' ]]; then
  [[ "${FAKE_GH_CREATE_FAIL:-0}" != 1 ]] || exit 1
  : >"$AGENT_RELEASE_TEST_GH_STATE.release"
else
  exit 2
fi
EOF
  chmod +x "$fixture/bin/"*
}

make_fixture() {
  local name=$1 fixture
  fixture=$tmp/$name
  mkdir -p "$fixture/repo/scripts/release" "$fixture/repo/release" \
    "$fixture/repo/internal/buildinfo" "$fixture/repo/migrations" \
    "$fixture/message-server/p2p" "$fixture/message-server/internal/agentgateway" \
    "$fixture/git-state" "$fixture/gh-state" "$fixture/docker-state"
  cp "$repo_root/scripts/release/"{lib,prepare,verify,publish}.sh "$fixture/repo/scripts/release/"
  cp "$repo_root/internal/buildinfo/version.go" "$fixture/repo/internal/buildinfo/version.go"
  cp "$repo_root/migrations/embed.go" "$fixture/repo/migrations/embed.go"
  printf '# Agent releases\n\n## %s\n\nStable Agent release.\n' "$version" >"$fixture/repo/release/RELEASE_NOTES.md"
  printf '{"version":"%s","schema_version":12,"schema_compat_version":1}\n' "$version" \
    >"$fixture/repo/release/$version.json"
  touch "$fixture/message-server/p2p/native_agent_catalog.go" \
    "$fixture/message-server/internal/agentgateway/runner.go" \
    "$fixture/message-server/internal/agentgateway/catalog_requirements.go" \
    "$fixture/commands.log"
  install_fake_tools "$fixture"
  printf '%s\n' "$fixture"
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
  run_script "$1" prepare.sh "$version" env
  run_script "$1" verify.sh "$version" env
}

assert_latest_not_moved() {
  if grep -F 'docker buildx imagetools create --tag dirextalk/agent:latest' "$1/commands.log" >/dev/null; then
    fail "$2 moved latest"
  fi
}

# Source identity stays deliberately small: canonical version, clean synchronized main,
# matching checked-in version/schema metadata and notes.
fixture=$(make_fixture noncanonical)
if run_script "$fixture" prepare.sh v1.0.069 env; then fail 'prepare accepted a noncanonical version'; fi

fixture=$(make_fixture dirty)
if run_script "$fixture" prepare.sh "$version" env FAKE_AGENT_DIRTY=' M tracked.go'; then
  fail 'prepare accepted a dirty checkout'
fi

fixture=$(make_fixture branch)
if run_script "$fixture" prepare.sh "$version" env FAKE_AGENT_BRANCH=feature; then
  fail 'prepare accepted a non-main branch'
fi

fixture=$(make_fixture remote-drift)
if run_script "$fixture" prepare.sh "$version" env FAKE_AGENT_REMOTE_HEAD="$other_commit"; then
  fail 'prepare accepted HEAD drift from origin/main'
fi

fixture=$(make_fixture source-version)
sed -i 's/v1\.0\.69/v9.9.9/' "$fixture/repo/internal/buildinfo/version.go"
if run_script "$fixture" prepare.sh "$version" env; then fail 'prepare accepted source version drift'; fi

# Verification builds and probes the three real entry points. Evidence is commit and
# version-tag bound, without carrying a local Docker image ID across workflow jobs.
fixture=$(make_fixture verify)
prepare_and_verify "$fixture"
grep -F "go message_server_root=$fixture/message-server test -p 1 -parallel 1 ./... -count=1" "$fixture/commands.log" >/dev/null || \
  fail 'verify omitted the Agent test suite'
grep -F 'docker build --pull' "$fixture/commands.log" >/dev/null || fail 'verify omitted the local image build'
for binary in dirextalk-agent dirextalk-extension-runner dirextalk-core-runner; do
  grep -F -- "--entrypoint /usr/local/bin/$binary" "$fixture/commands.log" >/dev/null || \
    fail "verify omitted the $binary version probe"
done
python3 - "$fixture/repo/.release/$version/verified.json" <<'PY' || fail 'verified evidence is not minimal'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert set(value) == {"kind", "version", "commit", "build_time", "image"}
assert value["kind"] == "verified"
PY

fixture=$(make_fixture verify-probe-failure)
run_script "$fixture" prepare.sh "$version" env
if run_script "$fixture" verify.sh "$version" env FAKE_VERSION_PROBE_FAIL_BINARY=dirextalk-core-runner; then
  fail 'verify ignored a binary version failure'
fi

# A GitHub Release failure must leave latest untouched.
fixture=$(make_fixture release-failure)
prepare_and_verify "$fixture"
: >"$fixture/commands.log"
if run_script "$fixture" publish.sh "$version" env FAKE_GH_CREATE_FAIL=1; then
  fail 'publish succeeded after GitHub Release creation failed'
fi
assert_latest_not_moved "$fixture" 'GitHub Release failure'

# A pulled version-tag label or executable mismatch also stops before latest.
fixture=$(make_fixture version-probe-failure)
prepare_and_verify "$fixture"
: >"$fixture/commands.log"
if run_script "$fixture" publish.sh "$version" env FAKE_VERSION_PROBE_FAIL_BINARY=dirextalk-extension-runner; then
  fail 'publish ignored a pulled version binary failure'
fi
assert_latest_not_moved "$fixture" 'version probe failure'

# A matching existing tag and Release are reused, while a conflicting one blocks latest.
fixture=$(make_fixture existing-release)
prepare_and_verify "$fixture"
: >"$fixture/git-state.local-tag"
: >"$fixture/git-state.remote-tag"
: >"$fixture/gh-state.release"
: >"$fixture/commands.log"
run_script "$fixture" publish.sh "$version" env
if grep -F "git push origin refs/tags/$version" "$fixture/commands.log" >/dev/null || \
   grep -F "gh release create $version" "$fixture/commands.log" >/dev/null; then
  fail 'publish recreated a matching Git tag or GitHub Release'
fi

fixture=$(make_fixture conflicting-release)
prepare_and_verify "$fixture"
: >"$fixture/git-state.local-tag"
: >"$fixture/git-state.remote-tag"
: >"$fixture/gh-state.release"
: >"$fixture/commands.log"
if run_script "$fixture" publish.sh "$version" env FAKE_GH_TITLE='wrong title'; then
  fail 'publish accepted a conflicting GitHub Release'
fi
assert_latest_not_moved "$fixture" 'conflicting GitHub Release'

# The maintained successful path is version build/push -> pulled version probes ->
# matching Git tag/Release -> latest move -> pulled latest probes.
fixture=$(make_fixture publish)
prepare_and_verify "$fixture"
: >"$fixture/commands.log"
run_script "$fixture" publish.sh "$version" env
build_line=$(grep -nF 'docker buildx build ' "$fixture/commands.log" | cut -d: -f1)
version_pull_line=$(grep -nF "docker pull --platform linux/amd64 dirextalk/agent:$version" "$fixture/commands.log" | cut -d: -f1)
release_line=$(grep -nF "gh release create $version" "$fixture/commands.log" | cut -d: -f1)
latest_line=$(grep -nF 'docker buildx imagetools create --tag dirextalk/agent:latest' "$fixture/commands.log" | cut -d: -f1)
latest_pull_line=$(grep -nF 'docker pull --platform linux/amd64 dirextalk/agent:latest' "$fixture/commands.log" | cut -d: -f1)
[[ -n "$build_line" && -n "$version_pull_line" && -n "$release_line" && \
   -n "$latest_line" && -n "$latest_pull_line" ]] || fail 'publish omitted a stable release phase'
(( build_line < version_pull_line && version_pull_line < release_line && \
   release_line < latest_line && latest_line < latest_pull_line )) || fail 'stable release phases are out of order'
for binary in dirextalk-agent dirextalk-extension-runner dirextalk-core-runner; do
  count=$(grep -Fc -- "--entrypoint /usr/local/bin/$binary" "$fixture/commands.log")
  [[ "$count" == 2 ]] || fail "publish did not probe $binary on version and latest"
done

fixture=$(make_fixture latest-probe-failure)
prepare_and_verify "$fixture"
if run_script "$fixture" publish.sh "$version" env FAKE_LATEST_PROBE_FAIL_BINARY=dirextalk-agent; then
  fail 'publish reported success after the pulled latest probe failed'
fi

printf 'Agent release contract tests passed\n'
