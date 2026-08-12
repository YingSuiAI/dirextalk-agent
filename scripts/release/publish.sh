#!/usr/bin/env bash
set -euo pipefail
# Resolved from this installed script directory.
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

release_init "$@"
release_preflight
release_require_json "$RELEASE_CONTEXT" prepared no
release_require_json "$RELEASE_VERIFIED" verified yes
VERIFIED_IMAGE_ID=${RELEASE_EVIDENCE[4]}
release_require_tools docker gh python3 mktemp
release_require_message_server
cd "$RELEASE_REPO_ROOT"

GITHUB_REPOSITORY=YingSuiAI/dirextalk-agent
LATEST_IMAGE=dirextalk/agent:latest
EXPECTED_RELEASE_TITLE="Dirextalk Agent $RELEASE_VERSION"
REMOTE_TAG_EXISTS=0
REMOTE_TAG_OBJECT=
FORMAL_RELEASE_EXISTS=0

assert_release_source() {
  local head image_id
  head=$(git rev-parse HEAD)
  [[ "$head" == "$RELEASE_COMMIT" ]] || release_die 'release source changed after verification'
  [[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || release_die 'working tree changed after verification'
  image_id=$(docker image inspect "$RELEASE_IMAGE" --format '{{.Id}}') || \
    release_die 'verified Agent image is unavailable'
  [[ "$image_id" == "$VERIFIED_IMAGE_ID" ]] || \
    release_die 'Agent image ID changed after verification'
}

verify_remote_platform_image() {
  local immutable_ref=$1 expected_config_digest=$2 image_id
  docker pull --platform linux/amd64 "$immutable_ref" >/dev/null || \
    release_die "could not pull remote linux/amd64 image: $immutable_ref"
  image_id=$(docker image inspect "$immutable_ref" --format '{{.Id}}') || \
    release_die 'remote Agent image ID is unavailable'
  [[ "$image_id" == "$expected_config_digest" ]] || \
    release_die 'pulled Agent image ID does not match the OCI platform config digest'
  release_verify_image "$immutable_ref"
}

validate_local_tag() {
  local tag_type tag_commit
  LOCAL_TAG_EXISTS=0
  LOCAL_TAG_OBJECT=
  if [[ -z "$(git tag --list "$RELEASE_VERSION")" ]]; then
    return
  fi
  LOCAL_TAG_EXISTS=1
  tag_type=$(git cat-file -t "refs/tags/$RELEASE_VERSION") || release_die 'local release tag is unreadable'
  [[ "$tag_type" == tag ]] || release_die 'local release tag must be annotated'
  tag_commit=$(git rev-parse "refs/tags/$RELEASE_VERSION^{}") || release_die 'local release tag cannot be peeled'
  [[ "$tag_commit" == "$RELEASE_COMMIT" ]] || release_die 'local release tag already points to another commit'
  LOCAL_TAG_OBJECT=$(git rev-parse "refs/tags/$RELEASE_VERSION")
  [[ "$LOCAL_TAG_OBJECT" =~ ^[0-9a-f]{40}$ ]] || release_die 'local release tag object is invalid'
}

validate_remote_tag() {
  local output line hash ref direct='' peeled=''
  if output=$(git ls-remote --tags origin \
      "refs/tags/$RELEASE_VERSION" "refs/tags/$RELEASE_VERSION^{}"); then
    :
  else
    release_die 'remote release tag lookup failed'
  fi
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    [[ "$line" =~ ^([0-9a-f]{40})[[:space:]](.+)$ ]] || release_die 'remote release tag response is invalid'
    hash=${BASH_REMATCH[1]}
    ref=${BASH_REMATCH[2]}
    if [[ "$ref" == "refs/tags/$RELEASE_VERSION" ]]; then
      [[ -z "$direct" ]] || release_die 'remote release tag response contains duplicates'
      direct=$hash
    elif [[ "$ref" == "refs/tags/$RELEASE_VERSION^{}" ]]; then
      [[ -z "$peeled" ]] || release_die 'remote release tag response contains duplicates'
      peeled=$hash
    else
      release_die 'remote release tag response is invalid'
    fi
  done <<<"$output"

  if [[ -z "$direct" && -z "$peeled" ]]; then
    REMOTE_TAG_EXISTS=0
    REMOTE_TAG_OBJECT=
    return
  fi
  [[ -n "$direct" && -n "$peeled" ]] || release_die 'remote release tag must be annotated'
  [[ "$peeled" == "$RELEASE_COMMIT" ]] || release_die 'remote release tag already points to another commit'
  REMOTE_TAG_EXISTS=1
  REMOTE_TAG_OBJECT=$direct
  if [[ "$LOCAL_TAG_EXISTS" == 1 ]]; then
    [[ "$REMOTE_TAG_OBJECT" == "$LOCAL_TAG_OBJECT" ]] || \
      release_die 'local and remote release tag objects differ'
  fi
}

refresh_formal_release_state() {
  local response
  if response=$(gh api --include --silent \
      "repos/$GITHUB_REPOSITORY/releases/tags/$RELEASE_VERSION" 2>&1); then
    FORMAL_RELEASE_EXISTS=1
    return
  fi
  if grep -Eq '^HTTP/[0-9.]+ 404([[:space:]]|$)' <<<"$response"; then
    FORMAL_RELEASE_EXISTS=0
    return
  fi
  release_die 'GitHub Release lookup failed'
}

assert_formal_release() {
  local metadata_file=$RELEASE_OUTPUT_DIR/github-release.json
  gh release view "$RELEASE_VERSION" \
    --repo "$GITHUB_REPOSITORY" \
    --json tagName,name,body,isDraft,isPrerelease,assets >"$metadata_file" || \
    release_die 'GitHub Release metadata lookup failed'
  python3 - "$metadata_file" "$RELEASE_VERSION" "$EXPECTED_RELEASE_TITLE" "$notes_file" <<'PY'
import json, pathlib, sys

metadata_path, expected_tag, expected_title, notes_path = sys.argv[1:]
try:
    metadata = json.loads(pathlib.Path(metadata_path).read_text(encoding="utf-8"))
except Exception as exc:
    raise SystemExit(f"invalid GitHub Release metadata: {exc}")

expected_notes = pathlib.Path(notes_path).read_text(encoding="utf-8")
if metadata.get("tagName") != expected_tag:
    raise SystemExit("GitHub Release is bound to another tag")
if metadata.get("name") != expected_title:
    raise SystemExit("GitHub Release title does not match the checked-in contract")
if metadata.get("body") != expected_notes:
    raise SystemExit("GitHub Release notes do not match the checked-in contract")
if metadata.get("isDraft") is not False or metadata.get("isPrerelease") is not False:
    raise SystemExit("GitHub Release must be formal")
assets = metadata.get("assets")
if not isinstance(assets, list) or assets:
    raise SystemExit("GitHub Release must not contain assets")
PY
}

notes_file=$RELEASE_OUTPUT_DIR/release-notes.md
release_write_notes "$notes_file"

# Resolve every pre-existing external identity before either Docker tag moves.
validate_local_tag
validate_remote_tag
refresh_formal_release_state
if [[ "$FORMAL_RELEASE_EXISTS" == 1 ]]; then
  [[ "$REMOTE_TAG_EXISTS" == 1 ]] || release_die 'existing GitHub Release requires its remote annotated tag'
  assert_formal_release
fi
if [[ "$REMOTE_TAG_EXISTS" == 0 && "$LOCAL_TAG_EXISTS" == 0 ]]; then
  git var GIT_COMMITTER_IDENT >/dev/null 2>&1 || \
    release_die 'annotated tag creation requires a valid Git committer identity'
fi

assert_release_source
release_verify_image "$RELEASE_IMAGE"
release_probe_remote_index "$RELEASE_IMAGE"
if [[ "$RELEASE_REMOTE_INDEX_EXISTS" == 1 ]]; then
  version_digest=$RELEASE_REMOTE_INDEX_DIGEST
else
  buildx_metadata=$RELEASE_OUTPUT_DIR/buildx-metadata.json
  rm -f "$buildx_metadata"
  assert_release_source
  docker buildx build \
    --pull \
    --platform linux/amd64 \
    --provenance=mode=max \
    --sbom=true \
    --push \
    --build-arg "VERSION=$RELEASE_VERSION" \
    --build-arg "REVISION=$RELEASE_COMMIT" \
    --build-arg "BUILD_TIME=$RELEASE_BUILD_TIME" \
    --tag "$RELEASE_IMAGE" \
    --metadata-file "$buildx_metadata" \
    --file deploy/container/agent.Containerfile . || \
    release_die 'Agent OCI index build and push failed'
  built_digest=$(release_buildx_metadata_digest "$buildx_metadata") || \
    release_die 'Agent buildx digest evidence is invalid'
  assert_release_source
  release_probe_remote_index "$RELEASE_IMAGE"
  [[ "$RELEASE_REMOTE_INDEX_EXISTS" == 1 ]] || \
    release_die 'published version OCI index is unavailable'
  version_digest=$RELEASE_REMOTE_INDEX_DIGEST
  [[ "$version_digest" == "$built_digest" ]] || \
    release_die 'buildx and registry version OCI index digests differ'
fi
[[ "$version_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || \
  release_die 'version OCI index digest is invalid'
version_immutable_ref="dirextalk/agent@$version_digest"
release_verify_remote_attestations "$RELEASE_IMAGE" "$RELEASE_REMOTE_PLATFORM_DIGEST"
version_config_digest=$(release_remote_platform_config_digest "$RELEASE_REMOTE_PLATFORM_DIGEST")
verify_remote_platform_image "$version_immutable_ref" "$version_config_digest"

# Re-read the tag immediately before mutation so a concurrent publisher cannot
# redirect this release between the initial conflict check and publication.
validate_local_tag
validate_remote_tag
if [[ "$REMOTE_TAG_EXISTS" == 0 ]]; then
  if [[ "$LOCAL_TAG_EXISTS" == 0 ]]; then
    git tag -a "$RELEASE_VERSION" -m "$EXPECTED_RELEASE_TITLE"
    validate_local_tag
  fi
  assert_release_source
  validate_remote_tag
  if [[ "$REMOTE_TAG_EXISTS" == 0 ]]; then
    git push origin "refs/tags/$RELEASE_VERSION"
  fi
fi
validate_local_tag
validate_remote_tag
[[ "$REMOTE_TAG_EXISTS" == 1 ]] || release_die 'remote release tag is missing after publication'

refresh_formal_release_state
if [[ "$FORMAL_RELEASE_EXISTS" == 1 ]]; then
  assert_formal_release
else
  assert_release_source
  if ! gh release create "$RELEASE_VERSION" \
      --repo "$GITHUB_REPOSITORY" \
      --title "$EXPECTED_RELEASE_TITLE" \
      --notes-file "$notes_file" \
      --verify-tag; then
    # A concurrent exact creator is safe; any other failure or drift is not.
    refresh_formal_release_state
    [[ "$FORMAL_RELEASE_EXISTS" == 1 ]] || release_die 'GitHub Release creation failed'
  fi
fi
refresh_formal_release_state
[[ "$FORMAL_RELEASE_EXISTS" == 1 ]] || release_die 'GitHub Release is missing after publication'
assert_formal_release

# latest is deliberately last: failures above leave the deployment channel
# untouched even when the immutable version index was already published.
validate_local_tag
validate_remote_tag
refresh_formal_release_state
[[ "$FORMAL_RELEASE_EXISTS" == 1 ]] || release_die 'GitHub Release disappeared before latest publication'
assert_formal_release
assert_release_source
release_probe_remote_index "$RELEASE_IMAGE"
[[ "$RELEASE_REMOTE_INDEX_EXISTS" == 1 && "$RELEASE_REMOTE_INDEX_DIGEST" == "$version_digest" ]] || \
  release_die 'version OCI index changed before latest publication'
release_verify_remote_attestations "$RELEASE_IMAGE" "$RELEASE_REMOTE_PLATFORM_DIGEST"
version_config_digest=$(release_remote_platform_config_digest "$RELEASE_REMOTE_PLATFORM_DIGEST")
verify_remote_platform_image "$version_immutable_ref" "$version_config_digest"
release_probe_remote_index "$LATEST_IMAGE"
if [[ "$RELEASE_REMOTE_INDEX_EXISTS" == 1 ]]; then
  current_latest_digest=$RELEASE_REMOTE_INDEX_DIGEST
else
  current_latest_digest=
fi
if [[ -n "$current_latest_digest" && "$current_latest_digest" != "$version_digest" ]]; then
  current_latest_version=$(docker buildx imagetools inspect "$LATEST_IMAGE" \
    --format '{{index .Image.Config.Labels "org.opencontainers.image.version"}}') || \
    release_die 'could not read current latest Agent version'
  python3 - "$current_latest_version" "$RELEASE_VERSION" <<'PY' || \
    release_die 'refusing to replace latest with an older Agent version'
import re, sys
current, candidate = sys.argv[1:]
pattern = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
left, right = pattern.fullmatch(current), pattern.fullmatch(candidate)
if left is None or right is None or tuple(map(int, left.groups())) > tuple(map(int, right.groups())):
    raise SystemExit(1)
PY
fi
if [[ "$current_latest_digest" != "$version_digest" ]]; then
  docker buildx imagetools create \
    --tag "$LATEST_IMAGE" \
    "$version_immutable_ref" || release_die 'latest OCI index promotion failed'
fi
latest_digest=$(release_remote_index_digest "$LATEST_IMAGE")
[[ "$latest_digest" == "$version_digest" ]] || \
  release_die 'version and latest tags resolve to different OCI indexes'
latest_immutable_ref="$LATEST_IMAGE@$latest_digest"
release_probe_remote_index "$LATEST_IMAGE"
[[ "$RELEASE_REMOTE_INDEX_EXISTS" == 1 && "$RELEASE_REMOTE_INDEX_DIGEST" == "$version_digest" ]] || \
  release_die 'latest OCI index changed before immutable verification'
release_verify_remote_attestations "$LATEST_IMAGE" "$RELEASE_REMOTE_PLATFORM_DIGEST"
latest_config_digest=$(release_remote_platform_config_digest "$RELEASE_REMOTE_PLATFORM_DIGEST")
verify_remote_platform_image "$latest_immutable_ref" "$latest_config_digest"

# Re-resolve both mutable tags for the final postcondition. The content probes
# above use immutable digest references, so a tag race cannot redirect them.
final_version_digest=$(release_remote_index_digest "$RELEASE_IMAGE")
final_latest_digest=$(release_remote_index_digest "$LATEST_IMAGE")
[[ "$final_version_digest" == "$version_digest" && "$final_latest_digest" == "$version_digest" ]] || \
  release_die 'version or latest OCI index changed during publication'

printf 'Agent release publish passed for %s (%s)\n' "$RELEASE_VERSION" "$version_digest"
