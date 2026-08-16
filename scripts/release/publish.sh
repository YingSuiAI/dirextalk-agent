#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

release_init "$@"
release_preflight
release_require_json "$RELEASE_CONTEXT" prepared
release_require_json "$RELEASE_VERIFIED" verified
release_require_tools docker gh
cd "$RELEASE_REPO_ROOT"

repository=YingSuiAI/dirextalk-agent
latest_image=dirextalk/agent:latest
notes_file=$RELEASE_OUTPUT_DIR/release-notes.md
release_write_notes "$notes_file"

# A release is one straightforward path: build the requested version, prove the
# published binaries report it, publish the source Release, then move latest.
docker buildx build \
  --pull \
  --platform linux/amd64 \
  --push \
  --build-arg "VERSION=$RELEASE_VERSION" \
  --build-arg "REVISION=$RELEASE_COMMIT" \
  --build-arg "BUILD_TIME=$RELEASE_BUILD_TIME" \
  --tag "$RELEASE_IMAGE" \
  --file deploy/container/agent.Containerfile .

docker pull --platform linux/amd64 "$RELEASE_IMAGE" >/dev/null
release_verify_image "$RELEASE_IMAGE"

if [[ -z "$(git tag --list "$RELEASE_VERSION")" ]]; then
  git tag -a "$RELEASE_VERSION" -m "Dirextalk Agent $RELEASE_VERSION"
fi
[[ "$(git cat-file -t "refs/tags/$RELEASE_VERSION")" == tag ]] || \
  release_die 'release tag must be annotated'
[[ "$(git rev-parse "refs/tags/$RELEASE_VERSION^{}")" == "$RELEASE_COMMIT" ]] || \
  release_die 'release tag points to another commit'
if remote_tag=$(git ls-remote --exit-code --tags origin "refs/tags/$RELEASE_VERSION^{}" 2>/dev/null); then
  [[ "$remote_tag" == "$RELEASE_COMMIT"$'\t'"refs/tags/$RELEASE_VERSION^{}" ]] || \
    release_die 'remote release tag points to another commit'
else
  git push origin "refs/tags/$RELEASE_VERSION"
fi

release_metadata=$RELEASE_OUTPUT_DIR/github-release.json
if gh release view "$RELEASE_VERSION" --repo "$repository" \
    --json tagName,name,body,isDraft,isPrerelease >"$release_metadata" 2>/dev/null; then
  python3 - "$release_metadata" "$RELEASE_VERSION" "$notes_file" <<'PY'
import json, pathlib, sys

metadata_path, version, notes_path = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_path).read_text(encoding="utf-8"))
expected = {
    "tagName": version,
    "name": f"Dirextalk Agent {version}",
    "body": pathlib.Path(notes_path).read_text(encoding="utf-8"),
    "isDraft": False,
    "isPrerelease": False,
}
if metadata != expected:
    raise SystemExit("GitHub Release does not match the checked-in release")
PY
else
  gh release create "$RELEASE_VERSION" \
    --repo "$repository" \
    --title "Dirextalk Agent $RELEASE_VERSION" \
    --notes-file "$notes_file" \
    --verify-tag
fi

docker buildx imagetools create --tag "$latest_image" "$RELEASE_IMAGE"
docker pull --platform linux/amd64 "$latest_image" >/dev/null
release_verify_image "$latest_image"

printf 'Agent release publish passed for %s\n' "$RELEASE_VERSION"
