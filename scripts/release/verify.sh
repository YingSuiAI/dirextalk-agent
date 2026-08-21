#!/usr/bin/env bash
set -euo pipefail
# Resolved from this installed script directory.
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

release_init "$@"
release_preflight
release_require_json "$RELEASE_CONTEXT" prepared
release_require_tools go buf docker
cd "$RELEASE_REPO_ROOT"

release_with_test_postgres go test -p 1 -parallel 1 ./... -count=1
go build ./cmd/...
buf lint

docker build --pull \
  --build-arg "VERSION=$RELEASE_VERSION" \
  --build-arg "REVISION=$RELEASE_COMMIT" \
  --build-arg "BUILD_TIME=$RELEASE_BUILD_TIME" \
  --tag "$RELEASE_IMAGE" \
  --file deploy/container/agent.Containerfile .
release_verify_image "$RELEASE_IMAGE"
release_write_json "$RELEASE_VERIFIED" verified
printf 'Agent release verify passed for %s\n' "$RELEASE_VERSION"
