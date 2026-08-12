#!/usr/bin/env bash
set -euo pipefail
# Resolved from this installed script directory.
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

release_init "$@"
release_preflight
release_require_json "$RELEASE_CONTEXT" prepared no
release_require_tools go buf docker
release_require_message_server
[[ -n "${AGENT_TEST_POSTGRES_DSN:-}" ]] || release_die 'AGENT_TEST_POSTGRES_DSN is required for formal verification'
cd "$RELEASE_REPO_ROOT"

DIREXTALK_MESSAGE_SERVER_ROOT="$RELEASE_MESSAGE_SERVER_ROOT" go test -p 1 ./... -count=1
go build ./cmd/...
buf lint

docker build --pull \
  --build-arg "VERSION=$RELEASE_VERSION" \
  --build-arg "REVISION=$RELEASE_COMMIT" \
  --build-arg "BUILD_TIME=$RELEASE_BUILD_TIME" \
  --tag "$RELEASE_IMAGE" \
  --file deploy/container/agent.Containerfile .
release_verify_image "$RELEASE_IMAGE"
image_id=$(docker image inspect "$RELEASE_IMAGE" --format '{{.Id}}')
[[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || release_die 'Agent image ID is invalid'
release_write_json "$RELEASE_VERIFIED" verified "$image_id"
printf 'Agent release verify passed for %s (%s)\n' "$RELEASE_VERSION" "$image_id"
