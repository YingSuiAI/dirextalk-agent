#!/bin/sh
set -eu

compose_file=${1:?usage: rotate-local.sh COMPOSE_FILE ENV_FILE [SERVICE]}
env_file=${2:?usage: rotate-local.sh COMPOSE_FILE ENV_FILE [SERVICE]}
service=${3:-core}
case "$compose_file" in /*) ;; *) compose_file="$(pwd -P)/$compose_file" ;; esac
case "$env_file" in /*) ;; *) env_file="$(pwd -P)/$env_file" ;; esac

env_value() {
  key=$1
  sed -n "s/^${key}=//p" "$env_file" | tail -n 1
}

config_file=$(env_value DIREXTALK_AGENT_CONFIG_FILE)
[ -n "$config_file" ] || { echo "rotate-local: missing DIREXTALK_AGENT_CONFIG_FILE" >&2; exit 1; }
artifact_dir=$(dirname "$config_file")
lock=$artifact_dir.lock
mkdir "$lock" 2>/dev/null || { echo "rotate-local: artifact lock is held; refusing concurrent rotation: $lock" >&2; exit 1; }
cleanup() {
  rmdir "$lock" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

# Only TLS/token material may differ from the prior complete set. Refresh the
# manifest before touching UID-owned secret volumes; failure is fail-closed.
"$(dirname "$0")/refresh-manifest.sh" --locked "$artifact_dir"

# Secret/config inputs are host files referenced by ENV_FILE. Recreate the
# init job so the UID-owned named volumes receive their new bytes, then force
# recreate only Core so it reloads the token/certificate after restart.
docker compose --env-file "$env_file" -f "$compose_file" up --no-deps --force-recreate --abort-on-container-exit --exit-code-from secret-init secret-init
docker compose --env-file "$env_file" -f "$compose_file" up -d --force-recreate "$service"
"$(dirname "$0")/readiness.sh" "$compose_file" "$service" "$env_file"
