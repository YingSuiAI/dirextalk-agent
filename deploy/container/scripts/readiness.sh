#!/bin/sh
set -eu

compose_file=${1:-deploy/container/compose.local.yaml}
service=${2:-core}
env_file=${3:-}
case "$compose_file" in
  /*) ;;
  *) compose_file="$(pwd -P)/$compose_file" ;;
esac
if [ -n "$env_file" ]; then
  case "$env_file" in
    /*) ;;
    *) env_file="$(pwd -P)/$env_file" ;;
  esac
  case "$(basename "$compose_file")" in
    compose.local.yaml) "$(dirname "$0")/preflight-local.sh" "$compose_file" "$env_file" ;;
  esac
  exec docker compose --env-file "$env_file" -f "$compose_file" exec -T "$service" /usr/local/bin/dirextalk-agent healthcheck
fi
case "$(basename "$compose_file")" in
  compose.local.yaml) echo "readiness: an environment file is required for local runner preflight" >&2; exit 1 ;;
esac
exec docker compose -f "$compose_file" exec -T "$service" /usr/local/bin/dirextalk-agent healthcheck
