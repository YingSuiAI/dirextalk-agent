#!/bin/sh
set -eu

compose_file=${1:?usage: preflight-local.sh COMPOSE_FILE ENV_FILE}
env_file=${2:?usage: preflight-local.sh COMPOSE_FILE ENV_FILE}

case "$compose_file" in
  /*) ;;
  *) compose_file="$(pwd -P)/$compose_file" ;;
esac
case "$env_file" in
  /*) ;;
  *) env_file="$(pwd -P)/$env_file" ;;
esac
[ -f "$compose_file" ] || { echo "preflight-local: missing Compose file: $compose_file" >&2; exit 1; }
[ -f "$env_file" ] || { echo "preflight-local: missing environment file: $env_file" >&2; exit 1; }

die() {
  echo "preflight-local: $*" >&2
  exit 1
}

env_value() {
  key=$1
  sed -n "s/^${key}=//p" "$env_file" | tail -n 1
}

docker=$(command -v docker 2>/dev/null || true)
[ -n "$docker" ] || die "docker is required"
if ! cgroup_driver=$($docker info --format '{{.CgroupDriver}}' 2>/dev/null); then
  die "unable to inspect the Docker daemon"
fi
[ "$cgroup_driver" = systemd ] || die "Docker must use the systemd cgroup driver (got: ${cgroup_driver:-unknown})"

check_root() {
  name=$1
  expected_uid=$2
  path=$(env_value "$name")
  [ -n "$path" ] || die "$name is missing from $env_file"
  case "$path" in
    /sys/fs/cgroup/*) ;;
    *) die "$name must be below /sys/fs/cgroup" ;;
  esac
  [ -d "$path" ] && [ ! -L "$path" ] || die "$name is not a real directory: $path"
  fs_type=$(stat -f -c '%T' "$path" 2>/dev/null || true)
  [ "$fs_type" = cgroup2fs ] || die "$name is not a cgroup-v2 filesystem: $path"
  owner=$(stat -c '%u' "$path" 2>/dev/null || true)
  [ "$owner" = "$expected_uid" ] || die "$name must be delegated to UID $expected_uid: $path"
  permissions=$(stat -c '%A' "$path" 2>/dev/null || true)
  [ "$(printf '%s' "$permissions" | cut -c6)" != w ] || die "$name is group-writable: $path"
  [ "$(printf '%s' "$permissions" | cut -c9)" != w ] || die "$name is world-writable: $path"
  [ -f "$path/cgroup.controllers" ] || die "$name has no cgroup.controllers: $path"
  [ -f "$path/cgroup.procs" ] || die "$name has no cgroup.procs: $path"
  controllers=$(tr -d '[:space:]' < "$path/cgroup.controllers")
  [ -n "$controllers" ] || die "$name has no delegated controllers: $path"
}

extension_root=$(env_value DIREXTALK_EXTENSION_CGROUP_ROOT)
workload_root=$(env_value DIREXTALK_CORE_RUNNER_CGROUP_ROOT)
[ -n "$extension_root" ] && [ "$extension_root" != "$workload_root" ] || die "runner cgroup roots must be distinct"
check_root DIREXTALK_EXTENSION_CGROUP_ROOT 65531
check_root DIREXTALK_CORE_RUNNER_CGROUP_ROOT 65530
