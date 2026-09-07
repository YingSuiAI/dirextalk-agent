package sshworker

// The package database is the authority for the untouched image baseline.
// Anything modified, linked, unreadable, or unverifiable remains protected.
const caddyConfigOwnershipScript = `caddy_config_may_be_managed() {
  local config="$1" metadata expected actual status
  if [[ -L "$config" ]]; then
    echo 'refusing to replace an unmanaged Caddyfile' >&2
    return 78
  fi
  if [[ ! -e "$config" ]]; then return 0; fi
  if [[ ! -f "$config" ]]; then return 78; fi
  if grep -qxF '# Managed by Dirextalk Agent' "$config"; then return 0; else
    status=$?
    if [[ "$status" != 1 ]]; then return 69; fi
  fi
  if metadata=$(dpkg-query -W -f='${Conffiles}\n' caddy); then :; else
    echo 'cannot verify the Caddy package baseline' >&2
    return 69
  fi
  expected=$(printf '%s\n' "$metadata" | awk -v path="$config" '$1 == path && NF == 2 {print $2}')
  if [[ ! "$expected" =~ ^[0-9a-f]{32}$ ]]; then
    echo 'cannot verify the Caddy package baseline' >&2
    return 69
  fi
  if actual=$(md5sum -- "$config"); then :; else return 69; fi
  if [[ "${actual%% *}" != "$expected" ]]; then
    echo 'refusing to replace an unmanaged Caddyfile' >&2
    return 78
  fi
  return 0
}
`
