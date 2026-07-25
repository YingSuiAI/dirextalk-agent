#!/bin/sh
set -eu

file=${1:?usage: validate-token.sh TOKEN_FILE}
[ -f "$file" ] && [ ! -L "$file" ] || exit 1
[ "$(wc -c < "$file")" -eq 43 ] || exit 1
token=$(cat "$file")
printf '%s' "$token" | grep -Eq '^[A-Za-z0-9_-]{43}$' || exit 1

decoded=$(mktemp)
cleanup() {
  rm -f "$decoded"
}
trap cleanup EXIT HUP INT TERM
if ! { tr '_-' '/+' < "$file"; printf '='; } | base64 -d > "$decoded" 2>/dev/null; then
  exit 1
fi
[ "$(wc -c < "$decoded")" -eq 32 ] || exit 1
canonical=$(base64 < "$decoded" | tr -d '\n=' | tr '+/' '-_')
[ "$canonical" = "$token" ]
