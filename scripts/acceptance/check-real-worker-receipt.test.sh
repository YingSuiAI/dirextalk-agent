#!/usr/bin/env bash

set -euo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
run=$(mktemp -d "${TMPDIR:-/tmp}/dirextalk-receipt-test.XXXXXX")
trap 'rm -rf -- "$run"' EXIT

valid=$run/valid.json
jq -n '{
  schema:"dirextalk.agent.worker.acceptance.v1",
  credential:{created_by_driver:false,preexisting_verified:true,tested:true,listed:true},
  catalog:{workers_server:true}, quote:{observed:true}, confirmation:{confirmed:true},
  worker:{created:true,status_observed:true,load_observed:true}, artifact:{downloaded:true},
  reuse:{completed:true,no_new_creation_confirmation:true},
  destroy:{completed:true,resources_absent:true}, s3_used:false
}' >"$valid"
"$script_dir/check-real-worker-receipt.sh" "$valid"

invalid=$run/invalid.json
jq '.credential.preexisting_verified=false' "$valid" >"$invalid"
if "$script_dir/check-real-worker-receipt.sh" "$invalid"; then
  printf 'receipt checker accepted absent credential establishment proof\n' >&2
  exit 1
fi

jq '.credential.created_by_driver=true | .credential.preexisting_verified=false' "$valid" >"$invalid"
"$script_dir/check-real-worker-receipt.sh" "$invalid"

jq '.s3_used=true' "$valid" >"$invalid"
if "$script_dir/check-real-worker-receipt.sh" "$invalid"; then
  printf 'receipt checker accepted S3 use\n' >&2
  exit 1
fi
