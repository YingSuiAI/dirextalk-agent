#!/usr/bin/env bash

set -u -o pipefail

[ "$#" -eq 1 ] || { printf 'usage: %s RECEIPT_JSON\n' "$0" >&2; exit 2; }
receipt=$1
[ -f "$receipt" ] && [ ! -L "$receipt" ] || { printf 'real Worker receipt is missing or unsafe\n' >&2; exit 1; }

jq -e '
  .schema == "dirextalk.agent.worker.acceptance.v1" and
  ((.credential.created_by_driver == true) or (.credential.preexisting_verified == true)) and
  .credential.tested and .credential.listed and
  .catalog.workers_server and
  .quote.observed and .confirmation.confirmed and
  .worker.created and .worker.status_observed and .worker.load_observed and
  .artifact.downloaded and
  .reuse.completed and .reuse.no_new_creation_confirmation and
  .destroy.completed and .destroy.resources_absent and
  (.s3_used == false)
' "$receipt" >/dev/null
