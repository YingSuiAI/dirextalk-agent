#!/usr/bin/env bash

set -euo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
exec go -C "$script_dir/realworker" run .
