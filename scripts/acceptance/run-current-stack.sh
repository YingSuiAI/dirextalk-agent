#!/usr/bin/env bash

set -u -o pipefail
umask 077

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
RUN_DIR=${DIREXTALK_ACCEPTANCE_RUN_DIR:-}
REAL_WORKER_DRIVER=""

usage() {
  printf '%s\n' \
    "usage: scripts/acceptance/run-current-stack.sh [--run-dir ABSOLUTE_PATH] [--real-worker-driver ABSOLUTE_EXECUTABLE]" \
    "" \
    "Runs every independent local Agent acceptance group without fail-fast." \
    "The optional driver is the only path that may perform real AWS writes."
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --run-dir)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      RUN_DIR=$2
      shift 2
      ;;
    --real-worker-driver)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      REAL_WORKER_DRIVER=$2
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

if [ -z "$RUN_DIR" ]; then
  RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/dirextalk-agent-acceptance.XXXXXX")
fi
case "$RUN_DIR" in
  /*) ;;
  *) printf 'run directory must be absolute\n' >&2; exit 2 ;;
esac
mkdir -p "$RUN_DIR/status" "$RUN_DIR/logs" "$RUN_DIR/bin"

if [ -n "$REAL_WORKER_DRIVER" ]; then
  case "$REAL_WORKER_DRIVER" in
    /*) ;;
    *) printf 'real Worker driver must be absolute\n' >&2; exit 2 ;;
  esac
  [ -x "$REAL_WORKER_DRIVER" ] || { printf 'real Worker driver is not executable\n' >&2; exit 2; }
fi

run_group() {
  local name=$1
  shift
  local log="$RUN_DIR/logs/$name.log"
  local status=failed
  local started ended
  started=$(date +%s)
  if (cd "$ROOT" && "$@") >"$log" 2>&1; then
    status=passed
    if grep -q -- '--- SKIP:' "$log" && ! grep -q -- '--- PASS:' "$log"; then
      status=skipped
    fi
  fi
  ended=$(date +%s)
  printf '%s\n' "$status" >"$RUN_DIR/status/$name"
  printf '%-30s %-8s %ss\n' "$name" "$status" "$((ended-started))"
}

check_builtin_mcp_stdio() {
  local binary="$RUN_DIR/bin/dirextalk-builtin-mcp"
  go build -o "$binary" ./cmd/dirextalk-builtin-mcp || return
  local kind output
  for kind in server_time server_load; do
    output="$RUN_DIR/logs/builtin_mcp_stdio.$kind.jsonl"
    printf '%s\n' \
      '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
      '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
      '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
      "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"$kind\",\"arguments\":{}}}" \
      | "$binary" "$kind" >"$output" || return
    jq -e -s --arg kind "$kind" '
      length == 3 and
      .[0].result.serverInfo.name == ("dirextalk-" + $kind) and
      .[1].result.tools == [{
        name: $kind,
        description: .[1].result.tools[0].description,
        inputSchema: {type:"object",properties:{},additionalProperties:false}
      }] and
      .[2].result.isError == false and
      (if $kind == "server_time" then
        (.[2].result.structuredContent.timezone == "UTC" and
         (.[2].result.structuredContent.rfc3339 | type) == "string")
       else
        (.[2].result.structuredContent.uptime_seconds > 0 and
         .[2].result.structuredContent.total_memory_bytes > 0)
       end)
    ' "$output" >/dev/null || return
  done
}

check_real_worker_receipt() {
  local receipt="$RUN_DIR/real-worker-receipt.json"
  DIREXTALK_ACCEPTANCE_RECEIPT="$receipt" \
    DIREXTALK_ACCEPTANCE_RUN_DIR="$RUN_DIR" \
    "$REAL_WORKER_DRIVER" || return
  scripts/acceptance/check-real-worker-receipt.sh "$receipt"
}

groups=()

run_batch_group() {
  local name=$1
  shift
  groups+=("$name")
  run_group "$name" "$@"
}

run_batch_group builtin_catalog \
  go test ./internal/coreextension/source ./cmd/dirextalk-agent \
    -run '^(TestBuiltinSkillsExposePinnedNetworkFreeCatalog|TestBuiltinMCPsExposeTwoPinnedReadOnlyServers|TestEnsureDefaultBuiltinSkillsSeedsOnceAndHonorsRemovalFence|TestEnsureDefaultBuiltinMCPsSeedsOnce)$' \
    -count=1 -timeout=2m -v

run_batch_group builtin_mcp_stdio check_builtin_mcp_stdio

run_batch_group credential_and_catalog \
  go test ./internal/agentcapability ./internal/agentcapability/worker ./cmd/dirextalk-agent \
    -run '^(TestCoreAWSCapabilityUsesLowerSnakeRedactedCredentialDTO|TestCoreAWSCapabilityRejectsSecondActiveCredential|TestCoreAWSCapabilityTestCredentialIsDurablyIdempotent|TestCloudWorkerCredentialReadinessTracksCurrentVerifiedView|TestDescriptorTracksVerifiedCredentialWithoutRestart|TestCatalogTracksVerifiedCredentialWithoutRestart|TestCoreInfoProviderProjectsReadyDescriptorsToStableClientTokens)$' \
    -count=1 -timeout=2m -v

run_batch_group worker_lifecycle \
  go test ./internal/cloudworker/sshworker ./internal/cloudworker/localartifact ./internal/agentcapability/worker ./internal/coreexecutionv2 \
    -run '^(TestExecuteRequiresConfirmationOnlyWhenCreatingAndRetainsWorker|TestAmbiguousCreateReconcilesAndDestroyRequiresExactAuthorization|TestListWorkersRefreshesPublicIPBeforeReadOnlyRunnerProbe|TestCommandStatusSourceReadsServerLoad|TestSinkPersistsSSHOutputAndArtifactsAcrossRestart|TestListProjectsObservedPublicIPv4TaskQuoteAndWorkload|TestDestroyAndDomainMutationsPassExactIdentityAndProofs|TestLocalCloudWorkerArtifactReadAndDownload|TestPersistentWorkerExecutionProjection)$' \
    -count=1 -timeout=2m -v

run_batch_group quote_confirmation_resume \
  go test ./internal/cloudworker ./internal/cloudworker/sshflow \
    -run '^(TestProductionQuoterUsesFreshBoundCatalogAndHardMaximum|TestProductionQuoterRequotesSamePriceCatalogRevisionDrift|TestAWSLivePricingCatalogReadsAWSForEveryQuoteWithoutCatalogState|TestHandlerTerminalizesFailureWithoutDestroyingPersistentWorker)$' \
    -count=1 -timeout=2m -v

run_batch_group postgres_durable \
  go test ./internal/store/postgres \
    -run '^(TestCoreAWSStoreAllowsOnlyOneActiveCredential|TestCoreExtensionBuiltinSkillSeedIsOneTimeAndRemovalSurvivesRestart|TestCoreExtensionBuiltinMCPSeedIsOneTimeAndRemovalSurvivesRestart|TestCloudWorkerPostgresConfirmationAndPredispatchCancelProjection|TestCloudWorkerFreshStateIntrinsicToVerifiedCompletionWithoutAWSMutation|TestSSHWorkerStoreLoadsConfirmedTurnSnapshotAndAtomicallyResumesConversation|TestCloudWorkerPostgresPersistsPrivateExactArtifactAndRestartSafeRetention)$' \
    -count=1 -timeout=5m -v

if [ -n "$REAL_WORKER_DRIVER" ]; then
  run_batch_group real_worker check_real_worker_receipt
fi

passed=0
failed=0
skipped=0
printf '\nAcceptance summary\n'
for name in "${groups[@]}"; do
  status=$(tr -d '\r\n' <"$RUN_DIR/status/$name")
  printf '%-30s %s\n' "$name" "$status"
  case "$status" in
    passed) passed=$((passed+1)) ;;
    skipped) skipped=$((skipped+1)) ;;
    *) failed=$((failed+1)) ;;
  esac
done
printf 'passed=%d failed=%d skipped=%d logs=%s\n' "$passed" "$failed" "$skipped" "$RUN_DIR/logs"

[ "$failed" -eq 0 ]
