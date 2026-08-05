# Worker AMI Release Operator

`dirextalk-worker-ami` is a closed, operator-only AWS SDK tool. It is not an
Agent RPC, Eino tool, Skill surface, arbitrary EC2 client, or credential
transport. Run it only from the committed release checkout and an authorized
operator context using the standard AWS SDK credential chain.

## Pi real-task recovery gate

The deployed v72 Agent and its Pi Worker AMI completed bootstrap, enrollment,
claim, heartbeat, input materialization, checkpointing, terminal completion,
and verified AWS cleanup for Task
`019fcbce-4100-7be6-a97d-0895d9cd6552`. The `execute-role` action failed after
Pi had run for about 67 seconds. The published evidence contains only
`action_failed` and `outcome=failed`; it does not contain the failure class.

The first irreversible loss in the deployed runtime occurs in
`internal/workerruntime`: Pi exits zero
for provider and agent errors and reports them in its JSON event stream, while
the deployed adapter collapses every `stopReason=error`, malformed event
sequence, and missing final tool result into `ErrExecution`. Process stderr and
exit details are also destroyed before a safe classification is retained.
Therefore the existing evidence cannot prove that the AMI package, credential,
provider call, Pi event contract, or required final tool call caused this
specific failure.

The deployed source baseline remains immutable commit
`ec95c313d31639aa97d9c70a0e0501295167ae7b`; recovery work uses a separate
branch and preserves the current AMI as the rollback Release.

On 2026-08-04, a single controlled provider qualification ran directly on
demo2 without EC2 or service mutation. It verified the official Pi `0.83.0`
Linux x64 archive and executable plus the exact result extension by SHA-256,
loaded the existing root-protected DeepSeek token, and selected
`deepseek-v4-pro` with a configured `maxTokens` of 128. Pi exited zero after
one provider turn, emitted no provider error, invoked
`dirextalk_submit_result` exactly once, and terminated the tool successfully
with status `completed`. Usage was 530 input tokens, 315 output tokens including
114 reasoning tokens, with zero cache tokens and Pi-recorded cost USD
0.0005046. All temporary files were independently confirmed absent afterward.
The structured summary was valid but did not exactly equal the smoke prompt's
requested sentence; exact wording is not part of the production result schema.

The 315-token output also exposed a separate budget-enforcement defect. Pi's
model list displayed the configured 128-token maximum, but a post-run loopback
inspection proved Pi's built-in DeepSeek profile emitted
`max_completion_tokens`, which this DeepSeek compatibility path did not enforce.
The deployed Worker additionally created an empty Pi config directory, so its
signed Team `output_maximum` never reached the model request at all. The
candidate now carries that signed maximum in the immutable runtime task and
writes a per-task `0600` `models.json`; DeepSeek explicitly selects
`maxTokensField=max_tokens`. Legacy tasks without the new optional field are
bounded to 8192 tokens. A digest-verified real Pi `0.83.0` loopback asserts the
actual outbound `max_tokens=128` field before accepting the tool result.

This evidence proves the released Linux Pi executable, demo2 credential,
DeepSeek model path, extension loading, tool declaration, tool execution, and
structured-result contract can work together. It does not recover the first
Worker's erased failure, so that historical failure remains unknown rather
than being retrospectively reclassified. The candidate's EC2 and complete
App-to-Worker-to-App acceptance were subsequently closed by the 2026-08-05
run recorded below.

### Recovery gate closeout

On 2026-08-05, App-originated Task
`019fd102-aee9-76e7-882e-9e4ac356d6f0` used Plan
`5f733ab7-faf5-58cb-a751-4ff0ac707408`, Execution
`3020fb7f-8a01-553e-9c42-738f8b64e342`, and one official Pi Worker from AMI
`ami-023e6b2d57694b86d`. The Worker enrolled, materialized input, ran the
approved role on its first attempt, uploaded a structured result, and reached
terminal success. Central validated artifact SHA-256
`bdf5bfcb60c7a5627c3a4f75fee6be26f2a387d3a154efea3c2e5f73188cadc6`
and froze Team Report digest
`sha256:369774cd87709048cac370cab96851161a82b500ee2c30395bbe0dafcccb4e7a`.
The App received the uniquely correlated completion only after Central had
verified cleanup.

Central's durable ledger records one EC2 instance, root EBS volume, ENI, EIP,
and security group, all `verified_destroyed` with negative provider read-back.
An independent AWS API query repeated on 2026-08-05 returned zero resources in
all five task-tagged scopes. The official AMI remains `available`; its root
snapshot `snap-0ae9af10d9f1a406e` remains `completed` and encrypted. This
closes the Worker recovery and Release-promotion gate. Later Agent-only result
projection fixes must use `docs/agent-image-release.md` and must not rebuild
this proven Worker AMI.

### Chosen recovery design

Blindly rebuilding the AMI is rejected because the image already booted and
ran Pi. Adding free-form stderr or provider messages to logs is also rejected
because those values can contain credentials, request content, or upstream
implementation details. Recovery instead has three bounded layers:

1. Run the digest-verified Pi `0.83.0` executable and the exact Dirextalk result
   extension against a local OpenAI-compatible fake provider. This release
   qualification must exercise the real CLI arguments and parse the real JSON
   event stream. It performs no model call and incurs no provider cost.
2. Preserve only a closed failure class and stage before raw process or Pi
   diagnostics are erased. Initial classes distinguish process start, timeout,
   output limit, non-zero exit, provider authentication, provider quota/rate
   limit, provider request/server/network failure, invalid Pi event stream,
   aborted execution, and missing structured final result. Raw stderr,
   `errorMessage`, response bodies, prompts, paths, and credentials remain
   forbidden from durable evidence and ordinary logs.
3. Use the classified result to fix the actual runtime boundary. A packaging
   change is permitted only if the real-binary qualification proves a packaged
   asset defect. A prompt, extension, or adapter change is permitted only when
   its failing test reproduces that exact class. One change is tested at a time.

The first compatibility release may expose the closed class in the Worker's
serial log while keeping the deployed completion RPC unchanged. Extending the
Agent protocol, PostgreSQL projection, or App failure UI is a separate change
after the Worker succeeds; it must not be bundled into the root-cause fix.

### Recovery implementation and acceptance

Implementation follows this order:

1. Add failing tests for real Pi provider-error events, missing final result,
   non-zero exit, timeout, and output overflow. Confirm every test fails for
   the intended missing classification.
2. Add the minimum typed error contract in `internal/workerruntime` and retain
   no raw diagnostic text after classification.
3. Add an opt-in real-binary qualification test. It requires an explicit Pi
   executable and result-extension path, verifies their digests before use,
   serves a loopback fake provider, and validates one complete structured
   result through `parsePiEvents`.
4. Run focused normal and race tests, all Worker packages, `go vet`, Worker
   command builds, repository secret scans, and `git diff --check`.
5. Only after those checks pass, prepare a new immutable Worker rootfs and AMI
   candidate. The 2026-08-04 direct provider qualification satisfies the
   model-path prerequisite but does not authorize an active Release switch.
6. Keep the current Release active. One bounded Worker task may select the
   candidate once. Promotion requires a verified structured result,
   App correlation, terminal cleanup, and independent zero-resource read-back.

The recovery is not complete when tests merely pass with a fake process or
handwritten event fixture. It is complete only after the exact Pi release runs
the loopback qualification and one authorized real task reaches the full
success-and-cleanup boundary.

### Test-driven implementation checklist

The recovery change set remains within the Worker runtime and immutable input
compiler:

- `internal/workerruntime/failure.go` owns the closed failure code and stage;
- `internal/workerruntime/types.go` carries the optional signed output bound
  while retaining a bounded compatibility path for old tasks;
- `internal/workerruntime/process.go` classifies process boundary failures;
- `internal/workerruntime/pi.go` classifies Pi JSON terminal failures and writes
  the task-local provider/model override;
- `internal/teaminput/compile.go` copies the approved role output maximum into
  the immutable runtime task;
- `internal/workerruntime/process_test.go` and `pi_test.go` prove each class
  plus exact DeepSeek and legacy output bounds;
- `internal/workerruntime/pi_binary_integration_test.go` runs an explicitly
  supplied, digest-verified Pi binary against a loopback provider;
- `cmd/dirextalk-cloud-worker/main.go` emits only failure code and stage in the
  final serial-console record; and
- `cmd/dirextalk-cloud-worker/main_test.go` proves raw upstream text and
  credential-shaped values cannot enter that record.

The red/green sequence is:

1. Add assertions for `process_start`, `process_timeout`,
   `process_output_limit`, and `process_exit_nonzero`; run
   `go test ./internal/workerruntime -run TestOSProcessRunner` and observe the
   new assertions fail because no code is available.
2. Add assertions for `provider_authentication`, `provider_quota`,
   `provider_rate_limit`, `provider_request`, `provider_server`,
   `provider_network`, `pi_aborted`, `pi_event_invalid`, and
   `pi_final_missing`; run `go test ./internal/workerruntime -run TestParsePi`
   and observe the missing classifications.
3. Implement only enough typed failure behavior to make those focused tests
   pass, then rerun `go test ./internal/workerruntime` and
   `go test -race ./internal/workerruntime`.
4. Add the opt-in real-binary loopback test and run it with the exact local Pi
   `0.83.0` asset and expected SHA-256. The fake provider must receive the
   expected model, exact `max_tokens=128`, and result-tool declaration, then return
   one tool call that produces a valid `dirextalk.agent.pi-final/v1` artifact.
5. Add the closed serial-log projection and its negative secret/raw-text test.
   Run `go test ./cmd/dirextalk-cloud-worker` before changing the command and
   again after the minimal implementation.
6. Run the complete no-cloud gate:

   ```text
   go test ./internal/workerruntime ./internal/workerrunner ./internal/workerlog
   go test -race ./internal/workerruntime ./internal/workerrunner
   go test ./cmd/dirextalk-cloud-worker ./cmd/dirextalk-worker-rootfs
   go vet ./internal/workerruntime ./internal/workerrunner ./cmd/dirextalk-cloud-worker
   go build ./cmd/dirextalk-cloud-worker ./cmd/dirextalk-worker-rootfs
   git diff --check
   ```

Any failure outside this list stops the change and is reported separately. The
implementation must not change the active Release, AMI catalog, AWS account,
demo2 container, completion RPC, database schema, or client behavior.

## Full-release preflight and resume boundary

Enter this path only when the classified diff changes a Worker/Reaper binary,
Worker rootfs, Pi installation/assets, result extension, or AMI construction.
Central-only controller or API changes use the Agent-only flow in
`docs/agent-image-release.md` and must not pay the AMI wait.

Before publishing a bundle or launching a builder, verify and record:

- a clean committed source revision with restrictive receipt-directory
  permissions and a known `umask`;
- builder disk, Docker/Buildx, Go, `gcc`/native build packages, AWS identity,
  Region, and immutable ECR repository policy;
- the complete Pi installation tree required by the executable, including
  runtime assets such as themes, rather than qualifying a copied binary alone;
- archive hygiene produced with macOS copy-file metadata disabled, with every
  `._*`/AppleDouble member rejected before upload; and
- exact archive ownership, mode, path, digest, and the runtime qualification
  result from the same rootfs bytes that will enter the AMI.

Every AWS CLI command must carry the recorded `--region` explicitly. Do not
use `AWS_REGION` as the only Region selector because AWS CLI v1 may continue
using its configured default. Confirm the account, VPC, subnet Availability
Zone, AMI Region, and ECR URI before interpreting any `Invalid*NotFound`
response or creating replacement infrastructure.

Treat release publication, AMI creation, snapshot availability, AMI
verification, and Release promotion as separate durable stages. Each stage
must write a protected receipt before moving forward. Resume from the first
stage whose AWS/ECR read-back is absent or inconsistent; never rebuild earlier
artifacts that still match their immutable digests.

AMI creation and encrypted snapshot finalization are asynchronous AWS
operations and can take several minutes. Poll the recorded AMI/snapshot IDs
with bounded backoff while preserving the builder cleanup facts. A long
snapshot wait is not evidence that compilation or upload should be restarted.
After success or failure, run the scoped destroy/read-back path and prove the
temporary builder, root EBS volume, ENI, endpoint/rule, credentials, and local
session artifacts are absent.

## Prepare a build-request v2

Preparation is read-only. It confirms the exact STS account and Region,
derives the deterministic Foundation stack from `agent_instance_id`, reads
back the stable stack and release outputs, resolves the isolated VPC/subnet/
security-group/route-table facts and regional S3 prefix list, and selects the
newest unambiguous public Canonical Ubuntu 24.04 LTS amd64 EBS/HVM AMI owned by
AWS account `099720109477`. It then re-verifies the release manifest and
Worker rootfs bytes and writes a new `0600` build request without replacing an
existing file.

Canonical's scheduled future `DeprecationTime` does not make an otherwise
current image ineligible; a malformed, current, or past deprecation time does.
The image must expose exactly one `gp3` root EBS mapping with a valid snapshot,
positive size, and delete-on-termination. Additional mappings are accepted only
when they are non-EBS `ephemeralN` virtual devices. The public source snapshot
may be unencrypted; `RunInstances` still replaces the root mapping with the
required encrypted, delete-on-termination `gp3` builder volume.

```text
dirextalk-worker-ami prepare \
  --account-id <12-digit-account-id> \
  --region <aws-region> \
  --agent-instance-id <canonical-agent-uuid> \
  --release-manifest <protected-release-manifest-path> \
  --rootfs-archive <protected-worker-rootfs-path> \
  --output <new-protected-build-request-v2-path>
```

The v2 document contains no CIDR, public-Internet test switch, credential,
profile, presigned URL, or arbitrary endpoint/service input. Build re-reads
the Foundation outputs, base AMI, route table, S3 prefix list, bucket
versioning/encryption, release manifest, and rootfs before mutation, so a
replaced file or changed provider fact fails closed.

## Build, verify, and destroy

```text
dirextalk-worker-ami build \
  --request <protected-build-request-v2-path> \
  --output <new-publication-manifest-path>

dirextalk-worker-ami verify \
  --manifest <publication-manifest-path>

dirextalk-worker-ami destroy \
  --request <strict-destroy-request-v2-path>
```

Build writes protected recovery files beside the publication output before it
can lose the corresponding provider facts:

- `.build-intent` binds the raw and normalized request digests;
- `.builder-reachability` binds the exact S3 Gateway endpoint and TCP/443
  security-group-rule IDs; and
- `.builder-cleanup` binds the exact builder, root EBS, and ENI IDs.

The builder has no public address and no IAM instance profile. Its only
temporary route is the tagged S3 Gateway endpoint on the exact Foundation
route table, and its only usable egress is TCP/443 to the exact AWS-managed
regional S3 prefix list. Cleanup always terminates and reads back the builder,
EBS, and ENI first, then revokes the rule, deletes the endpoint, and proves the
rule, endpoint, and S3 route absent. A response-lost operation is reconciled by
deterministic scope and exact tags; multiple matches, access denial, scope
drift, or incomplete evidence never selects or deletes a guessed resource.

Build-request v1 is retained solely for an explicit compatibility operation:

```text
dirextalk-worker-ami build --allow-legacy-v1 \
  --request <legacy-build-request-v1-path> \
  --output <new-publication-manifest-path>
```

The compatibility switch does not convert v1 into the v2 private-network
contract. Do not use it for real release evidence.
