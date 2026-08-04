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

The first irreversible loss occurs in `internal/workerruntime`: Pi exits zero
for provider and agent errors and reports them in its JSON event stream, while
the adapter currently collapses every `stopReason=error`, malformed event
sequence, and missing final tool result into `ErrExecution`. Process stderr and
exit details are also destroyed before a safe classification is retained.
Therefore the existing evidence cannot prove that the AMI package, credential,
provider call, Pi event contract, or required final tool call caused this
specific failure.

No Central OS feature work, demo2 replacement, Worker AMI publication, active
Release switch, or paid retry may proceed through this recovery gate. The
deployed source baseline is immutable commit
`ec95c313d31639aa97d9c70a0e0501295167ae7b`; recovery work uses a separate
branch and preserves the current AMI as the rollback Release.

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
   candidate. Preparation is read-only; any AWS build or model request requires
   a fresh explicit authorization.
6. Keep the current Release active. A separately approved one-Worker task may
   select the candidate once. Promotion requires a verified structured result,
   App correlation, terminal cleanup, and independent zero-resource read-back.

The recovery is not complete when tests merely pass with a fake process or
handwritten event fixture. It is complete only after the exact Pi release runs
the loopback qualification and one authorized real task reaches the full
success-and-cleanup boundary.

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
