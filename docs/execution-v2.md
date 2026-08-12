# Agent-owned Execution V2

`agent.execution.v2.*` is the only public execution surface. Message Server
keeps the ProductCore action envelope and proxies authenticated owner calls;
it does not store Agent plans, runs, confirmations, artifacts, worker leases,
AWS credentials, or result bodies.

## One execution model

Execution V2 keeps its non-conflicting analysis, target, deployment,
service-binding, secret, plan/run read, list, cancel, event, and artifact
operations. Cloud Worker plans are created only inside an authoritative Native
Agent turn by the built-in `cloud_worker_propose` tool. A client cannot create
an AWS Cloud Worker plan or run directly.

There is one confirmation authority:
`agent.core.confirmations.get/list/confirm/reject`. Provider progression is
owned by the durable Agent controller. Uncertain provider responses are
reconciled internally by immutable read-back; they are never treated as
permission to repeat a mutation.

For a non-Cloud-Worker run, create/retry atomically writes the run, first
stage, real `EXECUTION_V2_RUN` CoreTask, and real CoreConfirmation. Confirming
projects the task plus run/stage to `queued` in that same transaction;
rejecting or expiring the confirmation terminalizes all three before any
provider call. There is no Execution V2 confirmation record or reconciliation
shadow to repair after a restart.

This is a fresh-state contract. Execution plans, confirmations, provider
progression, and read-back each have one authoritative path.

## Local and cloud execution boundary

Native Agent conversations remain local-first. The existing local sandbox,
light-task worker pool, MCP, Skills, Knowledge, Conversation Tools, and
Extension Runner remain available. Only a `CLOUD_WORKER` CoreTask crosses the
AWS boundary.

The built-in proposal tool is eligible only when a trusted turn policy proves
one of these facts:

- the user explicitly requested cloud execution; or
- the local scheduler supplied immutable evidence that the current local
  execution budget cannot satisfy the request.

A model assertion and a local execution failure are not budget evidence. A
local failure never silently upgrades to paid cloud execution, and a cloud
failure never falls back to a hidden local rerun.

Cloud intent is evaluated by punctuation-delimited command clause. A negative
local directive paired with an independent explicit cloud command (for
example, “do not run locally; run this task on AWS”) is valid explicit cloud
authorization. An actual cloud negation, conditional, comparison, or
conflicting positive local command remains a fail-closed veto.

The cloud recipe and adapter are fixed:

```text
recipe  = ephemeral-pi-task
adapter = pi_json_task_v1
```

Every execution owns exactly one EC2 instance, one Worker process, and one Pi
process invocation. Pi may invoke ordinary approved tools, but a second Pi
exec is forbidden. The Worker does not load the user's local MCP installations, Skills,
Extension Runner, local sandbox credentials, or Agent database. It receives
only a short-lived model relay grant, exact versioned input objects, its exact
artifact prefix, and the approved network/secret grant descriptors.
The configured private Model Relay endpoint is an exact HTTPS base URL whose
path is `/v1`; startup rejects a bare origin, encoded path, or trailing slash.

Workspace modes are closed:

- `none`: no user workspace is mounted;
- `read_only`: the immutable manifest is fetched and mounted read-only;
- `write`: work happens in an isolated copy and returns a patch, archive, or
  artifact; it never writes directly into the user's local files.

For `write`, the Worker snapshots the isolated workspace before Pi starts and
collects only the post-run delta. The authoritative `workspace.delta.tar.gz` has the
fixed layout `meta/delta.json` plus `files/<canonical-workspace-path>` for each
added, modified, or type-replaced entry. Deletions are typed, sorted records in
`meta/delta.json`; unchanged input bytes are never repackaged. The optional
`changes.patch` is a convenience view and is never the apply or integrity
authority. The baseline retains an opened workspace root through collection;
directory enumeration and every content read are resolved beneath that fd with
Linux `openat2` using no-symlink, no-magic-link, and no-cross-mount constraints.
Collection starts only after the execution gate proves the Worker cgroup has
exactly the Worker process and no Pi or tool descendant left alive.

## Durable authorities and atomic offer

PostgreSQL migration `000004` adds the single Cloud Worker schema. The
authorities are:

| Fact | Authority |
|---|---|
| Conversation, offer, status reference, final reply | CoreConversation messages and turn events |
| Plan, quote, run, artifacts, AWS graph | Strongly typed Cloud Worker records under Execution V2 |
| Queue, attempt, lease, epoch | CoreTask with kind `CLOUD_WORKER` |
| User decision | CoreConfirmation |
| Claim, heartbeat, completion | private WorkerControlService session |
| App invalidation | Message Server's minimal completion receipt |

Worker progress reuses the private session `progress_sequence` as its exact
mutation/replay fence and the existing `agent.execution.v2.runs.events`
sequence as the only public resume cursor. Snapshots contain only a closed
phase plus bounded elapsed/activity, CPU, memory, invocation, upload, and
truncation counters. Complete and Fail carry their final snapshot in the same
serializable transaction as the terminal session mutation. PostgreSQL retains
the latest 4096 run events as one contiguous suffix; an older cursor resumes at
that suffix with `history_truncated=true`. Event pages remain
`{events,next_sequence,history_truncated}` and fail closed on any internal gap.
CPU and memory are bounded observations; `0` means the Worker has no verified
runtime metrics source, not that the task consumed zero resources.

One PostgreSQL transaction creates the plan, execution, waiting-user task,
confirmation, assistant offer message, turn event, complete reference snapshot,
and offer outbox. Confirm, reject, expiry, requote, and terminal conversation
projection updates use the same atomic boundary. A replay returns the exact
existing objects only when its canonical request digest matches.

A successful Cloud Worker CoreTask retains a display-oriented server snapshot
inside its existing result JSON. The snapshot keeps the stable Worker/stack
name, Region, any private or public IP observed before cleanup, and the sealed
non-secret Worker configuration from the Plan. An address is optional when the
qualified network shape does not publish one. Failed and canceled CoreTasks
retain their failure fields and no result, as required by the CoreTask schema;
their typed Plan and Execution records remain authoritative. Provider instance
IDs, AWS account identity, and account/plan generations remain authorization
evidence in those typed authorities and are not required to render a successful
task snapshot.

A public conversation reference carries account generation plus the exact
task, plan, run/execution, confirmation, revision, quote, binding, and execution
digests. It is an invalidation/link, not mutation authority. Clients must read
the current Plan, Run, and CoreConfirmation and verify their linkage before
confirming, rejecting, or cancelling.

## Authorization-bound plan

A sealed Cloud Worker plan binds all fields that affect cost or authority:

- owner, account generation, conversation, turn, objective digest and safe
  summary;
- exact input manifest and workspace mode;
- model profile/revision, provider/model/interface, credential version, and
  protected credential binding;
- AWS account, Region, credential revision, instance/EBS parameters;
- AMI, Worker release, and Pi runtime digests;
- maximum runtime, token and output limits;
- network grants, secret grant descriptors, artifact prefix and retention;
- quote source time, expiry, estimate, basis digest, and hard authorized cost
  ceiling.

Any change produces a different authorization/execution digest and therefore
a fresh quote and fresh CoreConfirmation. An expired quote, credential drift,
model drift, input drift, instance drift, or grant drift cannot reuse an old
confirmation.

For the Pi OpenAI-compatible adapter, the Plan carries one effective output
token limit computed before its authorization digest and quote. It is the
minimum of the server Cloud Worker limit, a positive exact-profile output
limit, and Pi's qualified provider-request ceiling of 384 Ki tokens, and it
must be at least 512 tokens. The same value is priced and then propagated
unchanged through the runtime task, Model Relay grant, and Pi model override.

Public projections are explicit allow-lists. They omit AWS credential IDs,
raw objectives, user-prompt and private model-binding digests, exact S3
locations, placement/bootstrap/relay material, provider resource IDs,
infrastructure/authorization-basis digests, secret values, and Worker
diagnostics.

## State machine and controller

The success path is fixed:

```text
waiting_user -> queued -> provisioning -> awaiting_worker
             -> running -> collecting -> validating -> cleaning -> succeeded
```

Reject and expiry terminate before the first AWS mutation. Cancellation first
fences the Worker session, then enters cleanup. Provision, Worker, collection,
and validation failures also enter cleanup. A failed, cancelled, or successful
execution cannot become terminal until every recorded EC2, EBS, ENI, EIP,
security-group, IAM role/profile, and stack identity is independently read
back as `verified_destroyed`.

The EIP provider identity recorded in the resource graph and ledger is the
immutable `eipalloc-*` AllocationId, never its public IPv4 address. The fixed
CloudFormation template publishes that value through an explicit `GetAtt`
output; an active stack without a valid AllocationId output fails closed.

The controller never synchronously runs Pi after provisioning. It waits for a
durable WorkerControl terminal session, collects the exact S3 object version,
validates its digest/schema/limits, freezes the result, cleans all resources,
and only then writes the final conversation result. Controller restart and
CoreTask lease reclaim read the original dispatch intent and resource ledger;
they cannot create a second instance.

## Worker identity and result boundary

WorkerControlService is private and runs on a dedicated TLS 1.3, worker-only
listener. It is not registered on the public Agent service-token listener or
in the Capability catalog. Identity challenge and claim bind AWS account,
Region, EC2 instance/launch identity, execution, task, account generation,
attempt, and lease epoch. Challenges are single-use; session tokens are stored
only as digests; heartbeat sequence and terminal calls are idempotent and
reject replay, cancellation, and stale leases.

Claim returns the exact runtime task, immutable input manifest, exact artifact
scope, short-lived model relay grant, heartbeat interval, and not-after time.
The immutable AMI qualification is the sole release record for the current
`worker_protocol_version=dirextalk.agent.cloud-worker-control/v1` and
`runtime_contract_version=dirextalk.agent.ephemeral-pi-runtime/v1`. The Worker
declares both values in Claim and the Agent returns the same exact pair. A
missing or different value is rejected before identity verification, session
creation, model-grant activation, runtime-task parsing, or Pi execution. There
is no version negotiation, fallback, or older qualification schema path; the
current qualification document schema is
`cloud_worker_runtime_qualification_v2`.
The canonical Pi final result is bounded by the approved `max_tokens` and
output bytes. Collection uses one exact versioned S3 object and verifies
version, key/prefix, media type, size, digest, manifest, task/lease binding,
and canonical final schema before any user-visible conclusion is accepted.
For a `write` result, central validation additionally requires exactly one
delta archive bound to the authorized runtime input-manifest digest. It rejects
non-canonical JSON/gzip/tar, undeclared or missing members, unsafe paths or
member types, metadata/content mismatches, and compressed or expanded output
over the Plan limit before an Artifact can become `verified`.

Pi execution is guarded by an independent root-owned systemd service using
`FAN_OPEN_EXEC_PERM`. Only this Gate holds `CAP_SYS_ADMIN`; the Worker holds
only the UID/GID transition capabilities and Pi holds none. Gate registration
is authenticated with kernel `SO_PEERCRED` and binds the Worker UID/PID, boot
identity, process start ticks, exact cgroup, execution/task/attempt, and lease
epoch. The first Worker child must be the pinned Pi device/inode/SHA-256; a
second exec of the same inode or a copied executable with the same digest is
denied while ordinary task tools remain available. Path replacement before
the first exec is also denied because the permission event validates the
kernel-opened FD rather than a mutable pathname.

WorkerControl completion carries the canonical terminal topology proof. The
Agent revalidates its current task lease/fence, runtime-task digest, Worker
release digest, Pi digest, and future clock skew. Proof age alone is not an
authorization boundary because bounded result upload happens after proof
creation. Completion requires exactly one allowed Pi exec, zero active Pi
processes or descendants, and exactly the Worker remaining in its cgroup;
result parsing and `write` workspace collection cannot precede that proof.
Gate loss, daemon/orphan residue, replay drift, or cancellation fails closed.

## AWS provider and cleanup

The typed AWS provider writes a deterministic dispatch intent and complete
owner/execution/launch identity before its first mutation. Every external
read, delete, retry, and postcondition revalidates account, Region, provider
ID, immutable launch identity, and owner/execution tags. An unknown create or
delete response causes read-back only; it is never followed by a blind repeat.

Workers have no inbound rule and no SSM access. Egress permits only controlled
DNS/TLS proxy routes and explicitly approved destinations. FQDN policy is
enforced by the controlled proxy; Security Groups are not claimed to provide
FQDN filtering.

The Resource Ledger and Reaper converge cleanup after process restart or
lease loss. Cleanup uncertainty remains non-terminal and retryable only through
identity-revalidated read-back/deletion of the original resources.

Every centrally accepted output artifact also has a private retention record
bound to owner/account generation, AWS account/Region/credential revision,
execution/Plan digest, exact bucket/key/version, media type, byte length,
SHA-256, and the Plan-authorized expiry. These S3 fields never enter the public
artifact DTO. At expiry, a durable cleaner claims one version with a fenced
lease, revalidates PostgreSQL and live AWS identity before and after the exact
`DeleteObjectVersion`, and concludes only from exact-version read-back. An
ambiguous delete is read back and retried after a durable delay; restart and
concurrent sweepers cannot delete a same-name replacement or publish
`verified_deleted` without absence proof.

The sole public byte-read path is
`agent.execution.v2.artifacts.download`. It accepts only
`record_kind=cloud_worker`, the artifact UUID, an offset below the 8 MiB
artifact ceiling, and a 1..512 KiB chunk limit. Every call reads a retained
authority snapshot, revalidates the current AWS binding, fetches the exact S3
version, verifies its bucket owner, KMS identity, media type, size, metadata
digest, and complete SHA-256, then repeats both PostgreSQL and AWS fences before
returning a non-empty chunk. A concurrent cleaner claim, expiry, credential
drift, object drift, or stale owner generation fails closed. Downloads neither
create a lease nor extend retention, and public results contain no S3 address.

## Completion callback and App recovery

After result freeze and verified cleanup, Agent appends one idempotent result
message to the original conversation and dispatches the durable completion
outbox through the fixed private
`product.agent_execution.v1/record_completion` callback. Message Server stores
only the minimal receipt and emits `agent.execution.v2.completed`; result text,
artifacts, plan details, and AWS evidence remain Agent-owned.

The App treats that realtime event only as invalidation. It reloads Agent
history and Execution V2, deduplicates the result message, and displays only
centrally validated deliverables. It never exposes S3 addresses, secrets,
private Worker diagnostics, or unvalidated risk conclusions.

## Activation and evidence

Startup and fake-provider qualification perform no AWS mutation. Real AWS
activation requires an explicitly supplied disposable account, Region, Worker
AMI, credential revision, and cost ceiling. Worker AMIs are rebuilt only when
their transitive Agent/Worker inputs change; Message Server or Flutter-only
changes reuse the proven immutable AMI digest.

Local checks may explicitly skip the real fanotify permission test when the
host lacks root or `CAP_SYS_ADMIN`; such a skip is not AMI evidence. The
candidate AMI/kernel must record a non-skipped fanotify pass plus boot evidence
that both required fence units are active before the Worker, only the Gate has
`CAP_SYS_ADMIN`, the Gate cgroup retains the release-bound task headroom needed
by its Go runtime and per-request handlers, Pi has no capability, the terminal
cgroup-empty proof is accepted centrally, and no SSH/SSM or inbound listener
exists. Any missing observation keeps that AMI digest unpublished.

Release evidence includes deterministic digest/requote tests, PostgreSQL
atomicity and restart tests, Worker identity/replay tests, Pi loopback and exact
S3 result tests, provider/Reaper fault injection, callback/realtime replay,
Flutter authority/linkage tests, and one explicitly authorized fresh-state
AWS inventory proving the temporary resource set is empty after completion.
