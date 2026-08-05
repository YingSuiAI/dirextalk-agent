# Core v1 API contract

Source behavior follows the `Agent Core v1 source contract`. Live production
activation is still readiness-gated; this contract does not claim that Compose,
Core Runner, or AWS live acceptance has completed.

The canonical public contract is the versioned Protobuf under
[`api/proto/dirextalk/agent/v1`](../api/proto/dirextalk/agent/v1). Generated Go
files are derived artifacts; the `.proto` files are the review surface.

## Services

The Core server may register these services, subject to configuration gates:

- `AgentService` for capabilities and instance information;
- `ModelProfileService` and `ConversationService`;
- `TaskService` and `ScheduleService`;
- `ConfirmationService`;
- `MCPService` and `SkillService`;
- `CoreKnowledgeService`;
- `CoreCloudControlService`.
- `WorkloadService` for durable workload planning and operations.
- `CoreExecutionV2Service` is the typed Agent-owned composition seam for the
  frozen `agent.execution.v2.*` action family. The public proxy uses the
  neutral Capability API and the exact operation IDs from `docs/execution-v2.md`.
  Its request and response messages use the Buf-standard
  `CoreExecutionV2Service<Method>{Request,Response}` names.

Health and reflection are optional server features. No REST API, admin UI, or
multi-user authorization surface is part of Core v1.

## Transport and authentication

The server uses TLS 1.3. A deployment-generated token is read from the
protected `service_token_file`; the token value is never stored in PostgreSQL
or returned by an API. Calls carry:

```text
authorization: DTX-Agent-Token <unpadded-base64url-32-byte-token>
```

The server compares the token in constant time and strips authorization
metadata before invoking a handler. Rotation is an atomic file replacement
followed by restart. There is no remote token-management API, caller scope,
role, device, or multi-tenant model.

## Mutation invariants

- Mutations use UUID idempotency keys where defined by the Protobuf.
- Revision-bearing mutations require the caller's expected revision; stale
  writes fail without changing state.
- Durable Task events and results are fenced by Task revision, attempt, and
  lease epoch. `WatchEvents` resumes strictly after its supplied sequence.
- Stored credentials and other secret values are write-only from ordinary
  read/list RPCs. Responses expose configuration status or fingerprints, not
  secret bytes.
- Durable Core secret fields are encrypted at rest with
  AES-256-GCM using the raw 32-byte mode-0400 mounted
  `core_secret_master_key_file`. The database stores only key version, nonce, and
  ciphertext; a wrong/missing key or revision/field AAD mismatch is a hard
  failure. Provider calls receive request-local material only.
- Account deprovision binds configured Agent-owned roots at startup and purges
  extension staging/workspaces plus Knowledge content recursively through
  trusted descriptors. The read-only `core_knowledge_mount_root` is an
  external source tree and is deliberately never unlinked. Symlinks and
  pathname replacements fail closed; the configured Qdrant base collection
  and exact `<collection>__stage_<generation>` children are deleted in the
  same external phase. Any partial filesystem/vector failure leaves
  `external_purged` false.
- Unknown enum values, malformed UUIDs, invalid digests, and unsupported
  combinations fail closed as `INVALID_ARGUMENT` or `FAILED_PRECONDITION`.

## Core workflows

`TaskService` creates, reads, lists, cancels, retries, deletes, and watches
durable Tasks. Tasks can reference a model profile, conversation, attachments,
Knowledge sources, and pinned MCP/Skill selections. `ScheduleService` creates
one independent Task per one-time or Cron occurrence; it is not a graph or
priority scheduler.

`ConversationService` provides durable `Chat` and streaming `StreamChat` over
server-owned model profiles. Model calls, extension calls, Knowledge context,
and attachment reads use the Task execution snapshot when background work is
required.

`ConfirmationService` is the common explicit-confirmation boundary. MCP/Skill
installation, upgrade, removal, and execution, plus AWS operations that create,
update, expose, spend, or destroy resources, must bind a confirmation to the
exact target revision and content/parameter digests before side effects.

`MCPService` and `SkillService` use pinned source versions and artifact/content
digests. Extension execution returns both durable `confirmation_id` and
non-runnable `task_id`; only exact confirmed binding consumption may queue the
task. The binding records owner, installation kind/revision, immutable
version/manifest/execution/permission digests, selected tool/command, canonical
input digest, and secret/network descriptors. Local stdio and Skill execution can occur only through the separate
Linux extension runner and its isolated namespaces. Remote MCP uses the exact
confirmed HTTPS endpoint. Secret resolution requires the exact installation,
version, reference, declared purpose, and binding digest; an empty or mismatched
purpose fails closed. Cancellation is reported as complete only after the
runner proves the delegated cgroup is empty and removed. The Agent never falls
back to in-process third-party execution.

If a worker is reclaimed after confirmation consumption without an exact
idempotent side-effect receipt, the Task is terminalized with the sanitized
`extension_execution_uncertain`/reconciliation-required marker while the
consumed reservation and installation fence remain active. It is not retryable
or automatically released; operational reconciliation is required.
The owner-only `ConfirmationService.AcknowledgeExtensionExecutionUncertain`
operation accepts only `acknowledged_unknown_no_retry` and exact confirmation,
Task, installation, and revision fences. It records a durable reconciliation
event, marks the consumed reservation released, and leaves the Task failed;
replays with the same idempotency digest return the same readback and a
different digest is an idempotency conflict.

`CoreKnowledgeService` owns mounts, uploads, memory sources, status, indexing,
and search for this Agent instance. Search and Task context are bound to exact
source revisions and index bindings.

`CoreCloudControlService` exposes typed AWS credentials, `TestCredentialIdentity`
identity checks, plans, quotes, and confirmed changes. It does not expose arbitrary AWS SDK calls or
let model/tool arguments bypass confirmation.

`WorkloadService` plans and confirms work durably. Its `WORKLOAD` Task handler
uses the normal revision/attempt/lease-epoch fence. The optional local Core
Runner is not a public transport: it accepts descriptor-only Unix packets,
exports sealed results, and has no raw secret or Agent credential channel.
`workload.core_runner` is advertised only after a nonce-backed full readiness
probe, including its bounded userns/tmpfs/seccomp/cgroup exercise. Supervisor
restart recovery persists `cleanup_required` before exact cgroup reaping;
cleanup uncertainty fails closed and does not create a successful destroy.

Owner-only terminal read-back uses three read-only ProductCore actions:

- `agent.core.workloads.operations.get` returns the current operation projection;
- `agent.core.workloads.operations.events` returns the exact `{events}` envelope
  and accepts an optional `after_sequence`; and
- `agent.core.workloads.actual.get` returns the current sparse workload snapshot.

An operation read-back is bound to its workload identity and may point to a
legal successor snapshot. A missing actual snapshot is an error, never proof of
successful destroy. These reads do not mutate, confirm, retry, or release an
operation.

Typed SSM/ECS registry execution is wired behind `core_aws_enabled`. A
capability is advertised only when its optional `core_aws_ssm_readiness` or
`core_aws_ecs_readiness` block names one exact durable credential reference and
target and the typed provider graph is complete. Process startup performs no
AWS API calls. The first explicit provider action performs the exact
STS/account/resource readiness probe; a failed probe is returned as a
per-operation precondition and is retried on a later explicit action. There is
no default target or account-wide scan. Per-operation credential, ARN target
binding, identity, and read-back checks remain a second fence.

The SSM proof requires the exact running Linux instance, its online managed
SSM record, and configured tags. The ECS proof requires the exact ACTIVE
cluster, available configured subnets/security groups, optional target-group
ARN/port, and an ACTIVE configured task-family revision.
Workload secret grants accept legacy UUID references or canonical Secrets
Manager/SSM ARNs; ARN grants bind confirmation to a versioned ARN-plus-purpose
digest, and AWS execution rejects UUID application references. Credential
resolution requires the current verified revision and exact stored principal
ARN, which must match STS before any resource call.
Two-Compose E2E, live AWS workload acceptance, and live Core Runner workload
acceptance remain pending; the documented isolation lane is not a live
Core-mode release claim.

## Contract changes

Core v1 has no public-API or database compatibility requirement. Any Protobuf
change must update the corresponding documentation and focused contract tests
in the same change.
