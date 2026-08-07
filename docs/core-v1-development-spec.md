# Dirextalk Agent Core v1 development specification

> This document freezes the Agent-owned product and implementation boundary at
> HEAD. Message Server owns the public action/stream proxy and Product
> Capability callback; Flutter uses that proxy and never connects to Agent Core
> directly. Production activation and live verification remain separate gates;
> capability advertisement stays disabled until its exact readiness proof is
> present.

This document is the current product and implementation boundary for the
independent Agent service. The versioned Protobuf in
`api/proto/dirextalk/agent/v1` and the PostgreSQL migrations are the executable
contract. A public or schema change updates this document and its contract tests
together.

The companion Message Server integration contract is
[`docs/message-server-integration-development-contract.md`](message-server-integration-development-contract.md).
The current implementation and tests in this repository override historical
planning notes; no compatibility path or fixture fallback is part of Core v1.

## Product boundary

- One private Agent instance serves one user and belongs to exactly one
  Dirextalk deployment.
- The service is bound one-to-one with its caller deployment, and one
  deployment-side caller consumes one Agent instance.
- The Agent runs outside the business server and owns conversations, Tasks,
  events, schedules, model profiles, prompts, extension installations,
  Knowledge metadata, typed AWS configuration, and encrypted Web Search
  configuration.
- The Agent also owns the current `agent.execution.v2.*` analysis, target,
  plan, deployment, run, artifact, service-binding, and secret records.
  Authorization is owned only by the generic CoreConfirmation domain; there
  is no Execution V2 confirmation shadow. Message Server remains a public
  action facade only; execution data and idempotency/event history are stored
  in the Agent database.
- Message Server calls Agent Core over TLS gRPC/Capability mTLS with
  deployment-generated protected credentials and account-generation fences. The
  Agent-to-Message-Server Product Capability callback is a separate direction;
  neither side shares the other's database or execution history.
- Flutter receives only Message Server's owner-authenticated ProductCore
  actions and Native Agent stream frames. Online Agent remains the real private
  Matrix `agent_room_id` conversation and does not share Native Agent history,
  model state, or online-state inference.
- Agent product/runtime code, Protobuf, migrations, and its deployment image
  are owned here. Product adapters, the public action envelope, and Flutter UI
  remain in their companion repositories; this document does not duplicate
  those APIs.

## Public capabilities

The Core server composes and registers the services listed in the [API
contract](api-contract.md). Registration and capability publication are
separate: a stable planning or introspection RPC such as `WorkloadService` may
be registered before an optional provider is ready. Health and reflection are
optional server features.

All mutation RPCs follow the Protobuf's UUID idempotency and expected-revision
rules. Ordinary reads never return stored secret values. Task events and
results are durable, redacted, resumable, and fenced by lease epoch and
revision. Optional client capabilities remain absent from the neutral
Capability registry until their production composition and readiness checks
pass; callers must not infer readiness from gRPC registration alone.

The neutral Capability API additionally publishes `agent.web_search.v1` only
when the Agent-owned encrypted repository and Tavily client are composed. Its
`get_config`, `update_config`, and `test` operations derive owner identity from
the authenticated permission context. API keys are accepted only by
`update_config`, never returned, and are not part of chat requests or durable
operation payloads. The client readiness projection is `web_search.server`.
The Web Search envelope reuses `core_secret_master_key_file`; its AAD binds
the Agent instance, authenticated owner, positive account generation, provider,
credential version, and field name. Config and replay rows are keyed by owner
and account generation, so a recreated account cannot read, decrypt, or replay
an earlier generation. Config revision advances independently so metadata-only
updates do not invalidate the existing ciphertext. The current provider set is exactly
`tavily`; adding another provider requires a typed schema, validator, adapter,
and encrypted field rather than an arbitrary key/value secret API.
Web Search mutations and provider dispatches take the shared account-
deprovision admission lock before their identity lock and recheck the durable
fence in the same transaction. Dispatch holds that shared guard only through
the bounded provider request; deprovision takes the exclusive form, so cleanup
cannot be followed by a configuration/replay resurrection or an outbound call
that won the race.

`WorkloadService` uses the distinct `WORKLOAD` Task kind and the readiness
semantics defined in the [API contract](api-contract.md). Missing or stale
target proof keeps a capability disabled; there is no implicit default target
or broad scan.

## Acceptance scenarios

The Core v1 acceptance set covers these ten observable scenarios:

1. TLS gRPC authenticates with the protected token file; atomic token
   replacement takes effect after restart.
2. Model profiles and model execution cover OpenAI-compatible providers
   (including OpenRouter, DeepSeek, and xAI), Anthropic, and Gemini.
3. Unary and streaming chat are durable and idempotent across retries and
   service recreation.
4. Immediate, one-time, and Cron schedules create FIFO Tasks and recover due
   work after interruption.
5. Task CRUD, retry, event watch/resume, cancellation, lease fencing, and
   concurrent mutation races preserve durable revisions.
6. MCP discovery and lifecycle cover the official registry, Smithery, Glama,
   and GitHub sources with stdio and Streamable HTTP transports.
7. Skill lifecycle covers skills.sh and GitHub pins; execution is isolated in
   the extension runner, and cancellation proves the complete descendant
   process tree and delegated cgroup are gone before the task is cleaned.
8. Knowledge covers Agent-owned mounts, bounded uploads, memory, indexing,
   and semantic search with revision and digest checks.
9. Core CloudControl and single Pi Cloud Worker fake-provider flows cover
   quote/confirmation, durable recovery, exact result validation, cancellation,
   and verified cleanup; provider acceptance evidence is recorded in the
   [delivery tracker](delivery-tracker.md).
10. Storage remains Agent-owned and tests prove operation without a business
    server repository or shared product database.

## Domain behavior

### Conversations and models

Model profiles are Agent-owned records with provider/model settings, prompts,
sampling limits, and a protected API-key revision. Conversations provide unary
and streaming chat. Provider-neutral model calls pass through Eino's
`ToolCallingChatModel` boundary. Background work uses a Task execution snapshot
so profile, extension, Knowledge, attachment, and secret bindings cannot drift
while a request is running.

Every Chat, StreamChat, and StartTurn request carries the exact model-profile
pin triple: `model_profile_id`, `model_profile_revision`, and
`credential_version`. All three values must be positive and match the resolved
profile exactly; there is no default-profile or partial-pin fallback. The
profile revision advances for any profile update, while the credential version
advances when API-key or provider-secret material is rotated or cleared. The
resolved snapshot, request fingerprint, durable turn, and replay receipt retain
the same pins without storing them as secret material. A stale pin fails before
provider work, while an idempotent replay returns the already-bound durable
snapshot even if the current profile has since rotated. Model-profile and
durable-turn responses project the profile revision and credential version so
the caller can pin its next request.

`agent.info.v1/list_models` is the provider catalog, separate from persisted
profile listing. It resolves either a write-only request credential or an
Agent-owned profile ID, performs a bounded provider request, and returns only
normalized non-secret model metadata. OpenRouter conversation discovery uses
the text-output filter; embedding discovery uses its dedicated embeddings
catalog endpoint.

When Web Search is enabled and configured, the conversation resolver adds one
compiled `web_search` tool. The resolver decrypts the credential only to prove
readiness; its stable selection and snapshot contain provider, config revision,
credential version, account identity, and non-secret schema/content digests,
never the key. Immediately before provider dispatch, the tool revalidates the
authenticated owner and generation, reloads the current encrypted config, and
requires exact revision and credential-version matches. Rotation, clear,
disable, generation change, or deprovision therefore fails closed before any
Tavily request. A service restart rebuilds the executable closure from the
encrypted repository.

When Knowledge is enabled, the same resolver chain adds one Agent-owned,
read-only `knowledge_search` tool for authenticated Native conversations. It
uses the existing semantic search boundary directly, accepts only a bounded
query, optional source IDs, and limit, and returns bounded passages with the
secret-free embedding provenance. Ready/promoted binding checks remain owned
by Knowledge storage; the tool does not route through Product Capability or
accept client-supplied credentials.

### Tasks and schedules

Tasks support immediate and scheduled execution, cancellation, retry as a new
idempotent Task, deletion, durable progress, and event replay. The supported
Task kinds are Agent, Extension, Conversation Tool, Knowledge indexing,
`AWS_CHANGE`, `WORKLOAD`, and `CLOUD_WORKER`. A Task is claimed with an
attempt, lease epoch, and expected revision; only the fenced owner may
checkpoint or terminalize it.
Schedules create independent Tasks for one-time or Cron occurrences. Core v1
has no priority, DAG/graph, task dependency authoring, or cluster/pool
scheduler.

Eino adapts each model round, while the Agent-owned Task ledger remains the
durable orchestrator for model dispatch, tool calls, retries, recovery, and
uncertain outcomes. Core v1 does not expose Eino graphs as a user-authored
workflow surface.

Workload Tasks use that same revision/attempt/lease-epoch fencing path. The
local runner receives only a descriptor request bound to the dispatch; it
never receives Agent credentials, raw secrets, or a database connection.

### Core Runner

Core Runner is a separate optional process reached through a protected Unix
packet socket with exact peer credentials and a v1 cryptographic nonce probe.
Readiness includes static-root validation plus a bounded real
user-namespace/tmpfs/seccomp/cgroup result-manager exercise; the
`workload.core_runner` capability remains absent when that proof fails.

Install commands export only a sealed descriptor result. Persistent services
receive zero raw host output and their sole writable area is the exact bounded
tmpfs. Before a ready receipt, supervisor intents and receipts are fsynced.
Restart reconciliation records `cleanup_required`, kills/reaps the exact
operation cgroup, proves `populated 0` and removal, then records `unknown`.
Any cleanup uncertainty blocks the runner and capability rather than
redispatching work.

### Confirmation

Confirmation is a generic durable flow for operations requiring explicit user
approval. The binding includes operation domain, target identity/revision,
source/content or parameter digests, network grants, secret grants, Task, and
expiry. Confirm/reject is revision- and idempotency-protected. MCP/Skill
installation, upgrade, removal, and execution, plus AWS mutations that create,
update, expose, spend, or destroy must pass this boundary before side effects.
Extension execution records the owner, installation kind/revision, immutable
version/manifest/execution/permission digests, selected tool/command, canonical
input digest, and secret/network grant descriptors. Execute requests create only
a durable `waiting_user` Task; exact confirmed binding consumption is the sole
transition to runnable work. If the worker is reclaimed after consumption
without an exact idempotent side-effect receipt, the Task is terminalized with
the sanitized `extension_execution_uncertain`/reconciliation-required marker;
the consumed reservation and installation execution fence remain active, so
retry and new proposals stay blocked until explicit operational reconciliation.

### MCP and Skills

Extensions are discovered from pinned sources and persisted with immutable
version, content, artifact, schema, network, and secret bindings. MCP supports
local stdio and remote HTTPS Streamable HTTP. A remote registry declaration
without required authentication has no credential reference or secret grant and
sends no Authorization header; a supported required bearer credential keeps its
write-only, version-bound secret grant. Skills use the pinned Skill artifact and
instructions. Local code runs only through the separate Linux
extension runner with another UID, namespaces, a task workspace, and explicit
secrets. No in-process or unconfirmed fallback is allowed.
The task workspace root is one runner-owned, Agent-group-writable boundary
with exact identity `65531:65532` and mode `0770`; Agent and runner deployments
mount the same volume, while extension staging remains Agent-private.

### Knowledge

Knowledge supports Agent-owned mounts, bounded uploads, memory, source status,
indexing, and semantic search. Semantic vectors and their staged/promoted
generations live in the Agent-owned PostgreSQL database through pgvector; no
external vector service or fallback is part of Core v1. Content is opened
through root-bound ports. Indexable content has one fixed aggregate quota of
64 MiB and a fixed 16 MiB maximum per source. Uploading reservations count
toward the aggregate quota. Knowledge status publishes exactly
`quota_used_bytes`, `quota_limit_bytes`, `quota_remaining_bytes`, and
`max_source_bytes`; an aggregate-quota rejection is the canonical
`knowledge_quota_exceeded` resource-exhausted failure, while parser and
single-source limits remain invalid requests.
Uploads declare one whole-content SHA-256 and size, validate each chunk's
SHA-256 and contiguous offset/ordinal, and become `ready` only after commit
rechecks the expected revision, full digest, size, and finalized content. Source
status is explicit (`uploading`, `ready`, `indexing`, `failed`, `deleting`,
`cleanup_pending`, or `deleted`) and is observable through status/list/get
projections. Task snapshots pin source revision, content digest, and index
binding; search must reject drift before context reaches the model. A
vector-search cursor snapshot also pins the secret-free embedding provenance at
page level:
`embedding_profile_id`, the model-profile `embedding_profile_revision`,
`embedding_model`, and any available `embedding_generation` and
`collection_config_digest`. Every page resumed from that cursor replays the
same provenance even if the current default embedding profile is rebound.
`agent.knowledge.v1` `get_config` and `update_config` return the same current
projection, without API keys or provider secret material.

### AWS

Typed AWS credentials, `TestCredentialIdentity` identity checks, plans, quotes,
and CloudFormation change requests are exposed through
`CoreCloudControlService`. Provider calls use typed SDK clients and durable
fencing. Confirmation is mandatory for mutating or spend/exposure operations;
model and extension tools cannot bypass it. Provider evidence is tracked in the
[delivery tracker](delivery-tracker.md).

AWS credential access still requires `core_aws_enabled`; all durable Core secret
envelopes require a raw 32-byte `core_secret_master_key_file` mounted with mode
`0400`. PostgreSQL
stores only the key version, nonce, and AES-256-GCM ciphertext; field AAD binds
the credential ID, revision, and secret field. Missing keys, wrong keys, and
version mismatches fail closed. Provider code materializes credentials only
for the request-local SDK call and never logs them.

Fake-provider lifecycle tests and source-level typed-provider checks cover
confirmation, read-back, and cleanup. Typed workload routes require their own
exact readiness blocks and lazy target probes. Generic non-Cloud-Worker
Execution V2 operations publish only when their own typed provider route is
ready, including a dedicated CloudFormation service role where that operation
requires one. The single Pi Cloud Worker route has its independent PostgreSQL,
controller, provider-ledger/Reaper, private-listener, and completion-outbox
readiness gate. The [API contract](api-contract.md) defines publication gates;
evidence and remaining verification are recorded in the
[delivery tracker](delivery-tracker.md).

### Single Pi Cloud Worker

The Native Agent remains local-first and retains its local sandbox, worker
pool, MCP, Skills, Knowledge, Conversation Tools, and Extension Runner. The
Core intrinsic `cloud_worker.propose` may create a paid offer only from a turn
whose trusted policy proves an explicit user cloud request or immutable local
budget insufficiency. A local failure is not proof and never triggers an
automatic upgrade.

The only recipe is `ephemeral-pi-task` with adapter `pi_json_task_v1`. One
confirmed execution creates exactly one EC2 instance, one Worker, and one Pi
process. Its plan binds every cost/authority field, including immutable input,
workspace mode, model and credential revisions, AWS/compute/AMI digests,
limits, grants, retention, quote expiry, and hard cost ceiling. Any drift
requires a fresh quote and CoreConfirmation.

The controller progresses the durable `CLOUD_WORKER` Task through
`waiting_user`, `queued`, `provisioning`, `awaiting_worker`, `running`,
`collecting`, `validating`, and `cleaning`. It waits for the private durable
WorkerControl session rather than running Pi itself. Success, failure, and
cancellation remain non-terminal until the Resource Ledger proves every AWS
resource `verified_destroyed`. Unknown AWS responses and reclaimed leases use
identity-bound read-back of the original dispatch; they cannot provision a
second instance.

The Worker receives no local MCP/Skill/Extension Runner state. It receives only
the exact runtime task and versioned input manifest, short-lived model relay
grant, exact artifact S3 prefix, heartbeat deadline, and approved grants.
Turn inputs use one owner/account-generation/request-bound upload authority for
images, approved ordinary code/document files, and at most one constrained
`application/vnd.dirextalk.workspace+tar+gzip` workspace archive. The Agent
validates the archive before commit and again before staging; the Worker repeats
validation while extracting into `workspace/`. Both boundaries reject links,
special files, traversal/absolute paths, path/case collisions, duplicate
entries, trailing data, excessive entries, and compressed expansion beyond
256 MiB. `read_only` removes write permission after extraction; `write` uses a
private copy and can return only centrally validated deltas/artifacts.
Workspace `write` produces a patch/archive/artifact from an isolated copy and
never writes into local files. The full contract is
[Execution V2](execution-v2.md).

## Security and data rules

- TLS 1.3 and `DTX-Agent-Token` authenticate the private gRPC boundary.
- PostgreSQL is the sole durable Agent schema authority; large files and
  artifacts live below configured Agent data roots and are referenced by
  relative path and digest.
- Third-party code receives only explicitly granted secrets and workspace
  access. Local execution uses a detached root, isolated namespaces, an empty
  environment, seccomp, and task-scoped cgroup-v2 limits. Cancellation is not
  complete until the cgroup reports `populated 0` and is removed. Isolation or
  cleanup uncertainty is a hard failure, never a fallback.
- Errors, events, logs, and ordinary API responses must not disclose secret
  values or unrestricted user/provider credentials.

## Non-goals

No REST public API, multi-user RBAC, Agent clusters or pools, task priority,
graph authoring, product adapters, or standalone admin UI is specified.
Status and release evidence are maintained in the [delivery tracker](delivery-tracker.md).
