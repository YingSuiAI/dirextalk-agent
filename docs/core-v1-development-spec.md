# Dirextalk Agent Core v1 development specification

> Source behavior for the Message Server adapter, typed workload providers, and
> isolated Compose assets is implemented at the companion integration revisions
> recorded below. Production activation and live verification remain separate
> release gates; capability advertisement stays disabled until its exact
> readiness proof is present.

This document is the current product and implementation boundary for the
independent Agent service. The versioned Protobuf in
`api/proto/dirextalk/agent/v1` and the PostgreSQL migrations are the executable
contract. A public or schema change updates this document and its contract tests
together.

Source behavior follows the `Agent Core v1 source contract`; production
activation and live verification remain separate release gates.

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
  plan, deployment, run, confirmation, artifact, service-binding, and secret
  records. Message Server remains a public action facade only; execution.v2
  data and idempotency/event history are stored in the Agent database.
- A future business-server proxy calls the Agent over TLS gRPC with one
  deployment-generated service token. The token is a protected file, not a
  database value; rotation is atomic replacement plus restart.
- Core v1 changes this repository only. Product adapters, a standalone admin
  UI, and deployment automation are outside this specification.

## Public capabilities

The Core server registers `AgentService`, `ModelProfileService`,
`ConversationService`, `TaskService`, `ScheduleService`,
`ConfirmationService`, `MCPService`, `SkillService`, `CoreKnowledgeService`,
and the optionally enabled `CoreCloudControlService`. Health and reflection
are optional server features.

All mutation RPCs follow the Protobuf's UUID idempotency and expected-revision
rules. Ordinary reads never return stored secret values. Task events and
results are durable, redacted, resumable, and fenced by lease epoch and
revision.

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

`WorkloadService` remains available for durable planning and confirmation.
Its `WORKLOAD` Task handler is registered when at least one exact target route
is available. `workload.core_runner` requires the local authenticated readiness
proof; `workload.aws_ssm` and `workload.aws_ecs` are advertised independently
only after an explicit readiness target is configured and the typed provider
graph is complete. Startup performs no AWS API calls; the first explicit
provider action proves STS/account binding plus exact target prerequisites.
Missing or stale readiness configuration keeps the capability disabled; there
is no implicit default target or broad scan. Per-operation credential, ARN,
and target checks remain a second fence.

## Acceptance scenarios

The Core v1 acceptance set covers these ten observable scenarios:

1. TLS gRPC authenticates with the protected token file; atomic token
   replacement takes effect after restart.
2. Model profiles and model execution cover the OpenAI-compatible, Anthropic,
   and Gemini providers.
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
9. AWS fake-provider flows cover confirmation, durable recovery, and confirmed
   destroy operations; authorized real-provider lifecycle evidence is recorded
   in the AWS section below.
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

### Tasks and schedules

Tasks support immediate and scheduled execution, cancellation, retry as a new
idempotent Task, deletion, durable progress, and event replay. The supported
Task kinds are Agent, Extension, Knowledge indexing, and AWS change. A Task is
claimed with an attempt, lease epoch, and expected revision; only the fenced
owner may checkpoint or terminalize it. Schedules create independent Tasks
for one-time or Cron occurrences. Core v1 has no priority, DAG/graph, task
dependency authoring, or cluster/pool scheduler.

Eino adapts each model round, while the Agent-owned Task ledger remains the
durable orchestrator for model dispatch, tool calls, retries, recovery, and
uncertain outcomes. Core v1 does not expose Eino graphs as a user-authored
workflow surface.

Workload Tasks use that same revision/attempt/lease-epoch fencing path. The
local runner receives only a descriptor request bound to the dispatch; it
never receives Agent credentials, raw secrets, or a database connection.

### Core Runner

The optional local Core Runner runs as a distinct non-root UID (`65530` in the
Compose example; Agent UID `65532`). It uses a protected Unix packet socket,
exact peer credentials, and a v1 cryptographic nonce probe. Readiness includes
static-root validation plus a bounded real user-namespace/tmpfs/seccomp/cgroup
result-manager exercise; the capability remains absent when that proof fails.

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
local stdio and remote HTTPS Streamable HTTP; Skills use the pinned Skill
artifact and instructions. Local code runs only through the separate Linux
extension runner with another UID, namespaces, a task workspace, and explicit
secrets. No in-process or unconfirmed fallback is allowed.

### Knowledge

Knowledge supports Agent-owned mounts, bounded uploads, memory, source status,
indexing, and semantic search. Content is opened through root-bound ports.
Task snapshots pin source revision, content digest, and index binding; search
must reject drift before context reaches the model. A vector-search cursor
snapshot also pins the secret-free embedding provenance at page level:
`embedding_profile_id`, the model-profile `embedding_profile_revision`,
`embedding_model`, and any available `embedding_generation` and
`collection_config_digest`. Every page resumed from that cursor replays the
same provenance even if the current default embedding profile is rebound.
`agent.knowledge.v1` `get_config` and `update_config` return the same current
projection, without API keys or provider secret material.

### AWS

Typed AWS credentials, `TestCredentialIdentity` identity checks, plans, quotes,
and change requests are exposed through `CoreCloudControlService`. Provider calls use typed SDK clients
and durable fencing. Confirmation is mandatory for mutating or spend/exposure
operations; model and extension tools cannot bypass it.

AWS credential access still requires `core_aws_enabled`; all durable Core secret
envelopes require a raw 32-byte `core_secret_master_key_file` mounted with mode
`0400`. PostgreSQL
stores only the key version, nonce, and AES-256-GCM ciphertext; field AAD binds
the credential ID, revision, and secret field. Missing keys, wrong keys, and
version mismatches fail closed. Provider code materializes credentials only
for the request-local SDK call and never logs them.

Fake-provider lifecycle tests and source-level typed-provider checks cover
confirmation, read-back, and cleanup. No live AWS workload lifecycle is claimed
by this document; a real run requires an explicitly configured target, owner
confirmation, independent read-back, and a zero-residue audit.

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
No behavior is promised beyond the current Protobuf, Core composition, and
focused tests.

Two isolated Compose projects, real DeepSeek conversation, extension
installation/execution, and live AWS workload acceptance are release evidence
gates rather than fabricated production-readiness claims. Until those gates are
completed against the configured targets, Core Runner and AWS capabilities stay
disabled by readiness policy.
