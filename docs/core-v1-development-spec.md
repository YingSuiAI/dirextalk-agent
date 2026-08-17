# Dirextalk Agent Core v1 development specification

> This document freezes the Agent-owned product and implementation boundary at
> HEAD. Message Server owns login/account control, short-lived session-ticket
> issuance, and Product Capability callbacks; Flutter uses the same-origin
> Agent HTTP data plane. Production activation and live verification remain separate gates;
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
  is no Execution V2 confirmation shadow or Message Server action facade;
  execution data and idempotency/event history are stored in the Agent database.
- Message Server calls Agent Core over TLS gRPC/Capability mTLS with
  deployment-generated protected credentials and account-generation fences. The
  Agent-to-Message-Server Product Capability callback is a separate direction;
  neither side shares the other's database or execution history.
- Flutter obtains an owner-authenticated short-lived ticket from Message Server
  and sends Native Agent data requests directly through `/agent/v1/*`. Online Agent remains the real private
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

The Agent also publishes `agent.text_tools.v1` only through the authenticated
owner-client Capability surface. PostgreSQL owns its full-list configuration
and configuration-mutation replay; executions create no text-tool,
conversation, history, or Task rows. The shared Capability ledger still keeps
its normal bounded result receipt (but discards selected-text request JSON),
and restart recovery fences an interrupted call uncertain without replay. The
four stable built-ins have server-side prompts, while canonical UUID items are
model-only transforms. Every execution carries the current UI output language
(`zh` or `en`); built-ins answer in that language and translation uses it as
the exact target instead of inferring a language from context. Search defaults
disabled, and enabling it together with
the global text-tool configuration requires an already enabled Tavily
configuration with a valid server-side credential. Execution rechecks and
reuses that encrypted Web Search snapshot and dispatch fence, so later
disablement or credential removal fails closed. The typed
`core_text_tool.proto` messages are DTO
schema authority only: no Core gRPC service is registered because that
listener does not carry authenticated owner/account-generation context.

Image extraction and image-text translation use the independent
`agent.image_tools.v1` owner-client Capability. Its dedicated ephemeral upload
store shares the 8 MiB/1 MiB/30-minute mature attachment bounds but never
creates or reuses a chat source. Consume is atomic and one-way, clears stored
bytes, and binds exact owner, generation, image request, source, and revision.
Execution is enabled only by the text-tool global switch and an explicit,
credentialed conversation Tool profile whose input modalities include image.
The provider-neutral typed in-memory image part is the only model input path;
URLs, paths, data URIs, arbitrary prompts, Tavily, and configurable text-tool
items are not accepted by this surface.

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
7. Skill lifecycle covers the `dirextalk-research-and-verify`,
   `dirextalk-review-code`, `dirextalk-verify-delivery`, and
   `dirextalk-write-technical-docs` built-ins plus skills.sh and GitHub pins; execution is isolated in
   the extension runner, and cancellation proves the complete descendant
   process tree and delegated cgroup are gone before the task is cleaned.
8. Knowledge covers Agent-owned mounts, bounded uploads, indexing,
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
while a request is running. Agent and Cloud Worker task creation rejects
non-conversation profiles, and execution verifies the exact protected-secret
reference plus the digest of every snapshotted provider parameter.
For OpenAI-compatible profiles, a bare HTTPS origin normalizes once to `/v1`;
an explicit gateway path remains exact. Model discovery and completion append
their operation paths to that same normalized root.

Profile sync durably stores separate conversation, tool, embedding, and speech
role defaults. The tool role references only a conversation-kind profile and
has no implicit conversation-default fallback; an absent tool binding remains
absent. The Protobuf and `agent.models.v1` Capability contracts project the
profile kind/modalities and all role defaults without credential material.
Historical conversations and Tasks retain immutable model snapshots, so their
profile references do not block a later profile update or deletion. Deletion
tombstones every model kind, clears its live client id and credentials, and
preserves the profile row plus revision secrets for history and replay. A
nondeleted schedule or active Knowledge generation remains a future consumer
and rejects deletion until it is removed. Schedule create/update transactions
hold a shared lock on the nondeleted profile through schedule/reference commit.
Knowledge indexing creates its generation reference in the `RequestIndex`
transaction and retires that job-owned reference only in the matching
success, failure, or cancellation transaction; successful promotion replaces
it with the source-owned generation reference.

Every Chat, StreamChat, and StartTurn request carries the exact model-profile
pin triple: `model_profile_id`, `model_profile_revision`, and
`credential_version`. All three values must be positive and match the resolved
profile exactly; there is no default-profile or partial-pin fallback. The
profile revision advances for any profile update, while the credential version
advances when API-key or provider-secret material is rotated or cleared. A
reconnect sync that submits the same effective profile and credential material
with the current revision fence preserves the revision. The
resolved snapshot, request fingerprint, durable turn, and replay receipt retain
the same pins without storing them as secret material. A stale pin fails before
provider work, while an idempotent replay returns the already-bound durable
snapshot even if the current profile has since rotated. Model-profile and
durable-turn responses project the profile revision and credential version so
the caller can pin its next request.

Provider tool requests keep the Agent-owned schema authoritative. Gemini
receives only fields declared by its documented `Schema` contract; unsupported
JSON Schema keywords are removed, while string `const` choices are projected
to the supported enum form. Agent still validates the original complete schema
when a tool executes. Provider-issued tool-call IDs remain authoritative;
Gemini calls without an ID receive a transcript-unique generated ID, and
adjacent Anthropic tool results are sent as one ordered user content-block
batch.

Streaming adapters parse full SSE events with CRLF support, comment and
non-`data` field elision, and ordered joining of multiple `data` fields before
provider JSON decoding. Provider failure types distinguish cancellation,
request and idle timeouts, rate limiting, other 4xx rejection, 5xx failure,
transport unavailability, invalid responses, truncation, and output limits.
Only safe classes cross the conversation boundary: 4xx is
`provider_rejected`, timeout is `provider_timeout`, and otherwise uncertain
dispatch remains `provider_uncertain` without automatic replay.

An accepted or running durable turn may receive revision-fenced same-turn
guidance. A confirmation-waiting turn also accepts guidance after its Cloud
Worker task is queued or running. Before a tool call becomes public, Core
invalidates and cancels the active provider lease and regenerates the same turn.
After a tool call is public or dispatched, Core preserves that authority and
lease and waits for its result. Ordinary tools then give the next model round
both the result and ordered guidance. The current SSH Worker text protocol
cannot inject guidance into an already running remote process. When its
terminal result has unapplied deferred guidance, Core resumes one normal model
round in the same durable turn with both the Worker result and that guidance;
the model may answer or reuse the retained Worker. No successor turn is
created.

`agent.info.v1/list_models` is the provider catalog, separate from persisted
profile listing. It resolves either a write-only request credential or an
Agent-owned profile ID, performs a bounded provider request, and returns only
normalized non-secret model metadata. OpenRouter conversation discovery uses
the text-output filter; embedding discovery uses its dedicated embeddings
catalog endpoint. Its positive `max_completion_tokens`, including the nested
`top_provider` value, is projected into the closed public catalog so clients
can select the advertised output budget. A resolved profile supplies only its
provider credential and origin; the requested catalog kind is independent, so
an existing OpenRouter conversation profile can bootstrap embedding discovery
before an embedding profile exists.

When Web Search is enabled and configured, the conversation resolver adds one
compiled `web_search` tool. The resolver decrypts the credential only to prove
readiness; its stable selection and snapshot contain provider, config revision,
credential version, account identity, and non-secret schema/content digests,
never the key. Immediately before provider dispatch, the tool revalidates the
authenticated owner and generation, reloads the current encrypted config, and
requires exact revision and credential-version matches. Rotation, clear,
disable, generation change, or deprovision therefore fails closed before any
Tavily request. A service restart rebuilds the executable closure from the
encrypted repository. Its model-facing contract requests one focused search
with enough results, permits another only for a distinct missing fact, and
directs the model to synthesize sufficient evidence instead of repeating
equivalent searches for exhaustive confirmation.
The conversation runtime detects only exact action/result repetition and exact
A/B alternation in the recent ordered tool history since the latest steer.
Canonical action identity ignores call identity and argument key order, while
normalized result identity ignores transport call IDs and timestamps. Three
identical pairs or six A/B pairs add a brief correction while preserving every
accepted extension and intrinsic. Only a fourth identical pair or eighth A/B
pair makes the next model request a one-pass, tool-free synthesis from all
durable evidence, with remaining gaps stated explicitly. Different arguments
or results are productive progress and never trigger this recovery.
The recovery is subordinate to the turn-wide maximum of 20 accepted tool calls.
At the limit, Core removes all extension and intrinsic tools for one synthesis
request; a returned batch that would exceed the limit fails durably as
`tool_budget_exhausted` before any excess call is dispatched.

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
Executable Extension and Conversation Tool Tasks seal one closed execution
target into their durable payload when they are created: `local_sandbox` for
stdio MCPs and executable Skills, `remote_extension` for remote MCP calls, or
`static_skill` for non-executable Skill reads. Claiming never reclassifies a
Task from mutable installation/version projections. The current fixed local
sandbox capacity is three slots, shared by the durable claim lane and Extension
Runner rather than exposed as another Task or YAML setting. At most three
unexpired `local_sandbox` Tasks may run at a time; additional local work remains
queued, while remote calls, static Skill reads, and unrelated Task kinds remain
claimable. An expired local lease is reclaimable through the normal durable
lease epoch path after restart.
Schedules create independent Tasks for one-time or Cron occurrences. Core v1
has no priority, DAG/graph, task dependency authoring, or cluster/pool
scheduler.

Natural-language Native turns create schedules only through the Core-owned
`agent_schedule_create` intrinsic. The model supplies the bounded schedule
intent and trigger; Core binds the authenticated owner/account generation,
current conversation, and pinned model profile from the durable turn lease.
The schedule template persists exactly the typed `payload.agent` owner and
positive generation authority in addition to its conversation/profile fields;
it contains no credential or arbitrary reference fields.
The PostgreSQL boundary atomically commits the schedule, idempotency replay,
turn response/event, and transcript, so recovery cannot expose either a
schedule without its conversation receipt or a receipt without its schedule.
The intrinsic accepts a renewed epoch of the same active turn lease and commits
under that current epoch. Invalid model-supplied intrinsic arguments are stored
as an error tool result for correction in the next model round rather than
discarding the turn. A known intrinsic call with valid bounded identity but
malformed arguments is normalized to the same correctable result; malformed
identity, unknown tools, oversize input, and external extension calls remain
terminal. While the latest completed intrinsic result is the
dedicated invalid-arguments correction for `static_site_publish`, the next
provider request forces that named tool through the provider-native tool-choice
field; the force survives partial-output continuation and clears after the next
non-correction intrinsic result.

Single-page static publication uses the Core-owned `static_site_publish`
intrinsic. One HTML file is published directly and is not wrapped in an
archive. Core derives all filesystem and URL identity, writes through a
same-filesystem staging directory, fsyncs and atomically renames the release,
then commits the verified SHA-256/size receipt and turn terminal state in one
PostgreSQL transaction. Releases are immutable and replay-safe at
`/.sites/{site_id}/{release_id}/`; the terminal response uses the configured
node HTTPS origin to return an absolute URL. The Agent owns the host root; the edge sees
only `public/` read-only. The current embedded design skill produces
responsive semantic HTML with inline CSS only. JavaScript, forms, external
assets, network requests, and multi-file bundles are not part of the current
contract.

The authenticated owner manages those same releases through
`agent.static_sites.v1/list_releases` and `delete_release`. List returns the
server-produced absolute public URL and receipt fields only. Delete accepts one
release UUID plus an idempotency UUID and derives the exact filesystem identity
from the owner/account-generation receipt. Public downloads continue to use
the release URL; there is no duplicate byte-download capability.

Eino adapts each model round, while the current conversation turn store owns
dispatch admission, persisted results, recovery, and uncertain outcomes. A
Native conversation turn retains a 24-dispatch, 20-minute cumulative
model-active fuse; tool, Worker, and confirmation execution or waiting do not
consume that clock. Exhaustion is a
durable `model_budget_exhausted` terminal outcome. Other background Tasks keep
their own execution deadline/context. The nonnegative round ordinal remains
the current replay identity. Core v1 does not expose Eino graphs as a
user-authored workflow surface.

A provider-declared output limit is a completed fragment, not an unknown
transport outcome. Core persists its streamed text and reasoning, releases the
model round, and reconstructs that fragment from ordered turn events before
continuing with the same frozen context and complete accepted tool catalog,
including after restart. A partial tool call from the limited fragment is not
published or executed; the continuation may issue a fresh complete call.

A durable model round may return multiple tool calls. Core persists the exact
model result once and processes calls in producer order, retaining that batch
across read-only execution, confirmation pauses, restart, and retry. Built-in
and remote calls do not consume a local-sandbox lane; executable local calls
enter the existing durable Task lane and are admitted only by its configured
concurrency limit. A model round is released for the next provider dispatch
only after every call in the retained batch has a durable result. A read-only
tool execution error is recorded as an error result for the next model round,
so invalid arguments or a provider failure do not discard the conversation.
The next model request replays that round as one assistant message with its
content, reasoning, and complete call batch, followed by one result message per
call in producer order.
Immediate read-only dispatch uses a compact private pending/dispatched/terminal
authority inside the current versioned turn-dispatch envelope; it never consumes
or leaks a public conversation event sequence. Public history contains only the
exact tool call and terminal result. This is a current-only envelope: rollout
must first prove there are no nonterminal turns carrying the superseded raw
model-result shape, or explicitly terminalize those turns before the new binary
may claim them.

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
write-only, version-bound secret grant. A Skill selected for a Native
conversation resolves its exact pinned `SKILL.md` once at turn admission and
enters the model as one instruction block without inventing a tool. Skills use
the same pinned artifact reader as durable Tasks. Local code runs only through the separate Linux
extension runner with another UID, namespaces, a task workspace, and explicit
secrets. No in-process or unconfirmed fallback is allowed.
Four Dirextalk-owned general Skills are bundled as a network-free `builtin`
source and seeded once as ordinary installed extensions: research and
verification, code review, technical documentation, and delivery verification.
The durable seed survives uninstall, so restart never silently reinstalls a
Skill the owner removed; reinstall uses the same discover, inspect,
confirmation, and lifecycle path as skills.sh or GitHub. Built-ins have no
network or secret grants and contain no executable entry.
Two Dirextalk-owned read-only MCP servers are bundled separately and seeded
once as ordinary installed extensions. `dirextalk-server-time` reads the UTC
server clock and `dirextalk-server-load` reads kernel load, uptime, process,
and memory totals. They have no network or secret grants and execute only
through the isolated extension runner; their seed fence survives uninstall.
Managed Node MCP uses the explicit `stdio_node` transport and only `npm` exact
package versions plus verified integrity, or GitHub exact commits. Source
inspection binds the immutable lock/tarball input; a network-disabled offline
builder and the lock-only resolver both disable lifecycle script execution,
while preserving script declarations in the immutable source, and the builder
rejects native add-ons. Only
its digest- and generation-fenced receipt may be promoted. There may be at
most 32 non-failed/non-removed extensions, one active install/update lifecycle,
64 MiB per expanded Node artifact, 8,192 files per artifact, and 512 MiB across
published Node artifacts. The installed public receipt exposes only package,
version, byte/file counts, fixed Node/npm versions, the scripts-disabled fact,
and the native-absence fact; prepared paths, cleanup tokens, and internal
digests remain private.
The production runner admits three one-shot executions at a time. A verified
capacity receipt fails with `local_resource_busy`; a verified fixed-limit,
timeout, CPU, or output receipt fails with `local_resource_exhausted`. Both use
sanitized summaries that ask the user to retry later or explicitly authorize a
Cloud Worker, and neither route automatically starts paid cloud execution. A
missing terminal runner receipt remains `extension_execution_uncertain` and
keeps the existing reconciliation fence.
The task workspace root is one runner-owned, Agent-group-writable boundary
with exact identity `65531:65532` and mode `0770`; Agent and runner deployments
mount the same volume, while extension staging remains Agent-private.

### Knowledge

Knowledge supports Agent-owned mounts, bounded uploads, source status,
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
Clearing the default embedding profile disables semantic search, cancels and
fences in-flight indexing, and removes promoted vectors while preserving source
documents. A later embedding binding automatically reconciles those
ready, unindexed sources without a migration or content fallback.

Conversation memory is a separate two-layer projection. Working memory is the
existing bounded conversation summary and recent transcript. Compaction is
monotonic: it adds only newly overflowed messages to the prior summary, and the
model receives that summary as delimited user-role history rather than a system
instruction. After a chat
commit, a transactionally enqueued observation is consolidated into
Agent-owned structured user facts and an append-only fact timeline. The active
`subject + predicate` row is the current truth projection; a changed value
atomically closes and supersedes the prior row instead of deleting history.
Automatic conversation memory is disabled by default. The owner may enable it
only after Knowledge has a live embedding profile with a configured credential;
the store rechecks that prerequisite in the update transaction. Disabling it
stops observation capture, consolidation, structured-fact recall, and timeline
recall while preserving facts, observations, history, Knowledge content, and
conversation history. Removing the active embedding binding atomically turns
automatic memory off, so a later model binding never silently opts the owner
back in. Owner-client `agent.memory.v1` operations expose config, revision,
embedding readiness/model identity, bounded current facts, the append-only
timeline, pending/failed observation counters, and exact-fact update/delete
mutations without secret material. Updates create an active replacement and
preserve the fact key and kind; deletes retract the selected active fact. The
immutable fact ID is the stale-write fence and UUID idempotency keys make
retries durable. Knowledge source CRUD is not a second memory surface.
Per-turn recall ranks current facts against the prompt, then adds a bounded
recent timeline. This internal
projection does not create another public action envelope or make Message
Server an Agent-memory database.

### AWS

`CoreCloudControlService` owns the sole App-managed AWS credential. The neutral
AWS Capability adds revision-fenced idempotent STS identity checks. Worker
selection, live pricing, EC2 lifecycle, and Route53 remain behind the Cloud
Worker domain rather than a generic AWS resource graph. Confirmation is
mandatory for Worker spend or exposure operations; model and extension tools
cannot bypass it.

AWS credential access is always composed so the sole App-uploaded credential
can immediately publish Worker readiness. All durable Core secret envelopes
require a raw 32-byte `core_secret_master_key_file` mounted with mode `0400`. PostgreSQL
stores only the key version, nonce, and AES-256-GCM ciphertext; field AAD binds
the credential ID, revision, and secret field. Missing keys, wrong keys, and
version mismatches fail closed. Provider code materializes credentials only
for the request-local SDK call and never logs them.

Cloud Worker readiness is independent of deploy-time infrastructure. It is
derived at request time from the durable Task/confirmation stores, local
artifact repository, persistent SSH Worker manager, and the sole active
App-uploaded AWS credential. The [API contract](api-contract.md) defines
publication gates; evidence and remaining verification are recorded in the
[delivery tracker](delivery-tracker.md).

### Persistent SSH Cloud Worker

The Native Agent remains local-first and retains its local sandbox, worker
pool, MCP, Skills, Knowledge, Conversation Tools, and Extension Runner. The
Core intrinsic `cloud_worker_propose` creates an offer when the user explicitly
requests cloud work or trusted scheduler evidence shows that the selected
substantial task exceeds the local runtime. Model wording and a local failure
are not authority. A cloud or local-only veto wins. The intrinsic requires an
explicit `execute` or `proposal_only` intent. Proposal-only returns a durable
non-executing summary without pricing, offer, Task, confirmation, or execution
state, so an idle retained Worker cannot turn a planning-only request into work.
Available specialized tools remain the first choice: lightweight web research,
small local transformations, and static HTML publication compose locally and
do not justify a Worker offer merely because the overall request uses network
research or produces a file.

After a successful Web Search, ordinary lightweight research, summary, report,
and static-page work synthesizes the available evidence and states any gaps;
completeness, exactness, freshness, or fetching the same research through a
different path does not by itself authorize Worker escalation. Repository
cloning, builds, deployments, services, and other required execution or network
behavior unavailable through specialized tools remain eligible for Worker use.

A proposal carries provider-neutral minimum vCPU, memory, disk, and estimated
runtime requirements. Agent intersects current-generation x86_64 on-demand
products with the Region's actual EC2 offerings and selects the cheapest shape
that satisfies them. The plan and confirmation expose that exact shape and its
live hourly compute price. Bounded jobs also expose their estimated cost and
maximum authorized cost; persistent services do not present a finite task cost
or cost ceiling for their open-ended lifetime.

A proposal atomically creates the plan, execution, `CLOUD_WORKER` Task and
`CoreConfirmation`. Creating a Worker requires a fresh EC2/EBS price read and
confirmation of that exact quote before any AWS mutation. Confirmation of the
current unexpired offer authorizes the first AWS write directly; there is no
second quote or confirmation step. Reusing a sufficiently large idle retained
Worker performs no creation mutation and needs no new creation confirmation.
The live inventory is read only through the static `cloud_worker_inventory`
intrinsic, whose definition contains no Worker identity or state. Execution
revalidates the turn owner/account generation and returns a bounded ordinary
`ToolResult`; Core records it in ordinary tool history without terminally
committing the turn, so the next model round can use the current instance type,
vCPU, memory, disk, status, load, pricing, and workload summary. The model
declares the task's actual minimums and prefers an adequate idle Worker without
inflating or reducing those requirements. The same direct reuse applies
to persistent services and hostname publication. A live hourly read still
reports its ongoing server cost.
Destroying a retained Worker is a separate explicit owner action available
from both the owner client and the Native Agent conversation. The conversation
flow first reads the current owner-scoped retained Worker IDs and passes the
exact returned UUID to the static destroy tool. Provider identity is resolved
only from Agent storage at execution time.

The manager keeps at most five Workers for the authenticated owner/account
generation. It discovers the newest Canonical official Ubuntu 24.04 LTS image
and the default VPC/subnet, launches an instance with an ordinary public IPv4, and
connects by outbound SSH. Agent uses short SSH operations to start work, read
status and load, stream logs by offset, and list or copy artifacts. A dropped
connection does not erase remote state. Job and service workloads share this
protocol, and a service may remain running across conversation turns.
The first accepted SSH host key is retained beside the Worker private key in an
owner-owned 0600 `known_hosts` file; subsequent status, execution, and
observation connections use that same pin, and key deletion removes both.
The existing Task event stream and originating turn `worker_status` event
report environment preparation, Worker selection/provisioning, connection,
remote execution (including periodic durable updates while it remains
running), result collection, and service verification before the
terminal event. The turn event keeps coarse status as authority and carries
only an optional phase enum for client localization. Remote finite execution runs
inside a task-named systemd scope; timeout cancellation stops that scope so
session-changing descendants cannot continue after the task is terminal.

Worker results are copied into the Agent-owned local artifact repository and
returned to the original durable turn. Finite execution persists
`RemoteCompleted` after observing remote completion and before collecting the
result. A transient collection failure leaves the execution running and the
Worker busy; restart recovery uses `CollectOnly` and cannot start that workload
again. Deterministic invalid or oversized results fail the execution and
release the Worker. That persisted `TaskFailed` result remains terminal on a
same-ID retry: retry performs no SSH work and may only reconcile the
authority-, credential-, Worker-, and execution-fenced release bookkeeping.
The configured result-byte ceiling is shared by logs and all artifacts rather
than applied independently to each. When an executing
user-requested service plan includes
a user-requested hostname, the application listens on its unused internal
localhost port while the active runtime installs the Ubuntu Caddy package and
publishes one managed per-workload reverse proxy with exact-host on-demand TLS.
Certificate issuance therefore starts only on the first HTTPS handshake after
host-owned DNS read-back. Agent opens only ports 80 and 443, then uses the same
App-uploaded credential to find
the longest matching public Route53 hosted zone and UPSERT an A record to the
Worker public IPv4. New Worker creation confirmation also covers the hostname;
retained Worker reuse publishes it directly without another confirmation. Agent reports HTTPS ready only after a
bounded public health probe succeeds. If no matching zone is available,
service deployment still succeeds and the result returns the public IPv4 plus
manual A-record instructions. DNS-only post-deployment binding is not exposed.
Route53 is not required for Worker creation or ordinary execution. There is no EIP, custom AMI, S3/KMS artifact
path, WorkerControl listener, model relay, or deploy-time Worker binding. The
complete read, cancellation, event, artifact, and management contract is
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

No multi-user RBAC, Agent clusters or pools, task priority,
graph authoring, product adapters, or standalone admin UI is specified.
Status and release evidence are maintained in the [delivery tracker](delivery-tracker.md).
