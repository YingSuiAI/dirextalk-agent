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
contract for private gRPC and durable storage. The owner-facing HTTP/session/SSE
wire authority is the generated Agent Data Plane V2 contract pinned from
`dirextalk-capability-api v1.2.0`; the shared conformance vectors replace local
fixture copies. A public or schema change updates this document and its contract
tests together.

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
Conversation profiles also persist an explicit versioned request dialect.
`openai_compatible_chat_v1` retains the compatible `max_tokens` projection,
while `openai_reasoning_chat_v1` uses `max_completion_tokens` and rejects
temperature or top-p sampling. `deepseek_dsml_v4` sends the same compatible
request shape but strictly normalizes a complete DeepSeek V4 DSML response to
provider-neutral tool calls. Native structured calls take precedence; prose,
unknown tools, malformed envelopes, and invalid arguments are never promoted
to executable calls. Anthropic and Gemini use
`anthropic_messages_2023_06` and `gemini_generate_content_v1beta` respectively;
the runtime never infers a dialect from a model name.
Create, update, and sync admission require that dialect explicitly; only
already-persisted rows may pass through the current-wire normalization used by
storage loading and migration.

Model connection testing keeps reachability and structured-tool compatibility
as separate verdicts. Existing tests remain a bounded authenticated discovery
request. A caller may explicitly request the potentially billable compatibility
handshake, which uses one synthetic, non-executable function to verify a forced
non-streaming call, a forced streaming call, and tool-result continuation. The
Agent validates returned calls only in memory and never routes them through a
tool resolver. Deterministic protocol failures are `incompatible`; transient
transport, timeout, rate-limit, and provider failures are `inconclusive`.
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

Chat, StreamChat, and StartTurn have one durable execution owner. Chat adapts
its request into StartTurn and waits for the authoritative terminal response;
StreamChat adapts the same request and projects the persisted Turn event ledger
in sequence order, including confirmation, Cloud Worker, and steer lifecycle
events. The former Chat ledger/model/tool executor is not retained. Once
admission succeeds, canceling a caller context detaches only that waiter or
stream; durable cancellation remains an explicit CancelTurn mutation.

The Native model envelope starts with one fixed platform-policy compiler. Its
highest-priority policy precedes the selected profile, which is encoded as the
single subordinate JSON field `profile_specialization`; admission, frozen
runtime validation, restart recovery, and execution must produce byte-identical
compiled text. Model-facing copies of every executable tool append one
canonical untrusted-content/stop-retry-finalization suffix. Intrinsic copies
append the additional final-call-in-round suffix after it. Normalization strips
copied canonical sentences from untrusted source descriptions before appending
the authoritative suffixes, while preserving the source catalog, name, schema,
order, and forced-tool identity. The automatic context estimator uses those
same copies so admission cannot undercharge provider input.

Intrinsic ordering is validated before any call in the provider batch can
cross an execution boundary. When an intrinsic is not last, Core durably
records the whole batch and closed invalid observations for every call without
executing an intrinsic, extension, MCP, search, or mutation. The offending
intrinsic alone consumes the existing one-correction ledger. Recovery may then
run one corrected intrinsic-only call and its atomic commit; a repeated
violation enters the existing terminal-tool finalization ledger and performs
one tools-disabled Markdown synthesis. No parallel retry state or compatibility
path exists.

Terminal execution calls one injectable `ConvergenceObserver` at most once per
root supervisor/execution invocation. Core retains no permanent per-Service
turn map; the default observer emits the structured `conversation turn
convergence` log with durable `turn_id` for downstream cross-restart
deduplication, rebuilt from the terminal Turn, event history, and finalization
intent. It contains duration/deadline class, useful-Markdown and
runtime-compatibility flags, model-dispatch/tool-call/directive/repeat counts,
finalization reason, fallback and recall-degraded flags, and durable Worker
inventory-poll count. Exactly one directive is persisted per physical model
dispatch. The projection contains no prompt, response body, tool arguments,
provider reasoning, runtime envelope, or secret.

Provider tool requests keep the Agent-owned schema authoritative. Gemini
receives only fields declared by its documented `Schema` contract; unsupported
JSON Schema keywords are removed, while string `const` choices are projected
to the supported enum form. Agent still validates the original complete schema
when a tool executes. Provider-issued tool-call IDs remain authoritative;
Gemini calls without an ID receive a transcript-unique generated ID, and
adjacent Anthropic tool results are sent as one ordered user content-block
batch.

Every durable, model-visible tool result is an explicit
`dirextalk.tool-observation/v1` observation. Its closed outcome is one of
`success`, `partial`, `not_found`, `invalid`, `auth`, `user_input`,
`retryable`, `fatal`, or `unknown_mutation`; the same record carries bounded
retry/correction counters, mutation state, summary, references, and cursor.
Core never infers an observation outcome from legacy content or `is_error`.
The immediate-tool supervisor retries only an explicitly `retryable`,
authoritative read-only dispatch, once, under the same call fence. It admits at
most 30 seconds of producer-requested retry delay, preserves any retry already
consumed by the producer, and does not consume the retry when its context is
canceled during that delay. It admits one model argument correction after
`invalid`; exhausted correction/retry,
authorization, user-input, fatal, and unknown-mutation outcomes persist a
terminal tool finalization intent and remove tools from the final synthesis.
An accepted same-turn steer starts a new supervisor window. Mutating Task
failures without an immutable no-mutation receipt are always
`unknown_mutation` and are never replayed blindly. The one narrower exception
is unapplied user guidance deferred while a Cloud Worker call was active: after
that Worker fails, Core may dispatch one forced `cloud_worker_propose` follow-up
with every extension and other intrinsic removed; the fatal outcome never
restores the turn's general tool authority.

Streaming adapters parse full SSE events with CRLF support, comment and
non-`data` field elision, and ordered joining of multiple `data` fields before
provider JSON decoding. Provider failure types distinguish cancellation,
request and idle timeouts, rate limiting, other 4xx rejection, 5xx failure,
transport unavailability, invalid responses, truncation, and output limits.
Only safe classes cross the conversation boundary: 4xx is
`provider_rejected`, timeout is `provider_timeout`, and otherwise uncertain
dispatch remains `provider_uncertain`. Before any nonempty provider payload,
one physical retry is allowed only for 408, 429, 502, 503, 504, or a confirmed
dial failure. Provider reasoning and incomplete tool-call fragments count as
nonempty payload for this no-replay boundary even though neither is a
meaningful action. `Retry-After` seconds and HTTP dates are honored up to 30
seconds; other transport failures and all post-payload failures are never
replayed. Once ordinary provider work stops because of one of these
classifications, invalid or empty terminal output, no-progress tool use, or an
ordinary model/tool budget, Core persists a versioned finalization intent. The
intent admits one separate tools-disabled provider attempt with a two-minute
deadline, plus only the single quarantined-format recovery described below.
It does not consume the ordinary active-time budget. A
provider dispatch already started under that intent is never replayed after
restart.

An accepted or running durable turn may receive revision-fenced same-turn
guidance. A confirmation-waiting turn also accepts guidance after its Cloud
Worker task is queued or running. Before a tool call becomes public, Core
invalidates and cancels the active provider lease and regenerates the same turn.
After a tool call is public or dispatched, Core preserves that authority and
lease and waits for its result. Ordinary tools then give the next model round
both the result and ordered guidance. The current SSH Worker text protocol
cannot inject guidance into an already running remote process. Worker terminal
stdout is internal evidence rather than a user deliverable. Without later
guidance, Core performs one tools-disabled model synthesis instead of copying
that report into the response; with unapplied deferred guidance, Core resumes
one normal model round in the same durable turn with both the Worker result and
that guidance, and the model may answer or reuse the retained Worker. Either
response uses the latest user message's language unless explicitly requested
otherwise. No successor turn is created.

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
The model receives a bounded normalized evidence projection with canonical
source URLs and retained reference identity, not raw provider JSON, HTML, or
presentation fragments. Its final response synthesizes concise natural-language
Markdown with descriptive linked citations and never dumps raw search snippets
or meaningless separator markup. `web_source` references, canonical URL
identity, evidence digests, fetched bodies, and snippets remain private model
evidence. Terminal public messages omit the separate Web reference list and
expose sources only through descriptive Markdown links in the answer body.
At each immediate or deferred tool-result transaction, the runtime derives a
versioned `ProgressObservation` when the result carries validated runtime
references. Its effective digest covers the normalized action, bounded result,
artifact/workspace changes, external receipts/resource state, error class, and
completed step while excluding call IDs, model-authored argument wrappers,
timestamps, and reference presentation fields. The third consecutive equal
digest since the latest steer atomically records the result and terminates the
turn as `AGENT_STALLED_NO_PROGRESS`; restart and lease transfer preserve that
window, and a durable steer starts a new one. A changed artifact digest,
resource revision/status/state, or receipt identity resets the count.
Tools without a structured runtime observation retain the conservative exact
action/result and A/B fallback. Three identical pairs or six A/B pairs add a
brief correction with tools intact; a fourth identical pair or eighth A/B pair
makes the next request a one-pass, tool-free synthesis from durable evidence.
The recovery is subordinate to the turn-wide maximum of 48 accepted tool calls.
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
Every execution error has a durable client-visible outcome. Generic Agent and
tool Tasks re-read the exact task/attempt/lease owner and retry only their
terminal compare-and-swap when a concurrent progress event advanced the
revision; tool or provider execution itself is never repeated by that repair.
Domain-owned handlers commit their terminal event with a bounded context that
survives request cancellation. If domain terminal persistence cannot complete,
they append a safe recovery phase when the same fence is still current so the
client sees that finalization is being reconciled instead of an indefinitely
silent running state.
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
`agent_schedule_create` intrinsic. A supported creation request calls it
exactly once. Only the intrinsic's atomic commit emits the reserved schedule
success receipt; a model-only receipt fails the Turn without a response or
schedule, while unsupported workflows are refused without a tool call. The
model supplies a concise task name as
the only schedule-card title, the bounded schedule intent and trigger, and one
closed capability: `scheduled_note`, `chat_summary`, `web_research`,
`room_message`, `contact_report`, `room_member_report`, `channel_digest`, or
`chat_summary_delivery`, plus the ordered two-source `web_digest_delivery`.
The latter searches the web and then sends a Matrix message to a group/channel
room; it never creates a channel post. `scheduled_note` requires an explicitly
empty tool set; the remaining capabilities bind exactly the Message MCP or
Tavily sources and tools declared by the API contract. Core binds the
authenticated owner/account generation and current conversation from the
durable turn lease. It requires a valid converged default conversation model
before accepting the schedule, but does not persist the creating Turn's model
as schedule authority. Before any schedule write it
requires the exact capability tools from the creating Turn's immutable
Message MCP or Tavily snapshot. Unknown workflows, wrong sources, and missing
tools produce a correctable intrinsic result and no schedule row; installed
extensions do not provide a generic scheduled-workflow capability.
The schedule template persists exactly the typed `payload.agent` owner and
positive generation authority plus its conversation; its model-profile field
is empty and it contains no credential or arbitrary reference fields. It carries only the
redacted, immutable snapshot and provider-facing tool names required by the
selected capability. Installed MCP/Skill, unrelated Message MCP, Product
Capability, and semantic Knowledge snapshots are excluded. Each due occurrence
revalidates those exact snapshots through the live Native resolver, filters out
every nonaccepted tool, and fails closed on catalog drift. In the same
transaction that accepts each occurrence, Core converges, resolves, and locks
the owner's then-current default conversation model, writes that exact profile,
revision, credential version, request dialect, model kind, configuration and
secret reference into the occurrence Task execution snapshot, and creates the
Task-level profile reference. Retry/reclaim reuses that snapshot and never
re-resolves the default. Conversation, tool, and embedding defaults independently
preserve a valid explicit selection; otherwise they select the next eligible
configured profile after the invalid/deleted selection and wrap to the first.
Legacy-null selects the first, using durable (`created_at`, `profile_id`)
creation order; zero eligible profiles leaves the role unset. Tool selection
does not read the conversation binding, and speech remains explicit-only. A
schedule remains uncreated only while the converged conversation role has no
eligible profile; Core never silently skips or pauses it.
Scheduled Agent Tasks use the durable Native `StartTurn` path, not the generic
Task agent loop. Request and turn UUIDs derive from the occurrence Task UUID,
and the immutable prompt binds `Task.AvailableAt` as the authoritative UTC
occurrence plus the persisted schedule timezone and local occurrence time.
Relative windows therefore do not drift when execution is delayed. The trusted
prompt also supplies capability-level single-pass guidance: an exact room ID
skips lookup, otherwise lookup is attempted at most once; summary reads are
attempted at most once; Web research performs one focused search; delivery
workflows synthesize before one send. A model-issued call is not repeated with
different arguments after error, insufficient data, or unknown completion;
safe provider-internal read retry stays below that model-call boundary.
Reclaim after a crash resumes the same turn and cannot append a second user
or assistant message. The Task succeeds with only the already-committed Native
assistant Markdown in `result.text`; no response JSON or duplicate transcript
message is produced. The internal execution context binds only the persisted
owner and account generation and never mints Product Capability scopes.
The admitted runtime snapshot also pins an intrinsic policy of `none`, so a
scheduled turn cannot see schedule creation, static-site, Cloud Worker, or any
other Core intrinsic.
`scheduled_note` writes only Native conversation and schedule-history Markdown;
it does not promise Matrix or operating-system push delivery. Message writes
in `room_message`, `chat_summary_delivery`, and `web_digest_delivery` are
durably dispatch-recorded before execution. Unknown provider completion is not
retried blindly and may terminate the occurrence without a duplicate send.
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

Schedule output history is read through
`agent.schedules.v1/list_outputs`. The adapter first revalidates the live
schedule identity, then performs one direct occurrence/Task join ordered by
`(scheduled_for, occurrence_id)` descending. Its opaque cursor is canonical,
bound to the requested schedule identity, and preserves that tuple order across
equal schedule times without duplicates. The projection is
closed to occurrence/task identity and times, current Task status, the same
safe Task result shape, and bounded failure fields; schedule templates, Task
payloads, model/extension snapshots, owner authority, and secrets remain
private. Soft-deleted Task rows remain part of occurrence history.

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

The read-only `static_site_read` intrinsic resolves source only inside the
current owner, account generation, and conversation. It reads either the
exact immutable release UUID supplied by the model or, when omitted, the
latest release in that conversation. PostgreSQL first resolves the complete
receipt; the filesystem reader then revalidates the server-derived path,
size, and SHA-256 before returning bounded HTML as untrusted model data. A
revision therefore reads the prior source in one model round and publishes a
new immutable release in a later round. Source HTML is never injected into
unrelated turns and this internal tool does not add a public byte-download
operation.

The authenticated owner manages those same releases through
`agent.static_sites.v1/list_releases` and `delete_release`. List returns the
server-produced absolute public URL and receipt fields only. Delete accepts one
release UUID plus an idempotency UUID and derives the exact filesystem identity
from the owner/account-generation receipt. Public downloads continue to use
the release URL; there is no duplicate byte-download capability.

Eino adapts each model round, while the current conversation turn store owns
dispatch admission, persisted results, recovery, and uncertain outcomes. Turn
acceptance atomically binds the complete compiled system prompt, profile and
request-dialect digest, intrinsic tool schemas, extension/attachment digests,
and versioned execution policy. Owner chat accepts only `interactive`, `deep`,
or `worker_orchestration`, defaulting omission to `interactive`; only the
trusted due-Task adapter may admit `scheduled`. Interactive, deep, scheduled,
and worker orchestration each admit 52 model dispatches, one cumulative
model-active hour, and 48 tool calls. The supported policy version validates persisted values against
absolute safety bounds rather than current presets, and every service and
PostgreSQL budget decision reads those admitted values. Unsupported versions,
unknown modes, unsafe values, and selector/runtime mismatches fail before turn
claim or event mutation. Runtime validation occurs before the first
provider reservation; mismatch or a missing admission snapshot fails with
`TURN_RUNTIME_INCOMPATIBLE`. Every physical provider attempt is then reserved
in a durable fenced attempt ledger before HTTP dispatch, including the single
allowed retry, and a retry copies the exact runtime snapshot. A Native
turn's dynamic loop control is a separate versioned dispatch directive bound
to the turn revision, dispatch epoch, lease identity, physical attempt, and
admitted-runtime digest. A directive may add the fixed loop nudge, force one
tool already present in the admitted envelope, or remove all tools for final
synthesis; it cannot change or expand the admitted prompt or tool catalog.
Retry copies the same directive, and restart reads it through the current
lease fence. Tool-budget and no-progress finalization outrank a prior
correctable-tool force so correction cannot suppress terminal synthesis. Tool,
Worker, and confirmation execution or waiting do not consume the admitted
model-active clock. Worker-owned runtime, token, output, remote-process, and
Task deadlines remain separate from the main conversation ReAct policy. Every
physical provider dispatch has a 15-second first-nonempty-payload deadline, a
90-second progress-idle deadline before its first meaningful action, and a
five-minute absolute deadline. Nonempty reasoning and incomplete tool-call
fragments satisfy the first deadline and renew the progress-idle window;
keepalives, empty deltas, and whitespace do not. User-visible text, a complete
valid tool call, or a normal runner return is meaningful and ends the
progress-idle check. The admitted remaining
model-active clock is stronger and owns equal expirations as
`model_budget_exhausted`; a dispatch-local expiry is `provider_timeout`. A
durable finalization intent normally reserves one additional physical attempt,
so the ledger permits at most sequence 53 without changing the admitted
ordinary fuse. The finalization attempt has no intrinsic tools, extensions,
extension snapshots, or forced tool; uses an independent two-minute deadline;
and is not added to ordinary model-active time. It never retries for an
ordinary failure. The sole exception is a quarantined
`MODEL_TOOL_CALL_FORMAT_INVALID` response from a turn whose admitted runtime
originally exposed structured tools: one live recovery attempt copies the same
tools-disabled directive, receives final-answer-only protocol guidance, and may
reach sequence 54 with a fresh full two-minute window. It never restores tool
authority. Final-window expiry is `finalization_timeout`, not ordinary budget
exhaustion; earlier provider deadlines remain provider failures. Intent
persistence before dispatch allows one attempt after restart. Persistence of a
finalization dispatch directive is the no-replay boundary: a started,
retryable, dispatched, or uncertain final attempt after process recovery
instead completes through deterministic fallback. A valid final response is
committed normally. Provider failure,
invalid/empty output, or a tool call from the final attempt produces a bounded
response that returns durable partial deltas directly when available, otherwise
uses concise same-language tool summaries or a retry message. Internal terminal
codes remain durable metadata and are not rendered in user-facing content; the
existing task, plan, reference, tool-summary, and tool-result projections remain
preserved.
Completed fallback is emitted through the normal `done` response, not a failed
turn. Completed public GET/list metadata omits retained internal attempt-error
diagnostics, while authoritative history retains the fallback body and validated
artifact references; failed/canceled turns still expose their terminal errors.
Integrity, authorization, persistence, revision/runtime-snapshot, and
unknown external-side-effect failures remain terminal failures. Other
background Tasks keep their own execution deadline/context. The nonnegative
round ordinal remains the current replay identity. Core v1 does not expose Eino
graphs as a user-authored workflow surface.

A provider-declared output limit is a completed fragment, not an unknown
transport outcome. Core persists its streamed text, releases the model round,
and reconstructs that fragment from ordered turn events before continuing with
the same frozen context and complete accepted tool catalog, including after
restart. Provider reasoning is never part of that durable reconstruction. A
partial tool call from the limited fragment is not published or executed; the
continuation may issue a fresh complete call.

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
content and complete call batch, followed by one result message per call in
producer order. Provider reasoning is absent from public and durable messages,
events, transcripts, history, and model-result envelopes. The live process may
carry parsed OpenAI-compatible reasoning exactly once into the immediately
following non-finalization, tools-admitted continuation for the same turn; it
is consumed on use and cleared by restart, cancel, steer, supervisor exit, or
service close.
Immediate read-only dispatch uses a compact private pending/dispatched/terminal
authority inside the current versioned turn-dispatch envelope; it never consumes
or leaks a public conversation event sequence. Public progress contains only
tool identity and bounded execution status; it omits tool arguments, exact
result content, cursors, and result references. The exact call and terminal
result stay in the private durable/model transcript, while terminal `done`
projects authoritative non-Web answer references; Web sources remain private
and appear publicly only as Markdown links in the answer body. This is a current-only envelope: rollout
must first prove there are no nonterminal turns carrying the superseded raw
model-result shape, or explicitly terminalize those turns before the new binary
may claim them.

OpenAI-compatible text is never promoted into tool authority. When the admitted
turn runtime exposes tools, model-authored content remains private until the
complete provider step is validated. Content accompanying a structured tool
call is not a public assistant delta. A response without structured
`tool_calls` that contains a protocol-shaped DSML envelope outside Markdown
fences, inline code, or quotes is quarantined in full and returns
`MODEL_TOOL_CALL_FORMAT_INVALID`; a natural-language prefix does not bypass the
guard, and no name or arguments are parsed. Core may retry that known
side-effect-free failure once with fixed guidance requiring standard
OpenAI-compatible `message.tool_calls`. Repeating it creates a durable
tools-disabled finalization that synthesizes the best answer from already
retained evidence. The guard remains active there, a single live recovery retry
retains zero tools, and another format failure creates deterministic Markdown.
No path executes the text or restores tool authority. Ordinary repository text
that quotes or fences the markers remains visible content.

The DeepSeek provider adaptation stays inside that same OpenAI-compatible
authority boundary. A DeepSeek tools-admitted dispatch, including thinking
mode, explicitly selects structured automatic tool choice and adds fixed
platform guidance before the first provider call. A quarantined format-recovery
dispatch with tools still available selects structured required tool choice;
an exact forced tool keeps the existing named choice instead. The adapter
quarantines known DSML, XML, and model-template text envelopes but never parses
them into calls, never changes
the admitted tool set, and never opts a profile into DeepSeek's beta endpoint.

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

Conversation memory is a separate two-layer projection. Working memory is a
versioned, schema-constrained `WorkingContext` plus the recent transcript.
Original goal and exact user constraints come only from durable user input;
artifact, external-resource, side-effect, and tool-receipt identities come only
from validated runtime references. Compaction may update decisions, completed
and pending steps, and the last failure, but PostgreSQL compares the protected
digest and rejects a stale or rewritten protected projection instead of
overwriting it. The model receives the structured JSON as delimited user-role
reference data, never as a system instruction. The complete raw transcript is
retained as audit truth. Automatic compaction is derived only after the Turn's
profile, compiled system prompt, selected Skill instructions, and intrinsic and
extension schemas are frozen. Its deterministic estimator is
`ceil(total UTF-8 bytes / 4)` over those inputs, the current prompt,
WorkingContext JSON, and authoritative retained message payloads. A known
positive input budget triggers at
`floor(0.8 * (context_window - max_output_tokens))`; a nonpositive or unknown
budget does not compact. The planner advances the smallest safe prefix while
preserving the largest suffix and never splits an assistant tool-call/result
round; if no suffix fits, it advances through the whole completed prefix. The
new projection records `source=authoritative_transcript`, the total first/through
message-ID scope and count, and the superseded protected digest. That metadata
is itself protected, while legacy JSON that omits it retains its existing
protected digest. PostgreSQL applies the projection and offset in the same
transaction as `StartTurnWithRuntime`, without incrementing the public
conversation revision, after revalidating the revision, prior offset/digest,
transcript count, and boundary IDs under lock. The derived sidecar changes
neither the public Turn request fingerprint nor the immutable runtime digest.
Explicit owner `compress_context` remains revision-bearing and uses the same
protected projection metadata. After a chat
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
recent timeline. All current automatic turn recall is optional: it has a fixed
three-second deadline and, on timeout or dependency failure, records one
restart-stable `memory_recall_degraded` warning, continues the same turn without
memory, and never retries recall for that turn, including after restart. That
warning is safe progress only; it never becomes model authority,
conversation content, tool output, runtime JSON, or final Markdown. A canceled
parent emits no degradation warning and starts no provider work. Explicit
authenticated `agent.memory.v1` reads and mutations remain fail closed, and no
current turn claims memory as an authorization or safety prerequisite. This
internal projection does not make Message Server an Agent-memory database.

### AWS

`CoreCloudControlService` owns the sole App-managed AWS credential. The neutral
AWS Capability adds revision-fenced idempotent STS identity checks. Worker
selection, live pricing, EC2 lifecycle, and Route53 remain behind the Cloud
Worker domain rather than a generic AWS resource graph. Confirmation is
mandatory for Worker creation and its quoted spend/exposure intent; model and
extension tools cannot bypass it. A later domain-only bind or unbind on an
already retained workload is executed directly by its authoritative Native
turn after exact identity revalidation and provider read-back, without a
second confirmation or Task.

AWS credential access is always composed so the sole App-uploaded credential
can immediately publish Worker readiness. All durable Core secret envelopes
require a raw 32-byte `core_secret_master_key_file` mounted with mode `0400`. PostgreSQL
stores only the key version, nonce, and AES-256-GCM ciphertext; field AAD binds
the credential ID, revision, and secret field. Missing keys, wrong keys, and
version mismatches fail closed. Provider code materializes credentials only
for the request-local SDK call and never logs them.

Cloud Worker readiness is derived at request time from the durable
Task/confirmation stores, local artifact repository, persistent SSH Worker
manager and the sole active App-uploaded AWS credential. The deployment-owned
host Region is an optional placement hint; missing configuration does not
withhold Cloud Worker publication. The credential's stored default Region is
not placement authority. The [API contract](api-contract.md) defines publication
gates and the latency-first three-Region placement/fallback policy;
evidence and remaining verification are recorded in the
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

A proposal carries provider-neutral minimum vCPU, system memory, disk,
estimated runtime, and an optional accelerator class (`gpu`, `neuron`, `fpga`,
`media`, or `any`), never an AWS instance type. GPU proposals also carry a
verified non-zero minimum assigned accelerator-memory working set. Before a
named model workload can be proposed, Core's intrinsic guidance requires the
exact model tag or artifact, quantization or precision, published size,
runtime and accelerator/driver compatibility, context length, concurrency, and
CPU-offload policy to be verified. Independent minima include loading peaks,
KV cache or training state, runtime workspace, temporary model copies, caches,
outputs, and explicit headroom; an unverified critical fact cannot produce a
paid proposal.

Agent intersects current-generation x86_64 on-demand products with the
selected Worker Region's actual EC2 offerings and live accelerator metadata
and selects the cheapest shape satisfying every hard minimum. Fractional GPU
instances contribute only their assigned accelerator memory. The plan and
confirmation expose the selected shape, concrete accelerator name and assigned
memory, and live hourly compute price. Bounded jobs also expose their estimated
cost and maximum authorized cost; persistent services do not present a finite
task cost or cost ceiling for their open-ended lifetime.

The selected concrete accelerator class is persisted with each retained
Worker. An accelerator request cannot reuse a Worker whose accelerator metadata
is absent or incompatible.

A proposal atomically creates the plan, execution, `CLOUD_WORKER` Task and
`CoreConfirmation`. Creating a Worker requires a fresh EC2/EBS price read and
confirmation of that exact quote before any AWS mutation. Confirmation of the
current unexpired offer authorizes the first AWS write directly; there is no
second quote or confirmation step. Reusing a sufficiently large idle retained
Worker performs no creation mutation and needs no new creation confirmation.
The proposal idempotency key is also its operation correlation ID, and all
offer object IDs are derived before persistence. A `CreateOffer` error enters
reconciliation instead of being treated as failure: a fresh bounded context
acquires the same PostgreSQL advisory lock and reads the exact operation
receipt plus request digest. A match returns the committed offer, absence
proves unchanged, and an unavailable/conflicting read stays
`unknown_mutation` with operation, plan, Task, and execution IDs. Reconciliation
is read-only and never creates a replacement offer.
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

The manager keeps at most four Workers for the authenticated owner/account
generation. CPU and GPU Workers use versioned, tested Dirextalk Ubuntu 24.04
public AMIs pinned in the Agent's embedded Region/flavor release catalog. The
catalog records only live-qualified images from publisher `066107820442`, with
schema, release/Pi compatibility and GPU families. Pre-quote discovery validates
the exact AMI ID, publisher and public visibility without reading customer SSM
parameters or publisher-only tags, then resolves the actual AMI root device and
snapshot minimum into the confirmed storage quantity. Missing, incompatible or
unverified images fail without a generic-image fallback. Launch re-resolves the
catalog image and requires a fresh quote rather than increasing storage silently.
Runtime discovery also resolves the default VPC/subnet and launches an instance with an ordinary
public IPv4, and connects by outbound SSH. Agent uses short SSH operations to start work, read
status and load, stream logs by offset, and list or copy artifacts. A dropped
connection or host reboot does not erase remote state under
`/var/lib/dirextalk-worker`. Image Builder installs the standard pinned Pi,
Python, Node, Git/GitHub CLI, Go, Caddy, build-tool, and shell-utility baseline;
the task bootstrap only validates that immutable manifest and command set. Job and service
workloads share this protocol, and a service may remain running across
conversation turns.
EC2 launch uses one physical `RunInstances` attempt. A confirmed
`VcpuLimitExceeded` rejection is read back as no instance, then the same current
creation confirmation authorizes one minimum regional On-Demand vCPU quota
increase request. Agent reuses a sufficient pending request and revalidates the
exact AWS identity before every Service Quotas call. It terminalizes the Task
and turn with an actionable request status or console link, and marks the
retained intent failed and destroyable instead of retrying provisioning.
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
returned to the original durable turn. Success does not force tools-disabled
synthesis: outstanding authorized follow-ups continue through the same pinned
tool catalog and remaining ordinary budget. Sending success requires its own
durable successful receipt, not a Worker report or partial model statement.
If required pinned capabilities cannot rehydrate after recovery, the turn safely
reduces to frozen finalization without inventing request grants. A failed final
synthesis uses the trusted Worker outcome and canonical artifact references,
never raw transport reports or unconfirmed sending claims, and marks actual
billed cost unavailable. Finite execution persists
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
manual A-record instructions. A later Native Agent conversation may bind or
unbind a same-account Route53 A record for an exact retained Worker workload
through the separate `cloud_worker_domain_bind` and
`cloud_worker_domain_unbind` model tools. Neither tool accepts confirmation as
an argument. The authoritative Native turn executes each tool directly and
creates no second confirmation, Task, action card, or `waiting_confirmation`
state. It resolves and revalidates exact owner generation, AWS account,
credential revision, Worker resource identity, workload, hosted-zone, and
record identity before each Route53 call. Bind uses the Worker's
authoritatively observed current public IPv4 and requires a longest-suffix
matching public hosted zone owned by the current verified AWS account. Private,
external/manual, and cross-account zones are unsupported; no match returns a
stable correctable tool error before Apply, provider write, binding persistence,
or turn-success commit. Bind also reads the existing A record before any
Worker proxy, security-group, workload-state, or DNS mutation. A differing
IPv4 or TTL returns a correctable `user_input` observation that includes the
existing and intended values and proves `mutation_state=unchanged`; it never
overwrites the record. The manual-DNS result allowed during initial service
deployment is not a fallback for this later bind tool. Unbind removes only the exact
persisted record and does not require the Worker to be available. Both verify
the mutation by provider read-back. A later bind is a complete publication
transaction: over the pinned Worker identity it reconciles the Agent-managed
Caddy route, opens ports 80 and 443, reconciles Route53, proves public HTTPS
against the exact Worker IPv4, closes the direct workload port, and only then
commits success. Any failed stage remains retryable under the same frozen
identity and cannot produce an HTTPS-ready result. Active binding state and the
last exact removed record provide idempotent reconciliation when a provider mutation
succeeds but the final turn commit must retry; the retry revalidates the same
identity and repeats provider read-back. Route53 is not required for Worker creation or
ordinary execution. Existing execution recovery reads retained state before
new AMI/network/public-egress discovery. Explicit owner-authorized destruction
cancels active execution and remains available for busy, provisioning, and
externally terminated Workers; the exact identity and cleanup contract is
defined in Execution V2. There is no EIP,
frontend AMI control, S3/KMS artifact path, WorkerControl listener, model relay,
or deploy-time Worker binding. The
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
