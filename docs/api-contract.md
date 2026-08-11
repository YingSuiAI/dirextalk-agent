# Core v1 API contract

This document defines the Agent-owned API at HEAD. The canonical public
surface is the versioned Protobuf under
[`api/proto/dirextalk/agent/v1`](../api/proto/dirextalk/agent/v1); generated Go
files are derived artifacts. Message Server owns the Flutter-facing
`agent.*` action and Native Agent stream proxy. Flutter never connects to this
listener directly, and Online Agent remains the separate Matrix transport.

## Services

Core gRPC composition may register:

- `AgentService` for capabilities and instance information;
- `ModelProfileService` and `ConversationService`;
- `TaskService` and `ScheduleService`;
- `ConfirmationService`;
- `MCPService` and `SkillService`;
- `CoreKnowledgeService`;
- `CoreCloudControlService`;
- `WorkloadService` for durable workload planning and operations.

`WorkerControlService` is not part of this public composition list. It is
registered only on a dedicated TLS 1.3 Worker listener with Worker identity
verification; Flutter, Message Server, and the Agent service token cannot call
it.

Registration means only that an authenticated RPC endpoint is present; it does
not publish a client capability or prove that an optional provider is ready.
At HEAD, `CoreExecutionV2Service` has a Protobuf/adapter seam but is not
registered on the Core gRPC server. The exact `agent.execution.v2.*` operations
in [execution-v2.md](execution-v2.md) are exposed only through the neutral
Capability service after their production graph and readiness proof pass.

Health and reflection are optional. Core has no REST API, admin UI, or
multi-user authorization surface.

`AgentService.GetInstanceInfo` and authenticated `agent.info.v1` status expose
the immutable image `release_version` separately from `api_version`. Release
builds inject a v-prefixed semantic version (for example `v1.0.0`) into the
Agent binary; local builds report `dev`. This field contains no revision,
credential, endpoint, or other secret deployment metadata.

## Transport and authentication

The server uses TLS 1.3 and one deployment-generated token read from the
protected `service_token_file`:

```text
authorization: DTX-Agent-Token <unpadded-base64url-32-byte-token>
```

The token is compared in constant time, stripped before handlers run, never
stored in PostgreSQL, and rotated by atomic file replacement followed by
restart. There is no remote token-management API, caller scope, device, or
multi-tenant model.

## Request and response invariants

- Mutations use the UUID idempotency keys defined by their Protobuf messages;
  revision-bearing mutations reject stale expected revisions without changing
  state.
- `agent.models.v1` sync/list responses expose durable conversation, tool,
  embedding, and speech client-profile defaults. The tool default is an
  independent binding to a conversation-kind profile; it never falls back to
  the conversation default and rejects embedding- or speech-kind profiles.
- Durable Task events/results are fenced by Task revision, attempt, and lease
  epoch. `WatchEvents` resumes strictly after its supplied sequence.
- `Chat`, `StreamChat`, and `StartTurn` require a positive, exact
  `model_profile_id`/`model_profile_revision`/`credential_version` triple.
  Partial or stale pins fail before provider work; there is no default-profile
  fallback, and durable replays retain their original snapshot.
- A Native conversation model stream has no total execution deadline. Its
  five-minute safety limit measures only provider inactivity and is renewed by
  every byte received from the SSE stream, including keepalives. Model output
  and tool-call progress may therefore continue for longer than five minutes;
  individual tool or sandbox executions keep their own resource limits. If a
  dispatched provider stream produces no data for the full idle interval, the
  turn fails with `provider_timeout` and an unknown-outcome summary. The
  dispatch is never replayed automatically, and recovery preserves the
  persisted timeout classification.
- Native conversation progress publishes the existing `tool_call` event only
  after the model step and tool identity are durable, and before the extension
  is dispatched. A successful call is followed by its exact `tool_result`; a
  failed dispatch retains the already-published call before the existing safe
  terminal error. Durable turns persist the same public ordering while their
  private pending/dispatched envelope remains the at-most-once authority and
  is never exposed as an additional client event.
- On the first turn of an empty Native conversation, `Chat`, `StreamChat`, and
  `StartTurn` perform an Agent-internal semantic recall over only ready memory
  sources whose current revision has a promoted embedding binding that exactly
  matches the active embedding profile ID, profile revision, and collection
  configuration digest. Sources awaiting reindex after an embedding-profile
  change are stale recall candidates and are skipped until promotion. The
  bounded result is inserted as explicitly untrusted user-level reference data
  before the current prompt for that model request only. It is never written to
  conversation messages, turn/event payloads, public Knowledge cursor
  snapshots, logs, or Capability results. An unavailable recall dependency
  fails closed before model dispatch; an empty recall is a successful empty
  context.
- Authenticated Native conversations also receive one Agent-owned, read-only
  `knowledge_search` model tool when Knowledge is enabled. It searches only
  ready sources with promoted bindings that match the active embedding
  profile revision and collection digest. The tool accepts a bounded query,
  optional source IDs, and a result limit; it returns bounded passages plus
  secret-free embedding provenance and never calls back through Product
  Capability.
- Authenticated durable Native turns receive the Core-owned
  `agent_schedule_create` intrinsic when the PostgreSQL conversation/schedule
  store is composed. Model input is limited to `name`, `goal`, exactly one
  `run_at` or `cron` plus IANA `timezone`, and optional `timeout_seconds`.
  Owner, account generation, conversation, and model profile are injected from
  the fenced turn lease. Owner and generation persist only in the typed
  `task_template.payload.agent` authority object; credentials,
  attachment/Knowledge references, and extension bindings are not accepted.
  Schedule creation, its replay receipt,
  both transcript messages, terminal turn response, and done event commit in
  one transaction. Schedule and idempotency identities are deterministic from
  the accepted turn/request/tool-call identity, so an uncertain same-call retry
  replays without creating another schedule.
- Capability conversation reads use a closed Flutter-facing projection.
  Conversations expose only id/title/revision/timestamps/status; history
  exposes only user/assistant messages with durable sequence, terminal status,
  and a references array. The first history page contains the newest bounded
  messages in ascending sequence order, and its opaque cursor is bound to the
  conversation id and prior sequence.
- Capability `agent.chat.v1/list_turns` accepts only a canonical conversation
  UUID, an optional opaque page token of at most 4,096 bytes, and an optional
  limit from 1 through 1,000. Its closed result projects exactly `turn_id`,
  the original start `idempotency_key`, `conversation_id`, `state`, `revision`,
  `last_sequence`, `terminal_code`, `terminal_summary`, `created_at`, and
  `updated_at`; prompts, request fingerprints, model/profile data, credentials,
  and execution snapshots never cross the Capability boundary.
- Capability `agent.chat.v1/stop_turn` is the revision-fenced durable-turn
  cancellation mutation. It accepts exactly `idempotency_key`, `turn_id`, and
  positive `expected_revision`, calls the conversation service cancellation
  path, and returns only the same public turn metadata plus the cancellation
  request `idempotency_key`. It does not alias generic Capability operation
  cancellation, accept unknown fields, or expose the original prompt/profile.
- Capability `agent.chat.v1/steer_turn` appends one non-empty instruction to
  the same accepted/running durable turn. It accepts exactly a mutation
  `idempotency_key`, `turn_id`, positive `expected_revision`, and
  `instruction`. The store records the instruction in the append-only turn
  ledger, advances the turn revision, invalidates the active provider lease,
  and cancels that provider context before regenerating from the original
  prompt plus every recorded instruction. It never creates or queues a second
  turn. The typed result returns the original turn idempotency identity plus
  the separate steer mutation receipt; prompt/profile data stays private.
- Capability `agent.chat.v1/stream_chat` starts and watches the same durable
  conversation turn exposed by `list_turns`. Its canonical Capability
  `operation_id` is the public `turn_id`; the request id remains the distinct
  client-message idempotency identity. Disconnecting a WatchOperation consumer
  does not cancel execution, while cancelling the Capability operation requests
  cancellation of that exact durable turn.
- Stored credentials are write-only from ordinary read/list APIs. Responses
  expose status, fingerprints, revisions, or binding digests, never secret
  bytes. Agent-owned secret fields use the configured encrypted-at-rest store.
- Every `agent.knowledge.v1` mutation, including `index_sources`, requires an
  explicit canonical UUID `idempotency_key`; missing or malformed keys are
  rejected, while read operations do not require one. Neutral
  `agent.aws.v1/test_credential` binds `credential_id`, `expected_revision`,
  and its UUID key to a durable, secret-free replay. The provider call runs
  outside database transactions and row locks. A same-key retry observing an
  active claim polls until its persisted 30-second lease plus short completion
  grace, then replays the completed result or deterministic provider-failure
  receipt; an abandoned or completion-uncertain claim becomes fail-closed and
  is never taken over for a second STS request. Credential verification
  timestamps and replay receipts are monotonic when different keys complete
  out of order. The legacy gRPC `TestCredentialIdentity` method remains the
  separate non-keyed seam.
- Neutral Capability model-profile mutations and conversation mutations also
  require explicit canonical UUID idempotency keys. Missing or malformed keys
  are rejected rather than replaced with adapter-generated identities.
- Knowledge upload fields include declared size and whole-content SHA-256;
  chunks carry contiguous ordinal/offset and per-chunk digests. Commit rejects
  revision, size, or digest drift. Search cursors retain the secret-free
  embedding provenance used for their page.
- Knowledge vectors are stored in Agent PostgreSQL through pgvector. Process
  configuration supplies only the vector dimension; endpoint, collection, and
  content-quota settings are not public configuration. The aggregate indexable
  content limit is 64 MiB, each source is limited to 16 MiB, and uploading
  reservations count toward the aggregate. Status returns
  `quota_used_bytes`, `quota_limit_bytes`, `quota_remaining_bytes`, and
  `max_source_bytes`. Only aggregate exhaustion returns
  `RESOURCE_EXHAUSTED` with the safe message
  `Knowledge content quota is exhausted` and detail code
  `knowledge_quota_exceeded`; parser and per-source limit failures remain
  `INVALID_ARGUMENT`.
- `agent.web_search.v1` exposes `get_config`, `update_config`, and `test` for
  the typed Tavily provider. Only `update_config` accepts the write-only key;
  chat requests carry no `tool_credentials` envelope.
- `agent.text_tools.v1` is an owner-client-only Capability with `get_config`
  (READ), `update_config` (MUTATION), and `execute` (MUTATION). Configuration
  is a full ordered-list replacement: at most 32 items, at most six enabled
  items, unique stable built-in or canonical UUID IDs, and contiguous order.
  Revision zero is a virtual disabled global config containing the four
  server-authored translation, summary, explanation, and search defaults;
  search alone defaults disabled. The first update must expect revision zero.
  An update that makes the global configuration and search enabled is accepted
  only when the same owner/account generation already has enabled Tavily Web
  Search with a valid server-side credential. Disabling either layer does not
  require a search credential. `execute` rechecks that fence and fails closed
  if Web Search is later disabled, cleared, rotated, or unavailable. `execute`
  accepts only `tool_id`, selected text, and the required current UI output
  language (`zh` or `en`). Stable built-ins bind their complete response to
  that language, so translation never guesses a target language from model
  context; UUID custom tools retain their authored prompt. Execution resolves
  the explicit `default_tool_client_profile_id`
  conversation profile and current credential server-side with no fallback,
  and never writes conversation, history, Task, or execution replay state.
  Search alone uses the fenced Tavily path with at most five results and sends
  its evidence as separate untrusted model context. Model execution is one
  shot, limited to 60 seconds and 64 KiB of output.
  Because `execute` is a Capability MUTATION, the common operation ledger
  retains the bounded output/sources JSON as its ordinary plaintext result and
  event receipt until ledger/account cleanup; deprovision purges it. The
  ledger always stores request JSON as `{}`, so selected text is not durable.
  Pending or running calls interrupted by restart become `uncertain` and are
  never automatically dispatched again.
- `agent.image_tools.v1` is the owner-client-only, five-operation image text
  boundary: `upload_begin`, `upload_append`, `upload_commit`, `extract_text`,
  and `translate_text`. JPEG, PNG, and WebP bytes use a dedicated PostgreSQL
  source store with an 8 MiB image limit, 1 MiB canonical chunks, SHA-256
  verification, 30-minute expiry, and exact owner/account-generation/image-
  request binding. A committed source is atomically consumed once and its
  database bytes are cleared before the provider call. Execution requires the
  global text-tool switch, the explicit conversation-kind Tool default, a
  current credential, and advertised `image` input modality; there is no
  profile or conversation fallback. Fixed server prompts provide only text
  extraction and translation to a canonical BCP-47 locale. Calls create no
  conversation, history, Task, or image replay rows outside bounded upload
  idempotency receipts; the common Capability ledger persists request `{}`.
- Unknown enum values, malformed UUIDs, invalid digests, and unsupported
  combinations fail closed as `INVALID_ARGUMENT` or `FAILED_PRECONDITION`.

`TaskService` and `ScheduleService` use one durable Task/event path for
background model, extension, Knowledge, and AWS work. `ConfirmationService`
is the common explicit-confirmation boundary for side-effecting MCP/Skill and
typed cloud operations. `WorkloadService` uses the distinct `WORKLOAD` Task
kind and owner-only operation/event/actual read-back actions. The single
ephemeral Pi path uses `CLOUD_WORKER`; its payload pins plan/revision/digest,
confirmation, conversation/turn, quote, execution digest, and account generation;
while the real CoreTask claim and launch material separately pin attempt and
lease epoch.

Cloud Worker offers are created only by the Core intrinsic
`cloud_worker_propose` during an authoritative conversation turn. Public
clients use `agent.execution.v2.plans.get/list`,
`agent.execution.v2.runs.get/list/cancel/events`, and
`agent.execution.v2.artifacts.get/download`; they use
`agent.core.confirmations.get/list/confirm/reject` for authorization. The
Execution V2 confirmation aliases and public `runs.reconcile` operation do not
exist. The durable controller performs provider reconciliation and cleanup.

`agent.chat.v1/upload_attachment_begin` requires `kind` (`image`, `file`, or
`workspace_archive`) and a matching approved `mime_type`. A turn accepts at
most four sources, at most one workspace archive, and at most 8 MiB combined;
each source remains immutably bound to owner, account generation, turn request,
revision, size, and SHA-256. Workspace archives use the single constrained
tar+gzip media type and are never exposed as arbitrary local paths.

`agent.execution.v2.artifacts.download` is a safe read for retained,
centrally verified Cloud Worker artifacts only. Its closed request contains
`record_kind=cloud_worker`, one artifact UUID, a bounded offset below the
8 MiB output ceiling, and a 1..512 KiB chunk limit. Each call revalidates the
owner/account generation, retention revision and expiry, current AWS
account/Region/credential revision, then reads and verifies the complete exact
S3 object version before returning one non-empty top-level base64 chunk with
chunk and whole-object SHA-256. It creates no download lease, extends no
retention, and exposes no S3 identity.

## Capability and readiness semantics

Registration is not publication. `AgentService.GetCapabilities` and the
neutral Capability registry expose a descriptor only when its production graph
and required readiness proof are complete; configuration-disabled or partial
domains stay absent and fail closed when selected.

- `workload.core_runner` requires its nonce-backed full local isolation proof.
- `workload.aws_ssm` and `workload.aws_ecs` require one exact configured
  credential/target readiness block and the complete typed provider graph.
  Startup performs no AWS calls; the first explicit provider action probes the
  exact target and returns a per-operation precondition on failure.
- `agent.execution.v2` publishes only operations whose complete typed route is
  ready. Cloud Worker mutation readiness additionally requires its PostgreSQL
  store/controller, private WorkerControl listener, provider ledger/Reaper,
  exact account/Region/credential/AMI pins, and completion outbox. Fake
  qualification does not imply real AWS readiness; see
  [execution-v2.md](execution-v2.md).

The private WorkerControl Claim has one exact bidirectional protocol handshake.
Both peers must declare the current `worker_protocol_version` and
`runtime_contract_version`; absent or unequal values fail before model-grant
activation and have no compatibility or fallback route. The immutable AMI
qualification binds the same pair.

WorkerControl Heartbeat, Complete, and Fail carry one bounded, secret-free
progress snapshot with an exact session-local sequence. The service replaces
the Worker wall-clock activity timestamp with its own mutation time and
enriches invocation count from the durable model-invocation ledger. Complete
and Fail persist the final progress event atomically with session terminal
state; no second progress API or cursor exists.

Message Server reaches Agent through the authenticated Capability boundary and
projects only its existing ProductCore action names and Native Agent stream
frames to Flutter. Product Capability callbacks use their separate mTLS
direction; the two services keep separate databases, credentials, and
execution histories.

## Contract changes

Core is a fresh-state service with no legacy public-API or database
compatibility path. Any Protobuf or schema change updates this contract and
focused boundary tests in the same change.
