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

Cloud Workers expose no inbound Agent gRPC service. Their lifecycle and task
observation use Agent-initiated SSH only; Flutter and Message Server continue
to use the authenticated Capability boundary.

Registration means only that an authenticated RPC endpoint is present; it does
not publish a client capability or prove that an optional provider is ready.
At HEAD, `CoreExecutionV2Service` has a Protobuf/adapter seam but is not
registered on the Core gRPC server. The exact `agent.execution.v2.*` operations
in [execution-v2.md](execution-v2.md) are exposed only through the neutral
Capability service after their production graph and readiness proof pass.

Health and reflection are optional. Core has no REST API, admin UI, or
multi-user authorization surface.

`AgentService.GetInstanceInfo` and authenticated `agent.info.v1/get_backends`
expose the immutable image `release_version` separately from `api_version`. Release
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
- Native conversation progress durably publishes visible assistant `delta`
  text as it arrives from the provider, followed by the terminal response; it
  never publishes provider reasoning content. It publishes the existing
  `tool_call` event only after the model step and tool identity are durable,
  and before the extension is dispatched. A successful call is followed by its
  exact `tool_result`; a failed dispatch retains the already-published call
  before the existing safe terminal error. Durable turns persist the same
  public ordering while their private pending/dispatched envelope remains the
  at-most-once authority and is never exposed as an additional client event.
- On every Native conversation turn, `Chat`, `StreamChat`, and `StartTurn`
  compose two memory layers before model dispatch. Working memory remains the
  durable conversation summary plus recent transcript window. Long-term memory
  combines relevance-ranked current user facts with a bounded newest-first
  fact timeline. Current facts take precedence over older timeline entries.
  The bounded envelope is inserted as
  explicitly delimited model-only reference data before the current prompt; it
  is never copied into conversation messages, turn/event payloads, public
  Knowledge cursor snapshots, logs, or Capability results. An unavailable
  structured-memory dependency fails closed before model dispatch; an empty recall is a
  successful empty context.
- Every successfully committed Native exchange atomically creates a private
  consolidation observation. A restart-safe worker uses the selected
  conversation model to extract only explicit durable user facts. Facts use a
  stable subject/predicate identity: the same value confirms the current fact,
  a different value supersedes it, and an explicit negation retracts it. The
  previous row is retained with a validity end time and an append-only
  `added`, `confirmed`, `replaced`, or `retracted` event. Extraction failures
  are retried with a bounded durable lease and never roll back the completed
  chat. Secrets, assistant assertions, transient requests, guesses, and
  sensitive inferences are excluded by the extraction contract.
- Automatic structured conversation memory starts disabled. The owner-client
  `agent.memory.v1/get_config`, `update_config`, `status`, `update_fact`, and
  `delete_fact` operations expose the only long-term-memory surface. Config
  changes use revision fencing; fact edits and retractions fence the exact
  immutable active fact ID. Mutations use UUID idempotency. Editing preserves
  subject, predicate, kind, and confidence while creating a replacement fact
  plus a `replaced` timeline event; deleting retracts the exact active fact and
  appends a `retracted` event. Enabling requires the current
  Knowledge embedding binding to resolve to a non-deleted embedding profile
  with configured credentials. Disabling preserves facts and the complete
  conflict timeline but returns an empty structured-memory recall and stops new
  observations; Knowledge search and durable conversation history keep their
  independent contracts. Timeline events publish separate RFC3339
  `effective_at` and `observed_at` clocks.
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
- Authenticated durable Native turns receive `static_site_publish` only when
  the Agent-owned static-site root passes startup readiness. The model supplies
  one self-contained UTF-8 `html` document of at most 192 KiB; it never
  supplies a path, URL, site identity, archive, or storage credential. Core
  derives immutable site/release UUIDs from the fenced owner, conversation,
  turn, request, and tool-call identities, publishes exactly `index.html`, and
  records its digest, size, and `/.sites/{site_id}/{release_id}/` path before
  atomically completing the turn with the absolute
  `https://<node-domain>/.sites/{site_id}/{release_id}/` URL. Same-call
  recovery verifies and reuses the
  exact file and PostgreSQL receipt. The embedded `publish-static-site` skill
  instructs the model to produce semantic, responsive, self-contained HTML;
  the edge sandbox CSP blocks scripts, forms, external subresources, and
  programmatic network access even when generated markup drifts.
- Ready static-site composition publishes `agent.static_sites.v1` for the
  authenticated owner. `list_releases` accepts only bounded page input and
  returns `site_id`, `release_id`, `conversation_id`, server-produced
  `public_url`/`public_path`, `size_bytes`, and `created_at`.
  `delete_release` accepts exactly `release_id` plus a UUID
  `idempotency_key`, removes only the receipt-derived release, and returns
  `{release_id,deleted,replayed}`. Public page bytes remain available through
  the absolute URL; no second download operation exists.
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
  Exactly one credential may be active: concurrent creates are serialized and
  a second create is rejected until the current credential is deleted.
- Optional `agent.worker.v1` publishes only after the persistent SSH Worker
  manager and the sole current verified AWS credential source are composed.
  `list_workers` and `get_worker` expose the exact
  AWS resource identity, observed EC2 state and ordinary auto-assigned public
  IPv4, Worker/task phase, server load and last-seen time, live hourly quote,
  availability and optional workload/domain status. An unavailable historical
  credential or one failed AWS observation is projected on that retained
  Worker without hiding other records. At most five retained Workers may exist
  for one authenticated owner/account generation across credential revisions;
  a destroying Worker whose compute resources are already gone does not occupy
  a slot while DNS cleanup is retried. A domain is optional per workload;
  `bind_domain` and `unbind_domain` pass their explicit confirmation literal
  to the Route53 port, which maps the A record to the current public IPv4 and
  performs read-back. Route53 support may be unavailable when the current
  account/zone is not configured; this does not suppress Worker creation,
  reuse, list, get, or destroy. There is no EIP field or operation. `destroy_worker`
  requires its explicit confirmation literal and the complete identity
  returned by list/get; a busy or changed resource identity fails closed.
  If credentials rotate after a provisioning intent, recovery only discovers
  and persists resources carrying that intent's exact tags so partial resources
  remain destroyable; it never creates a missing resource or resumes execution.
  A successful retained-Worker completion durably records its exact
  `worker_id` and a structured `next_action` bound to that same ID asking
  whether to run `destroy_worker`; retain is the default and the completion
  itself never destroys the Worker. The client resolves that ID through the
  current Worker inventory before offering the existing identity-bound destroy
  action. Deleting a credential revision is rejected while that revision has a
  retained Worker. Account deprovision is rejected before destructive mutation
  while any retained Worker remains on the Agent, including an older owner or
  account generation; the owner must destroy every such Worker and retry.
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
  out of order. There is no separate non-keyed credential test RPC.
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

`SkillService` exposes the same pinned lifecycle for `builtin`, `skills_sh`,
and `github` sources. Empty Skill discovery selects `builtin`; empty MCP
discovery selects `official_registry`. Built-in Skills are seeded exactly once
as ordinary installed records under the public identifiers
`dirextalk-research-and-verify`, `dirextalk-review-code`,
`dirextalk-verify-delivery`, and `dirextalk-write-technical-docs`. Uninstall
keeps the seed fence, so a process
restart cannot recreate the installation; an owner may explicitly discover
and reinstall the current built-in version.
Two network-free, read-only built-in MCP installations are also seeded once:
`dirextalk-server-time` exposes `server_time`, and `dirextalk-server-load`
exposes `server_load`. They use ordinary installed-extension records, the
isolated runner, MCP discovery, and MCP execution. Their durable seed fence
has the same uninstall semantics as built-in Skills.

Managed Node MCP is current-only `stdio_node`. `npm` candidates require one
exact package version and verified immutable integrity; GitHub candidates
require one exact commit. Lifecycle script declarations stay bound to the
immutable source, while both lock-only resolution and offline installation
disable script execution. Runtime network, native add-ons, mutable tags/ranges,
and host Git are rejected. Provider and dependency-resolution HTTP clients use
the public-IP-fenced direct transport and ignore ambient process proxy
variables; a managed outbound proxy requires a future explicit validated
contract. Durable limits are 32 live
extensions, one install/update lifecycle, 64 MiB and 8,192 files per published
Node artifact, and 512 MiB total Node storage. Admission failures publish only
`extension_install_busy`, `extension_installation_limit`, or
`extension_node_storage_quota`. Installed version output contains the closed
eight-field `node_artifact` receipt with `lifecycle_scripts_disabled=true` and
never exposes prepared paths, cleanup tokens, tools, or internal
artifact/input/entry/lock digests. Empty installation/version grants and Node
stdio arguments are canonical JSON arrays, never `null` or omitted. Only
queued, running, and waiting-user task snapshots pin an installed artifact;
terminal task snapshots remain audit records and do not block a
revision-fenced uninstall.

Cloud Worker offers are created only by the Core intrinsic
`cloud_worker_propose` during an authoritative conversation turn. Public
clients use `agent.execution.v2.plans.get/list`,
`agent.execution.v2.runs.get/list/cancel/events`, and
`agent.execution.v2.artifacts.get/download`; they use
`agent.core.confirmations.get/list/confirm/reject` for authorization. Every
proposal or requote that would create a new Worker performs a fresh AWS Price
List read for the selected EC2 instance and gp3 volume. The quote is not served
from a persisted pricing catalog. Confirmation of that exact quote is required
before key-pair, security-group, or EC2 creation. Reusing an already retained
idle Worker performs no creation mutation and therefore needs no new creation
quote. Worker destruction is a separate explicit owner-confirmed operation.
The intrinsic may create a priced offer for an explicit cloud request or when
trusted Native scheduler evidence proves that the local conversation runtime
lacks the general project/shell executor required by a substantial task. The
model may select it without cloud or remote wording, but model text and local
failures are not capability evidence. Cloud/local-only vetoes remain binding,
and AWS resources start only after the owner confirms the pending quote. The
manager supports no more than five retained Workers for one authenticated
owner/account generation across credential revisions. It discovers the newest
AWS-owned Amazon Linux 2023 image and the
default VPC/subnet at runtime, assigns an ordinary public IPv4, and uses
outbound SSH. Image identity remains internal provider data. There is no EIP,
custom AMI, S3/KMS, WorkerControl callback, model relay, Worker domain, or
deployment-time binding. Terminal Worker output returns to the same durable
turn as a tool result with related task/plan IDs and local Agent-owned artifact
metadata; Central resumes the turn and authors the final user-facing answer.

`agent.chat.v1/upload_attachment_begin` requires `kind` (`image`, `file`, or
`workspace_archive`) and a matching approved `mime_type`. A turn accepts at
most four sources, at most one workspace archive, and at most 8 MiB combined;
each source remains immutably bound to owner, account generation, turn request,
revision, size, and SHA-256. Workspace archives use the single constrained
tar+gzip media type and are never exposed as arbitrary local paths.

`agent.execution.v2.artifacts.download` is a safe read for retained Cloud
Worker artifacts copied into the Agent-owned local artifact repository. Its
closed request contains `record_kind=cloud_worker`, one artifact UUID, a
bounded offset below the output ceiling, and a bounded chunk limit. Each call
revalidates owner/account generation and the stored relative path, size, and
SHA-256 before returning bytes. It does not contact AWS, create a download
lease, or expose a Worker filesystem path.

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
  ready. Cloud Worker proposal and management readiness is evaluated from its
  PostgreSQL task/confirmation stores, local artifact repository, SSH manager,
  and the sole current STS-verified AWS credential. It does not depend on a
  deploy-time account, Region, AMI, network, Route53 zone, private listener, or
  artifact service. See [execution-v2.md](execution-v2.md).

The remote runner persists task state and logs by task ID. Agent uses separate,
short SSH commands to start work, query status and server load, read logs from
an offset, and list or download artifacts. SSH disconnect does not erase the
remote task or require a long-lived callback connection. Job and service
workloads share this protocol; service lifetime is independent of the
conversation turn until the owner stops it or destroys its Worker.

Message Server reaches Agent through the authenticated Capability boundary and
projects only its existing ProductCore action names and Native Agent stream
frames to Flutter. Product Capability callbacks use their separate mTLS
direction; the two services keep separate databases, credentials, and
execution histories.

## Contract changes

Core is a fresh-state service with no legacy public-API or database
compatibility path. Any Protobuf or schema change updates this contract and
focused boundary tests in the same change.
