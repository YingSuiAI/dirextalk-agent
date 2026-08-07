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
- Durable Task events/results are fenced by Task revision, attempt, and lease
  epoch. `WatchEvents` resumes strictly after its supplied sequence.
- `Chat`, `StreamChat`, and `StartTurn` require a positive, exact
  `model_profile_id`/`model_profile_revision`/`credential_version` triple.
  Partial or stale pins fail before provider work; there is no default-profile
  fallback, and durable replays retain their original snapshot.
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
- Capability conversation reads use a closed Flutter-facing projection.
  Conversations expose only id/title/revision/timestamps/status; history
  exposes only user/assistant messages with durable sequence, terminal status,
  and a references array. The first history page contains the newest bounded
  messages in ascending sequence order, and its opaque cursor is bound to the
  conversation id and prior sequence.
- Capability `agent.chat.v1/list_turns` accepts only a canonical conversation
  UUID, an optional opaque page token of at most 4,096 bytes, and an optional
  limit from 1 through 1,000. Its closed result projects exactly `turn_id`,
  `conversation_id`, `state`, `revision`, `last_sequence`, `terminal_code`,
  `terminal_summary`, `created_at`, and `updated_at`; prompts, request identity,
  model/profile data, credentials, and execution snapshots never cross the
  Capability boundary.
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
- `agent.web_search.v1` exposes `get_config`, `update_config`, and `test` for
  the typed Tavily provider. Only `update_config` accepts the write-only key;
  chat requests carry no `tool_credentials` envelope.
- Unknown enum values, malformed UUIDs, invalid digests, and unsupported
  combinations fail closed as `INVALID_ARGUMENT` or `FAILED_PRECONDITION`.

`TaskService` and `ScheduleService` use one durable Task/event path for
background model, extension, Knowledge, and AWS work. `ConfirmationService`
is the common explicit-confirmation boundary for side-effecting MCP/Skill and
typed cloud operations. `WorkloadService` uses the distinct `WORKLOAD` Task
kind and owner-only operation/event/actual read-back actions.

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
- `agent.execution.v2` additionally requires `core_execution_v2_enabled`,
  every typed provider route, the exact target proof, and the configured
  CloudFormation service role. A missing route leaves all operation IDs
  unpublished; see [execution-v2.md](execution-v2.md).

Message Server reaches Agent through the authenticated Capability boundary and
projects only its existing ProductCore action names and Native Agent stream
frames to Flutter. Product Capability callbacks use their separate mTLS
direction; the two services keep separate databases, credentials, and
execution histories.

## Contract changes

Core is a fresh-state service with no legacy public-API or database
compatibility path. Any Protobuf or schema change updates this contract and
focused boundary tests in the same change.
