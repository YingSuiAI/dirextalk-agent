# Message Server and Agent integration contract

This document freezes the cross-repository boundary for the independent Agent
service. Agent-owned API and domain invariants remain in the [API
contract](api-contract.md), [Core v1 specification](core-v1-development-spec.md),
and [Execution V2 contract](execution-v2.md). Implementation status and live
verification belong only in the [delivery tracker](delivery-tracker.md).

## Control and data boundaries

Message Server authenticates Flutter for login and account control, then signs
a 15-minute, owner/account-generation/scope-bound Agent session ticket with the
existing capability-grant key. Flutter uses that ticket only through the node's
same-origin `/agent/v1/*` edge route. Caddy forwards the full path to Agent's
internal HTTP listener; it never publishes the listener itself. Flutter never
receives the long-lived Agent service token.

The cross-client v1 session shape and Agent error vocabulary are frozen by
`internal/agenthttp/testdata/session_stream_contract_v1.json`. The Message
Server session response supplies `ticket`, `expires_at`, `server_time`,
`base_path`, `session_id`, and `scopes`, with RFC3339 UTC timestamps,
`base_path=/agent/v1`, and a 900-second ticket TTL. Agent returns exactly
`AGENT_TICKET_EXPIRED`, `AGENT_TICKET_STALE`, `AGENT_TICKET_INVALID`, or
`AGENT_TICKET_SCOPE_FORBIDDEN` for their named ticket conditions. If SSE
`after_seq` and `Last-Event-ID` are both present, they must be equal; otherwise
Agent returns HTTP 400 with `AGENT_CURSOR_CONFLICT` and does not open a stream.

The Agent owns the independent runtime, database, files, secrets, model and
conversation state, Tasks, Knowledge, Web Search, AWS, Execution V2, and
runner processes and the Native Agent HTTP/SSE protocol. Message Server owns
owner authentication, account control, ticket issuance, Product Capability
callbacks, and Matrix product data. The two services keep separate databases,
credentials, and execution histories.

Online Agent is the real private Matrix `agent_room_id` conversation. It is a
separate transport from Native Agent Core and does not share its history,
model state, or online-state inference.

## Capability directions

Private service integration may still use the authenticated TLS gRPC boundary
and deployment-generated credentials. Owner-client discovery and data calls
use Agent's scoped HTTP catalog directly; Message Server no longer maintains a
parallel action-binding or schema-pin catalog.

The Agent-to-Message-Server direction is the separate Product Capability
callback over its authenticated mTLS channel. This private service connection
explicitly bypasses ambient `HTTP_PROXY`/`HTTPS_PROXY` settings; those settings
belong to controlled outbound web traffic and cannot redirect the authenticated
peer channel. Callbacks do not become a second Agent database or execution
ledger, and neither direction accepts raw Agent secrets from Flutter.

Native conversations also receive one deployment-owned Message Server MCP
source at the fixed `core_message_mcp_endpoint`. Agent authenticates each
Streamable HTTP request with the stable bootstrap `agent_token` read from
`core_message_mcp_token_file`; the token value is never stored in YAML, Agent
PostgreSQL, logs, tool metadata, or model-visible results. This source is
composed only inside Core conversation admission and persisted-turn recovery;
the enclosing HTTP/gRPC admission remains authenticated. Its exact endpoint and
advertised tool schemas form the deterministic synthetic snapshot. Core records
the standard MCP `readOnlyHint`, `destructiveHint`, `idempotentHint`, and
`openWorldHint` annotations as part of that snapshot. Only a complete,
internally consistent read annotation is treated as read-only; missing or
contradictory metadata is an unsafe mutation. A five-minute fresh catalog is
retained with stale-if-error use up to one hour. Discovery failure without a
valid retained catalog omits Message MCP for a new turn instead of blocking
ordinary chat, while accepted snapshots cannot silently change schema or
effect. Core records dispatch before each tool call and never automatically
repeats a mutation whose completion is unknown; ambiguous Message mutations
require an authoritative read before the model decides whether to retry. An
annotated read may re-discover the exact same catalog and retry once after an
unavailable/no-response result. Successful calls retain bounded structured
content only long enough to project known Message Server room and contact
shapes into validated `room` references; arbitrary structured fields and
nested channel posts/comments are not persisted as references. The current
Message MCP endpoint is stateless and does not use `Mcp-Session-Id`; no
speculative session manager or session generation is part of this contract.

Text tools cross only as the owner-client `agent.text_tools.v1` descriptor.
The Agent HTTP data plane accepts the canonical typed config/update/execute
payloads and does not accept an inline model profile, credential, prompt
fallback, owner field, or execution history. Agent resolves its explicit Tool
model default and stored secrets after validating the session ticket. There is
no parallel Core gRPC TextTool service.

Image tools cross only as `agent.image_tools.v1` with the exact five-operation
descriptor, published only when all five are ready. The Agent HTTP data plane
accepts bounded canonical chunks and the two typed execute requests. Requests
cannot supply URLs, inline profile/credential material, owner identity,
prompts, or chat attachment identifiers. `image_request_id` is
established at begin, must equal execute `idempotency_key`, and source revision
is exactly one.

Automatic conversation memory crosses only as the owner-client
`agent.memory.v1` descriptor through the scoped Agent HTTP catalog. The Agent
validates closed payloads and projects no internal fields. It owns the
default-off toggle, embedding prerequisite,
config revision, exact active-fact fencing, mutation idempotency, facts,
timeline, and observation counters. Message Server does not extract, persist,
merge, or recall facts.

The one Cloud Worker terminal callback is the fixed private
`product.agent_execution.v1/record_completion` operation. Agent dispatches it
only from a durable outbox after the result message is frozen and all recorded
AWS resources are independently `verified_destroyed`. It uses a fresh
Agent-to-Product call context and canonical request digest; it carries no
owner/model Permission. Message Server still authenticates mTLS, direction
token, Agent instance, and account generation, injects its local owner, and
stores only an idempotent minimal receipt plus
`agent.execution.v2.completed` invalidation. Result text and artifacts stay in
Agent authority.

Agent HTTP/SSE conversation projections carry additive `related_task_ids`,
`related_plan_ids`, and strict reference snapshots. A Cloud Worker reference
binds account generation and exact task, plan, run/execution, confirmation,
revision, quote, binding, and execution digests. The Agent returns these
server-authored values without reconstructing them; Flutter must read the
current Agent Plan, Run, and CoreConfirmation before any mutation.

Artifact bytes cross the direct data plane only through the read-only
`agent.execution.v2.artifacts.download` operation. The Agent remains responsible for
owner/account-generation and retention fences, complete exact-version object
verification, and the per-chunk and whole-artifact digests; neither service
publishes an S3 bucket, key, or version.

The Native durable SSE starts with the Agent-authored `accepted` event. Every
event carries the start `idempotency_key`, Agent `turn_id`, conversation id,
and turn revision; no `request_id` alias is published. Cloud Worker execution
transitions cross the same stream as `worker_status`, containing only that base
turn identity/revision, `created_at`, `execution_id`, and canonical status. A
running event may also carry one optional phase enum for localized Worker
progress; the phase never controls lifecycle or input state. Agent writes these
events at the actual queued, provisioning, running, and terminal transitions.
Turn history uses the same
`turn_id`/`idempotency_key` pair, and `agent.chat.v1/stop_turn` accepts only its
own UUID idempotency key plus the authoritative turn id. Cancellation is
monotonic and does not depend on the changing turn revision.
Same-turn guidance uses `agent.chat.v1/steer_turn` with a separate mutation
UUID, that authoritative turn id/revision, one bounded instruction, and up to
four optional attachment source IDs uploaded under that same mutation UUID. Agent
Core persists it on the current turn. Guidance interrupts a provider generation
before tool publication, but waits for an already public/dispatched tool result
without changing that tool's authority. The current SSH text runtime has no
mid-run guidance injection channel. After a terminal Worker result, unapplied
guidance is consumed with that result by one normal model round in the same
durable turn; it may answer or reuse the retained Worker. Flutter may not
represent the guidance as a queued successor turn.

## Deployment boundary

The split deployment builds one immutable image from
`deploy/container/agent.Containerfile`. It contains `dirextalk-agent`,
`dirextalk-extension-runner`, and `dirextalk-core-runner`; Compose runs that
image as three isolated services with distinct UIDs (Core `65532`, extension
runner `65531`, Core Runner `65530`), sockets, mounts, networks, and delegated
cgroup-v2 roots.

Starting a runner service does not publish its workload capability. Core and
Message Server require the corresponding nonce/full runner proof and exact
target readiness before exposing a route. No Message Server database/data
volume or Docker socket is mounted into the Agent project.

## Change rule

Changes to ProductCore action envelopes, Native Agent stream frames, Matrix
rooms, or Message Server Capability callbacks are owned by the companion
repository and must preserve this boundary. Changes to Agent Protobuf,
migrations, or Agent-owned runtime behavior update this repository's owning
contract and focused tests together. The service is fresh-state; do not add
legacy compatibility shims, fixture fallbacks, or parallel public contracts.
