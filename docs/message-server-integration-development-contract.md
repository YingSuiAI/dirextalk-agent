# Message Server and Agent integration contract

This document freezes the cross-repository boundary for the independent Agent
service. Agent-owned API and domain invariants remain in the [API
contract](api-contract.md), [Core v1 specification](core-v1-development-spec.md),
and [Execution V2 contract](execution-v2.md). Implementation status and live
verification belong only in the [delivery tracker](delivery-tracker.md).

## Proxy boundary

Message Server is the current owner-authenticated proxy between Flutter and
Agent Core. Flutter sends owner access-token requests to Message Server;
Message Server maps ProductCore action envelopes and Native Agent stream frames
to the Agent's authenticated Capability/gRPC boundary. Flutter never connects
to the Agent listener, receives the Agent service token, or sends Agent-owned
provider credentials and durable histories directly.

The Agent owns the independent runtime, database, files, secrets, model and
conversation state, Tasks, Knowledge, Web Search, AWS, Execution V2, and
runner processes. Message Server owns owner authentication, ProductCore action
names, Native Agent WebSocket frames, Product Capability callbacks, and Matrix
product data. The two services keep separate databases, credentials, and
execution histories.

Online Agent is the real private Matrix `agent_room_id` conversation. It is a
separate transport from Native Agent Core and does not share its history,
model state, or online-state inference.

## Capability directions

The Message Server-to-Agent direction uses the authenticated TLS gRPC/
Capability boundary and deployment-generated protected credentials. Optional
Agent descriptors are published only after their complete composition and
readiness proof pass; a schema or proxy registration alone is not a live
capability.

Before an Agent release, the local catalog preflight reads the sibling Message
Server baseline, explicit action bindings, and generated schema pins as release
inputs, then validates them against the Agent's real descriptor constructors.
It is test-only tooling and introduces no runtime cross-repository dependency;
all missing and mismatched baseline actions are reported together.

The Agent-to-Message-Server direction is the separate Product Capability
callback over its authenticated mTLS channel. Callbacks do not become a second
Agent database or execution ledger, and neither direction accepts raw Agent
secrets from Flutter.

Text tools cross only as the owner-client `agent.text_tools.v1` descriptor.
Message Server forwards the canonical typed config/update/execute payloads and
does not supply a model profile, credential, prompt fallback, owner field, or
execution history. Agent resolves its explicit Tool model default and stored
secrets after validating the authenticated Permission context. There is no
parallel Core gRPC TextTool service. The ordinary Capability operation receipt
retains bounded output for result observation, but its durable request is `{}`
and an interrupted execution is never automatically replayed.

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

Unary/stream conversation projections carry additive `related_task_ids`,
`related_plan_ids`, and strict reference snapshots. A Cloud Worker reference
binds account generation and exact task, plan, run/execution, confirmation,
revision, quote, binding, and execution digests. Message Server forwards these
server-authored values without reconstructing them; Flutter must read the
current Agent Plan, Run, and CoreConfirmation before any mutation.

Artifact bytes cross this proxy only through the read-only
`agent.execution.v2.artifacts.download` operation. Message Server forwards its
closed four-field request and strict top-level chunk result without storing the
bytes or reconstructing storage identity. The Agent remains responsible for
owner/account-generation and retention fences, complete exact-version object
verification, and the per-chunk and whole-artifact digests; neither service
publishes an S3 bucket, key, or version.

The Native durable stream starts with the Agent-authored `accepted` progress
event. Every progress event carries the start `idempotency_key`, Agent-internal
`turn_id`, conversation id, and turn revision; no `request_id` alias is
published. Message Server forwards this business acceptance and identity rather
than synthesizing a second accepted event. Turn history uses the same
`turn_id`/`idempotency_key` pair, and `agent.chat.v1/stop_turn` accepts only its
own UUID idempotency key plus the authoritative turn id and expected revision.

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
