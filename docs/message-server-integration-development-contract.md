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

The Agent-to-Message-Server direction is the separate Product Capability
callback over its authenticated mTLS channel. Callbacks do not become a second
Agent database or execution ledger, and neither direction accepts raw Agent
secrets from Flutter.

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
