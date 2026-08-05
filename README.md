# Dirextalk Agent

Dirextalk Agent is the independent, private single-user runtime for one
Dirextalk deployment. It owns Agent data and execution outside the Message
Server. Flutter reaches it only through the Message Server's
owner-authenticated proxy; Flutter never connects to the Agent listener or
receives its service token.

## Core capabilities

- Conversations and server-owned model profiles through an Eino boundary.
- Durable Tasks, events, cancellation, leases, schedules, and recovery.
- Confirmations, pinned MCP/Skills, and isolated extension execution.
- Agent-owned Knowledge and encrypted Tavily Web Search configuration.
- Typed AWS control and the readiness-gated `agent.execution.v2.*` domain.

This is not a REST API, admin console, multi-user control plane, cluster, pool,
or graph editor. Product actions, Native Agent stream frames, and Matrix-room
traffic remain separate Message Server/Matrix contracts.

## Runtime image

`deploy/container/agent.Containerfile` builds one immutable image containing
`dirextalk-agent`, `dirextalk-extension-runner`, and
`dirextalk-core-runner`. Split Compose runs that image in three isolated
containers; sockets, mounts, networks, identities, and cgroup boundaries are
separate, and capabilities publish only after their readiness proofs pass.

## Authoritative documents

- [Architecture](docs/architecture.md) — runtime topology, ownership, and
  security boundaries.
- [API contract](docs/api-contract.md) — Agent Protobuf/services,
  authentication, fields, and readiness semantics.
- [Core v1 specification](docs/core-v1-development-spec.md) — development
  invariants and product boundary.
- [Message Server integration contract](docs/message-server-integration-development-contract.md)
  — proxy, capability, and deployment boundary.
- [Delivery tracker](docs/delivery-tracker.md) — implementation status and
  verification evidence.
- [Execution V2 contract](docs/execution-v2.md) — the domain-specific
  `agent.execution.v2.*` contract.
