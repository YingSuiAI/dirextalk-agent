# Dirextalk Agent

This repository is the authority for the independent, private, single-user
`dirextalk-agent` service. The Agent runs outside the Message Server and owns
its runtime, PostgreSQL data, files, secrets, model/conversation state, Tasks,
MCP/Skills, Knowledge, AWS/Execution V2 state, and runner processes.

## Source of truth

- [Architecture](docs/architecture.md) defines runtime composition and
  ownership boundaries.
- [API contract](docs/api-contract.md) defines the Agent-owned Protobuf and
  service behavior.
- [Message Server integration contract](docs/message-server-integration-development-contract.md)
  defines the cross-repository proxy and capability boundary.
- [Core v1 specification](docs/core-v1-development-spec.md) defines the
  product and implementation contract.
- [Delivery tracker](docs/delivery-tracker.md) records implementation status
  and verification evidence.
- [Stable release contract](docs/release-contract.md) and the repository-owned
  `scripts/release/{prepare,verify,publish}.sh` define formal Agent releases.
- Versioned Protobuf under `api/proto/dirextalk/agent/v1` and `migrations/`
  are executable contract authorities for API and schema changes.

When these sources disagree with historical notes, follow current source,
tests, and the four contract documents above; do not invent a compatibility
path or fixture fallback.

## Ownership and integration boundaries

- Message Server owns owner authentication, ProductCore action envelopes,
  Native Agent stream frames, and Product Capability callbacks. Flutter talks
  to Message Server only; it never connects directly to the Agent listener or
  receives the Agent service token.
- Online Agent Matrix-room traffic is a separate transport from the
  Message-Server-proxied Native Agent runtime.
- Agent-owned mutable data and credentials stay in Agent storage. Secret values
  enter through authenticated write-only paths, remain protected at rest, and
  never appear in ordinary reads, logs, fixtures, or Git.
- The unified immutable image built by
  `deploy/container/agent.Containerfile` contains `dirextalk-agent`,
  `dirextalk-extension-runner`, and `dirextalk-core-runner`. Compose runs that
  image as three isolated containers with separate identities, sockets,
  mounts, networks, and cgroup boundaries; capability publication still
  requires the corresponding readiness proof.
- Core uses Go, Eino, PostgreSQL, and versioned Protobuf/gRPC. Keep model,
  MCP/Skill, Knowledge, and AWS background work on the durable Task/event
  path. Isolated execution must not fall back into the Agent process.
- This is a fresh-state service: do not add legacy database/public-API
  compatibility shims, fallback paths, or deprecated parallel contracts.
  Migration versions and checksums are immutable once the baseline is
  committed.
- Do not add multi-tenancy, Agent clusters/pools, graph/DAG authoring, task
  priority, REST APIs, or a standalone admin UI without an explicit contract
  change.

## Configuration and storage

- Process configuration is strict YAML loaded through Viper; the default path
  is `/etc/dirextalk-agent/config.yaml`.
- YAML may name the protected `service_token_file`, but never contains the
  token value. Rotation is an atomic file replacement followed by restart.
- Mutable user configuration and credentials belong in Agent-owned PostgreSQL,
  not process YAML. Large packages, workspaces, uploads, and artifacts live
  under the configured Agent data directory; PostgreSQL stores relative paths
  and digests.

## Working rules

1. Work on one observable workflow at a time and preserve unrelated user
   changes.
2. Before changing behavior, read the affected code, Protobuf, migration, and
   applicable contract document.
3. Add focused boundary tests for authentication, idempotency, persistence,
   scheduling, cancellation, confirmation, isolation, and recovery as needed.
4. Update the owning contract and implementation-status entry when behavior
   changes; do not duplicate detailed specifications here.
5. Real AWS mutation checks require explicit authorization, a disposable
   account, and independent resource read-back.
6. Write Git commit messages in English.

Typical checks:

```text
go test ./...
go vet ./...
go build ./cmd/...
buf lint
git diff --check
```

Stable releases must use the repository-owned scripts in prepare, verify, then
publish order. The maintained release gate is the clean synchronized `main`,
matching source/image/binary version identity, matching Git tag and GitHub
Release, followed by a pulled `latest` probe. Never reconstruct these release
objects by hand or add digest, attestation, image-ID, or tag-history gates that
are outside the stable release contract.
