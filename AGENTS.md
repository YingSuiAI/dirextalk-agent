# Dirextalk Agent

Dirextalk Agent is a private, single-user service for conversations, durable
tasks, schedules, model API access, MCP, Skills, Knowledge, and typed AWS
operations. It runs outside the owning product's business server and owns all
Agent data.

## Source of truth

- [docs/core-v1-development-spec.md](docs/core-v1-development-spec.md) is the
  approved Core v1 product and implementation target.
- [docs/delivery-tracker.md](docs/delivery-tracker.md) records the current
  implementation gap and delivery order.
- Versioned Protobuf under `api/proto/dirextalk/agent/v1` is the implemented
  public API. It may be changed while establishing Core v1; update its contract
  documentation in the same change.
- `migrations` is the sole Agent database schema authority.

## Core v1 boundaries

- One Agent instance serves one user and belongs to exactly one Dirextalk
  product deployment. It is never shared between old and vNext products.
- Core v1 changes only this repository. Message Server, Flutter, vNext Server,
  and vNext Client adapters are deferred.
- Keep Go, Eino, PostgreSQL, and Protobuf/gRPC as the primary stack.
- Agent owns conversations, Tasks, events, results, schedules, model profiles,
  prompts, MCP/Skill installations, Knowledge metadata, and AWS configuration.
- TLS gRPC plus one deployment-generated service token file authenticates the
  future business-server proxy. The token is not stored in PostgreSQL; rotation
  is an atomic file replacement plus restart. Do not add remote token
  management, multi-user RBAC, or caller scopes.
- Agent is a trusted private service and may persist plaintext user-supplied
  model, MCP, and AWS credentials. Do not return stored secret values from
  ordinary read/list APIs or place them in test fixtures or Git.
- MCP and Skill installation, upgrade, and removal require a revision- and
  digest-bound user confirmation. Third-party code runs through the separate
  Linux extension runner under another UID and namespaces, with a task
  workspace and only explicitly granted secrets; never fall back to in-process
  execution when isolation is unavailable.
- AWS calls use typed SDK clients. Any operation that creates, updates, exposes,
  spends, or destroys enters the common user-confirmation flow before mutation.
- Do not add Agent clusters, Agent Pools, Graph/DAG authoring, multi-tenancy,
  task priority, REST public APIs, or a standalone admin UI.

## Configuration and migrations

- Process configuration remains strict YAML loaded through Viper. The default
  path is `/etc/dirextalk-agent/config.yaml`.
- Process YAML may name the protected `service_token_file`; it never contains
  the token value.
- Mutable user configuration and credentials belong in the Agent-owned
  PostgreSQL database, not process YAML.
- Core v1 has no legacy database or public API compatibility requirement. A
  clean schema baseline may replace legacy migrations, but once the Core v1
  baseline is committed its versions and checksums become immutable.
- Large installed packages, task workspaces, uploaded files, and generated
  artifacts live under the configured Agent data directory; PostgreSQL stores
  their relative paths and digests.

## Working rules

1. Work on one observable Core v1 workflow at a time and preserve unrelated
   user changes.
2. Read the affected code, Protobuf, migration, and Core v1 contract before
   changing behavior.
3. Use the durable Task/event path for model, MCP, Skill, Knowledge, and AWS
   background work rather than creating parallel execution histories.
4. Add boundary-first tests for authentication, idempotency, persistence,
   scheduling, cancellation, confirmation, restricted execution, and recovery.
5. Update the Core v1 spec, delivery tracker, API contract, and operational
   documentation whenever behavior changes.
6. Real AWS mutation checks require an authorized disposable account and
   independent resource read-back.

Typical checks:

```text
go test ./...
go vet ./...
go build ./cmd/...
buf lint
git diff --check
```
