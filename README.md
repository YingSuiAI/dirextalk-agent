# Dirextalk Agent

Dirextalk Agent is a reusable, single-tenant control service for persistent AI
tasks and typed cloud workloads. It exposes versioned gRPC, persists durable
facts in PostgreSQL, runs Eino only through typed tools, and delegates
privileged execution to an exclusive Cloud Worker VM.

It is independent of Matrix, ProductCore, Flutter, and the legacy deployer.
Other services integrate directly over TLS gRPC with a scoped pairwise Service
Key and retain their own user-facing transport and authentication.

## What it provides

- Durable Tasks, Steps, idempotency, revision/lease fencing, cancellation, and
  resumable events.
- Persisted AI conversations with `RuntimeService.Chat` and `StreamChat`,
  server-owned model profiles, mounted secret references, and restricted
  planning tools.
- Typed AWS identity, quote, plan, approval, Foundation, Worker, resource,
  lifecycle, and recovery capabilities behind a default-off control gate.
- Controlled Knowledge configuration, ingestion, search, and retained
  lifecycle operations through the exclusive Worker boundary.

See [the API contract](docs/api-contract.md) and
[architecture](docs/architecture.md) for the public and security boundaries.

## Configuration

The process reads a strict YAML configuration through Viper. Its default path
is `/etc/dirextalk-agent/config.yaml`; use `--config <path>` for a different
location. `AGENT_CONFIG_FILE` remains a compatibility-only path override. No
operational `AGENT_*` setting is required by the service itself.

Start from
[deploy/container/config/config.example.yaml](deploy/container/config/config.example.yaml).
The file contains identifiers, feature gates, and mounted-file paths only;
never place a DSN, TLS private key, service key, model credential, or other
secret value in it. The runtime model-secret directory must be distinct from
the Docker secret directory so a `mounted:<name>` model reference cannot resolve
database, TLS, pepper, or master-key files.

The commands are:

```text
dirextalk-agent [--config PATH] migrate
dirextalk-agent [--config PATH] bootstrap-service-key
dirextalk-agent [--config PATH] bootstrap-approval-device
dirextalk-agent [--config PATH] healthcheck
dirextalk-agent [--config PATH] serve
```

`migrate` and `bootstrap-service-key` must complete before `serve`. The same
immutable `instance_id` and Agent-owned PostgreSQL database/role must be used
for every command. On Linux, mounted secret files must be regular and not
group/world-readable.

## Docker Compose

Two deployment forms are provided; neither runs a local Worker or Reaper,
because those have exclusive VM and AWS Lambda boundaries.

- `deploy/container/compose.local.yaml` is the local multi-container stack:
  PostgreSQL 18 → migration → idempotent service-key bootstrap → Agent. Supply
  immutable image references, host paths to the non-secret YAML config, and
  host secret-file paths, then run:

  ```text
  docker compose -f deploy/container/compose.local.yaml config --quiet
  docker compose -f deploy/container/compose.local.yaml up -d
  ```

- `deploy/container/compose.yaml` keeps the production-style external
  PostgreSQL boundary. Run migration and bootstrap explicitly, then start the
  Agent. Add `compose.shared-postgres.yaml` only to join an existing database
  network; it does not own or change that PostgreSQL container.

Detailed mount, secret, and release guidance is in
[deploy/container/README.md](deploy/container/README.md).

## Development

Requirements: Go 1.26, Buf, Protobuf compiler, and PostgreSQL 18 only for the
opt-in integration lanes.

```text
buf generate
go test ./...
go vet ./...
go build ./cmd/...
buf lint
```

`AGENT_TEST_POSTGRES_DSN` enables PostgreSQL integration checks. Real AWS
tests, image publication, AMI operations, and destructive resource checks need
separate authorization and independent read-back.

## Delivery status

The durable task/runtime and first-validation AWS/Worker/Knowledge code paths
are implemented and locally or fake-provider tested. Real ECR publication,
Worker AMI build/verification/destruction, and end-to-end AWS product
acceptance have not been run; keep AWS control off in production until those
gates close. The concise current status and priorities are in
[docs/delivery-tracker.md](docs/delivery-tracker.md).
