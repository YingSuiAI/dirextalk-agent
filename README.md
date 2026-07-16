# Dirextalk Agent

Dirextalk Agent is a reusable, single-tenant control service for persistent AI tasks and typed cloud workloads. It exposes a versioned gRPC API, stores all durable facts in PostgreSQL, plans work through Eino, and runs privileged installation only on exclusive cloud Workers.

The control container does not depend on Matrix or ProductCore and does not run arbitrary user commands. Projects integrate through a pairwise service key and keep their own user-facing transport and authentication.

## Current delivery

The first vertical slice provides service-key authentication, durable Task creation/cancellation, idempotency, revision fencing, and cursor-resumable events. AWS, Worker, Eino, and Message Server cutover progress is tracked in [docs/delivery-tracker.md](docs/delivery-tracker.md).

## Development

Requirements: Go 1.26, Buf, Protobuf compiler, and the workspace PostgreSQL 18 service for integration tests.

```powershell
buf generate
go test ./...
go build ./cmd/...
```

Production startup requires TLS certificate/key files, a PostgreSQL DSN, an immutable instance ID, a service-key pepper file, and an initial service-key file. Secret values must be mounted as files rather than supplied in command arguments.

## P0 operation

The control process has three commands: `migrate`, `bootstrap-service-key`, and `serve`. All three use the same immutable `AGENT_INSTANCE_ID` and read the PostgreSQL DSN from `AGENT_DATABASE_URL_FILE`; the legacy plaintext `AGENT_DATABASE_URL` environment variable is deliberately ignored.

`serve` additionally requires:

- `AGENT_GRPC_LISTEN` (defaults to `:9443`).
- `AGENT_TLS_CERT_FILE` and a protected `AGENT_TLS_KEY_FILE`.
- `AGENT_SERVICE_KEY_PEPPER_FILE` containing at least 32 bytes of random material.

`bootstrap-service-key` additionally requires a protected `AGENT_BOOTSTRAP_SERVICE_KEY_FILE`, `AGENT_BOOTSTRAP_CLIENT_ID`, and optional comma-separated `AGENT_BOOTSTRAP_SCOPES`. The key file contains `key_id.<32-byte-base64url-secret>`. Generate it outside the process, mount it read-only, and never place its value in shell history, Compose YAML, logs, or source control.

On Linux, DSN, TLS private key, pepper, and bootstrap key files must be regular files without group/world permission bits. Run `migrate` before bootstrap or serve; startup rejects a database owned by another `agent_instance_id` or a migration whose recorded checksum differs.

P0 PostgreSQL integration checks are opt-in and documented in [test/integration/p0/README.md](test/integration/p0/README.md). Later Runtime, AWS, and Worker surfaces report disabled capabilities or `UNIMPLEMENTED` until their tracker stage is accepted.

The Agent requires an independent logical database and role, not an independent PostgreSQL process. A Dirextalk deployment should reuse the existing Message Server PostgreSQL 18 server/container and create a separate Agent database and least-privilege role. Agent and Message Server must not share tables, schemas, migration ledgers, or database credentials.
