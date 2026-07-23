# Dirextalk Agent

Dirextalk Agent is a reusable, single-tenant control service for durable AI
tasks, typed cloud planning/control, exclusive Workers, Recipes, and managed
resource lifecycle. It is intentionally independent of Matrix, ProductCore,
Flutter, Connect, vNext, deployer, and updater contracts.

## Source of truth

- [docs/delivery-tracker.md](docs/delivery-tracker.md) records the current
  product state, open acceptance work, and delivery priorities.
- Versioned Protobuf under `api/proto/dirextalk/agent/v1` is the public API.
- `migrations` is the sole Agent database schema authority.
- Repository-local container and CloudFormation assets own this service's
  deployment boundary; do not change another repository to implement it.

## Non-negotiable boundaries

- One Agent instance serves one project and one Agent-owned PostgreSQL
  database/role. It may share a PostgreSQL 18 server, but never a database,
  schema, migration ledger, role, or credential with another service.
- The control process is non-root and may use typed AWS SDK clients only. It
  must never expose shell execution, Docker access, arbitrary provider APIs,
  or arbitrary HTTP credentials to a model.
- Root work runs only inside one exclusive Cloud Worker VM. Workers never hold
  IAM, EC2, EBS, or Foundation-control credentials.
- Service keys authenticate caller services. Spending, network exposure,
  secret delivery, managed acceptance, and destruction require separately
  verified device approval.
- Secrets enter through protected mounted files or the encrypted bootstrap
  protocol only. Never put secret bytes in configuration, prompts, gRPC
  messages, logs, events, fixtures, command arguments, or Git.
- Use Go and CloudFormation YAML. Do not add Node/npm, AWS CLI orchestration,
  local MCP daemons, Docker sockets, or raw provider passthrough.

## Configuration and migrations

- Process configuration is strict YAML loaded through Viper. The default path
  is `/etc/dirextalk-agent/config.yaml`; configuration holds paths and
  non-secret policy only, never secret values.
- The migration bundle preserves the original virtual migration versions and
  byte-level checksums. Do not reformat, renumber, combine transaction
  boundaries, or remove a virtual migration without an explicit compatible
  migration strategy and PostgreSQL evidence.

## Working rules

1. Work on one observable workflow at a time. Preserve public protobuf,
   authorization, persistence, approval, and ownership contracts.
2. Read the local code and affected contract before changing behavior. Keep
   the smallest coherent diff; preserve unrelated user work.
3. Add boundary-first tests for authentication, approvals, persistence,
   concurrency, billing mutations, and public contracts.
4. Run affected checks, inspect the accumulated diff once, and update current
   operational/product documentation with the same change.
5. Run PostgreSQL and real-AWS checks only through their explicit integration
   or release lanes. Real cloud work requires an authorized disposable account
   and independent resource read-back.

Typical checks:

```text
go test ./...
go vet ./...
go build ./cmd/...
buf lint
git diff --check
```
