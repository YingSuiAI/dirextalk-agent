# Dirextalk Agent

This repository owns the reusable, single-tenant Dirextalk Agent service: Eino runtime, durable tasks, cloud plans, AWS control, Worker protocol, recipes, and managed-resource lifecycle.

`docs/delivery-tracker.md` is the authoritative goal and progress ledger. Read its fixed decisions and the current highest-priority incomplete stage before implementation. Check an item only after its observable capability and stage checks pass; do not create competing task plans in other repositories.

## Boundaries

- The canonical public API is versioned Protobuf/gRPC under `api/proto/dirextalk/agent/v1`.
- One deployment serves one project and one Agent-owned PostgreSQL database/role. It may share the same PostgreSQL 18 server or container with Message Server, but never its database, schema, role, or migrations. `agent_instance_id` is immutable and is part of every cloud-resource ownership tag.
- The control service is one non-root process/container. It may use typed AWS SDK clients but must never execute user shell commands or expose arbitrary AWS APIs to an LLM.
- Root automation runs only inside an exclusive Cloud Worker VM. Workers never receive IAM, EC2, EBS, or foundation-control credentials.
- Service keys authenticate caller services only. Spending, network exposure, secret delivery, managed acceptance, and destruction require a separately verified device approval.
- Secrets enter only through mounted secret files or the encrypted bootstrap protocol. Never place secret material in prompts, ordinary gRPC messages, logs, events, tests, fixtures, command arguments, or Git.
- Keep this repository independent from Matrix, ProductCore, Flutter routes, MXIDs, Dirextalk rooms, deployer scripts, updater logic, Connect, and vNext Run contracts.
- Use Go and CloudFormation YAML. Do not add Node/npm, AWS CLI orchestration, local MCP daemons, Docker socket access, or raw provider passthrough.

## Structure

- `cmd/dirextalk-agent`: control service and migration entry point.
- `cmd/dirextalk-cloud-worker`: exclusive VM Worker.
- `cmd/dirextalk-aws-reaper`: AWS-side expiry safety net.
- `internal/task`: task, step, lease, idempotency, and event domain.
- `internal/agent`: generic Eino runtime and native skills.
- `internal/cloud`, `internal/awsprovider`, `internal/awsfoundation`: typed cloud control.
- `internal/worker`, `internal/recipe`: Worker protocol and validated recipes.
- `migrations`: the only Agent database schema authority.

## Work And Verification

Implement one observable workflow at a time. Add boundary-first tests for authentication, approvals, persistence, concurrency, billing mutations, and public contracts; batch internal scaffolding. At stage close run the affected tests, build all commands, inspect the accumulated diff once, and update `docs/delivery-tracker.md`.

Typical checks:

```text
go test ./...
go vet ./...
go build ./cmd/...
buf lint
git diff --check
```

Run PostgreSQL and real-AWS tests only through their explicit integration/release lanes. Real cloud tests require an authorized disposable account and must finish with independent resource read-back.

IDE run configurations are optional local tooling. Never expose their environment values.
