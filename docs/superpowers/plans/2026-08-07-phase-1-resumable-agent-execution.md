# Phase 1 Implementation Plan: Resumable Agent Execution

Date: 2026-08-07

Design authority:
`docs/superpowers/specs/2026-08-07-product-agent-capability-migration-design.md`

## Objective

Remove the eight-round product termination behavior without creating an
unbounded loop. Productive work continues under the task's durable deadline;
repeated identical tool work stops as `agent_no_progress`; a large internal
ledger fuse remains only for fault containment.

## Slice 1: Durable rounds beyond eight

Files:

- `internal/coretask/execution.go`
- `internal/coretask/execution_test.go`
- `internal/store/postgres/core_task_ledger.go`
- `migrations/agent_migrations.sql`
- `migrations/embed.go`
- `migrations/bundle_test.go`

Changes:

1. Introduce a versioned Agent execution policy in the immutable task
   snapshot.
2. Use a 512-round internal ledger fuse, distinct from a user-facing task
   limit.
3. Add migration 4 to widen the model/tool round constraints without changing
   migrations 1-3.
4. Prove round 8 and round 511 are valid while round 512 is rejected.

## Slice 2: No-progress watchdog

Files:

- `internal/coreruntime/bounded_agent.go`
- `internal/coreruntime/bounded_agent_test.go`
- `internal/coreruntime/runtime.go`
- `internal/store/postgres/core_task_snapshot.go`

Changes:

1. Bind the default policy into newly created Agent task snapshots.
2. Build a deterministic round-progress digest from tool name, canonical
   arguments, and redacted durable result.
3. Continue when tool state changes, including beyond eight rounds.
4. Stop after five consecutive identical tool round digests.
5. Classify internal fuse and no-progress failures separately.

## Slice 3: Contract and evidence

Files:

- `docs/core-v1-development-spec.md`
- `docs/api-contract.md`
- `docs/delivery-tracker.md`

Changes:

1. Document deadline, no-progress, and internal-fuse semantics.
2. Record exact verification commands and remaining gates.

## Verification

Focused Windows-compatible checks:

```text
go test ./internal/coretask ./internal/coreruntime ./internal/store/postgres ./migrations
go vet ./internal/coretask ./internal/coreruntime ./internal/store/postgres ./migrations
go build ./cmd/dirextalk-agent
git diff --check
```

Required Linux CI before merge:

```text
go test ./...
go vet ./...
go build ./cmd/...
buf lint
```

PostgreSQL acceptance must run migration 4 against a database with migrations
1-3 already applied and prove that completed rounds above seven survive
restart and replay.

## Stop Conditions

- Do not add image behavior.
- Do not create another task table or Agent loop.
- Do not expose the internal fuse as a normal user budget.
- Stop the phase if widening the ledger requires weakening lease/revision
  fencing or uncertain-outcome handling.
