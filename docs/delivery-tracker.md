# Core v1 delivery tracker

This tracker describes the current independent Agent contract and its
verification. External product work is not included.

## Implemented Core v1

- Core-only `dirextalk-agent` entrypoint with `migrate` and `serve`.
- TLS 1.3 gRPC server with protected `DTX-Agent-Token` authentication,
  optional health/reflection, and capability/instance discovery.
- PostgreSQL-backed model profiles, conversations, Tasks, events, schedules,
  confirmation records, and fenced recovery paths.
- Eino-adapted model calls inside the durable conversation and Task execution
  paths, without moving Task recovery or tool ledgers into an opaque graph.
- Core MCP/Skill lifecycle RPCs and isolated extension-runner composition.
- Current-only extension execution: the obsolete in-process/legacy sandbox
  surface is removed, and execution uses the descriptor-only Linux boundary.
- Core Knowledge uploads, mounts, memory, indexing/search composition.
- Typed Core AWS credentials, plans, and confirmation-bound change composition.
- Versioned Core Protobufs and Core-focused contract tests.
- `WorkloadService` planning/confirmation and a fenced `WORKLOAD` Task path.
- Optional Core Runner protocol: nonce/full readiness, descriptor-only sealed
  result export, exact tmpfs writable quota, zero persistent raw output, and
  restart `cleanup_required` reconciliation.

## Verification status

The Core acceptance suite covers the ten scenarios listed in the [Core v1
specification](core-v1-development-spec.md). Local verification uses:

```text
go test ./...
go vet ./...
go build ./cmd/dirextalk-agent ./cmd/dirextalk-extension-runner
buf lint
git diff --check
```

Set `AGENT_TEST_POSTGRES_DSN` for opt-in PostgreSQL integration tests; Knowledge
integration also accepts `DIREXTALK_TEST_DATABASE_URL`.

The opt-in Linux isolation acceptance passed both in a privileged cgroup-v2
test environment and in a non-root delegated systemd user scope. It verifies
the detached root, hidden host/config paths, denied network, exact secret
exposure, descendant creation, cancellation through `cgroup.kill`, the
`populated 0` read-back, workspace cleanup, and zero process/cgroup residue.

The final local acceptance run completed 435 tests across 24 packages in both
normal and race modes. Vet, both command builds, Buf lint, deterministic
Protobuf generation, formatting, module tidiness, and diff checks also passed.

On 2026-07-25, an explicitly authorized real AWS Core lifecycle ran in
`us-east-1` through the production typed provider and Agent confirmation/durable
Task path. It created exactly one CloudFormation stack containing one tagged
idle SQS queue; independent stack, resource, and tag read-back succeeded. The
stack was deleted through Agent confirmation/Task, deletion was independently
verified, and a post-run prefix audit found zero active stacks or queues. This
delivery evidence is separate from the Agent runtime boundary.

## Maintenance policy

Runner-focused verification passed without credentials: `go test -race
./internal/coreworkload/runner ./internal/extensionrunner`, focused Core Runner
and Agent command/config/app tests, `go build ./cmd/...`, `git diff --check`,
and `TestLinuxIsolationIntegrationOptIn` in a transient non-root delegated
systemd user scope. This is extension-isolation lane evidence only.

Production SSM/ECS registry wiring is implemented with independent
`workload.aws_ssm`/`workload.aws_ecs` capabilities, durable verified-credential
and strict reference-only ARN adapters, and exact target multiplexer routing.
Startup performs no AWS calls; the first explicit provider action performs the
configured exact-target probe and reports failures as per-operation
preconditions. Two-Compose E2E, live AWS workload acceptance, and real Core
Runner workload acceptance remain pending. Runtime probe failure continues to
leave `workload.core_runner` disabled while planning RPCs remain available.

## Product boundary

Product adapters, REST, admin UI, multi-user/RBAC, clusters, pools,
graph/DAG authoring, task priority, and deployment automation are not part of
the Agent runtime. The real-account AWS lifecycle above is delivery validation,
separate from these runtime and product boundaries.

See [the Core v1 specification](core-v1-development-spec.md),
[architecture](architecture.md), and [API contract](api-contract.md) for the
stable boundaries.
