# Dirextalk Agent

Dirextalk Agent is a private, single-user service that owns durable agent data
for one Dirextalk deployment. It exposes versioned TLS gRPC, stores state in
PostgreSQL, and runs background work through the durable Core Task path.

## Core v1 capabilities

- Conversations and server-owned model profiles through an Eino model
  boundary.
- Durable Tasks, events, cancellation, leases, schedules, and recovery.
- Generic user confirmations for operations that need explicit approval.
- MCP and Skills with pinned revisions and isolated extension-runner execution.
- Agent-owned Knowledge sources, uploads, indexing, and semantic search.
- Typed AWS credentials, plans, and confirmed cloud changes.

The service is not a REST API, admin console, cluster, pool, graph editor, or
multi-user control plane. Product clients use their own business server; that
server is the future proxy to this Agent instance.

## Authentication and configuration

The process reads strict YAML from `/etc/dirextalk-agent/config.yaml` or the
path supplied with `--config`. YAML contains identifiers, feature gates, and
protected file paths, never credential values. The Core gRPC server uses TLS
1.3 and one deployment-generated token file:

```text
dirextalk-agent [--config PATH] migrate
dirextalk-agent [--config PATH] serve
```

`migrate` applies the Agent-owned PostgreSQL schema. `serve` starts the Core
gRPC server, worker pool, scheduler, and enabled domain compositions. Token
rotation is an atomic replacement of the protected file followed by restart;
there is no remote token-management API.

## Development

Requirements are Go, Buf/protobuf tooling, and PostgreSQL for opt-in
integration tests.

```text
go test ./...
go vet ./...
go build ./cmd/dirextalk-agent ./cmd/dirextalk-extension-runner ./cmd/dirextalk-core-runner
buf lint
```

Set `AGENT_TEST_POSTGRES_DSN` for normal PostgreSQL integration tests; Knowledge
integration also accepts `DIREXTALK_TEST_DATABASE_URL`. The authorized real AWS
lane requires `DIREXTALK_REAL_AWS_ACCEPTANCE=1`,
`DIREXTALK_COREV1_TEST_DSN`, `DIREXTALK_REAL_AWS_CREDENTIAL_CSV`, and
`DIREXTALK_REAL_AWS_ACCOUNT_ID`; `DIREXTALK_REAL_AWS_REGION` is optional and
defaults to `us-east-1`.

The Linux extension isolation lane is opt-in because it needs a delegated
cgroup-v2 subtree and user/mount namespace support. Set
`DIREXTALK_EXTENSION_RUNNER_INTEGRATION=1` and point
`DIREXTALK_EXTENSION_RUNNER_CGROUP_ROOT` at that subtree. The acceptance test
covers the detached filesystem, denied network, explicit secret visibility,
descendant cancellation, and verified cgroup removal.

The authorized AWS lane completed on 2026-07-25: the production typed provider
and Agent confirmation/Task path created and independently read back exactly
one tagged idle SQS queue in one CloudFormation stack, then confirmed and
deleted it; independent deletion verification and a post-run prefix audit found
zero active stacks or queues.

See [the API contract](docs/api-contract.md),
[architecture](docs/architecture.md), and the
[Core v1 development specification](docs/core-v1-development-spec.md).
