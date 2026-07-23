# Dirextalk Agent delivery status

## Purpose

Dirextalk Agent is an independent, reusable, single-tenant control service for
durable AI tasks and typed cloud workloads. This document records the current
product state and the next acceptance work; detailed historical handoffs and
closed checkpoints are intentionally not retained here.

## Fixed product boundary

- One Agent instance owns one project and one PostgreSQL database/role. It may
  reuse a PostgreSQL 18 server, never another service's database, schema,
  credentials, or migration ledger.
- The public boundary is versioned Protobuf/gRPC. Caller services use scoped,
  pairwise Service Keys; user-facing authentication and transports remain
  outside Agent.
- The control container is non-root and has no shell, Docker socket, arbitrary
  provider API, or arbitrary credential capability. Privileged work is limited
  to an exclusive Cloud Worker VM and a closed signed-command protocol.
- Device approval is mandatory for spending, network exposure, secret delivery,
  managed acceptance, and destruction. Service Keys cannot perform those
  approvals.
- AWS is the only current cloud provider. The supported execution kinds are
  `CONTROL_PLANE` and `CLOUD_WORKER`; multi-tenancy, multi-cloud, EKS,
  SageMaker, distributed training, Connect, and vNext Run are out of scope.

## Delivered capability

| Area | Current state |
| --- | --- |
| Task kernel | TLS gRPC authentication, durable Tasks/Steps, idempotency, revisions, leases, cancellation, outbox events, and cursor resume are implemented. |
| Runtime | Eino-backed persisted `Chat`/`StreamChat`, server-owned model profiles, context control, mounted secret references, optional trusted HTTP MCP metadata, and restricted Cloud Goal planning are implemented. |
| Cloud planning | Encrypted one-time AWS bootstrap, STS identity preview, typed price/quota evidence, deterministic plans, device-signed approvals, and Foundation lifecycle contracts are implemented behind an explicit gate. |
| Worker and lifecycle | Typed EC2/EBS/network resource ledger, fenced Worker enrollment/checkpoints, scoped artifacts, health evidence, DynamoDB expiry manifests, Reaper, recovery, and approved destroy flows are implemented and locally/fake-provider tested. |
| Managed Knowledge | Controlled Knowledge configuration, attachment/memory/search operations, deterministic Worker profile, backup/restore/upgrade/rollback/destroy, and cross-store recovery fencing are implemented locally. |
| Packaging | Repository-local Agent, Worker, Reaper, deterministic rootfs, ECR release, and Worker AMI operator tooling are implemented. Their real AWS publication and acceptance have not been executed. |

## Current delivery priorities

1. **Real-cloud release evidence.** From a clean revision and authorized
   disposable AWS account, publish immutable Agent/Worker/Reaper artifacts,
   build/attest/verify/destroy a Worker AMI, import the publication, and prove
   cleanup with independent read-back. Until then,
   `enable_aws_control` remains off for production use.
2. **Product façade/client cutover.** Complete the remaining Message Server
   and Flutter Cloud/Knowledge/attachment contracts, exact event projections,
   cursor recovery, and user workflows. Agent remains directly consumable via
   gRPC regardless of that façade work.
3. **End-to-end acceptance.** In an authorized account, prove the complete
   encrypted bootstrap → quote → approval → Worker → monitored lifecycle →
   approved destruction path. Do not claim an OpenClaw or knowledge-node
   deployment before that evidence exists.

## Verification policy

- Local changes require affected unit/contract tests, `go vet`, command builds,
  Buf lint when protobuf changes, and `git diff --check`.
- PostgreSQL integration tests are opt-in through `AGENT_TEST_POSTGRES_DSN` and
  must clean up their own database/role artifacts.
- AWS mutation, release, and destructive checks require explicit authority and
  independent resource read-back. Fake-provider coverage is not a production
  acceptance substitute.
- Migration sources retain their original virtual versions and checksums. Any
  schema change must preserve replay/partial-upgrade behavior or provide a
  separately tested compatibility transition.

## Documentation map

- [Architecture](architecture.md): runtime and trust boundaries.
- [API contract](api-contract.md): public gRPC and security semantics.
- [Container deployment](../deploy/container/README.md): configuration and
  Compose operation.
- [Agent image release](agent-image-release.md),
  [artifact origin](artifact-origin-release.md),
  [managed ECR verification](ecr-managed-release.md), and
  [Worker AMI release](worker-ami-release.md): current operator runbooks.
