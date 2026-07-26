# Core v1 API contract

The canonical public contract is the versioned Protobuf under
[`api/proto/dirextalk/agent/v1`](../api/proto/dirextalk/agent/v1). Generated Go
files are derived artifacts; the `.proto` files are the review surface.

## Services

The Core server may register these services, subject to configuration gates:

- `AgentService` for capabilities and instance information;
- `ModelProfileService` and `ConversationService`;
- `TaskService` and `ScheduleService`;
- `ConfirmationService`;
- `MCPService` and `SkillService`;
- `CoreKnowledgeService`;
- `CoreCloudControlService`.
- `WorkloadService` for durable workload planning and operations.

Health and reflection are optional server features. No REST API, admin UI, or
multi-user authorization surface is part of Core v1.

## Transport and authentication

The server uses TLS 1.3. A deployment-generated token is read from the
protected `service_token_file`; the token value is never stored in PostgreSQL
or returned by an API. Calls carry:

```text
authorization: DTX-Agent-Token <unpadded-base64url-32-byte-token>
```

The server compares the token in constant time and strips authorization
metadata before invoking a handler. Rotation is an atomic file replacement
followed by restart. There is no remote token-management API, caller scope,
role, device, or multi-tenant model.

## Mutation invariants

- Mutations use UUID idempotency keys where defined by the Protobuf.
- Revision-bearing mutations require the caller's expected revision; stale
  writes fail without changing state.
- Durable Task events and results are fenced by Task revision, attempt, and
  lease epoch. `WatchEvents` resumes strictly after its supplied sequence.
- Stored credentials and other secret values are write-only from ordinary
  read/list RPCs. Responses expose configuration status or fingerprints, not
  secret bytes.
- Unknown enum values, malformed UUIDs, invalid digests, and unsupported
  combinations fail closed as `INVALID_ARGUMENT` or `FAILED_PRECONDITION`.

## Core workflows

`TaskService` creates, reads, lists, cancels, retries, deletes, and watches
durable Tasks. Tasks can reference a model profile, conversation, attachments,
Knowledge sources, and pinned MCP/Skill selections. `ScheduleService` creates
one independent Task per one-time or Cron occurrence; it is not a graph or
priority scheduler.

`ConversationService` provides durable `Chat` and streaming `StreamChat` over
server-owned model profiles. Model calls, extension calls, Knowledge context,
and attachment reads use the Task execution snapshot when background work is
required.

`ConfirmationService` is the common explicit-confirmation boundary. MCP/Skill
installation, upgrade, and removal, plus AWS operations that create, update,
expose, spend, or destroy resources, must bind a confirmation to the exact
target revision and content/parameter digests before side effects.

`MCPService` and `SkillService` use pinned source versions and artifact/content
digests. Local stdio and Skill execution can occur only through the separate
Linux extension runner and its isolated namespaces. Remote MCP uses the exact
confirmed HTTPS endpoint. Secret resolution requires the exact installation,
version, reference, declared purpose, and binding digest; an empty or mismatched
purpose fails closed. Cancellation is reported as complete only after the
runner proves the delegated cgroup is empty and removed. The Agent never falls
back to in-process third-party execution.

`CoreKnowledgeService` owns mounts, uploads, memory sources, status, indexing,
and search for this Agent instance. Search and Task context are bound to exact
source revisions and index bindings.

`CoreCloudControlService` exposes typed AWS credentials, `TestCredentialIdentity`
identity checks, plans, quotes, and confirmed changes. It does not expose arbitrary AWS SDK calls or
let model/tool arguments bypass confirmation.

`WorkloadService` plans and confirms work durably. Its `WORKLOAD` Task handler
uses the normal revision/attempt/lease-epoch fence. The optional local Core
Runner is not a public transport: it accepts descriptor-only Unix packets,
exports sealed results, and has no raw secret or Agent credential channel.
`workload.core_runner` is advertised only after a nonce-backed full readiness
probe, including its bounded userns/tmpfs/seccomp/cgroup exercise. Supervisor
restart recovery persists `cleanup_required` before exact cgroup reaping;
cleanup uncertainty fails closed and does not create a successful destroy.

Typed SSM/ECS registry execution is wired behind `core_aws_enabled`; startup
only constructs clients and resolvers, while credential verification, strict
ARN target binding, and AWS identity/read-back checks happen per operation.
Workload secret grants accept legacy UUID references or canonical Secrets
Manager/SSM ARNs; ARN grants bind confirmation to a versioned ARN-plus-purpose
digest, and AWS execution rejects UUID application references. Credential
resolution requires the current verified revision and exact stored principal
ARN, which must match STS before any resource call.
Two-Compose E2E, live AWS workload acceptance, and live Core Runner workload
acceptance remain pending; the documented isolation lane is not a live
Core-mode release claim.

## Contract changes

Core v1 has no public-API or database compatibility requirement. Any Protobuf
change must update the corresponding documentation and focused contract tests
in the same change.
