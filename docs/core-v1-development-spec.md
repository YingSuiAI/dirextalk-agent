# Dirextalk Agent Core v1 development specification

This document is the current product and implementation boundary for the
independent Agent service. The versioned Protobuf in
`api/proto/dirextalk/agent/v1` and the PostgreSQL migrations are the executable
contract. A public or schema change updates this document and its contract tests
together.

## Product boundary

- One private Agent instance serves one user and belongs to exactly one
  Dirextalk deployment.
- The service is bound one-to-one with its caller deployment, and one
  deployment-side caller consumes one Agent instance.
- The Agent runs outside the business server and owns conversations, Tasks,
  events, schedules, model profiles, prompts, extension installations,
  Knowledge metadata, and typed AWS configuration.
- A future business-server proxy calls the Agent over TLS gRPC with one
  deployment-generated service token. The token is a protected file, not a
  database value; rotation is atomic replacement plus restart.
- Core v1 changes this repository only. Product adapters, a standalone admin
  UI, and deployment automation are outside this specification.

## Public capabilities

The Core server registers `AgentService`, `ModelProfileService`,
`ConversationService`, `TaskService`, `ScheduleService`,
`ConfirmationService`, `MCPService`, `SkillService`, `CoreKnowledgeService`,
and the optionally enabled `CoreCloudControlService`. Health and reflection
are optional server features.

All mutation RPCs follow the Protobuf's UUID idempotency and expected-revision
rules. Ordinary reads never return stored secret values. Task events and
results are durable, redacted, resumable, and fenced by lease epoch and
revision.

## Acceptance scenarios

The Core v1 acceptance set covers these ten observable scenarios:

1. TLS gRPC authenticates with the protected token file; atomic token
   replacement takes effect after restart.
2. Model profiles and model execution cover the OpenAI-compatible, Anthropic,
   and Gemini providers.
3. Unary and streaming chat are durable and idempotent across retries and
   service recreation.
4. Immediate, one-time, and Cron schedules create FIFO Tasks and recover due
   work after interruption.
5. Task CRUD, retry, event watch/resume, cancellation, lease fencing, and
   concurrent mutation races preserve durable revisions.
6. MCP discovery and lifecycle cover the official registry, Smithery, Glama,
   and GitHub sources with stdio and Streamable HTTP transports.
7. Skill lifecycle covers skills.sh and GitHub pins; execution is isolated in
   the extension runner, and cancellation proves the complete descendant
   process tree and delegated cgroup are gone before the task is cleaned.
8. Knowledge covers Agent-owned mounts, bounded uploads, memory, indexing,
   and semantic search with revision and digest checks.
9. AWS fake-provider flows cover confirmation, durable recovery, and confirmed
   destroy operations; authorized real-provider lifecycle evidence is recorded
   in the AWS section below.
10. Storage remains Agent-owned and tests prove operation without a business
    server repository or shared product database.

## Domain behavior

### Conversations and models

Model profiles are Agent-owned records with provider/model settings, prompts,
sampling limits, and a protected API-key revision. Conversations provide unary
and streaming chat. Provider-neutral model calls pass through Eino's
`ToolCallingChatModel` boundary. Background work uses a Task execution snapshot
so profile, extension, Knowledge, attachment, and secret bindings cannot drift
while a request is running.

### Tasks and schedules

Tasks support immediate and scheduled execution, cancellation, retry as a new
idempotent Task, deletion, durable progress, and event replay. The supported
Task kinds are Agent, Extension, Knowledge indexing, and AWS change. A Task is
claimed with an attempt, lease epoch, and expected revision; only the fenced
owner may checkpoint or terminalize it. Schedules create independent Tasks
for one-time or Cron occurrences. Core v1 has no priority, DAG/graph, task
dependency authoring, or cluster/pool scheduler.

Eino adapts each model round, while the Agent-owned Task ledger remains the
durable orchestrator for model dispatch, tool calls, retries, recovery, and
uncertain outcomes. Core v1 does not expose Eino graphs as a user-authored
workflow surface.

### Confirmation

Confirmation is a generic durable flow for operations requiring explicit user
approval. The binding includes operation domain, target identity/revision,
source/content or parameter digests, network grants, secret grants, Task, and
expiry. Confirm/reject is revision- and idempotency-protected. MCP/Skill
installation, upgrade, removal, and AWS mutations that create, update,
expose, spend, or destroy must pass this boundary before side effects.

### MCP and Skills

Extensions are discovered from pinned sources and persisted with immutable
version, content, artifact, schema, network, and secret bindings. MCP supports
local stdio and remote HTTPS Streamable HTTP; Skills use the pinned Skill
artifact and instructions. Local code runs only through the separate Linux
extension runner with another UID, namespaces, a task workspace, and explicit
secrets. No in-process or unconfirmed fallback is allowed.

### Knowledge

Knowledge supports Agent-owned mounts, bounded uploads, memory, source status,
indexing, and semantic search. Content is opened through root-bound ports.
Task snapshots pin source revision, content digest, and index binding; search
must reject drift before context reaches the model.

### AWS

Typed AWS credentials, `TestCredentialIdentity` identity checks, plans, quotes,
and change requests are exposed through `CoreCloudControlService`. Provider calls use typed SDK clients
and durable fencing. Confirmation is mandatory for mutating or spend/exposure
operations; model and extension tools cannot bypass it.

On 2026-07-25, an explicitly authorized real AWS Core lifecycle ran in
`us-east-1` through the production typed provider and Agent confirmation/durable
Task path. It created exactly one CloudFormation stack containing one tagged
idle SQS queue; independent stack, resource, and tag read-back succeeded. The
stack was deleted through Agent confirmation/Task, deletion was independently
verified, and a post-run prefix audit found zero active stacks or queues.

## Security and data rules

- TLS 1.3 and `DTX-Agent-Token` authenticate the private gRPC boundary.
- PostgreSQL is the sole durable Agent schema authority; large files and
  artifacts live below configured Agent data roots and are referenced by
  relative path and digest.
- Third-party code receives only explicitly granted secrets and workspace
  access. Local execution uses a detached root, isolated namespaces, an empty
  environment, seccomp, and task-scoped cgroup-v2 limits. Cancellation is not
  complete until the cgroup reports `populated 0` and is removed. Isolation or
  cleanup uncertainty is a hard failure, never a fallback.
- Errors, events, logs, and ordinary API responses must not disclose secret
  values or unrestricted user/provider credentials.

## Non-goals

No REST public API, multi-user RBAC, Agent clusters or pools, task priority,
graph authoring, product adapters, or standalone admin UI is specified.
No behavior is promised beyond the current Protobuf, Core composition, and
focused tests.
