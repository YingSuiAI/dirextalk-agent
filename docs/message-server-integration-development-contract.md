# Message Server and workload integration contract

Status: approved implementation target, not current behavior  
Approved: 2026-07-25  
Agent baseline: `11eed51e2a9e6431f28039a542f2424f290e6fff`

The cross-repository product contract is owned by the Message Server document
`docs/agent-core-integration-development-contract.md` in the companion
repository. This document freezes the Agent-owned portion.

## Scope

Agent Core remains a one-deployment, one-owner private service reached only by
Message Server over TLS gRPC. This integration adds:

- production Chat/StreamChat support for selected MCP and Skills;
- model-profile synchronization using a stable client profile reference;
- arbitrary, owner-confirmed Core-host workload installation;
- arbitrary CloudFormation, EC2+SSM, and ECS deployment workflows;
- container/release assets for an Agent-owned Compose project; and
- contract and end-to-end tests used by the Message Server adapter.

Flutter, ProductCore JSON DTOs, Matrix rooms, and the embedded Eino runtime are
not owned here.

## Conversation and extension correctness

The current production composition rejects every non-empty Chat/StreamChat
`extensions` and `knowledge_refs`, and constructs the conversation service
without a production extension resolver. This is a release-blocking defect for
this integration.

The corrected path must:

1. accept exact installed MCP/Skill selections;
2. resolve installation, pinned version, content/artifact digest, allowed tool
   names, network grants, and secret bindings before model execution;
3. seal the resolved selection into the chat claim/snapshot;
4. provide MCP tool schemas to the model and Skill instructions as bounded,
   untrusted instructions;
5. execute tool calls through the existing isolated Runner/dispatcher;
6. persist tool summaries and related Task IDs in the durable conversation;
7. fail closed on drift, unavailable Runner composition, or missing grants; and
8. preserve idempotency for unary and streaming retries.

Knowledge references may be enabled only after the same snapshot/drift
invariants are implemented for conversation Chat. They must not remain
advertised while production RPCs reject them without an explicit disabled
capability.

Required production-composition tests cover unary and streaming chat with:

- one pinned MCP tool;
- one pinned Skill;
- combined selection;
- retry with the same idempotency key;
- changed digest/revision rejection;
- Runner unavailable/cancelled;
- secret/network grant mismatch; and
- process/service recreation.

The Message Server integration does not use the current request-context-owned
`StreamChat` as its durable transport. `ConversationService` adds:

- `StartTurn`
- `GetTurn`
- `WatchTurnEvents`
- `CancelTurn`

`StartTurn` durably binds the caller UUID/idempotency key, request digest,
conversation and expected revision, model-profile snapshot, prompt, and
extension/Knowledge selections before returning. A lease-driven executor owns
the turn independently of the initiating gRPC context. Turn events and terminal
results are durable and sequence-numbered.

`WatchTurnEvents` resumes strictly after `after_sequence` and reports replay
bounds on a gap. `CancelTurn` is idempotent and revision-aware. A previously
committed terminal result wins a cancellation race; otherwise cancelled is
terminal only after the active lease and all delegated execution are fenced and
cleaned. Restart recovery resumes or reconciles accepted turns without creating
a new request ID or resubmitting an already claimed prompt.

## Model profile synchronization

Core model profiles add an optional, unique `client_profile_id` scoped to the
Agent instance. It is a stable non-secret reference from the owner client's
single model configuration page.

Sync behavior:

- create is idempotent by `client_profile_id` and request UUID;
- update requires the current Core revision;
- an omitted API key preserves the configured key;
- a non-empty API key rotates it without returning it;
- reads return only `api_key_configured` and safe metadata;
- duplicate client references fail closed; and
- explicit delete remains separate from automatic synchronization.

`ModelProfileService.Sync` is an atomic batch RPC. The request carries a batch
idempotency UUID, `default_client_profile_id`, and entries containing a stable
`client_profile_id`, optional expected Core revision, full public settings, and
an optional write-only API key. Missing profiles are preserved.

The store validates and applies profile changes plus default selection in one
transaction. One invalid/stale entry changes nothing. A same-key/same-digest
replay returns the original sanitized result; the same key with different
content conflicts. The default reference must resolve to a profile in the
resulting state.

The supported providers remain OpenAI-compatible, Anthropic, and Gemini with
owner-provided credentials.

## Confirmation boundary

MCP/Skill lifecycle, arbitrary commands, local workload exposure, CloudFormation
changes, EC2 SSM commands, ECS deployments, and destruction use
`ConfirmationService`.

Ordinary owner data mutations—conversation records/chat, atomic model sync,
task cancel/retry, and AWS credential record CRUD—use authentication,
idempotency and revisions but do not consume `ConfirmationService`.

Confirming installation of an exact MCP/Skill version makes it discoverable and
selectable; it does not authorize later side effects. Only code-shipped,
contract-tested read-only tools may execute without a per-call confirmation.
Every third-party, unknown/unclassified, secret-using, network-changing, or
side-effecting tool call requires a new durable confirmation binding its exact
tool/version/digest, argument summary, target revision, and grants.

The originating durable turn records `confirmation_required` before execution,
pauses without releasing its request identity, and resumes the same tool step
only after confirmation consumption. Rejection/expiry produces a durable tool
denial; it cannot silently choose another tool/backend or execute first.

A confirmation binds:

- operation and target kind/ID/revision;
- normalized plan and content digest;
- source/artifact/image digest;
- exact command steps or CloudFormation template/parameters;
- AWS credential reference, account, region, and target;
- network exposure;
- secret references and purposes;
- quote/impact summary; and
- expiry.

Confirming does not execute inline. It consumes the confirmation into a durable
Task. Rejection/expiry is terminal. A changed plan requires a new confirmation.
Unknown execution outcomes are fenced and reported as uncertain, never blindly
replayed.

## Workload API

Add a versioned `WorkloadService` to the Core v1 Protobuf with:

- `Plan`
- `Get`
- `List`
- `Quote`
- `RequestApply`
- `RequestDestroy`

The canonical workload targets are:

- `CORE_RUNNER`
- `AWS_EC2_SSM`
- `AWS_ECS`

A plan contains an immutable revision and digest, owner-visible summary,
artifact/source description, command steps or image digest, target settings,
network and secret grants, resource limits, and expiry. Apply/destroy return
the created confirmation and durable Task identity.

There is no interactive terminal RPC. The model may help construct a plan, but
model/tool output cannot confirm or bypass it.

Workloads use a distinct `WORKLOAD` Task kind and payload; they do not overload
the current CloudFormation-only `AWS_CHANGE` kind. The payload pins workload,
plan and operation IDs, plan revision/digest, target kind, confirmation ID, and
the execution snapshot. Task validation and the database task-kind constraint
add this branch explicitly.

`RequestApply`/`RequestDestroy` atomically create the requested workload
operation, a waiting Task, and a pending Confirmation, following the existing
AWS coordinator pattern. `ConfirmationService.Confirm` only changes approval
state; it does not enqueue or execute inline. A fenced Workload Task handler
consumes the exact confirmed operation, dispatches the target provider, records
events/read-back, and owns the single terminal transition.

### Core Runner target

Arbitrary installation commands execute only through a separate Runner
identity. They never execute in the Core API/migration process.

The first implementation favors functionality but still requires:

- a separate non-root UID and non-privileged process/container boundary;
- detached root, isolated namespaces, seccomp, and a task cgroup-v2;
- a task/workload-owned filesystem root and read-only fixed inputs;
- an empty base environment plus explicit variables and secret grants;
- deny-by-default egress with exact confirmed host grants;
- no privileged mode, added capabilities, devices, Docker socket, or host
  mounts;
- CPU, memory, process, disk, time, and output quotas;
- bounded stdout/stderr capture with redaction;
- descendant cancellation with cgroup `populated 0` and removal proof;
- restart-time workload supervisor reconciliation; and
- a durable workload record for long-running services.

Services must be started by an explicit workload supervisor/runtime contract;
they cannot survive accidentally as orphan children.

### AWS EC2 SSM target

Core uses typed AWS SDK clients to:

1. plan/provision or select an EC2 instance;
2. verify account, region, instance identity, tags, and SSM readiness;
3. submit the exact confirmed command document/parameters;
4. poll command invocation to a durable terminal state;
5. independently read back the service/resource state; and
6. destroy only through a new confirmation.

The product does not open or manage SSH. Commands may install arbitrary
services because the owner explicitly approved their exact digest.

### AWS ECS target

Core can deploy an arbitrary OCI workload. Confirmation pins:

- registry and image digest;
- cluster/service/task definition revisions;
- CPU/memory/count;
- ports, load balancer and public/private exposure;
- secret references;
- account/region/tags; and
- create/update/destroy impact.

Tags identify the owning Agent instance and workload. Core independently reads
back the running task definition and service state after a mutation.

### Existing CloudFormation

The current typed CloudFormation credential/plan/quote/change contract remains
supported. Workload plans may compose it but do not replace its confirmation,
fencing, or read-back guarantees. Arbitrary SDK and shell arguments may not
bypass a confirmed CloudFormation/SSM/ECS plan.

## Scheduling

Scheduled deployment work may create or refresh a plan and pending
confirmation. It must not consume a confirmation or mutate/spend automatically.
The owner manually confirms every apply, update, command, exposure, and destroy
operation.

## Service composition and capabilities

`AgentService.GetCapabilities` advertises a capability only when its production
composition is usable. At minimum:

- `agent.info`, `model.profile`, and `conversation` are the minimum basic-chat
  set;
- `conversation.extensions` only when chat extension resolution and Runner
  dispatch are wired;
- `task`, `schedule`, `confirmation`, `mcp`, `skill`, `knowledge`, and
  `aws.control` retain their exact current meanings;
- `workload.core_runner` only when the workload Runner is ready;
- `workload.aws_ssm` only when the AWS provider supports the required calls;
- `workload.aws_ecs` only when the AWS provider supports the required calls.

Registration alone is not readiness. Configuration-disabled or partially
wired services report disabled.

## Deployment assets

The repository adds:

- a reproducible Agent Core image;
- a migration image/command using the same immutable revision;
- a separate Runner image;
- an Agent-owned Compose project with its own PostgreSQL and volumes;
- health/readiness checks;
- protected-file examples for database URL, TLS key/cert, service token, model
  and AWS secrets; and
- a runbook for token/certificate rotation, migration, backup, upgrade and
  rollback.

Agent gRPC is exposed only on the shared private integration network in the
local two-project test. No Message Server database/data volume or Docker socket
is mounted.

## Acceptance

Focused checks must prove:

- protobuf generation and breaking checks;
- all existing Core tests;
- real Chat/StreamChat model exchange through the production composition;
- MCP and Skill installation, confirmation, invocation and cleanup;
- Core Runner arbitrary install success/failure/cancel;
- fake AWS CloudFormation, SSM and ECS create/read-back/destroy;
- crash/restart recovery and idempotency;
- secret and error redaction;
- Agent image/migration/Runner image builds; and
- authenticated TLS operation from the separate Message Server project.

Real provider acceptance is performed only with explicit account, region,
budget and owner confirmations. Evidence records immutable revisions and
proves cleanup independently.
