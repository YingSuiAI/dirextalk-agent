# Agent Team Worker Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `agent.team.v1` to Agent Core v1 and restore the verified Central OS + official Pi Worker AWS execution loop without restoring the retired Native Agent runtime, Task, confirmation, or credential stacks.

**Architecture:** One `team_execution` Core Task owns each Team Plan and execution. Team-specific tables own the role DAG, Worker leases, resource ledger, results, milestones, and notification outboxes, while existing Core confirmation, encrypted AWS credentials, Capability grants, typed providers, conversation storage, and account-generation fences remain authoritative.

**Tech Stack:** Go 1.26, PostgreSQL 18, Protobuf/Buf, Dirextalk Capability API, AWS SDK v2, CloudFormation/EC2/ECR/S3/CloudWatch Logs, Pi 0.83.0.

---

## File Map

- Modify `internal/coretask/types.go`, `internal/coretask/coretask_test.go`, and `migrations/agent_migrations.sql` to add the closed `team_execution` Task kind and Team schema.
- Create `internal/coreteam/` for Team domain types, compilation, service, projections, controller, confirmation binding, results, progress, and repository ports.
- Create `internal/store/postgres/core_team_*.go` for durable Plan/execution, dispatch, Worker, result, resource, milestone, and Outbox storage.
- Create `internal/agentcapability/team/capability.go` for the `agent.team.v1` JSON operation contract.
- Create `cmd/dirextalk-agent/team_conversation_resolver.go` for the two server-owned model tools.
- Create `api/proto/dirextalk/agent/v1/core_team_worker.proto` and `internal/coreteamworker/` for the private Worker protocol.
- Restore `cmd/dirextalk-cloud-worker/`, `internal/coreteamruntime/`, `internal/coreteaminput/`, release/rootfs/AMI tooling, typed AWS lifecycle, and Reaper by capability-level port from the proven closure. Reuse both implementation and tests where ownership boundaries still match; adapt them deliberately rather than blind cherry-picking.
- Create `cmd/dirextalk-agent/core_team_compose.go` and extend current Core composition/configuration only after all readiness gates pass.

## Mandatory Reuse Gate

Before implementing or closing every Task, inspect the corresponding source
row in `docs/central-os-pi-worker-migration-design.md#61-旧闭环全链路复用矩阵`.
Record the exact old files/tests being ported and classify each as direct
implementation port, behavior-test port with Agent Core rewiring, Core-already-
supersedes, or explicit discard. A Task cannot be closed merely because new
tests pass if an accepted old failure/recovery vector was omitted.

The source worktrees are read-only references. Do not merge their branches,
make the new checkout depend on them, or include their uncommitted Worker
progress drafts. “No blind cherry-pick” does not mean “rewrite from zero”:
compatible code should be ported and simplified only after its tests pass on
the Agent Core v1 types.

### Task 1: Add The Closed Core Task Kind

**Files:**
- Modify: `internal/coretask/types.go`
- Modify: `internal/coretask/coretask_test.go`
- Modify: `api/proto/dirextalk/agent/v1/core_task.proto`
- Modify: `migrations/agent_migrations.sql`
- Modify: `migrations/core_v1_contract_test.go`

- [x] **Step 1: Write failing Task union and schema tests**

Add a test that accepts exactly this payload and rejects missing IDs, non-canonical digests, a fourth payload branch, or a model/conversation field outside the payload:

```go
func TestTeamExecutionTaskPayloadIsClosed(t *testing.T) {
	p := TeamExecutionTaskPayload{
		PlanID: "11111111-1111-4111-8111-111111111111",
		PlanRevision: 1,
		PlanDigest: strings.Repeat("a", 64),
		ExecutionID: "22222222-2222-4222-8222-222222222222",
		ConfirmationID: "33333333-3333-4333-8333-333333333333",
		ConversationID: "44444444-4444-4444-8444-444444444444",
		CredentialID: "55555555-5555-4555-8555-555555555555",
		CredentialRevision: 2,
	}
	spec := TaskSpec{Kind: TaskKindTeamExecution, Payload: TaskPayload{TeamExecution: &p}, Goal: "bounded team task", IdempotencyKey: "66666666-6666-4666-8666-666666666666"}
	if _, err := spec.Normalize(); err != nil { t.Fatal(err) }
}
```

Require the migration constraint to contain `team_execution` and the proto enum to contain `CORE_TASK_KIND_TEAM_EXECUTION`.

- [x] **Step 2: Run the focused tests and verify failure**

Run: `GOWORK=off go test ./internal/coretask ./migrations -run 'Test.*TeamExecution' -count=1`

Expected: FAIL because the kind, payload, enum, and migration constraint do not exist.

- [x] **Step 3: Implement the closed union**

Add these exact contracts and extend `normalizePayload` so exactly one payload branch is present:

```go
const TaskKindTeamExecution TaskKind = "team_execution"

type TeamExecutionTaskPayload struct {
	PlanID             string `json:"plan_id"`
	PlanRevision       uint64 `json:"plan_revision"`
	PlanDigest         string `json:"plan_digest"`
	ExecutionID        string `json:"execution_id"`
	ConfirmationID     string `json:"confirmation_id"`
	ConversationID     string `json:"conversation_id"`
	CredentialID       string `json:"credential_id"`
	CredentialRevision uint64 `json:"credential_revision"`
}

type TaskPayload struct {
	// existing branches stay unchanged
	TeamExecution *TeamExecutionTaskPayload `json:"team_execution,omitempty"`
}
```

Update the SQL check to admit `team_execution` without weakening any existing model-profile or payload constraints, then regenerate proto output with `buf generate`.

- [x] **Step 4: Run focused and contract tests**

Run: `GOWORK=off go test ./internal/coretask ./migrations ./internal/rpcapi -run 'Test.*(TeamExecution|TaskKind|Proto)' -count=1`

Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/coretask api/proto/dirextalk/agent/v1/core_task.proto api/gen/dirextalk/agent/v1 migrations
git commit -m "feat: add Core Team execution task kind"
```

### Task 2: Freeze The Team Domain And Compiler

**Files:**
- Create: `internal/coreteam/types.go`
- Create: `internal/coreteam/validation.go`
- Create: `internal/coreteam/compiler.go`
- Create: `internal/coreteam/compiler_test.go`
- Create: `internal/coreteam/repository.go`

- [x] **Step 1: Write failing closed-domain tests**

Cover one to three roles, acyclic dependencies, unique role IDs, Pi-only runtime, `t3.small`, `ap-northeast-3`, positive credential revision, output budget, quote expiry, and stable digest. Require a fourth role, unknown runtime, cycle, expired quote, free-form AWS request, or credential bytes to fail.

```go
func TestCompilerProducesBoundedPiPlan(t *testing.T) {
	plan, err := NewCompiler(fakeCatalog(), fakeQuote()).Compile(context.Background(), CompileCommand{
		OwnerID: ownerID, AccountGeneration: accountGeneration,
		Goal: "research and verify", ConversationID: conversationID,
		CredentialID: credentialID, CredentialRevision: 3,
		Roles: []RoleProposal{{RoleID: "research", Goal: "research"}, {RoleID: "review", Goal: "review", DependsOn: []string{"research"}}},
	})
	if err != nil || len(plan.Roles) != 2 || plan.Runtime.Adapter != "pi-v1" || !plan.Valid() { t.Fatalf("plan=%#v err=%v", plan, err) }
}
```

- [x] **Step 2: Verify the tests fail**

Run: `GOWORK=off go test ./internal/coreteam -run 'TestCompiler|Test.*Valid' -count=1`

Expected: FAIL because `internal/coreteam` does not exist.

- [x] **Step 3: Implement the domain**

Define these closed types and ports:

```go
const MaxRoles = 3
type PlanStatus string
const (PlanWaitingUser PlanStatus = "waiting_user"; PlanApproved PlanStatus = "approved"; PlanExpired PlanStatus = "expired")
type ExecutionStatus string
const (ExecutionQueued ExecutionStatus = "queued"; ExecutionRunning ExecutionStatus = "running"; ExecutionCleaningUp ExecutionStatus = "cleaning_up"; ExecutionCompleted ExecutionStatus = "completed"; ExecutionFailed ExecutionStatus = "failed"; ExecutionCanceled ExecutionStatus = "canceled"; ExecutionTimedOut ExecutionStatus = "timed_out")
type RuntimeBinding struct { RuntimeID, Adapter, ImageDigest, AMIID string; OutputTokens uint32 }
type QuoteBinding struct { Region, AvailabilityZone, InstanceType, Currency, Amount, HardBudget string; ExpiresAt time.Time }
type Role struct { RoleID, Goal string; DependsOn []string; Capabilities []Capability }
type Plan struct { PlanID, OwnerID, TaskID, ConversationID, CredentialID, ConfirmationID string; AccountGeneration int64; Revision, CredentialRevision uint64; Goal, Digest string; Runtime RuntimeBinding; Quote QuoteBinding; Roles []Role; Status PlanStatus }
type Compiler struct { catalog RuntimeCatalog; quotes QuoteProvider; now func() time.Time }
```

Canonical JSON must sort roles and dependencies and hash only immutable fields. No AWS SDK type, command string, URL, secret, or provider error may enter a Plan.

- [x] **Step 4: Run normal and race tests**

Run: `GOWORK=off go test ./internal/coreteam -count=1 && GOWORK=off go test -race ./internal/coreteam -count=1`

Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/coreteam
git commit -m "feat: define bounded Pi Team plans"
```

### Task 3: Persist Team Plans, Executions, Roles, And Replays

**Files:**
- Modify: `migrations/agent_migrations.sql`
- Modify: `migrations/core_v1_contract_test.go`
- Create: `internal/store/postgres/core_team_store.go`
- Create: `internal/store/postgres/core_team_store_integration_test.go`
- Modify: `internal/store/postgres/store.go`

- [x] **Step 1: Write failing PostgreSQL integration tests**

Require atomic creation of Core Task + Plan + roles + execution + replay, exact replay preservation, conflicting replay rejection, owner/account isolation, restart recovery, immutable Plan rows, monotonic execution revision, and no secret-shaped columns.

```go
created, replayed, err := store.CreateTeamPlan(ctx, command, now)
if err != nil || replayed || created.Plan.TaskID == "" { t.Fatalf("created=%#v replayed=%v err=%v", created, replayed, err) }
same, replayed, err := store.CreateTeamPlan(ctx, command, now.Add(time.Minute))
if err != nil || !replayed || same.Plan.Digest != created.Plan.Digest || !same.CreatedAt.Equal(created.CreatedAt) { t.Fatalf("same=%#v replayed=%v err=%v", same, replayed, err) }
```

- [x] **Step 2: Verify failure against disposable PostgreSQL 18**

Run: `AGENT_TEST_POSTGRES_DSN="$AGENT_TEAM_TEST_DSN" GOWORK=off go test ./internal/store/postgres -run 'TestCoreTeamStore' -count=1`

Expected: FAIL because schema and store methods are absent.

- [x] **Step 3: Add the durable schema and store**

Add closed tables named `core_team_plans`, `core_team_roles`, `core_team_executions`, `core_team_role_runs`, and `core_team_replays`. Every row includes `owner_id` and `account_generation`; Plan and role definitions are immutable; execution mutations use expected revision. `core_team_plans.task_id` references `core_tasks(task_id)` and `confirmation_id` references `core_confirmations(confirmation_id)`.

Expose this repository contract:

```go
type Repository interface {
	CreatePlan(context.Context, CreatePlanCommand) (PlanRecord, bool, error)
	GetPlan(context.Context, Scope, string) (PlanRecord, error)
	CreateExecution(context.Context, CreateExecutionCommand) (Execution, bool, error)
	GetExecution(context.Context, Scope, string) (Execution, error)
	ListExecutions(context.Context, ListQuery) (Page, error)
	CompareAndSwapExecution(context.Context, Scope, Execution, uint64) (Execution, error)
	ListRunnableRoles(context.Context, Scope, string, uint32) ([]RoleRun, error)
}
```

`CreatePlanCommand` carries the owner/account-generation scope, immutable Plan,
initial execution ID, exact Core Confirmation binding, idempotency key, request
digest, and creation time. `CreateExecutionCommand` carries the same scope and
binding around a complete retry Execution. The first Plan, Core Task, Core
Confirmation, execution, role runs, and replay record commit atomically.

- [x] **Step 4: Run migration, restart, concurrency, and race tests**

Run: `AGENT_TEST_POSTGRES_DSN="$AGENT_TEAM_TEST_DSN" GOWORK=off go test ./migrations ./internal/store/postgres -run 'Test(CoreTeam|CoreV1Contract)' -count=1 && AGENT_TEST_POSTGRES_DSN="$AGENT_TEAM_TEST_DSN" GOWORK=off go test -race ./internal/store/postgres -run 'TestCoreTeamStore' -count=1`

Expected: PASS with one Plan/execution under concurrent duplicate creation.

The target branch has unrelated Darwin-only build-tag defects outside Team, so
the PostgreSQL 18 integration binary and race suite were executed in Linux
containers. All ten Team store integration cases, the focused race suite, and
`go vet` passed.

- [x] **Step 5: Commit**

```bash
git add migrations internal/store/postgres internal/coreteam/repository.go
git commit -m "feat: persist Core Team executions"
```

### Task 4: Bind Core Confirmation And Block Credential Rotation

**Files:**
- Create: `internal/coreteam/confirmation.go`
- Create: `internal/coreteam/confirmation_test.go`
- Create: `internal/store/postgres/core_team_confirmation.go`
- Create: `internal/coretask/owner_scope.go`
- Create: `internal/store/postgres/core_task_scope.go`
- Modify: `internal/coreaws/service_credentials_plan.go`
- Modify: `internal/coreaws/coreaws_test.go`
- Modify: `internal/agentcapability/core_adapters.go`
- Modify: `internal/capability/operation/manager.go`
- Modify: `internal/store/postgres/core_task_store.go`
- Modify: `internal/store/postgres/core_task_queue.go`
- Modify: `internal/store/postgres/core_schedule_store.go`
- Modify: `internal/store/postgres/core_knowledge_indexer.go`
- Modify: `internal/store/postgres/core_confirmation_lifecycle.go`
- Modify: `internal/store/postgres/core_confirmation_domain.go`
- Modify: `internal/store/postgres/core_aws_coordinator_request.go`
- Modify: `migrations/agent_migrations.sql`
- Create: `internal/store/postgres/core_team_credential_guard_integration_test.go`

- [x] **Step 1: Write failing binding and mutation-guard tests**

Test exact owner, Plan revision/digest, runtime/image/AMI, credential revision, quote, budget, region, instance, network, input digest, and expiry binding. Test create/update/delete credential returns `team_execution_active` while any Team execution is nonterminal and succeeds after verified cleanup.

- [x] **Step 2: Verify failure**

Run: `GOWORK=off go test ./internal/coreteam ./internal/coreaws ./internal/store/postgres -run 'Test.*(TeamConfirmation|TeamCredential)' -count=1`

Expected: FAIL because resolver and guard are absent.

- [x] **Step 3: Implement the exact Core boundary**

```go
type ActiveExecutionGuard interface { RequireNoActiveTeamExecution(context.Context, coreteam.Scope) error }
const ErrorCodeTeamExecutionActive = "team_execution_active"

func ConfirmationBinding(plan Plan) (coreconfirmation.Binding, error) {
	return coreconfirmation.Binding{
		OwnerID: plan.OwnerID, OperationDomain: "team_execution", TargetID: plan.PlanID,
		TargetRevision: int64(plan.Revision), TargetKind: "team_plan", SourceVersion: plan.Runtime.RuntimeID,
		ContentDigest: coreconfirmation.Digest(plan.Digest), ParameterDigest: digestParameters(plan),
		NetworkDigest: digestNetwork(plan), SecretGrantDigest: digestCredentialGrant(plan),
	}, nil
}
```

Call the guard inside the same PostgreSQL transaction that mutates `core_aws_credentials`; do not implement a check-then-write race in the service layer.

The implementation also closes the pre-existing public Task/Confirmation
tenant boundary. Every Task receives a durable `owner_id +
account_generation` scope; AWS, Team, Schedule, Knowledge, Extension, Workload,
and conversation-tool creation bind or inherit that scope in the same
transaction. Owner-neutral internal work uses a reserved, non-public owner
namespace. Public Capability operations derive scope only from
`PermissionContext` and enforce it for reads, lists, events, confirmation,
cancellation, retry, and affected replay boundaries. The service-token Core
gRPC surface remains the separate internal API.

Legacy AWS request replays remain readable but are upgraded from hash version
1 only after the complete Change, Plan, Credential, Task, Confirmation, Task
scope, and immutable confirmation-target relationship is locked and verified.
Malformed legacy relationships fail closed rather than being promoted.

- [x] **Step 4: Run focused and PostgreSQL race tests**

Run: `AGENT_TEST_POSTGRES_DSN="$AGENT_TEAM_TEST_DSN" GOWORK=off go test -race ./internal/coreteam ./internal/coreaws ./internal/store/postgres -run 'Test.*(TeamConfirmation|TeamCredential)' -count=1`

Expected: PASS, including concurrent launch vs key rotation.

Delivered evidence on 2026-08-06:

- exact Team binding and credential create/replace/delete fencing pass;
- foreign owner/generation Task and Confirmation read/mutation attempts return
  not found, while the authenticated owner succeeds;
- pending and confirmed-but-unclaimed Team rejection, expiry, task timeout, and
  cancellation terminalize role/execution rows with verified cleanup before
  releasing credential rotation;
- Team execution creation versus rejection uses one canonical advisory/row
  lock order and completes without deadlock;
- eight concurrent scoped AWS request calls create one durable graph; malformed
  legacy replay relationships are rejected and concurrent v1-to-v3 promotion
  converges to one replay;
- AWS Plan creation stores its owner-scoped idempotency receipt in the same
  transaction as the immutable Plan; restart and eight-way concurrent replay
  return one Plan, while changed input conflicts;
- legacy request replay migration validates Change, Plan, Credential, Task and
  Confirmation IDs, Confirmation scalar columns, Plan owner, and both
  immutable binding copies before promotion;
- public Task and Confirmation adapters preserve the caller's raw idempotency
  key, while PostgreSQL receipts isolate that key by owner, account generation,
  and operation; the v2-to-v3 migration replays legacy create, cancel, retry,
  confirm, and reject results through the real public Capability API without
  creating a duplicate Task;
- Schedule and Knowledge mutation/index receipts use the same
  owner-generation isolation while preserving raw caller keys; valid v2
  Schedule and Knowledge receipts remain replayable after migration, malformed
  entity links fail the migration, and receipts without authoritative entity
  provenance move to a reserved internal quarantine scope;
- public Knowledge source, upload, memory, list, search, status, and embedding
  configuration operations enforce the same owner and account-generation
  scope; source ownership is immutable, cursor snapshots are scope-keyed, and
  legacy global configuration/snapshots migrate only to the Agent instance's
  reserved internal Knowledge principal;
- v3 freezes the Capability operation ledger before ExecutionV2 and Knowledge
  scope migration, rejects nonterminal authoritative secret/source operations,
  performs a final in-transaction conflict recheck, and leaves a database
  trigger that rejects late completions from rolling-upgrade legacy processes
  when their owner/account generation does not match the durable entity;
- every Knowledge index Task/job snapshots the embedding profile ID, profile
  revision, vector dimension, and collection-config digest; the Worker restores
  owner scope from `core_task_scopes`, validates profile/source ownership again
  before indexing and promotion, and never replaces the queued binding with the
  current default configuration;
- owner-neutral Knowledge maintenance scans only the reserved internal scope,
  discovers a bounded set of public source owners, and reconciles each public
  owner in its own authenticated scope rather than sweeping all tenants through
  an unscoped query;
- switching the owner-scoped Knowledge embedding model returns the stable
  `ErrActiveTasks`/`FailedPrecondition` contract while a queued or running index
  job exists; canceling or completing the task releases the Task profile
  reference and permits the switch. Task creation and model switching share one
  PostgreSQL advisory lock, while immutable Worker bindings remain a defense
  against old binaries or recovery races that bypass admission;
- ExecutionV2 records, revisions, events, secrets, provider outcomes, and
  replay receipts are account-generation scoped; provider intent is durable
  before dispatch, persisted outcomes are resumed without redispatch, and an
  unknown outcome remains safely in progress instead of repeating a paid or
  destructive provider action;
- deterministic mutation markers and event IDs recover receipt loss, missing
  journal events, and partial Run/Stage/Confirmation graphs while rejecting a
  changed request under the same idempotency key; authentic legacy secret AAD
  remains decryptable only in the uniquely recovered account generation;
- legacy Task ownership accepts only exact `agent.tasks.v1` create/retry result
  paths plus complete Schedule occurrence, Knowledge index/source, and AWS
  Change/Plan/Credential/Confirmation relationship chains; get/list/read
  results and recursive `related_task_ids` are never ownership evidence, and
  conflicting authoritative chains abort the migration atomically;
- public Capability domain failures map to stable public codes and fixed safe
  messages; provider, database, and unknown error details are not persisted or
  returned;
- focused PostgreSQL migration, double-owner maintenance, model-switch,
  cancellation, legacy-bypass, Worker binding, and promotion tests pass; the
  complete PostgreSQL package passes in 68.191 seconds after these changes;
- full PostgreSQL 18 suite and PostgreSQL race suite pass in Linux containers;
- Linux full repository suite and full race suite pass with the
  filesystem-hardening runner executed separately as uid 65534; `go vet
  ./...`, native Go cross-compilation of `GOOS=linux GOARCH=amd64 go build
  ./cmd/...`, `buf lint`, and `git diff --check` pass.

- [x] **Step 5: Commit**

```bash
git add cmd/dirextalk-agent docs internal/agentcapability internal/capability/operation internal/coreaws internal/coreruntime internal/coretask internal/coreteam internal/rpcapi internal/store/postgres migrations
git commit -m "feat: bind Team spend to Core confirmation"
```

### Task 5: Publish `agent.team.v1`

**Files:**
- Create: `internal/agentcapability/team/capability.go`
- Create: `internal/agentcapability/team/capability_test.go`
- Create: `internal/coreteam/service.go`
- Create: `internal/coreteam/service_test.go`
- Modify: `internal/agentcapability/core_adapters.go`
- Modify: `internal/agentcapability/core_adapters_test.go`

- [x] **Step 1: Write failing descriptor and operation tests**

Require capability ID `agent.team.v1`, protocol 1, readiness false until all dependencies are ready, exact operations `plans_get`, `executions_list`, `executions_get`, and `executions_cancel`, safe/read vs high/mutation risks, 1 MiB maximum requests, strict schemas, owner from PermissionContext, and no internal identifiers in JSON.

- [x] **Step 2: Verify failure**

Run: `GOWORK=off go test ./internal/agentcapability/... ./internal/coreteam -run 'Test.*TeamCapability' -count=1`

Expected: FAIL because the capability does not exist.

- [x] **Step 3: Implement the capability adapter**

```go
const CapabilityID = "agent.team.v1"
var operations = []Operation{
	{ID: "plans_get", Action: "agent.team.plans.get", Read: true},
	{ID: "executions_list", Action: "agent.team.executions.list", Read: true},
	{ID: "executions_get", Action: "agent.team.executions.get", Read: true},
	{ID: "executions_cancel", Action: "agent.team.executions.cancel", Read: false},
}
```

Generate deterministic schemas with `additionalProperties:false`; result schemas must enumerate public fields rather than use the current Execution V2 permissive result schema.

- [x] **Step 4: Run capability, grant, and canary tests**

Run: `GOWORK=off go test ./internal/agentcapability/... ./internal/capability/... ./internal/coreteam -run 'Test.*(Team|Grant|Schema)' -count=1`

Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/agentcapability internal/coreteam
git commit -m "feat: publish Team execution capability"
```

### Task 6: Inject The Two Central Model Tools

**Files:**
- Create: `cmd/dirextalk-agent/team_conversation_resolver.go`
- Create: `cmd/dirextalk-agent/team_conversation_resolver_test.go`
- Modify: `cmd/dirextalk-agent/core_serve.go`
- Modify: `cmd/dirextalk-agent/core_serve_test.go`

- [x] **Step 1: Write failing resolver and tool contract tests**

Require exactly `team_plan_prepare` and `team_task_status` in the model-facing catalog when Team readiness, owner permission, account generation, signed Pi runtime catalog, and typed provider readiness all pass. Require both tools to disappear on any fence failure, and reject a Skill/MCP that tries to publish either reserved name.

```go
want := map[string]bool{"team_plan_prepare": true, "team_task_status": true}
for _, extension := range resolved {
	for _, tool := range extension.Tools {
		delete(want, tool.Name)
	}
}
if len(want) != 0 { t.Fatalf("missing Team tools: %v", want) }
```

Test canonical arguments, unknown fields, one-to-three roles, dependency cycles, owner/account replacement between resolve and invoke, duplicate model calls, safe summaries, related Core Task IDs, and secret canaries in arguments/service errors.

- [x] **Step 2: Verify failure**

Run: `GOWORK=off go test ./cmd/dirextalk-agent -run 'TestTeamConversationResolver' -count=1`

Expected: FAIL because the resolver is absent.

- [x] **Step 3: Implement the built-in resolver**

Follow the existing `webSearchConversationResolver` composition pattern, but use a reserved deterministic selection ID/source and a closed Team service port:

```go
type teamConversationResolver struct {
	base coreconversation.ExtensionResolver
	team teamConversationService
}

type teamConversationService interface {
	PreparePlan(context.Context, coreteam.PrepareCommand) (coreteam.PlanProjection, error)
	TaskStatus(context.Context, coreteam.StatusQuery) (coreteam.ExecutionProjection, error)
	ReadyForPublication() bool
}
```

`team_plan_prepare` accepts only a bounded goal plus one-to-three role proposals, dependencies, and closed capability requirements. The service, not the model, chooses credential revision, region, quote, hard budget, instance type, network policy, runtime/image/AMI and expiry. It returns only `task_id`, `plan_id`, Plan revision/state, safe Plan summary, and generic `confirmation_id`; it cannot approve or provision.

`team_task_status` accepts one canonical `task_id` or `execution_id` and returns the same sanitized projection used by `agent.team.v1`. It never returns Worker output, raw milestones, cloud coordinates, tool traffic, or audit log references.

- [x] **Step 4: Compose and verify model-context privacy**

Chain the resolver after existing extension, Product, and Web Search resolvers with deterministic reserved-name conflict detection. Assert durable conversation snapshots contain only schema/content digests and safe tool summaries, while canonical Team Proposal arguments remain Agent-owned and never appear in public turn events.

Run: `GOWORK=off go test -race ./cmd/dirextalk-agent ./internal/coreconversation ./internal/coreteam -run 'Test.*(TeamConversation|ReservedTool|ToolPrivacy)' -count=1`

Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add cmd/dirextalk-agent/team_conversation_resolver.go cmd/dirextalk-agent/team_conversation_resolver_test.go cmd/dirextalk-agent/core_serve.go cmd/dirextalk-agent/core_serve_test.go
git commit -m "feat: expose Team planning to Central Agent"
```

### Task 7: Add The Private Worker Identity And Lease Protocol

**Files:**
- Create: `api/proto/dirextalk/agent/v1/core_team_worker.proto`
- Create: `internal/coreteamworker/types.go`
- Create: `internal/coreteamworker/service.go`
- Create: `internal/coreteamworker/service_test.go`
- Create: `internal/store/postgres/core_team_worker_store.go`
- Create: `internal/store/postgres/core_team_worker_store_integration_test.go`
- Modify: `migrations/agent_migrations.sql`

- [x] **Step 1: Write failing protocol tests**

Cover challenge, one-time enrollment, assignment, claim, heartbeat, milestone, complete, attempt/lease fencing, expired enrollment, replay, foreign Worker, and a secret canary in provider errors.

- [x] **Step 2: Verify failure**

Run: `GOWORK=off go test ./internal/coreteamworker ./internal/store/postgres -run 'TestCoreTeamWorker' -count=1`

Expected: FAIL because the protocol and store do not exist.

- [x] **Step 3: Define and implement the closed protocol**

The proto service exposes only `CreateIdentityChallenge`, `Enroll`, `GetAssignment`, `Claim`, `Heartbeat`, `EmitMilestone`, and `Complete`. Private wire messages carry canonical IDs, attempt, lease epoch, closed enums, digests, timestamps, and bounded digest-bound structured result JSON plus metadata. `Complete` accepts only canonical `ResultPayloadV1`: schema version, closed status, bounded summary/deliverables/tests/risks, and aggregate token counters. Unknown fields, secret canaries, non-canonical JSON, raw reasoning, tool traffic, terminal output, and provider errors are rejected before repository persistence. No message contains an AWS credential, shell command, IP, AMI, or log reference.

```go
type LeaseFence struct { ExecutionID, RoleID, WorkerID string; Attempt uint32; LeaseEpoch uint64 }
type Service struct { repo Repository; verifier IdentityVerifier; now func() time.Time }
```

Persist `core_team_worker_challenges`, `core_team_workers`, result payload, and lease fields on `core_team_role_runs`; all mutations use the account-deprovision guard, exact idempotent replay, `SELECT ... FOR UPDATE`, and complete owner/generation/execution/role/attempt/lease fencing. Worker `Complete` only moves the role to `cleaning_up`; Task 10 validates the closed result schema, promotes accepted content to ResultStore, proves cloud cleanup, and only then permits a terminal success.

- [x] **Step 4: Generate, test, and race-test**

Run: `buf lint && buf generate && AGENT_TEST_POSTGRES_DSN="$AGENT_TEAM_TEST_DSN" GOWORK=off go test -race ./internal/coreteamworker ./internal/store/postgres -run 'TestCoreTeamWorker' -count=1`

Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add api/proto api/gen internal/coreteamworker internal/store/postgres migrations
git commit -m "feat: add fenced Team Worker protocol"
```

### Task 8: Restore The Official Pi Runtime And Worker Release

**Files:**
- Create: `internal/coreteaminput/types.go`
- Create: `internal/coreteaminput/compile.go`
- Create: `internal/coreteaminput/compile_test.go`
- Create: `internal/coreteamruntime/pi.go`
- Create: `internal/coreteamruntime/pi_test.go`
- Create: `internal/coreteamruntime/process.go`
- Create: `internal/coreteamruntime/pi_binary_integration_test.go`
- Create: `internal/pisandbox/`
- Create: `cmd/dirextalk-pi-sandbox/`
- Create: `cmd/dirextalk-cloud-worker/receipt.go`
- Create: `cmd/dirextalk-cloud-worker/receipt_unix.go`
- Create: `cmd/dirextalk-cloud-worker/receipt_test.go`
- Create: `cmd/dirextalk-cloud-worker/secret_unix.go`
- Create: `cmd/dirextalk-cloud-worker/secret_unix_test.go`
- Create: `cmd/dirextalk-cloud-worker/control_key_linux.go`
- Create: `cmd/dirextalk-cloud-worker/control_key_linux_test.go`
- Create: `internal/coreteamruntime/result.go`
- Create: `internal/coreteamruntime/result_test.go`
- Create: `cmd/dirextalk-cloud-worker/main.go`
- Create: `cmd/dirextalk-cloud-worker/main_test.go`
- Create: `deploy/container/pi-worker/worker.Containerfile`
- Create: `deploy/container/pi-worker/dirextalk-cloud-worker.service`
- Create: `deploy/container/pi-worker/README.md`
- Modify: `api/proto/dirextalk/agent/v1/core_team_worker.proto`
- Modify: `internal/coreteamworker/types.go`
- Modify: `internal/coreteamworker/service.go`
- Modify: `internal/store/postgres/core_team_worker_store.go`
- Modify: `migrations/agent_migrations.sql`

**Qualified migration sources:** Port compatible implementation and tests from
old `internal/workerruntime/{pi,process,failure,installation}*`,
`internal/teaminput`, `internal/taskinput`,
`internal/workerrunner/{input_action,runtime_action,runtime_result}*`, and
`internal/workeroperation`. Rewire their identities and persistence to
`coreteamworker`; do not recreate the old Worker RPC or Task stack. The old
action checkpoint and root-helper receipt did not fence Pi execution, and the
old credential reader did not unlink after read. Reuse their atomic journal,
CAS, validation, and secret-canary patterns only; the model no-duplicate
boundary and secure one-time secret consumption are new required behavior.

- [x] **Step 1: Port the accepted behavior tests before implementation**

Recreate tests for Pi 0.83.0 event parsing, `dirextalk_submit_result`, output-token override, process timeout/output/non-zero failures, closed provider/auth/quota/rate/request/server/network failures, invalid event, missing final result, empty workspace, result size/digest, and raw-error destruction. Also port canonical context/input manifest tests and add exact model/revision/context/credential/workspace digest binding, secure one-time secret-file consumption, write-before-run receipt, Complete-response validation, and restart replay that never invokes Pi twice.

- [x] **Step 2: Verify the tests fail**

Run: `GOWORK=off go test ./internal/coreteamruntime ./cmd/dirextalk-cloud-worker -count=1`

Expected: FAIL because the runtime and command do not exist.

- [x] **Step 3: Implement the exact runtime contract**

```go
type FailureStage string
const (FailureProcess FailureStage = "process"; FailurePi FailureStage = "pi")
type Result = coreteamworker.ResultPayloadV1
type Runner interface { Run(context.Context, Assignment, Workspace) (Result, ClosedFailure, error) }
```

Use argv arrays only inside the Worker process, an empty environment plus explicitly materialized model variables, a task-local `0600` Pi override, fixed output limits, no provider text in returned failures, and cleanup of temporary files in `defer`. Central stores a required canonical runtime-context digest binding execution/role/attempt/Plan, model provider/name/interface/revision, context, credential, input manifest, and canonical materialized-workspace tree digest. The tree digest is domain-separated and covers every relative path, entry kind, executable bit, safe symlink target, regular-file size, and file-content digest under fixed file/byte/path limits. The Worker verifies the real workspace tree and every other materialized byte against the assignment before consuming the model credential or launching Pi. TLS, context, manifest, secret, receipt, runtime-state, and immutable digest-sidecar paths must remain outside the fixed workspace root.

The sandbox policy is derived only from the role's closed capability list. A
role without `repository.write` receives read/execute access to the current
workspace even when it has shell, test, or Git capability; only an explicit
`repository.write` capability grants workspace mutation. Before result
collection, Pi-owned entries are normalized to the shared Worker group while
preserving executable intent. Recovery and cleanup use the parent Worker's
fixed scoped filesystem identity transition for Pi-owned private entries and
fail closed if the task root cannot be removed.

Before Pi spawn it atomically persists and fsyncs `launch_committed` together
with the deterministic, fence-bound `execution_uncertain` `CompleteRequest`;
recovery from that state never initializes or runs Pi and submits only those
exact bytes. After Pi returns it atomically persists the complete canonical
`CompleteRequest` as `completion_pending`; recovery replays only those exact
bytes and the stable completion ID. Central accepts this late completion after
lease TTL expiry only while the Worker and exact execution/role/attempt/lease
epoch are still current; any superseding attempt or epoch remains fenced. The
Worker writes `completion_acked` only after validating every response field.
Model
credentials are safely opened through a fixed private directory, checked for
owner/mode/link/size, unlinked and directory-fsynced before Pi. The mTLS
credential remains outside Pi's filesystem view until completion recovery no
longer needs it. The adapter converts the qualified Pi final extension plus
aggregate usage into canonical `ResultPayloadV1`; it never forwards Pi event
streams, tool payloads, stdout, stderr, or reasoning text.

- [x] **Step 4: Run real-binary qualification and build checks**

Run: `DIREXTALK_PI_QUALIFY=1 GOWORK=off go test ./internal/coreteamruntime -run TestOfficialPiBinaryLoopback -count=1 && GOWORK=off go test -race ./internal/coreteaminput ./internal/coreteamruntime ./internal/coreteamworker ./cmd/dirextalk-cloud-worker -count=1 && GOWORK=off GOOS=linux GOARCH=amd64 go build ./cmd/dirextalk-cloud-worker`

Expected: PASS with pinned Pi and extension digests and one structured result.

Verified on 2026-08-07 with source archive SHA-256
`92747519a06e8c8c4b446508144e4f869f50755a554239b565141d10ca09f048`
on disposable AWS AL2023 `x86_64` instance `i-08b93e7d3f7876449` in
`ap-northeast-3`. SSM command
`b97b9bd6-72ae-4342-a073-2f6f599eb13e` passed focused and race tests, native
Landlock ABI 2 enforcement, kernel child-credential transition from Worker UID
`65532` to Pi UID `65533`, zero Pi capabilities, control-key isolation, real
two-process no-duplicate execution, exact completion replay after response
loss without Pi initialization, pinned Pi 0.83.0 loopback model execution, and
the `linux/amd64` Containerfile build. The final image also ran bash and git as UID/GID
`65532:65532`, pinned the parent Worker's three effective file capabilities,
and verified parent-only receipt plus shared workspace modes. The capability
qualification ran the parent as UID/GID `65532:65532` and proved it can recover
and remove Pi-owned private entries using only `CAP_KILL`, `CAP_SETGID`, and
`CAP_SETUID`. Worker- and Pi-owned repository files were normalized to the
shared GID contract, a real Git status ran as Pi UID `65533`, and hard-linked
workspace files failed closed. The resulting local qualification image was
`sha256:f4833a7fb5f4fb2463d8106a79f81055d5aa368cd79d78a5c745a2995bf3ee5a`;
the Worker and sandbox binary digests were respectively
`fb760be314613fe70b5f1b6a042fbd1fff19867892c89478e9fdc2bf081d8b79`
and `dcc1c648bdde144b9097d8414680e79b7731725a4834757ec8ac883504a43f2f`.

- [x] **Step 5: Commit**

```bash
git add internal/coreteaminput internal/coreteamruntime internal/coreteamworker internal/store/postgres api/proto migrations cmd/dirextalk-cloud-worker deploy/container/pi-worker
git commit -m "feat: restore qualified Pi Worker runtime"
```

### Task 9: Add Typed Ephemeral AWS Worker Lifecycle

**Files:**
- Create: `cmd/dirextalk-worker-rootfs/main.go`
- Create: `cmd/dirextalk-worker-rootfs/main_test.go`
- Create: `cmd/dirextalk-worker-ami/main.go`
- Create: `cmd/dirextalk-worker-ami/main_test.go`
- Create: `cmd/dirextalk-ecrctl/main.go`
- Create: `cmd/dirextalk-ecrctl/main_test.go`
- Create: `cmd/dirextalk-releasectl/main.go`
- Create: `cmd/dirextalk-releasectl/main_test.go`
- Create: `cmd/dirextalk-aws-reaper/main.go`
- Create: `cmd/dirextalk-aws-reaper/main_test.go`
- Create: `internal/releaseartifact/`
- Create: `internal/releaseecr/`
- Create: `internal/releasepublish/`
- Create: `internal/workerrootfs/`
- Create: `internal/workerami/`
- Create: `internal/workeramictl/`
- Create: `internal/coreteamfoundation/`
- Create: `internal/coreteamrelease/`
- Create: `internal/coreteambundle/`
- Create: `internal/coreteamcredential/`
- Create: `internal/coreteamreaper/`
- Create: `internal/coreteamaws/provider.go`
- Create: `internal/coreteamaws/provider_test.go`
- Create: `internal/coreteamaws/sdk.go`
- Create: `internal/coreteamaws/sdk_test.go`
- Create: `internal/coreteamaws/template.go`
- Create: `internal/coreteamaws/template_test.go`
- Create: `internal/store/postgres/core_team_resource_store.go`
- Create: `internal/store/postgres/core_team_resource_store_integration_test.go`
- Create: `internal/store/postgres/core_team_release_store.go`
- Create: `internal/store/postgres/core_team_reaper_store.go`
- Create: `deploy/awsfoundation/team-worker.yaml`
- Create: `deploy/container/reaper.Containerfile`
- Modify: `migrations/agent_migrations.sql`

**Qualified migration source:**

Use local branch `codex/pi-worker-real-task-fix` at inspected commit
`51bc9ae1d9c367ca58ea2cc35fbd090eb5b7a484` as a behavior and implementation
reference for `workerrootfs + workerami`. Its Osaka Linux x86_64 AMI
`ami-023e6b2d57694b86d` previously completed a correlated real Pi 0.83.0
task and retained encrypted snapshot `snap-0ae9af10d9f1a406e`. Do not promote
that AMI into Agent Core v1: it embeds the old Worker Harness and protocol.
Port the tested archive hygiene, immutable installation manifest, private
builder, digest attestation, resumable publication, bounded polling, cleanup,
and independent AWS read-back. Replace the Worker binary, installation
contract, bootstrap material, and control protocol with the current Agent Core
v1 implementation.

Also port the accepted behavior from old `workerrelease`, `workeramictl`,
`releaseecr`, `releasepublish`, `awsfoundation`, `teambundle`,
`teamcredential`, `secretbootstrap`, `workerrunner/s3_store`,
`awsprovider`, `resource`, and `awsreaper`. Keep only the Pi Team
resource graph and task-scoped bootstrap path; old generic installer,
Knowledge, Managed service, Cloud Connection, and root-helper surfaces are not
part of this migration.

- [ ] **Step 1: Port the accepted rootfs/AMI tests, then write failing provider and recovery tests**

First recreate the accepted tests for deterministic rootfs packing, Linux
x86_64 release identity, complete Pi runtime assets, AppleDouble rejection,
fixed `dirextalk-worker` passwd/group records at UID/GID `65532:65532`,
immutable installation manifest, private builder reachability, AMI
attestation, resumable publication, builder cleanup, and independent negative
read-back. Require workspace archives to retain their independent download
digest, then have the materializer compute the Task 8 canonical tree digest
after extraction and reject any mismatch before credential consumption. Prove
that all mutable control roots and fixed immutable digest sidecars remain
disjoint from the workspace root. Add ECR immutable-tag publication/readback, release resume, release
import/selection, Foundation KMS/S3/DynamoDB/Lambda schedule, digest-only
Reaper image, task bundle encryption/materialization, task-scoped model
credential, expiry manifest, and Reaper CAS/fence tests. Then require no ingress/SSH/SSM on task Workers, encrypted root
volume, exact AMI/runtime digest, SG/ENI/EIP/EC2/EBS tags, stable request
tokens, write-before-mutate intents, create response-loss readback, delete
response-loss readback, concurrent reconciliation, and
`verified_destroyed` only after every resource is absent.

- [ ] **Step 2: Verify failure**

Run: `GOWORK=off go test ./internal/releaseartifact ./internal/releaseecr ./internal/releasepublish ./internal/workerrootfs ./internal/workerami ./internal/workeramictl ./internal/coreteamfoundation ./internal/coreteamrelease ./internal/coreteambundle ./internal/coreteamcredential ./internal/coreteamreaper ./cmd/dirextalk-worker-rootfs ./cmd/dirextalk-worker-ami ./cmd/dirextalk-ecrctl ./cmd/dirextalk-releasectl ./cmd/dirextalk-aws-reaper ./internal/coreteamaws ./internal/store/postgres -run 'Test.*(RootFS|AMI|Release|Foundation|Bundle|Credential|Reaper|TeamAWS)' -count=1`

Expected: FAIL because the provider and ledger are absent.

- [ ] **Step 3: Implement narrow typed ports**

```go
type Provider interface {
	Quote(context.Context, QuoteRequest) (Quote, error)
	Create(context.Context, CreateRequest, workaws.CredentialHandle) (Readback, error)
	Read(context.Context, ReadRequest, workaws.CredentialHandle) (Readback, error)
	Destroy(context.Context, DestroyRequest, workaws.CredentialHandle) (Readback, error)
	Ready() bool
}
type CreateRequest struct { OwnerID, TaskID, ExecutionID, RoleID, AMIID, ImageDigest, Region, AvailabilityZone, InstanceType, ClientToken string; RootVolumeGiB uint32 }
```

Reuse `coreworkload/aws.CredentialResolver` and the target Core pricing/readiness components. Reuse the old qualified publication, Foundation, and AMI construction mechanics by capability-level port, not by branch merge or historical AMI selection. The release command must publish immutable Agent/Worker/Reaper digests and produce only Linux `x86_64` Worker/Reaper artifacts; every tag is reconciled by digest read-back. Bootstrap may create only the fixed Team Foundation and a typed, task-scoped encrypted bundle with least-privilege object/secret access derived by Central; no caller/model can provide IAM policy, URL, user data, command, or shell. The Team provider may expose only the fixed Worker resource graph. Controller cleanup is primary; the independently scheduled digest-pinned Reaper is the expiry fallback and must use the same immutable ownership/fence facts.

The task materializer verifies each downloaded archive/object digest, extracts
into the fixed task workspace using the qualified archive-hygiene rules, then
computes the canonical materialized-tree digest from Task 8 and binds that
value into the runtime context. It creates context, manifest, mTLS, secret,
receipt, and runtime-state paths only in fixed private roots outside the
workspace tree; archive-byte digests and materialized-tree digests are
different typed facts and must never be substituted for one another.

- [ ] **Step 4: Run template, provider, PostgreSQL, and race tests**

Run: `AGENT_TEST_POSTGRES_DSN="$AGENT_TEAM_TEST_DSN" GOWORK=off go test -race ./internal/releaseartifact ./internal/releaseecr ./internal/releasepublish ./internal/workerrootfs ./internal/workerami ./internal/workeramictl ./internal/coreteamfoundation ./internal/coreteamrelease ./internal/coreteambundle ./internal/coreteamcredential ./internal/coreteamreaper ./cmd/dirextalk-worker-rootfs ./cmd/dirextalk-worker-ami ./cmd/dirextalk-ecrctl ./cmd/dirextalk-releasectl ./cmd/dirextalk-aws-reaper ./internal/coreteamaws ./internal/store/postgres -run 'Test.*(RootFS|AMI|Release|Foundation|Bundle|Credential|Reaper|TeamAWS)' -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/dirextalk-worker-rootfs cmd/dirextalk-worker-ami cmd/dirextalk-ecrctl cmd/dirextalk-releasectl cmd/dirextalk-aws-reaper internal/releaseartifact internal/releaseecr internal/releasepublish internal/workerrootfs internal/workerami internal/workeramictl internal/coreteamfoundation internal/coreteamrelease internal/coreteambundle internal/coreteamcredential internal/coreteamreaper internal/coreteamaws internal/store/postgres deploy/awsfoundation/team-worker.yaml deploy/container/reaper.Containerfile migrations
git commit -m "feat: manage ephemeral Pi Workers on AWS"
```

### Task 10: Run The Durable Team Controller And Verify Results

**Files:**
- Create: `internal/coreteam/controller.go`
- Create: `internal/coreteam/controller_test.go`
- Create: `internal/coreteam/result.go`
- Create: `internal/coreteam/result_test.go`
- Create: `internal/coreteam/artifact.go`
- Create: `internal/coreteam/artifact_test.go`
- Create: `internal/coreteam/report.go`
- Create: `internal/coreteam/report_test.go`
- Modify: `internal/coreteam/service.go`
- Modify: `internal/coreteam/service_test.go`
- Modify: `internal/agentcapability/team/capability.go`
- Modify: `internal/agentcapability/team/capability_test.go`
- Create: `internal/store/postgres/core_team_result_store.go`
- Create: `internal/store/postgres/core_team_controller_integration_test.go`
- Modify: `migrations/agent_migrations.sql`

**Qualified migration sources:** Port recovery vectors and compatible pure
domain code from old `teamdispatch`, `teamcontroller`, `teamresult`,
`teamartifact`, `teamreport`, `workerresult`, and
`app/team_{result_collector,role_cleanup,task_coordinator}*`. Rewire their
stores and task transitions to Agent Core v1.

- [ ] **Step 1: Write failing lifecycle tests**

Cover `intent -> input_ready -> provisioning -> active -> result_ready -> destroying -> completed`, max 3 active roles, dependency ordering, retry with new attempt/lease, cancel before/after create, result upload during cancel, controller restart, result digest/size/media-type mismatch, artifact retention binding, canonical immutable report and usage aggregation, Worker-authored cloud claim removal, and terminal success only after cleanup. Extend the public execution projection and canonical capability result schemas with bounded role state/dependencies, progress, verified artifact metadata, report summary, and cleanup status; reject every internal Worker/cloud/lease/log field.

- [ ] **Step 2: Verify failure**

Run: `GOWORK=off go test ./internal/coreteam ./internal/agentcapability/team ./internal/store/postgres -run 'Test.*Team(Controller|Projection|Schema)' -count=1`

Expected: FAIL because the controller does not exist.

- [ ] **Step 3: Implement one bounded reconciliation step**

```go
type Controller struct { repo ControllerRepository; workers WorkerControl; cloud CloudProvider; results ResultStore; maxActive uint32; now func() time.Time }
func (c *Controller) ReconcileOnce(ctx context.Context, ownerID, executionID string) (Execution, error)
```

Each call locks one execution, reads provider facts before mutation, starts at most `3-activeCount` runnable roles, validates result schema/digest before success, and moves every terminal path through cleanup. Store the immutable report only after all roles terminal and every resource ledger row is `verified_destroyed`.

- [ ] **Step 4: Run normal, race, and PostgreSQL restart tests**

Run: `AGENT_TEST_POSTGRES_DSN="$AGENT_TEAM_TEST_DSN" GOWORK=off go test -race ./internal/coreteam ./internal/agentcapability/team ./internal/store/postgres -run 'Test.*Team(Controller|Projection|Schema)' -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/coreteam internal/agentcapability/team internal/store/postgres migrations
git commit -m "feat: reconcile Team Worker executions"
```

### Task 11: Persist Public Progress And Relay Audit Logs

**Files:**
- Create: `internal/coreteam/progress.go`
- Create: `internal/coreteam/progress_test.go`
- Create: `internal/store/postgres/core_team_progress_store.go`
- Create: `internal/store/postgres/core_team_progress_store_integration_test.go`
- Create: `internal/coreteam/audit_relay.go`
- Create: `internal/coreteam/audit_relay_test.go`
- Create: `cmd/dirextalk-cloud-worker/milestone.go`
- Create: `cmd/dirextalk-cloud-worker/milestone_test.go`
- Modify: `cmd/dirextalk-cloud-worker/main.go`
- Modify: `cmd/dirextalk-cloud-worker/main_test.go`
- Modify: `internal/coreteam/service.go`
- Modify: `internal/coreteam/service_test.go`
- Modify: `internal/agentcapability/team/capability.go`
- Modify: `internal/agentcapability/team/capability_test.go`
- Modify: `migrations/agent_migrations.sql`

**Qualified migration sources:** Reuse old `internal/workerlog` CloudWatch
adapter, `internal/workerrunner/grpc_milestone_sink.go`, and their
closed-vocabulary, session/fence, failure, secret, and stream tests. Use the reviewed three-repo Worker
progress plans as requirements only; the uncommitted old
`internal/workerprogress` and migration 64 draft are excluded.

- [ ] **Step 1: Write failing milestone/replay/Outbox tests**

Require stable event digest, exact replay preserving first receipt, same ID/different event rejection, stale lease rejection, immutable events, one Outbox row, fenced claim/confirm/retry, CloudWatch failure after durable ack, owner-scoped list/get, bounded timeline, and JSON absence of Worker/deployment/cloud/log/raw fields. Prove the Worker emits stable closed milestones before expensive execution, at result readiness, and on closed failure; an unavailable pre-run milestone prevents Pi launch, while a post-run relay failure uses the local completion receipt and never causes Pi to run again.

- [ ] **Step 2: Verify failure**

Run: `GOWORK=off go test ./internal/coreteam ./internal/agentcapability/team ./internal/store/postgres ./cmd/dirextalk-cloud-worker -run 'Test.*TeamProgress|Test.*TeamMilestone|Test.*Milestone' -count=1`

Expected: FAIL because durable progress is absent.

- [ ] **Step 3: Implement closed progress and audit delivery**

```go
type Stage string
const (StageQueued Stage = "queued"; StagePreparing Stage = "preparing"; StageStartingWorker Stage = "starting_worker"; StagePreparingInput Stage = "preparing_input"; StageRunning Stage = "running"; StageValidatingResult Stage = "validating_result"; StageCleaningUp Stage = "cleaning_up"; StageCompleted Stage = "completed"; StageFailed Stage = "failed"; StageCanceled Stage = "canceled"; StageTimedOut Stage = "timed_out")
type Health string
const (HealthHealthy Health = "healthy"; HealthDelayed Health = "delayed"; HealthRecovering Health = "recovering"; HealthAttentionRequired Health = "attention_required"; HealthTerminal Health = "terminal")
```

Use `core_team_milestones` immutable rows and `core_team_audit_outbox`. Worker RPC returns after the database transaction; the supervised relay writes the existing 30-day CloudWatch stream asynchronously and stores only closed retry codes. Project only the bounded public milestone vocabulary and derived progress through `agent.team.v1/executions_get`; update the canonical schema digest and keep raw Worker events, action identifiers, failure internals, and CloudWatch coordinates private.

- [ ] **Step 4: Run PostgreSQL, race, and outage tests**

Run: `AGENT_TEST_POSTGRES_DSN="$AGENT_TEAM_TEST_DSN" GOWORK=off go test -race ./internal/coreteam ./internal/agentcapability/team ./internal/store/postgres ./cmd/dirextalk-cloud-worker -run 'Test.*(TeamProgress|TeamMilestone|AuditRelay|Milestone)' -count=1`

Expected: PASS, including simulated CloudWatch outage with Worker ack success.

- [ ] **Step 5: Commit**

```bash
git add internal/coreteam internal/agentcapability/team internal/store/postgres cmd/dirextalk-cloud-worker migrations
git commit -m "feat: persist bounded Team Worker progress"
```

### Task 12: Commit Final Conversation Messages And Completion Notifications

**Files:**
- Create: `internal/coreteam/completion.go`
- Create: `internal/coreteam/completion_test.go`
- Create: `internal/store/postgres/core_team_completion_store.go`
- Create: `internal/store/postgres/core_team_completion_store_integration_test.go`
- Modify: `migrations/agent_migrations.sql`
- Create: `cmd/dirextalk-agent/core_team_completion_sink.go`
- Create: `cmd/dirextalk-agent/core_team_completion_sink_test.go`
- Modify: `internal/capability/client/client.go`
- Create: `internal/capability/client/service_notification_test.go`

**Qualified migration sources:** Port old Agent Team finalizer/report
atomicity, Message Server `agentcompletion/relay` correlation/cursor/replay,
and Flutter completion dedupe test vectors. Do not port the old polling RPC or
the Flutter code that creates a localized final assistant message; Central is
the only final-message author in Agent Core v1.

- [ ] **Step 1: Write failing atomicity and replay tests**

Require report/message/Outbox atomicity, exact conversation binding, one final message, no message before verified cleanup, stable event ID, Outbox restart recovery, callback replay, and safe final content containing Central-owned cloud facts only. Also prove a completed task can publish after the originating chat/delegation has expired, while wrong peer generation, wrong fixed capability/operation, stale account, changed payload under the same event ID, and user-grant replay all fail closed.

- [ ] **Step 2: Verify failure**

Run: `GOWORK=off go test ./internal/coreteam ./internal/store/postgres ./cmd/dirextalk-agent -run 'Test.*TeamCompletion' -count=1`

Expected: FAIL because completion integration is absent.

- [ ] **Step 3: Implement the completion boundary**

```go
type CompletionEvent struct {
	EventID, ExecutionID, TaskID, ConversationID, ResultMessageID string
	State string
	CompletedAt time.Time
}
type CompletionSink interface { Publish(context.Context, CompletionEvent) error }
```

Use the existing Core conversation store to append a structured Central message and insert `core_team_completion_outbox` in the same PostgreSQL transaction as report finalization. The relay publishes exactly the closed event above through `product.agent_team.v1/completion_record`; it never includes report content/digest, full Worker output, cloud coordinates, or a caller-selected owner/action.

Add a narrow `StartServiceNotification` client path over the existing Product Capability mTLS connection. It creates a valid `agent -> product` call context, sends the stable `event_id` as operation ID, and sends no expired user `PermissionContext`. This method is hard-coded to the Team completion capability/operation and is unavailable to generic Product calls; Message Server derives owner/account generation from its authenticated deployment context.

- [ ] **Step 4: Run restart/race tests**

Run: `AGENT_TEST_POSTGRES_DSN="$AGENT_TEAM_TEST_DSN" GOWORK=off go test -race ./internal/coreteam ./internal/store/postgres ./internal/capability/client ./cmd/dirextalk-agent -run 'Test.*TeamCompletion|Test.*ServiceNotification' -count=1`

Expected: PASS with one message and one logical event after repeated delivery.

- [ ] **Step 5: Commit**

```bash
git add internal/coreteam internal/store/postgres internal/capability/client migrations cmd/dirextalk-agent/core_team_completion_sink.go cmd/dirextalk-agent/core_team_completion_sink_test.go
git commit -m "feat: deliver verified Team completion"
```

### Task 13: Compose, Qualify, Release, And Close Agent Gates

**Files:**
- Create: `cmd/dirextalk-agent/core_team_compose.go`
- Create: `cmd/dirextalk-agent/core_team_compose_test.go`
- Modify: `cmd/dirextalk-agent/core_serve.go`
- Modify: `cmd/dirextalk-agent/core_serve_test.go`
- Modify: `internal/config/config.go`
- Modify: `deploy/container/config/config.example.yaml`
- Modify: `deploy/container/agent.Containerfile`
- Modify: `docs/api-contract.md`
- Modify: `docs/core-v1-development-spec.md`
- Modify: `docs/delivery-tracker.md`

- [ ] **Step 1: Write failing composition/readiness tests**

Require Team absent when disabled or any DB/credential/provider/release/controller/Worker-listener dependency is missing; present only with exact schema digest and Pi release proof; background controller/audit/completion relays stop cleanly; no startup AWS call.

- [ ] **Step 2: Verify failure**

Run: `GOWORK=off go test ./cmd/dirextalk-agent ./internal/agentcapability/... -run 'Test.*Team.*(Compose|Readiness|Shutdown)' -count=1`

Expected: FAIL because composition does not exist.

- [ ] **Step 3: Wire the production composition**

```go
type coreTeamComposition struct { service *coreteam.Service; controller *coreteam.Controller; worker *coreteamworker.Service; audit *coreteam.AuditRelay; completion *coreteam.CompletionRelay }
func composeCoreTeam(cfg config.Config, deps coreTeamComposeDeps) (*coreTeamComposition, error)
```

Add explicit config for enablement, Worker listener, Pi release manifest, max concurrency fixed at 3, AWS region, and relay intervals. The private Worker listener sets an explicit receive limit of `coreteamworker.MaxResultSizeBytes` plus fixed Protobuf envelope overhead and keeps all other RPCs under their narrower field limits; the Product/Core listener does not inherit this larger limit. Secret values remain file references or encrypted database records. Register `agent.team.v1` only after `ReadyForPublication()`.

- [ ] **Step 4: Run full Agent verification and record current evidence**

Run:

```bash
GOWORK=off go test ./...
GOWORK=off go test -race ./internal/coreteam/... ./internal/coreteamworker/... ./internal/coreteamaws/... ./internal/coreteamruntime/...
GOWORK=off go vet ./...
GOWORK=off GOOS=linux GOARCH=amd64 go build ./cmd/...
buf lint
git diff --check
```

Expected: PASS. Any platform-only skip must name its exact build tag and Linux CI replacement; no broad unexplained skip is accepted.

- [ ] **Step 5: Commit**

```bash
git add cmd internal/config deploy docs
git commit -m "feat: compose Agent Core Team execution"
```

## Agent Release Gate

After Message Server and Flutter plans are complete, publish a new immutable Agent Core control image and official Pi Worker image. Do not reuse the old v89 Agent image as the new architecture release. Keep the old accepted AMI/ECR facts only as a comparison source until the new App-to-Worker-to-App acceptance and independent task-tagged zero-resource readback pass.
