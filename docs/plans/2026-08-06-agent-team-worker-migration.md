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
- Restore `cmd/dirextalk-cloud-worker/`, `internal/coreteamruntime/`, `internal/coreteamaws/`, and `deploy/container/pi-worker/` by behavior, not by cherry-picking old packages.
- Create `cmd/dirextalk-agent/core_team_compose.go` and extend current Core composition/configuration only after all readiness gates pass.

### Task 1: Add The Closed Core Task Kind

**Files:**
- Modify: `internal/coretask/types.go`
- Modify: `internal/coretask/coretask_test.go`
- Modify: `api/proto/dirextalk/agent/v1/core_task.proto`
- Modify: `migrations/agent_migrations.sql`
- Modify: `migrations/core_v1_contract_test.go`

- [ ] **Step 1: Write failing Task union and schema tests**

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

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `GOWORK=off go test ./internal/coretask ./migrations -run 'Test.*TeamExecution' -count=1`

Expected: FAIL because the kind, payload, enum, and migration constraint do not exist.

- [ ] **Step 3: Implement the closed union**

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

- [ ] **Step 4: Run focused and contract tests**

Run: `GOWORK=off go test ./internal/coretask ./migrations ./internal/rpcapi -run 'Test.*(TeamExecution|TaskKind|Proto)' -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

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

- [ ] **Step 1: Write failing closed-domain tests**

Cover one to three roles, acyclic dependencies, unique role IDs, Pi-only runtime, `t3.small`, `ap-northeast-3`, positive credential revision, output budget, quote expiry, and stable digest. Require a fourth role, unknown runtime, cycle, expired quote, free-form AWS request, or credential bytes to fail.

```go
func TestCompilerProducesBoundedPiPlan(t *testing.T) {
	plan, err := NewCompiler(fakeCatalog(), fakeQuote()).Compile(context.Background(), CompileCommand{
		OwnerID: ownerID, Goal: "research and verify", ConversationID: conversationID,
		CredentialID: credentialID, CredentialRevision: 3,
		Roles: []RoleProposal{{RoleID: "research", Goal: "research"}, {RoleID: "review", Goal: "review", DependsOn: []string{"research"}}},
	})
	if err != nil || len(plan.Roles) != 2 || plan.Runtime.Adapter != "pi-v1" || !plan.Valid() { t.Fatalf("plan=%#v err=%v", plan, err) }
}
```

- [ ] **Step 2: Verify the tests fail**

Run: `GOWORK=off go test ./internal/coreteam -run 'TestCompiler|Test.*Valid' -count=1`

Expected: FAIL because `internal/coreteam` does not exist.

- [ ] **Step 3: Implement the domain**

Define these closed types and ports:

```go
const MaxRoles = 3
type PlanStatus string
const (PlanWaitingUser PlanStatus = "waiting_user"; PlanApproved PlanStatus = "approved"; PlanExpired PlanStatus = "expired")
type ExecutionStatus string
const (ExecutionQueued ExecutionStatus = "queued"; ExecutionRunning ExecutionStatus = "running"; ExecutionCleaningUp ExecutionStatus = "cleaning_up"; ExecutionCompleted ExecutionStatus = "completed"; ExecutionFailed ExecutionStatus = "failed"; ExecutionCanceled ExecutionStatus = "canceled"; ExecutionTimedOut ExecutionStatus = "timed_out")
type RuntimeBinding struct { RuntimeID, Adapter, ImageDigest, AMIID string; OutputTokens uint32 }
type QuoteBinding struct { Region, AvailabilityZone, InstanceType, Currency, Amount, HardBudget string; ExpiresAt time.Time }
type Role struct { RoleID, Goal string; DependsOn []string }
type Plan struct { PlanID, OwnerID, TaskID, ConversationID, CredentialID, ConfirmationID string; Revision, CredentialRevision uint64; Goal, Digest string; Runtime RuntimeBinding; Quote QuoteBinding; Roles []Role; Status PlanStatus }
type Compiler struct { catalog RuntimeCatalog; quotes QuoteProvider; now func() time.Time }
```

Canonical JSON must sort roles and dependencies and hash only immutable fields. No AWS SDK type, command string, URL, secret, or provider error may enter a Plan.

- [ ] **Step 4: Run normal and race tests**

Run: `GOWORK=off go test ./internal/coreteam -count=1 && GOWORK=off go test -race ./internal/coreteam -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

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

- [ ] **Step 1: Write failing PostgreSQL integration tests**

Require atomic creation of Core Task + Plan + roles + execution + replay, exact replay preservation, conflicting replay rejection, owner/account isolation, restart recovery, immutable Plan rows, monotonic execution revision, and no secret-shaped columns.

```go
created, replayed, err := store.CreateTeamPlan(ctx, command, now)
if err != nil || replayed || created.Plan.TaskID == "" { t.Fatalf("created=%#v replayed=%v err=%v", created, replayed, err) }
same, replayed, err := store.CreateTeamPlan(ctx, command, now.Add(time.Minute))
if err != nil || !replayed || same.Plan.Digest != created.Plan.Digest || !same.CreatedAt.Equal(created.CreatedAt) { t.Fatalf("same=%#v replayed=%v err=%v", same, replayed, err) }
```

- [ ] **Step 2: Verify failure against disposable PostgreSQL 18**

Run: `AGENT_TEST_POSTGRES_DSN="$AGENT_TEAM_TEST_DSN" GOWORK=off go test ./internal/store/postgres -run 'TestCoreTeamStore' -count=1`

Expected: FAIL because schema and store methods are absent.

- [ ] **Step 3: Add the durable schema and store**

Add closed tables named `core_team_plans`, `core_team_roles`, `core_team_executions`, `core_team_role_runs`, and `core_team_replays`. Every row includes `owner_id`; Plan and role definitions are immutable; execution mutations use expected revision. `core_team_plans.task_id` references `core_tasks(task_id)` and `confirmation_id` references `core_confirmations(confirmation_id)`.

Expose this repository contract:

```go
type Repository interface {
	CreatePlan(context.Context, CreatePlanCommand) (PlanRecord, bool, error)
	GetPlan(context.Context, string, string) (PlanRecord, error)
	CreateExecution(context.Context, CreateExecutionCommand) (Execution, bool, error)
	GetExecution(context.Context, string, string) (Execution, error)
	ListExecutions(context.Context, ListQuery) (Page, error)
	CompareAndSwapExecution(context.Context, Execution, uint64) (Execution, error)
	ListRunnableRoles(context.Context, string, string, uint32) ([]RoleRun, error)
}
```

- [ ] **Step 4: Run migration, restart, concurrency, and race tests**

Run: `AGENT_TEST_POSTGRES_DSN="$AGENT_TEAM_TEST_DSN" GOWORK=off go test ./migrations ./internal/store/postgres -run 'Test(CoreTeam|CoreV1Contract)' -count=1 && AGENT_TEST_POSTGRES_DSN="$AGENT_TEAM_TEST_DSN" GOWORK=off go test -race ./internal/store/postgres -run 'TestCoreTeamStore' -count=1`

Expected: PASS with one Plan/execution under concurrent duplicate creation.

- [ ] **Step 5: Commit**

```bash
git add migrations internal/store/postgres internal/coreteam/repository.go
git commit -m "feat: persist Core Team executions"
```

### Task 4: Bind Core Confirmation And Block Credential Rotation

**Files:**
- Create: `internal/coreteam/confirmation.go`
- Create: `internal/coreteam/confirmation_test.go`
- Create: `internal/store/postgres/core_team_confirmation.go`
- Modify: `internal/coreaws/service_credentials_plan.go`
- Modify: `internal/coreaws/coreaws_test.go`
- Create: `internal/store/postgres/core_team_credential_guard_integration_test.go`

- [ ] **Step 1: Write failing binding and mutation-guard tests**

Test exact owner, Plan revision/digest, runtime/image/AMI, credential revision, quote, budget, region, instance, network, input digest, and expiry binding. Test create/update/delete credential returns `team_execution_active` while any Team execution is nonterminal and succeeds after verified cleanup.

- [ ] **Step 2: Verify failure**

Run: `GOWORK=off go test ./internal/coreteam ./internal/coreaws ./internal/store/postgres -run 'Test.*(TeamConfirmation|TeamCredential)' -count=1`

Expected: FAIL because resolver and guard are absent.

- [ ] **Step 3: Implement the exact Core boundary**

```go
type ActiveExecutionGuard interface { RequireNoActiveTeamExecution(context.Context, string) error }
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

- [ ] **Step 4: Run focused and PostgreSQL race tests**

Run: `AGENT_TEST_POSTGRES_DSN="$AGENT_TEAM_TEST_DSN" GOWORK=off go test -race ./internal/coreteam ./internal/coreaws ./internal/store/postgres -run 'Test.*(TeamConfirmation|TeamCredential)' -count=1`

Expected: PASS, including concurrent launch vs key rotation.

- [ ] **Step 5: Commit**

```bash
git add internal/coreteam internal/coreaws internal/store/postgres
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

- [ ] **Step 1: Write failing descriptor and operation tests**

Require capability ID `agent.team.v1`, protocol 1, readiness false until all dependencies are ready, exact operations `plans_get`, `executions_list`, `executions_get`, and `executions_cancel`, safe/read vs high/mutation risks, 1 MiB maximum requests, strict schemas, owner from PermissionContext, and no internal identifiers in JSON.

- [ ] **Step 2: Verify failure**

Run: `GOWORK=off go test ./internal/agentcapability/... ./internal/coreteam -run 'Test.*TeamCapability' -count=1`

Expected: FAIL because the capability does not exist.

- [ ] **Step 3: Implement the capability adapter**

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

- [ ] **Step 4: Run capability, grant, and canary tests**

Run: `GOWORK=off go test ./internal/agentcapability/... ./internal/capability/... ./internal/coreteam -run 'Test.*(Team|Grant|Schema)' -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

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

- [ ] **Step 1: Write failing resolver and tool contract tests**

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

- [ ] **Step 2: Verify failure**

Run: `GOWORK=off go test ./cmd/dirextalk-agent -run 'TestTeamConversationResolver' -count=1`

Expected: FAIL because the resolver is absent.

- [ ] **Step 3: Implement the built-in resolver**

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

- [ ] **Step 4: Compose and verify model-context privacy**

Chain the resolver after existing extension, Product, and Web Search resolvers with deterministic reserved-name conflict detection. Assert durable conversation snapshots contain only schema/content digests and safe tool summaries, while canonical Team Proposal arguments remain Agent-owned and never appear in public turn events.

Run: `GOWORK=off go test -race ./cmd/dirextalk-agent ./internal/coreconversation ./internal/coreteam -run 'Test.*(TeamConversation|ReservedTool|ToolPrivacy)' -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

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

- [ ] **Step 1: Write failing protocol tests**

Cover challenge, one-time enrollment, assignment, claim, heartbeat, milestone, complete, attempt/lease fencing, expired enrollment, replay, foreign Worker, and a secret canary in provider errors.

- [ ] **Step 2: Verify failure**

Run: `GOWORK=off go test ./internal/coreteamworker ./internal/store/postgres -run 'TestCoreTeamWorker' -count=1`

Expected: FAIL because the protocol and store do not exist.

- [ ] **Step 3: Define and implement the closed protocol**

The proto service exposes only `CreateIdentityChallenge`, `Enroll`, `GetAssignment`, `Claim`, `Heartbeat`, `EmitMilestone`, and `Complete`. Public messages carry canonical IDs, attempt, lease epoch, closed enums, digests, timestamps, and bounded result metadata. They contain no AWS credential, shell command, IP, AMI, log reference, raw error, stdout, reasoning, or tool payload.

```go
type LeaseFence struct { ExecutionID, RoleID, WorkerID string; Attempt uint32; LeaseEpoch uint64 }
type Service struct { repo Repository; verifier IdentityVerifier; now func() time.Time }
```

Persist `core_team_worker_challenges`, `core_team_workers`, and lease fields on `core_team_role_runs`; all mutations use `SELECT ... FOR UPDATE` and exact fence comparison.

- [ ] **Step 4: Generate, test, and race-test**

Run: `buf lint && buf generate && AGENT_TEST_POSTGRES_DSN="$AGENT_TEAM_TEST_DSN" GOWORK=off go test -race ./internal/coreteamworker ./internal/store/postgres -run 'TestCoreTeamWorker' -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api/proto api/gen internal/coreteamworker internal/store/postgres migrations
git commit -m "feat: add fenced Team Worker protocol"
```

### Task 8: Restore The Official Pi Runtime And Worker Release

**Files:**
- Create: `internal/coreteamruntime/pi.go`
- Create: `internal/coreteamruntime/pi_test.go`
- Create: `internal/coreteamruntime/result.go`
- Create: `internal/coreteamruntime/result_test.go`
- Create: `cmd/dirextalk-cloud-worker/main.go`
- Create: `cmd/dirextalk-cloud-worker/main_test.go`
- Create: `deploy/container/pi-worker/worker.Containerfile`
- Create: `deploy/container/pi-worker/dirextalk-cloud-worker.service`
- Create: `deploy/container/pi-worker/README.md`

- [ ] **Step 1: Port the accepted behavior tests before implementation**

Recreate tests for Pi 0.83.0 event parsing, `dirextalk_submit_result`, output-token override, process timeout/output/non-zero failures, closed provider/auth/quota/rate/request/server/network failures, invalid event, missing final result, empty workspace, result size/digest, and raw-error destruction.

- [ ] **Step 2: Verify the tests fail**

Run: `GOWORK=off go test ./internal/coreteamruntime ./cmd/dirextalk-cloud-worker -count=1`

Expected: FAIL because the runtime and command do not exist.

- [ ] **Step 3: Implement the exact runtime contract**

```go
type FailureStage string
const (FailureProcess FailureStage = "process"; FailurePi FailureStage = "pi")
type Result struct { SchemaVersion uint32; Summary string; Deliverables []Deliverable; Tests []TestResult; Usage Usage }
type Runner interface { Run(context.Context, Assignment, Workspace) (Result, ClosedFailure, error) }
```

Use argv arrays only inside the Worker process, an empty environment plus explicitly materialized model variables, a task-local `0600` Pi override, fixed output limits, no provider text in returned failures, and cleanup of temporary files in `defer`.

- [ ] **Step 4: Run real-binary qualification and build checks**

Run: `DIREXTALK_PI_QUALIFY=1 GOWORK=off go test ./internal/coreteamruntime -run TestOfficialPiBinaryLoopback -count=1 && GOWORK=off go test -race ./internal/coreteamruntime ./cmd/dirextalk-cloud-worker -count=1 && GOWORK=off GOOS=linux GOARCH=amd64 go build ./cmd/dirextalk-cloud-worker`

Expected: PASS with pinned Pi and extension digests and one structured result.

- [ ] **Step 5: Commit**

```bash
git add internal/coreteamruntime cmd/dirextalk-cloud-worker deploy/container/pi-worker
git commit -m "feat: restore qualified Pi Worker runtime"
```

### Task 9: Add Typed Ephemeral AWS Worker Lifecycle

**Files:**
- Create: `internal/coreteamaws/provider.go`
- Create: `internal/coreteamaws/provider_test.go`
- Create: `internal/coreteamaws/sdk.go`
- Create: `internal/coreteamaws/sdk_test.go`
- Create: `internal/coreteamaws/template.go`
- Create: `internal/coreteamaws/template_test.go`
- Create: `internal/store/postgres/core_team_resource_store.go`
- Create: `internal/store/postgres/core_team_resource_store_integration_test.go`
- Modify: `migrations/agent_migrations.sql`

- [ ] **Step 1: Write failing provider and recovery tests**

Require no ingress/SSH/SSM, encrypted root volume, exact AMI/runtime digest, SG/ENI/EIP/EC2/EBS tags, stable request tokens, write-before-mutate intents, create response-loss readback, delete response-loss readback, concurrent reconciliation, and `verified_destroyed` only after every resource is absent.

- [ ] **Step 2: Verify failure**

Run: `GOWORK=off go test ./internal/coreteamaws ./internal/store/postgres -run 'Test.*TeamAWS' -count=1`

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

Reuse `coreworkload/aws.CredentialResolver` and the target Core pricing/readiness components. The Team provider may expose only the fixed Worker resource graph; no generic EC2 input, arbitrary tag, user data, IAM policy, URL, or shell field is representable.

- [ ] **Step 4: Run template, provider, PostgreSQL, and race tests**

Run: `AGENT_TEST_POSTGRES_DSN="$AGENT_TEAM_TEST_DSN" GOWORK=off go test -race ./internal/coreteamaws ./internal/store/postgres -run 'Test.*TeamAWS' -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/coreteamaws internal/store/postgres migrations
git commit -m "feat: manage ephemeral Pi Workers on AWS"
```

### Task 10: Run The Durable Team Controller And Verify Results

**Files:**
- Create: `internal/coreteam/controller.go`
- Create: `internal/coreteam/controller_test.go`
- Create: `internal/coreteam/result.go`
- Create: `internal/coreteam/result_test.go`
- Create: `internal/store/postgres/core_team_result_store.go`
- Create: `internal/store/postgres/core_team_controller_integration_test.go`
- Modify: `migrations/agent_migrations.sql`

- [ ] **Step 1: Write failing lifecycle tests**

Cover `intent -> input_ready -> provisioning -> active -> result_ready -> destroying -> completed`, max 3 active roles, dependency ordering, retry with new attempt/lease, cancel before/after create, result upload during cancel, controller restart, result digest mismatch, Worker-authored cloud claim removal, and terminal success only after cleanup.

- [ ] **Step 2: Verify failure**

Run: `GOWORK=off go test ./internal/coreteam ./internal/store/postgres -run 'Test.*TeamController' -count=1`

Expected: FAIL because the controller does not exist.

- [ ] **Step 3: Implement one bounded reconciliation step**

```go
type Controller struct { repo ControllerRepository; workers WorkerControl; cloud CloudProvider; results ResultStore; maxActive uint32; now func() time.Time }
func (c *Controller) ReconcileOnce(ctx context.Context, ownerID, executionID string) (Execution, error)
```

Each call locks one execution, reads provider facts before mutation, starts at most `3-activeCount` runnable roles, validates result schema/digest before success, and moves every terminal path through cleanup. Store the immutable report only after all roles terminal and every resource ledger row is `verified_destroyed`.

- [ ] **Step 4: Run normal, race, and PostgreSQL restart tests**

Run: `AGENT_TEST_POSTGRES_DSN="$AGENT_TEAM_TEST_DSN" GOWORK=off go test -race ./internal/coreteam ./internal/store/postgres -run 'Test.*TeamController' -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/coreteam internal/store/postgres migrations
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
- Modify: `migrations/agent_migrations.sql`

- [ ] **Step 1: Write failing milestone/replay/Outbox tests**

Require stable event digest, exact replay preserving first receipt, same ID/different event rejection, stale lease rejection, immutable events, one Outbox row, fenced claim/confirm/retry, CloudWatch failure after durable ack, owner-scoped list/get, bounded timeline, and JSON absence of Worker/deployment/cloud/log/raw fields.

- [ ] **Step 2: Verify failure**

Run: `GOWORK=off go test ./internal/coreteam ./internal/store/postgres -run 'Test.*TeamProgress|Test.*TeamMilestone' -count=1`

Expected: FAIL because durable progress is absent.

- [ ] **Step 3: Implement closed progress and audit delivery**

```go
type Stage string
const (StageQueued Stage = "queued"; StagePreparing Stage = "preparing"; StageStartingWorker Stage = "starting_worker"; StagePreparingInput Stage = "preparing_input"; StageRunning Stage = "running"; StageValidatingResult Stage = "validating_result"; StageCleaningUp Stage = "cleaning_up"; StageCompleted Stage = "completed"; StageFailed Stage = "failed"; StageCanceled Stage = "canceled"; StageTimedOut Stage = "timed_out")
type Health string
const (HealthHealthy Health = "healthy"; HealthDelayed Health = "delayed"; HealthRecovering Health = "recovering"; HealthAttentionRequired Health = "attention_required"; HealthTerminal Health = "terminal")
```

Use `core_team_milestones` immutable rows and `core_team_audit_outbox`. Worker RPC returns after the database transaction; the supervised relay writes the existing 30-day CloudWatch stream asynchronously and stores only closed retry codes.

- [ ] **Step 4: Run PostgreSQL, race, and outage tests**

Run: `AGENT_TEST_POSTGRES_DSN="$AGENT_TEAM_TEST_DSN" GOWORK=off go test -race ./internal/coreteam ./internal/store/postgres -run 'Test.*(TeamProgress|TeamMilestone|AuditRelay)' -count=1`

Expected: PASS, including simulated CloudWatch outage with Worker ack success.

- [ ] **Step 5: Commit**

```bash
git add internal/coreteam internal/store/postgres migrations
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

Add explicit config for enablement, Worker listener, Pi release manifest, max concurrency fixed at 3, AWS region, and relay intervals. Secret values remain file references or encrypted database records. Register `agent.team.v1` only after `ReadyForPublication()`.

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
