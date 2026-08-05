# Worker Progress Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Central persist authenticated Worker milestones, deliver CloudWatch audit records asynchronously, and expose owner-scoped Team execution progress without raw runtime output.

**Architecture:** PostgreSQL receives each stable Worker event and its log Outbox row in one transaction. A supervised relay writes CloudWatch later, while a read model combines Team dispatch, Worker lease/heartbeat, milestones, result verification, and cleanup facts into bounded public progress.

**Tech Stack:** Go 1.26, PostgreSQL 18 migrations/pgx, gRPC/Protobuf/Buf, AWS SDK v2 CloudWatch Logs.

---

## File Map

- Create `migrations/000064_worker_milestone_events.up.sql` and `migrations/worker_milestone_events_test.go` for immutable milestone and audit-Outbox storage.
- Create `internal/workerprogress/types.go` and tests for private receipts and public stage/health contracts.
- Create `internal/store/postgres/worker_milestone_store.go` and integration tests for replay and Outbox fencing.
- Create `internal/store/postgres/team_execution_progress_store.go` and integration tests for owner-scoped list/get projections.
- Refactor `internal/app/worker_milestone_writer.go`; create `internal/app/worker_milestone_log_relay.go`; wire both through `internal/app/cloud_composition.go`.
- Extend `api/proto/dirextalk/agent/v1/team.proto`, regenerate Go stubs, and update RPC descriptor tests.
- Extend `internal/rpcapi/team_plan_service.go`, `internal/rpcapi/team_execution_codec.go`, service tests, and `internal/app/server.go` authorization/wiring.
- Update `docs/api-contract.md` and `docs/delivery-tracker.md` only after implementation evidence exists.

### Task 1: Freeze The Durable Schema And Closed Domain

**Files:**
- Create: `migrations/000064_worker_milestone_events.up.sql`
- Create: `migrations/worker_milestone_events_test.go`
- Create: `internal/workerprogress/types.go`
- Create: `internal/workerprogress/types_test.go`

- [ ] **Step 1: Write failing schema and vocabulary tests**

Require both tables, immutable event rows, exact kind/outcome checks, and absence of free-form message/output/error columns. Require these public values:

```go
func TestPublicProgressVocabularyIsClosed(t *testing.T) {
	stages := []workerprogress.Stage{
		workerprogress.StageQueued, workerprogress.StagePreparing,
		workerprogress.StageStartingWorker, workerprogress.StagePreparingInput,
		workerprogress.StageRunning, workerprogress.StageValidatingResult,
		workerprogress.StageCleaningUp, workerprogress.StageCompleted,
		workerprogress.StageFailed, workerprogress.StageCanceled,
		workerprogress.StageTimedOut,
	}
	for _, stage := range stages {
		if !stage.Valid() { t.Fatalf("invalid stage %q", stage) }
	}
}
```

- [ ] **Step 2: Verify tests fail before implementation**

Run: `go test ./migrations ./internal/workerprogress -count=1`

Expected: FAIL because migration 64 and the package do not exist.

- [ ] **Step 3: Add immutable receipt and Outbox tables**

The migration must contain this exact information model:

```sql
CREATE TABLE worker_milestone_events (
    event_seq bigserial PRIMARY KEY,
    event_id uuid NOT NULL UNIQUE,
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id) ON DELETE RESTRICT,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    deployment_id uuid NOT NULL REFERENCES worker_deployments(deployment_id) ON DELETE RESTRICT,
    task_id uuid NOT NULL,
    step_id uuid NOT NULL,
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 100),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    kind text NOT NULL CHECK (kind IN ('execution_started','action_started','action_succeeded','action_failed','execution_finished')),
    action_id text CHECK (action_id IS NULL OR action_id ~ '^[a-z][a-z0-9._-]{0,127}$'),
    outcome text CHECK (outcome IS NULL OR outcome IN ('succeeded','failed','canceled','timed_out','interrupted')),
    failure_stage text CHECK (failure_stage IS NULL OR failure_stage IN ('process','pi')),
    failure_code text CHECK (failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    event_digest bytea NOT NULL CHECK (octet_length(event_digest)=32),
    received_at timestamptz NOT NULL,
    FOREIGN KEY (task_id, step_id) REFERENCES task_steps(task_id, step_id) ON DELETE RESTRICT
);

CREATE TABLE worker_milestone_log_outbox (
    event_id uuid PRIMARY KEY REFERENCES worker_milestone_events(event_id) ON DELETE RESTRICT,
    available_at timestamptz NOT NULL,
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 100),
    claimed_by text,
    claim_epoch bigint NOT NULL DEFAULT 0 CHECK (claim_epoch >= 0),
    claim_expires_at timestamptz,
    delivered_at timestamptz,
    failure_code text CHECK (failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    CHECK ((claimed_by IS NULL)=(claim_expires_at IS NULL))
);
```

Add a trigger rejecting UPDATE/DELETE on milestone events and a deployment/event-sequence index.

- [ ] **Step 4: Add exact Go contracts**

Define `Stage`, `Health`, `Receipt`, `LogDelivery`, `TimelineEvent`, `Role`, `Execution`, `Summary`, `ListQuery`, `Page`, `Recorder`, `LogOutbox`, and `Reader`. Public types must omit Worker/Deployment IDs, lease epoch, object/log references, resource IDs, and free-form diagnostics.

- [ ] **Step 5: Format, test, and commit**

Run: `gofmt -w internal/workerprogress migrations/worker_milestone_events_test.go && go test ./migrations ./internal/workerprogress -count=1`

Expected: PASS.

```bash
git add migrations/000064_worker_milestone_events.up.sql migrations/worker_milestone_events_test.go internal/workerprogress
git commit -m "feat: persist closed Worker milestone schema"
```

### Task 2: Persist Exact Replays And Audit Deliveries

**Files:**
- Create: `internal/store/postgres/worker_milestone_store.go`
- Create: `internal/store/postgres/worker_milestone_store_integration_test.go`

- [ ] **Step 1: Write failing PostgreSQL replay/fencing tests**

Use one leased Team Worker and require first receipt plus exact replay:

```go
receipt, replayed, err := store.RecordWorkerMilestone(ctx, target, event, now)
if err != nil || replayed || receipt.EventSeq < 1 { t.Fatalf("receipt=%#v replayed=%v err=%v", receipt, replayed, err) }
same, replayed, err := store.RecordWorkerMilestone(ctx, target, event, now.Add(time.Second))
if err != nil || !replayed || same.EventSeq != receipt.EventSeq || !same.ReceivedAt.Equal(now) { t.Fatalf("replay=%#v replayed=%v err=%v", same, replayed, err) }
```

Reject same ID/different content, stale lease, foreign owner/Worker, forged log reference, and concurrent duplicate insert. Verify one milestone and one Outbox row survive store restart.

- [ ] **Step 2: Verify the focused test fails**

Run: `go test ./internal/store/postgres -run 'TestWorkerMilestone' -count=1`

Expected: FAIL because store methods are missing; PostgreSQL cases may SKIP without `AGENT_TEST_POSTGRES_DSN`, so digest validation must also run outside the skip path.

- [ ] **Step 3: Implement stable digest and transaction**

Hash a canonical struct containing schema/event/deployment/Worker/Owner/attempt/lease/kind/action/outcome/failure fields but excluding receipt time. Lock `worker_deployments`, recheck state and registered log scope, preserve first `received_at`, and insert the milestone plus Outbox row in one transaction.

- [ ] **Step 4: Implement fenced Outbox methods**

Expose:

```go
ClaimWorkerMilestoneLogDeliveries(context.Context, string, time.Time, time.Time, uint32) ([]workerprogress.LogDelivery, error)
ConfirmWorkerMilestoneLogDelivery(context.Context, string, int64, time.Time) error
RetryWorkerMilestoneLogDelivery(context.Context, string, int64, time.Time, workerprogress.LogFailureCode) error
```

Claims use `FOR UPDATE SKIP LOCKED`, increment `claim_epoch`, and return the original receipt timestamp. Confirm/retry require the exact event ID and claim epoch.

- [ ] **Step 5: Run normal/race tests and commit**

Run: `gofmt -w internal/store/postgres/worker_milestone_store*.go && go test ./internal/store/postgres -run 'TestWorkerMilestone' -count=1 && go test -race ./internal/store/postgres -run 'TestWorkerMilestone' -count=1`

Expected: PASS or an explicit PostgreSQL SKIP, with non-PostgreSQL validation PASS.

```bash
git add internal/store/postgres/worker_milestone_store.go internal/store/postgres/worker_milestone_store_integration_test.go
git commit -m "feat: record Worker milestones transactionally"
```

### Task 3: Move CloudWatch Off The Worker RPC Path

**Files:**
- Modify: `internal/app/worker_milestone_writer.go`
- Modify: `internal/app/worker_milestone_writer_test.go`
- Create: `internal/app/worker_milestone_log_relay.go`
- Create: `internal/app/worker_milestone_log_relay_test.go`
- Modify: `internal/app/cloud_composition.go`

- [ ] **Step 1: Write failing durable-ack and relay tests**

Require `EmitMilestone` to call only `workerprogress.Recorder`. Separately cover successful audit delivery, fixed-code retry after CloudWatch failure, connection/foundation mismatch, stale claim, cancellation, and a provider-error canary that never reaches returned text.

- [ ] **Step 2: Verify old synchronous behavior fails**

Run: `go test ./internal/app -run 'TestWorkerMilestone' -count=1`

Expected: FAIL until receipt and provider delivery are split.

- [ ] **Step 3: Reduce writer to the durable boundary**

```go
type workerMilestoneWriter struct {
	recorder workerprogress.Recorder
	now func() time.Time
}

func (writer *workerMilestoneWriter) EmitMilestone(ctx context.Context, target worker.MilestoneTarget, event workerlog.EventV1) error {
	if writer == nil || writer.recorder == nil || ctx == nil { return errors.New("Worker milestone relay is unavailable") }
	event.OccurredAt = writer.now().UTC()
	if _, _, err := writer.recorder.RecordWorkerMilestone(ctx, target, event, event.OccurredAt); err != nil { return errors.New("Worker milestone receipt failed") }
	return nil
}
```

- [ ] **Step 4: Implement and supervise the audit relay**

`RunOnce` claims a bounded batch, reuses existing derived Connection/Foundation/sink checks, emits the stored event, then confirms or retries with `deployment_unavailable`, `connection_unavailable`, `control_scope_unavailable`, `sink_unavailable`, or `delivery_failed`. Add the relay to `CloudComposition.Recover` and `CloudComposition.Run`.

- [ ] **Step 5: Run focused/race tests and commit**

Run: `gofmt -w internal/app/worker_milestone*.go internal/app/cloud_composition.go && go test ./internal/app ./internal/rpcapi -run 'WorkerMilestone' -count=1 && go test -race ./internal/app -run 'WorkerMilestone' -count=1`

Expected: PASS, including a simulated CloudWatch outage while the writer returns success.

```bash
git add internal/app/worker_milestone_writer.go internal/app/worker_milestone_writer_test.go internal/app/worker_milestone_log_relay.go internal/app/worker_milestone_log_relay_test.go internal/app/cloud_composition.go
git commit -m "feat: relay Worker audit logs asynchronously"
```

### Task 4: Build The Owner-Scoped Progress Read Model

**Files:**
- Create: `internal/store/postgres/team_execution_progress_store.go`
- Create: `internal/store/postgres/team_execution_progress_store_integration_test.go`
- Modify: `internal/workerprogress/types.go`
- Modify: `internal/workerprogress/types_test.go`

- [ ] **Step 1: Write failing stage, health, paging, and isolation tests**

Require this phase/milestone mapping:

```go
var cases = []struct {
	phase teamdispatch.Phase
	kind workerlog.Kind
	action string
	want workerprogress.Stage
}{
	{teamdispatch.PhaseIntent, "", "", workerprogress.StagePreparing},
	{teamdispatch.PhaseProvisioning, "", "", workerprogress.StageStartingWorker},
	{teamdispatch.PhaseActive, workerlog.KindActionStarted, "materialize-input", workerprogress.StagePreparingInput},
	{teamdispatch.PhaseActive, workerlog.KindActionStarted, "execute-role", workerprogress.StageRunning},
	{teamdispatch.PhaseResultReady, "", "", workerprogress.StageValidatingResult},
	{teamdispatch.PhaseDestroying, "", "", workerprogress.StageCleaningUp},
}
```

Test active/history filters, owner-bound cursor rejection, descending pagination, terminal outcome precedence, expired heartbeat, scheduled retry, timeline cap, and JSON absence of internal identifiers.

- [ ] **Step 2: Verify focused tests fail**

Run: `go test ./internal/workerprogress ./internal/store/postgres -run 'Test.*Progress' -count=1`

Expected: FAIL because mapping and reads are missing.

- [ ] **Step 3: Implement pure mapping**

Terminal outcomes win first. Otherwise map dispatch phase, then refine active execution from the latest valid milestone. Health is `terminal` for a terminal outcome, `recovering` for a scheduled retry, `delayed` for an expired active lease, and `healthy` otherwise.

- [ ] **Step 4: Implement owner-scoped list/get**

Add:

```go
func (store *Store) ListTeamExecutionProgress(ctx context.Context, query workerprogress.ListQuery) (workerprogress.Page, error)
func (store *Store) GetTeamExecutionProgress(ctx context.Context, ownerID, executionID string, timelineLimit uint32) (workerprogress.Execution, error)
```

Read Team execution/role/dispatch, Worker lease, and milestone facts in one repeatable-read snapshot. Bind opaque cursors to owner and active/history scope. Cap timelines at 50 and map private action IDs to public stages before returning.

- [ ] **Step 5: Run normal/race tests and commit**

Run: `gofmt -w internal/workerprogress internal/store/postgres/team_execution_progress_store*.go && go test ./internal/workerprogress ./internal/store/postgres -run 'Test.*Progress' -count=1 && go test -race ./internal/store/postgres -run 'Test.*Progress' -count=1`

Expected: PASS or explicit PostgreSQL SKIP where applicable.

```bash
git add internal/workerprogress internal/store/postgres/team_execution_progress_store.go internal/store/postgres/team_execution_progress_store_integration_test.go
git commit -m "feat: project Team execution progress"
```

### Task 5: Add The Bounded Protobuf Contract

**Files:**
- Modify: `api/proto/dirextalk/agent/v1/team.proto`
- Regenerate: `api/gen/dirextalk/agent/v1/team.pb.go`
- Regenerate: `api/gen/dirextalk/agent/v1/team_grpc.pb.go`
- Modify: `internal/rpcapi/proto_contract_test.go`

- [ ] **Step 1: Write a failing descriptor contract test**

Require `ListTeamExecutionsV3`, exact field numbers, closed stage/health enums, `TeamExecutionV3.progress = 18`, and absence of `worker_id`, `deployment_id`, `lease_epoch`, `resource_id`, `log`, `output`, `reasoning`, `tool_arguments`, and `error_message`.

- [ ] **Step 2: Verify descriptor test fails**

Run: `go test ./internal/rpcapi -run 'TestTeamExecutionProgressProtoContract' -count=1`

Expected: FAIL because the descriptors do not exist.

- [ ] **Step 3: Add list and progress messages**

Use this stable outer shape:

```proto
message TeamExecutionProgressV1 {
  string schema_version = 1;
  TeamExecutionProgressStageV1 stage = 2;
  TeamExecutionProgressHealthV1 health = 3;
  uint32 active_role_count = 4;
  uint32 terminal_role_count = 5;
  google.protobuf.Timestamp updated_at = 6;
  repeated TeamExecutionRoleProgressV1 roles = 7;
}

message ListTeamExecutionsV3Request {
  string owner_id = 1;
  TeamExecutionListScopeV3 scope = 2;
  int32 page_size = 3;
  string page_token = 4;
}

message ListTeamExecutionsV3Response {
  repeated TeamExecutionSummaryV3 executions = 1;
  string next_page_token = 2;
}
```

Each role includes role ID/title, runtime family/adapter, stage, health, attempt, timestamps, optional fixed failure enums, and at most 50 public timeline entries. Add field 18 to `TeamExecutionV3` and the list RPC beside Get.

- [ ] **Step 4: Regenerate, lint, test, and commit**

Run: `buf generate && buf lint && go test ./internal/rpcapi -run 'TestTeamExecutionProgressProtoContract' -count=1`

Expected: PASS with generated changes only from Buf.

```bash
git add api/proto/dirextalk/agent/v1/team.proto api/gen/dirextalk/agent/v1/team.pb.go api/gen/dirextalk/agent/v1/team_grpc.pb.go internal/rpcapi/proto_contract_test.go
git commit -m "feat: define Team execution progress contract"
```

### Task 6: Wire List/Get RPCs And Read Authorization

**Files:**
- Modify: `internal/rpcapi/team_plan_service.go`
- Modify: `internal/rpcapi/team_execution_codec.go`
- Modify: `internal/rpcapi/team_plan_service_test.go`
- Modify: `internal/app/server.go`
- Modify: `internal/app/server_team_auth_test.go`

- [ ] **Step 1: Add failing service/codec tests**

Cover active/history requests, cursor forwarding, owner isolation, invalid scope/page size, Get correlation, timeline cap, terminal cleanup agreement, unknown stage rejection, and unchanged report/artifact projection.

- [ ] **Step 2: Verify tests fail**

Run: `go test ./internal/rpcapi ./internal/app -run 'TeamExecution|TeamAuth' -count=1`

Expected: FAIL until service, codec, and method scope exist.

- [ ] **Step 3: Add a narrow read dependency**

```go
type TeamExecutionProgressReader interface {
	ListTeamExecutionProgress(context.Context, workerprogress.ListQuery) (workerprogress.Page, error)
	GetTeamExecutionProgress(context.Context, string, string, uint32) (workerprogress.Execution, error)
}
```

Add `WithExecutionProgressReads(store)` in `app.NewServer` without changing Team mutation authority.

- [ ] **Step 4: Implement strict list/get projection**

Get reads the existing execution/report/artifacts and progress, verifies identical Owner/Execution/Task/Plan bindings, and sets field 18. List requires explicit active/history scope and maps compact summaries only.

- [ ] **Step 5: Map authorization**

Map `TeamPlanService_ListTeamExecutionsV3_FullMethodName` to existing `team.plan.read`; extend `server_team_auth_test.go` to prove no broader scope.

- [ ] **Step 6: Run normal/race tests and commit**

Run: `gofmt -w internal/rpcapi/team_plan_service.go internal/rpcapi/team_execution_codec.go internal/rpcapi/team_plan_service_test.go internal/app/server.go internal/app/server_team_auth_test.go && go test ./internal/rpcapi ./internal/app -run 'TeamExecution|TeamAuth' -count=1 && go test -race ./internal/rpcapi -run 'TeamExecution' -count=1`

Expected: PASS.

```bash
git add internal/rpcapi/team_plan_service.go internal/rpcapi/team_execution_codec.go internal/rpcapi/team_plan_service_test.go internal/app/server.go internal/app/server_team_auth_test.go
git commit -m "feat: expose owner-scoped Team progress"
```

### Task 7: Verify Agent And Record Evidence

**Files:**
- Modify: `docs/api-contract.md`
- Modify: `docs/delivery-tracker.md`

- [ ] **Step 1: Run focused and broad checks**

Run each command separately:

```bash
go test ./migrations ./internal/workerprogress ./internal/workerlog ./internal/workerrunner ./internal/worker ./internal/store/postgres ./internal/app ./internal/rpcapi -count=1
go test -race ./internal/workerprogress ./internal/store/postgres ./internal/app ./internal/rpcapi -count=1
go vet ./internal/workerprogress ./internal/store/postgres ./internal/app ./internal/rpcapi
buf lint
go build ./cmd/dirextalk-agent ./cmd/dirextalk-cloud-worker
git diff --check
```

Expected: all configured lanes PASS. Any PostgreSQL SKIP must be rerun against disposable PostgreSQL 18.

- [ ] **Step 2: Run the PostgreSQL 18 lane**

Apply all migrations to a disposable PostgreSQL 18 database and rerun milestone/progress store tests with `AGENT_TEST_POSTGRES_DSN`. Expected: migration 64 applies once, restart/checksum checks pass, and focused tests PASS.

- [ ] **Step 3: Update documents with observed evidence**

Record the durable receipt, async audit relay, List/Get contract, exact tests, and remaining Message Server/Flutter/live work. Do not mark the three-repository feature complete at this checkpoint.

- [ ] **Step 4: Commit Agent evidence**

```bash
git add docs/api-contract.md docs/delivery-tracker.md
git commit -m "docs: record Agent Worker progress contract"
```
