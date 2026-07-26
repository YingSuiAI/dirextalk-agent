package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/google/uuid"
)

type pgRecoveryProvider struct {
	readState string
	readErr   error
	applyN    int
	readN     int
}

func pgWorkloadTarget() coreworkload.TargetSettings {
	return coreworkload.TargetSettings{Identity: coreworkload.TargetIdentity{Kind: coreworkload.TargetCoreRunner, CoreRunnerID: "runner-pg-test", CoreRunnerService: "workload-pg-test"}}
}

type pgFailEventStore struct {
	coreworkload.Store
	fail bool
}

func (s *pgFailEventStore) AppendEvent(ctx context.Context, id string, event coreworkload.Event) (coreworkload.Event, error) {
	if s.fail {
		return coreworkload.Event{}, errors.New("transient event store failure")
	}
	return s.Store.AppendEvent(ctx, id, event)
}

func (p *pgRecoveryProvider) Apply(context.Context, coreworkload.Plan, coreworkload.Operation) (coreworkload.Readback, error) {
	p.applyN++
	return coreworkload.Readback{}, errors.New("provider token=redacted")
}
func (p *pgRecoveryProvider) Destroy(context.Context, coreworkload.Plan, coreworkload.Operation) (coreworkload.Readback, error) {
	p.applyN++
	return coreworkload.Readback{}, errors.New("provider secret=redacted")
}
func (p *pgRecoveryProvider) Read(_ context.Context, plan coreworkload.Plan, op coreworkload.Operation) (coreworkload.Readback, error) {
	p.readN++
	if p.readErr != nil {
		return coreworkload.Readback{}, p.readErr
	}
	return coreworkload.Readback{TargetKind: plan.TargetKind, WorkloadID: op.WorkloadID, State: p.readState, Identity: plan.Target.Identity, At: time.Now().UTC()}, nil
}

func TestCoreWorkloadPostgresAtomicLifecycle(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	ws := NewCoreWorkloadStore(store)
	plan, err := ws.CreatePlan(ctx, coreworkload.PlanInput{IdempotencyKey: uuid.NewString(), Summary: "integration workload", TargetKind: coreworkload.TargetCoreRunner, Target: pgWorkloadTarget(), CommandSteps: []string{"install"}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	request := coreworkload.RequestCommand{PlanID: plan.ID, Kind: coreworkload.OperationApply, IdempotencyKey: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour)}
	first, err := ws.RequestOperation(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := ws.RequestOperation(ctx, request)
	if err != nil || replay.Operation.ID != first.Operation.ID {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	var taskKind, taskStatus, confirmationState, operationStatus string
	if err = store.pool.QueryRow(ctx, `SELECT t.task_kind,t.status,c.state,o.status FROM core_tasks t JOIN core_confirmations c ON c.task_id=t.task_id JOIN core_workload_operations o ON o.task_id=t.task_id WHERE t.task_id=$1`, first.Task.ID).Scan(&taskKind, &taskStatus, &confirmationState, &operationStatus); err != nil {
		t.Fatal(err)
	}
	if taskKind != "workload" || taskStatus != "waiting_user" || confirmationState != "pending" || operationStatus != "waiting_user" {
		t.Fatalf("kind=%s task=%s conf=%s op=%s", taskKind, taskStatus, confirmationState, operationStatus)
	}
	confirmDomain, err := coreconfirmation.NewService(NewCoreConfirmationStore(store))
	if err != nil {
		t.Fatal(err)
	}
	confirmRPC, err := rpcapi.NewCoreConfirmationService(confirmDomain)
	if err != nil {
		t.Fatal(err)
	}
	confirmedRPC, err := confirmRPC.Confirm(ctx, &agentv1.ConfirmationServiceConfirmRequest{ConfirmationId: first.Confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: first.Confirmation.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if confirmedRPC.GetConfirmation().GetState() != agentv1.CoreConfirmationState_CORE_CONFIRMATION_STATE_CONFIRMED {
		t.Fatalf("state=%s", confirmedRPC.GetConfirmation().GetState())
	}
	var stillWaiting string
	if err = store.pool.QueryRow(ctx, `SELECT status FROM core_tasks WHERE task_id=$1`, first.Task.ID).Scan(&stillWaiting); err != nil {
		t.Fatal(err)
	}
	if stillWaiting != "waiting_user" {
		t.Fatalf("task transitioned during confirmation: %s", stillWaiting)
	}
	consumed, _, err := ws.Consume(ctx, first.Operation.ID, first.Confirmation.ConfirmationID, plan.Digest, first.Operation.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.Status != coreworkload.OperationRunning {
		t.Fatalf("status=%s", consumed.Status)
	}
	completionReadback := coreworkload.Readback{TargetKind: plan.TargetKind, WorkloadID: consumed.WorkloadID, State: "ready", Identity: plan.Target.Identity, At: time.Now().UTC()}
	done, terminalTask, err := ws.CompleteDispatch(ctx, consumed.ID, consumed.TaskID, consumed.DispatchClaim, consumed.DispatchEpoch, "", completionReadback, "")
	if err != nil || done.Status != coreworkload.OperationSucceeded {
		t.Fatalf("done=%+v err=%v", done, err)
	}
	replayed, replayTask, err := ws.CompleteDispatch(ctx, consumed.ID, consumed.TaskID, consumed.DispatchClaim, consumed.DispatchEpoch, "", completionReadback, "")
	var replayJSON, terminalJSON any
	if terminalTask.Result != nil {
		_ = json.Unmarshal(terminalTask.Result.JSON, &terminalJSON)
	}
	if replayTask.Result != nil {
		_ = json.Unmarshal(replayTask.Result.JSON, &replayJSON)
	}
	if err != nil || !reflect.DeepEqual(replayed, done) || !reflect.DeepEqual(replayTask, terminalTask) || replayTask.Result == nil || !reflect.DeepEqual(replayJSON, terminalJSON) {
		t.Fatalf("terminal replay=%+v task=%+v initial=%+v err=%v", replayed, replayTask, terminalTask, err)
	}
	events, err := ws.ListEvents(ctx, consumed.ID, 0)
	if err != nil || len(events) < 3 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
}

func TestCoreWorkloadPostgresFencedTaskIDIsolation(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	ws := NewCoreWorkloadStore(store)
	plan, err := ws.CreatePlan(ctx, coreworkload.PlanInput{IdempotencyKey: uuid.NewString(), Summary: "fence isolation", TargetKind: coreworkload.TargetCoreRunner, Target: pgWorkloadTarget(), CommandSteps: []string{"run"}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	r1, err := ws.RequestOperation(ctx, coreworkload.RequestCommand{PlanID: plan.ID, Kind: coreworkload.OperationApply, IdempotencyKey: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := ws.RequestOperation(ctx, coreworkload.RequestCommand{PlanID: plan.ID, Kind: coreworkload.OperationApply, IdempotencyKey: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ws.Confirm(ctx, r1.Confirmation.ConfirmationID, r1.Confirmation.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err = ws.Confirm(ctx, r2.Confirmation.ConfirmationID, r2.Confirmation.Revision); err != nil {
		t.Fatal(err)
	}
	holder := uuid.NewString()
	at := time.Now().UTC().Add(time.Hour)
	for _, taskID := range []string{r1.Task.ID, r2.Task.ID} {
		if _, err = store.pool.Exec(ctx, `UPDATE core_tasks SET status='running',attempt=1,lease_epoch=7,lease_holder=$2,lease_expires_at=$3,revision=2 WHERE task_id=$1`, taskID, holder, at); err != nil {
			t.Fatal(err)
		}
	}
	f1 := coreworkload.TaskFence{TaskID: r1.Task.ID, Holder: holder, Attempt: 1, LeaseEpoch: 7, Revision: 2, ExpiresAt: at}
	f2 := f1
	f2.TaskID = r2.Task.ID
	if _, _, err = ws.ConsumeFenced(ctx, r1.Operation.ID, r1.Confirmation.ConfirmationID, plan.Digest, r1.Operation.Revision, f2); !errors.Is(err, coreworkload.ErrRevisionConflict) {
		t.Fatalf("cross consume err=%v", err)
	}
	run, _, err := ws.ConsumeFenced(ctx, r1.Operation.ID, r1.Confirmation.ConfirmationID, plan.Digest, r1.Operation.Revision, f1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ws.RenewDispatchLeaseFenced(ctx, run.ID, run.DispatchClaim, run.DispatchEpoch, f2); !errors.Is(err, coreworkload.ErrRevisionConflict) {
		t.Fatalf("cross renew err=%v", err)
	}
	if _, err = ws.RecoverClaimFenced(ctx, run.ID, "", f2); !errors.Is(err, coreworkload.ErrRevisionConflict) {
		t.Fatalf("cross recover err=%v", err)
	}
	rb := coreworkload.Readback{TargetKind: plan.TargetKind, WorkloadID: run.WorkloadID, State: "ready", Identity: plan.Target.Identity, At: time.Now().UTC()}
	if _, _, err = ws.CompleteDispatchFenced(ctx, run.ID, run.TaskID, run.DispatchClaim, run.DispatchEpoch, "", rb, "", f2); !errors.Is(err, coreworkload.ErrRevisionConflict) {
		t.Fatalf("cross complete err=%v", err)
	}
	if _, err = ws.RenewDispatchLeaseFenced(ctx, run.ID, run.DispatchClaim, run.DispatchEpoch, f1); err != nil {
		t.Fatal(err)
	}
	if _, _, err = ws.CompleteDispatchFenced(ctx, run.ID, run.TaskID, run.DispatchClaim, run.DispatchEpoch, "", rb, "", f1); err != nil {
		t.Fatal(err)
	}
	if _, _, err = ws.ConsumeFenced(ctx, r2.Operation.ID, r2.Confirmation.ConfirmationID, plan.Digest, r2.Operation.Revision, f1); !errors.Is(err, coreworkload.ErrRevisionConflict) {
		t.Fatalf("second cross consume err=%v", err)
	}
	if _, _, err = ws.ConsumeFenced(ctx, r2.Operation.ID, r2.Confirmation.ConfirmationID, plan.Digest, r2.Operation.Revision, f2); err != nil {
		t.Fatal(err)
	}
}

func TestCoreWorkloadPostgresReplayConflictAndExpiry(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	ws := NewCoreWorkloadStore(store)
	plan, err := ws.CreatePlan(ctx, coreworkload.PlanInput{IdempotencyKey: uuid.NewString(), Summary: "replay", TargetKind: coreworkload.TargetCoreRunner, Target: pgWorkloadTarget(), CommandSteps: []string{"run"}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	key := uuid.NewString()
	first, err := ws.RequestOperation(ctx, coreworkload.RequestCommand{PlanID: plan.ID, Kind: coreworkload.OperationApply, IdempotencyKey: key, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ws.RequestOperation(ctx, coreworkload.RequestCommand{PlanID: plan.ID, Kind: coreworkload.OperationDestroy, WorkloadID: first.Operation.WorkloadID, IdempotencyKey: key, ExpiresAt: time.Now().UTC().Add(time.Hour)}); err == nil {
		t.Fatal("same key/different content accepted")
	}
	expired, err := ws.CreatePlan(ctx, coreworkload.PlanInput{IdempotencyKey: uuid.NewString(), Summary: "expired", TargetKind: coreworkload.TargetCoreRunner, Target: pgWorkloadTarget(), CommandSteps: []string{"run"}, ExpiresAt: time.Now().UTC().Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ws.RequestOperation(ctx, coreworkload.RequestCommand{PlanID: expired.ID, Kind: coreworkload.OperationApply, IdempotencyKey: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour)}); err == nil {
		t.Fatal("expired plan accepted")
	}
}

func TestCoreWorkloadPostgresRejectProjection(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	ws := NewCoreWorkloadStore(store)
	p, err := ws.CreatePlan(ctx, coreworkload.PlanInput{IdempotencyKey: uuid.NewString(), Summary: "reject", TargetKind: coreworkload.TargetCoreRunner, Target: pgWorkloadTarget(), CommandSteps: []string{"run"}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	r, err := ws.RequestOperation(ctx, coreworkload.RequestCommand{PlanID: p.ID, Kind: coreworkload.OperationApply, IdempotencyKey: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := coreconfirmation.NewService(NewCoreConfirmationStore(store))
	if _, err = d.Reject(ctx, coreconfirmation.RejectCommand{ConfirmationID: r.Confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: r.Confirmation.Revision, Reason: "owner rejected", At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	op, err := ws.GetOperation(ctx, r.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != coreworkload.OperationRejected {
		t.Fatalf("status=%s", op.Status)
	}
	var taskStatus string
	if err = store.pool.QueryRow(ctx, `SELECT status FROM core_tasks WHERE task_id=$1`, r.Task.ID).Scan(&taskStatus); err != nil {
		t.Fatal(err)
	}
	if taskStatus != "canceled" {
		t.Fatalf("task=%s", taskStatus)
	}
	assertWorkloadTaskEventSequence(t, ctx, store, r.Task.ID, 1, 2)
}

func TestCoreWorkloadPostgresCrashRecoveryClaimFence(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	ws := NewCoreWorkloadStore(store)
	plan, err := ws.CreatePlan(ctx, coreworkload.PlanInput{IdempotencyKey: uuid.NewString(), Summary: "recovery", TargetKind: coreworkload.TargetCoreRunner, Target: pgWorkloadTarget(), CommandSteps: []string{"run"}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	r, err := ws.RequestOperation(ctx, coreworkload.RequestCommand{PlanID: plan.ID, Kind: coreworkload.OperationApply, IdempotencyKey: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	confirm, _ := coreconfirmation.NewService(NewCoreConfirmationStore(store))
	if _, err = confirm.Confirm(ctx, coreconfirmation.ConfirmCommand{ConfirmationID: r.Confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: r.Confirmation.Revision, At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	running, _, err := ws.Consume(ctx, r.Operation.ID, r.Confirmation.ConfirmationID, plan.Digest, r.Operation.Revision)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	claims := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := ws.RecoverClaim(ctx, running.ID, ""); claims <- e }()
	}
	wg.Wait()
	close(claims)
	var won, fenced bool
	for e := range claims {
		if e == nil {
			won = true
		}
		if e == coreworkload.ErrRevisionConflict {
			fenced = true
		}
	}
	if won || !fenced {
		t.Fatalf("live lease recovery claims won=%v fenced=%v", won, fenced)
	}
	op, err := ws.GetOperation(ctx, running.ID)
	if err != nil || op.DispatchState != "dispatched" || op.DispatchEpoch != running.DispatchEpoch || op.DispatchClaim != running.DispatchClaim {
		t.Fatalf("live lease mutated op=%+v err=%v", op, err)
	}
	leaseTag, err := store.pool.Exec(ctx, `UPDATE core_workload_operations SET dispatch_lease_until=clock_timestamp()-interval '1 second' WHERE owner_id=$1 AND operation_id=$2`, store.instanceID, op.ID)
	if err != nil || leaseTag.RowsAffected() != 1 {
		t.Fatalf("lease update err=%v rows=%d", err, leaseTag.RowsAffected())
	}
	claims = make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := ws.RecoverClaim(ctx, op.ID, ""); claims <- e }()
	}
	wg.Wait()
	close(claims)
	won, fenced = false, false
	for e := range claims {
		if e == nil {
			won = true
		}
		if e == coreworkload.ErrRevisionConflict {
			fenced = true
		}
	}
	if !won || !fenced {
		t.Fatalf("expired lease recovery claims won=%v fenced=%v", won, fenced)
	}
	takenOver, err := ws.GetOperation(ctx, op.ID)
	if err != nil || takenOver.DispatchEpoch != op.DispatchEpoch+1 || takenOver.DispatchClaim == op.DispatchClaim {
		t.Fatalf("takeover=%+v err=%v", takenOver, err)
	}
	op = takenOver
	sameClaim, err := ws.RecoverClaim(ctx, op.ID, op.DispatchClaim)
	if err != nil || sameClaim.DispatchEpoch != op.DispatchEpoch || sameClaim.DispatchClaim != op.DispatchClaim {
		t.Fatalf("same-token retry=%+v err=%v", sameClaim, err)
	}
	var beforeRevision uint64
	var beforeEvents int
	if err = store.pool.QueryRow(ctx, `SELECT revision FROM core_workload_operations WHERE owner_id=$1 AND operation_id=$2`, store.instanceID, op.ID).Scan(&beforeRevision); err != nil {
		t.Fatal(err)
	}
	if err = store.pool.QueryRow(ctx, `SELECT count(*) FROM core_workload_events WHERE owner_id=$1 AND operation_id=$2`, store.instanceID, op.ID).Scan(&beforeEvents); err != nil {
		t.Fatal(err)
	}
	if _, _, err = ws.CompleteDispatch(ctx, op.ID, op.TaskID, uuid.NewString(), op.DispatchEpoch, "", coreworkload.Readback{TargetKind: plan.TargetKind, WorkloadID: op.WorkloadID, State: "ready", Identity: plan.Target.Identity, At: time.Now().UTC()}, ""); err != coreworkload.ErrRevisionConflict {
		t.Fatalf("stale complete err=%v", err)
	}
	var afterRevision uint64
	var afterEvents int
	if err = store.pool.QueryRow(ctx, `SELECT revision FROM core_workload_operations WHERE owner_id=$1 AND operation_id=$2`, store.instanceID, op.ID).Scan(&afterRevision); err != nil {
		t.Fatal(err)
	}
	if err = store.pool.QueryRow(ctx, `SELECT count(*) FROM core_workload_events WHERE owner_id=$1 AND operation_id=$2`, store.instanceID, op.ID).Scan(&afterEvents); err != nil {
		t.Fatal(err)
	}
	if beforeRevision != afterRevision || beforeEvents != afterEvents {
		t.Fatalf("stale complete mutated revision/events %d/%d -> %d/%d", beforeRevision, beforeEvents, afterRevision, afterEvents)
	}
	done, task, err := ws.CompleteDispatch(ctx, op.ID, op.TaskID, op.DispatchClaim, op.DispatchEpoch, "", coreworkload.Readback{TargetKind: plan.TargetKind, WorkloadID: op.WorkloadID, State: "ready", Identity: plan.Target.Identity, At: time.Now().UTC()}, "")
	if err != nil || done.Status != coreworkload.OperationSucceeded || task.Result == nil {
		t.Fatalf("done=%+v task=%+v err=%v", done, task, err)
	}
}

func TestCoreWorkloadPostgresProviderErrorReadbackProjection(t *testing.T) {
	testCase := func(t *testing.T, state string, readErr error, want coreworkload.OperationStatus) {
		ctx, store, _, cleanup := corePG18Fixture(t)
		defer cleanup()
		ws := NewCoreWorkloadStore(store)
		plan, err := ws.CreatePlan(ctx, coreworkload.PlanInput{IdempotencyKey: uuid.NewString(), Summary: "provider recovery", TargetKind: coreworkload.TargetCoreRunner, Target: pgWorkloadTarget(), CommandSteps: []string{"run"}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		r, err := ws.RequestOperation(ctx, coreworkload.RequestCommand{PlanID: plan.ID, Kind: coreworkload.OperationApply, IdempotencyKey: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		confirm, _ := coreconfirmation.NewService(NewCoreConfirmationStore(store))
		if _, err = confirm.Confirm(ctx, coreconfirmation.ConfirmCommand{ConfirmationID: r.Confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: r.Confirmation.Revision, At: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		provider := &pgRecoveryProvider{readState: state, readErr: readErr}
		h, _ := coreworkload.NewHandler(ws, provider)
		op, gotErr := h.Handle(ctx, r.Operation.ID, plan.Digest, r.Operation.Revision)
		if op.Status != want || provider.applyN != 1 || provider.readN != 1 {
			t.Fatalf("op=%+v err=%v provider=%+v", op, gotErr, provider)
		}
		var persistedSummary string
		if err = store.pool.QueryRow(ctx, `SELECT failure_summary FROM core_workload_operations WHERE operation_id=$1`, op.ID).Scan(&persistedSummary); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(persistedSummary, "password") || strings.Contains(persistedSummary, "secret") || strings.Contains(op.FailureSummary, "password") {
			t.Fatalf("provider secret persisted: %q / %q", persistedSummary, op.FailureSummary)
		}
		if want == coreworkload.OperationUncertain {
			replayed, recoverErr := h.Recover(ctx, op.ID)
			if recoverErr != nil || replayed.Status != coreworkload.OperationUncertain || provider.readN != 1 {
				t.Fatalf("terminal uncertain mutated: op=%+v err=%v reads=%d", replayed, recoverErr, provider.readN)
			}
		}
		if want == coreworkload.OperationSucceeded && gotErr != nil {
			t.Fatal(gotErr)
		}
	}
	t.Run("read-match", func(t *testing.T) { testCase(t, "ready", nil, coreworkload.OperationSucceeded) })
	t.Run("read-mismatch", func(t *testing.T) { testCase(t, "not_ready", nil, coreworkload.OperationUncertain) })
	t.Run("read-error", func(t *testing.T) {
		testCase(t, "", errors.New("provider password=redacted"), coreworkload.OperationUncertain)
	})
}

func TestCoreWorkloadPostgresRecoveryEventFailureLeaseTakeover(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	ws := NewCoreWorkloadStore(store)
	plan, err := ws.CreatePlan(ctx, coreworkload.PlanInput{IdempotencyKey: uuid.NewString(), Summary: "transient recovery", TargetKind: coreworkload.TargetCoreRunner, Target: pgWorkloadTarget(), CommandSteps: []string{"run"}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	r, err := ws.RequestOperation(ctx, coreworkload.RequestCommand{PlanID: plan.ID, Kind: coreworkload.OperationApply, IdempotencyKey: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	confirm, _ := coreconfirmation.NewService(NewCoreConfirmationStore(store))
	if _, err = confirm.Confirm(ctx, coreconfirmation.ConfirmCommand{ConfirmationID: r.Confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: r.Confirmation.Revision, At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	running, _, err := ws.Consume(ctx, r.Operation.ID, r.Confirmation.ConfirmationID, plan.Digest, r.Operation.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if tag, e := store.pool.Exec(ctx, `UPDATE core_workload_operations SET dispatch_lease_until=clock_timestamp()-interval '1 second' WHERE owner_id=$1 AND operation_id=$2`, store.instanceID, running.ID); e != nil || tag.RowsAffected() != 1 {
		t.Fatalf("expire initial lease err=%v rows=%d", e, tag.RowsAffected())
	}
	wrapped := &pgFailEventStore{Store: ws, fail: true}
	provider := &pgRecoveryProvider{readState: "ready"}
	h, _ := coreworkload.NewHandler(wrapped, provider)
	if _, err = h.Recover(ctx, running.ID); err == nil {
		t.Fatal("transient event failure accepted")
	}
	var state, dispatchState, claim string
	var lease time.Time
	if err = store.pool.QueryRow(ctx, `SELECT status,dispatch_state,COALESCE(dispatch_claim::text,''),dispatch_lease_until FROM core_workload_operations WHERE owner_id=$1 AND operation_id=$2`, store.instanceID, running.ID).Scan(&state, &dispatchState, &claim, &lease); err != nil {
		t.Fatal(err)
	}
	if state != "running" || dispatchState != "uncertain" || claim == "" || !lease.After(time.Now().UTC()) {
		t.Fatalf("event failure lost recovery lease state=%s dispatch=%s claim=%q lease=%v", state, dispatchState, claim, lease)
	}
	var terminalCount int
	if err = store.pool.QueryRow(ctx, `SELECT count(*) FROM core_workload_events WHERE owner_id=$1 AND operation_id=$2 AND kind='terminal'`, store.instanceID, running.ID).Scan(&terminalCount); err != nil {
		t.Fatal(err)
	}
	if terminalCount != 0 {
		t.Fatalf("terminal event emitted on transient event failure: %d", terminalCount)
	}
	tag, err := store.pool.Exec(ctx, `UPDATE core_workload_operations SET dispatch_lease_until=clock_timestamp()-interval '1 second' WHERE owner_id=$1 AND operation_id=$2`, store.instanceID, running.ID)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("expire lease err=%v rows=%d", err, tag.RowsAffected())
	}
	wrapped.fail = false
	op, err := h.Recover(ctx, running.ID)
	if err != nil || op.Status != coreworkload.OperationSucceeded || provider.readN != 2 {
		t.Fatalf("takeover op=%+v err=%v reads=%d", op, err, provider.readN)
	}
	if err = store.pool.QueryRow(ctx, `SELECT count(*) FROM core_workload_events WHERE owner_id=$1 AND operation_id=$2 AND kind='terminal'`, store.instanceID, running.ID).Scan(&terminalCount); err != nil {
		t.Fatal(err)
	}
	if terminalCount != 1 {
		t.Fatalf("terminal events=%d", terminalCount)
	}
}

func TestCoreWorkloadPostgresCancelLedgerAndPostClaimFence(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	ws := NewCoreWorkloadStore(store)
	p, err := ws.CreatePlan(ctx, coreworkload.PlanInput{IdempotencyKey: uuid.NewString(), Summary: "cancel", TargetKind: coreworkload.TargetCoreRunner, Target: pgWorkloadTarget(), CommandSteps: []string{"run"}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	key := uuid.NewString()
	r, err := ws.RequestOperation(ctx, coreworkload.RequestCommand{PlanID: p.ID, Kind: coreworkload.OperationApply, IdempotencyKey: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	o, err := ws.CancelOperation(ctx, r.Operation.ID, key, r.Operation.Revision)
	if err != nil || o.Status != coreworkload.OperationCanceled {
		t.Fatalf("cancel=%+v err=%v", o, err)
	}
	assertWorkloadTaskEventSequence(t, ctx, store, r.Task.ID, 1, 2)
	replay, err := ws.CancelOperation(ctx, r.Operation.ID, key, r.Operation.Revision)
	if err != nil || replay.Status != coreworkload.OperationCanceled {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	if _, err = ws.CancelOperation(ctx, r.Operation.ID, uuid.NewString(), r.Operation.Revision); err == nil {
		t.Fatal("cancel mismatch accepted")
	}
	r2, err := ws.RequestOperation(ctx, coreworkload.RequestCommand{PlanID: p.ID, Kind: coreworkload.OperationApply, IdempotencyKey: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	confirm, _ := coreconfirmation.NewService(NewCoreConfirmationStore(store))
	if _, err = confirm.Confirm(ctx, coreconfirmation.ConfirmCommand{ConfirmationID: r2.Confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: r2.Confirmation.Revision, At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	run, _, err := ws.Consume(ctx, r2.Operation.ID, r2.Confirmation.ConfirmationID, p.Digest, r2.Operation.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ws.CancelOperation(ctx, run.ID, uuid.NewString(), run.Revision); err == nil {
		t.Fatal("post-claim cancel accepted")
	}
}

func TestCoreWorkloadPostgresOwnerIsolationAndIdempotency(t *testing.T) {
	ctx, storeA, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	storeB, err := New(storeA.pool, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	wsA, wsB := NewCoreWorkloadStore(storeA), NewCoreWorkloadStore(storeB)
	key := uuid.NewString()
	in := coreworkload.PlanInput{IdempotencyKey: key, Summary: "owner isolation", TargetKind: coreworkload.TargetCoreRunner, Target: pgWorkloadTarget(), CommandSteps: []string{"run"}, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	pA, err := wsA.CreatePlan(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wsB.GetPlan(ctx, pA.ID); !errors.Is(err, coreworkload.ErrNotFound) {
		t.Fatalf("owner B read plan err=%v", err)
	}
	pB, err := wsB.CreatePlan(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if pA.ID == pB.ID {
		t.Fatal("owner-scoped idempotency reused plan across owners")
	}
	if _, err = wsB.RequestOperation(ctx, coreworkload.RequestCommand{PlanID: pA.ID, Kind: coreworkload.OperationApply, IdempotencyKey: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour)}); !errors.Is(err, coreworkload.ErrNotFound) {
		t.Fatalf("owner B mutated owner A plan err=%v", err)
	}
}

func assertWorkloadTaskEventSequence(t *testing.T, ctx context.Context, store *Store, taskID string, want ...int64) {
	t.Helper()
	rows, err := store.pool.Query(ctx, `SELECT sequence FROM core_task_events WHERE task_id=$1 ORDER BY sequence`, taskID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []int64
	for rows.Next() {
		var sequence int64
		if err = rows.Scan(&sequence); err != nil {
			t.Fatal(err)
		}
		got = append(got, sequence)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("task event sequence=%v want=%v", got, want)
	}
	var progress int64
	if err = store.pool.QueryRow(ctx, `SELECT progress_sequence FROM core_tasks WHERE task_id=$1`, taskID).Scan(&progress); err != nil {
		t.Fatal(err)
	}
	if len(want) == 0 || progress != want[len(want)-1] {
		t.Fatalf("progress_sequence=%d want=%v", progress, want)
	}
}
