package coreworkload

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type fakeProvider struct{ applied, destroyed int }

type errorThenReadProvider struct {
	applyCalls int
	readCalls  int
	readErr    error
	state      string
}

type failEventStore struct {
	Store
	fail bool
}
type failRenewStore struct{ Store }

func (s *failRenewStore) RenewDispatchLease(context.Context, string, string, uint64) (Operation, error) {
	return Operation{}, ErrRevisionConflict
}

func (s *failEventStore) AppendEvent(ctx context.Context, id string, event Event) (Event, error) {
	if s.fail {
		return Event{}, errors.New("transient event store failure")
	}
	return s.Store.AppendEvent(ctx, id, event)
}

func (p *errorThenReadProvider) Apply(context.Context, Plan, Operation) (Readback, error) {
	p.applyCalls++
	return Readback{}, errors.New("provider token=should-not-persist")
}
func (p *errorThenReadProvider) Destroy(context.Context, Plan, Operation) (Readback, error) {
	p.applyCalls++
	return Readback{}, errors.New("provider secret=should-not-persist")
}
func (p *errorThenReadProvider) Read(_ context.Context, plan Plan, op Operation) (Readback, error) {
	p.readCalls++
	if p.readErr != nil {
		return Readback{}, p.readErr
	}
	return Readback{TargetKind: plan.TargetKind, WorkloadID: op.WorkloadID, State: p.state, Identity: plan.Target.Identity, At: time.Now().UTC()}, nil
}

func (p *fakeProvider) Apply(_ context.Context, plan Plan, _ Operation) (Readback, error) {
	p.applied++
	return Readback{TargetKind: plan.TargetKind, State: "ready", WorkloadID: plan.ID, Identity: plan.Target.Identity, At: time.Now().UTC()}, nil
}
func (p *fakeProvider) Destroy(_ context.Context, plan Plan, _ Operation) (Readback, error) {
	p.destroyed++
	return Readback{TargetKind: plan.TargetKind, State: "destroyed", WorkloadID: plan.ID, Identity: plan.Target.Identity, At: time.Now().UTC()}, nil
}
func (p *fakeProvider) Read(_ context.Context, plan Plan, op Operation) (Readback, error) {
	return Readback{TargetKind: plan.TargetKind, State: "ready", WorkloadID: op.WorkloadID, Identity: plan.Target.Identity, At: time.Now().UTC()}, nil
}

func testPlanInput(key string) PlanInput {
	return PlanInput{Summary: "install demo", TargetKind: TargetCoreRunner, Target: TargetSettings{Identity: TargetIdentity{Kind: TargetCoreRunner, CoreRunnerID: "runner-test", CoreRunnerService: "workload-test"}}, CommandSteps: []string{"install demo"}, ExpiresAt: time.Now().UTC().Add(time.Hour), IdempotencyKey: key}
}
func TestWorkloadRequestConfirmConsumeAndTerminal(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	st := NewMemoryStore(clock)
	svc, _ := NewService(st, clock)
	pl, err := svc.CreatePlan(context.Background(), testPlanInput("00000000-0000-4000-8000-000000000001"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := svc.RequestApply(context.Background(), pl.ID, "", "00000000-0000-4000-8000-000000000002")
	if err != nil {
		t.Fatal(err)
	}
	if r.Operation.Status != OperationWaitingUser || r.Task.Status != "waiting_user" || r.Confirmation.State != "pending" {
		t.Fatalf("unexpected request state: %+v", r)
	}
	if _, err = svc.Confirm(context.Background(), r.Confirmation.ConfirmationID, 1); err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{}
	h, _ := NewHandler(st, p)
	done, err := h.Handle(context.Background(), r.Operation.ID, pl.Digest, 1)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != OperationSucceeded || p.applied != 1 {
		t.Fatalf("done=%+v applied=%d", done, p.applied)
	}
	events, _ := svc.ListEvents(context.Background(), r.Operation.ID, 0)
	if len(events) < 3 {
		t.Fatalf("events=%d", len(events))
	}
}
func TestWorkloadPlanDigestAndFence(t *testing.T) {
	st := NewMemoryStore(time.Now)
	svc, _ := NewService(st, nil)
	pl, err := svc.CreatePlan(context.Background(), testPlanInput("00000000-0000-4000-8000-000000000003"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := svc.RequestApply(context.Background(), pl.ID, "", "00000000-0000-4000-8000-000000000004")
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Confirm(context.Background(), r.Confirmation.ConfirmationID, 1)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := NewHandler(st, &fakeProvider{})
	if _, err = h.Handle(context.Background(), r.Operation.ID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1); !errors.Is(err, ErrStale) {
		t.Fatalf("err=%v", err)
	}
}

func TestWorkloadPreDispatchTerminalizationIsAtomicAndFenced(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	st := NewMemoryStore(clock)
	svc, _ := NewService(st, clock)
	plan, err := svc.CreatePlan(context.Background(), testPlanInput("00000000-0000-4000-8000-000000000021"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := svc.RequestApply(context.Background(), plan.ID, "", "00000000-0000-4000-8000-000000000022")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.Reject(context.Background(), r.Confirmation.ConfirmationID, r.Confirmation.Revision, "no"); err != nil {
		t.Fatal(err)
	}
	op, _ := st.GetOperation(context.Background(), r.Operation.ID)
	task := st.tasks[r.Task.ID]
	if op.Status != OperationRejected || task.Status != coretask.StatusCanceled || len(st.events[op.ID]) != 2 {
		t.Fatalf("op=%+v task=%+v events=%d", op, task, len(st.events[op.ID]))
	}
	if _, _, err = st.Consume(context.Background(), op.ID, r.Confirmation.ConfirmationID, plan.Digest, op.Revision); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("consume after terminal=%v", err)
	}
}

func TestWorkloadTerminalReplayIsStructStable(t *testing.T) {
	for _, tc := range []struct{ name, code, state string }{
		{"success", "", "ready"},
		{"failure", "provider_error", "failed"},
		{"uncertain", "provider_uncertain", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
			st := NewMemoryStore(clock)
			svc, _ := NewService(st, clock)
			plan, err := svc.CreatePlan(context.Background(), testPlanInput(uuid.NewString()))
			if err != nil {
				t.Fatal(err)
			}
			r, err := svc.RequestApply(context.Background(), plan.ID, "", uuid.NewString())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = svc.Confirm(context.Background(), r.Confirmation.ConfirmationID, r.Confirmation.Revision); err != nil {
				t.Fatal(err)
			}
			run, _, err := st.Consume(context.Background(), r.Operation.ID, r.Confirmation.ConfirmationID, plan.Digest, r.Operation.Revision)
			if err != nil {
				t.Fatal(err)
			}
			rb := Readback{TargetKind: plan.TargetKind, WorkloadID: run.WorkloadID, State: tc.state, Identity: plan.Target.Identity, At: clock()}
			firstOp, firstTask, err := st.CompleteDispatch(context.Background(), run.ID, run.TaskID, run.DispatchClaim, run.DispatchEpoch, tc.code, rb, "provider detail")
			if err != nil {
				t.Fatal(err)
			}
			replayOp, replayTask, err := st.CompleteDispatch(context.Background(), run.ID, run.TaskID, run.DispatchClaim, run.DispatchEpoch, tc.code, rb, "provider detail")
			if err != nil || !reflect.DeepEqual(firstOp, replayOp) || !reflect.DeepEqual(firstTask, replayTask) {
				t.Fatalf("first=(%+v,%+v) replay=(%+v,%+v) err=%v", firstOp, firstTask, replayOp, replayTask, err)
			}
		})
	}
}

func TestWorkloadRecoverClaimsDispatchedFenceWithoutRedispatch(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	st := NewMemoryStore(clock)
	svc, _ := NewService(st, clock)
	pl, err := svc.CreatePlan(context.Background(), testPlanInput("00000000-0000-4000-8000-000000000005"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := svc.RequestApply(context.Background(), pl.ID, "", "00000000-0000-4000-8000-000000000006")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Confirm(context.Background(), r.Confirmation.ConfirmationID, 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err = st.Consume(context.Background(), r.Operation.ID, r.Confirmation.ConfirmationID, pl.Digest, 1); err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	claimed := st.operations[r.Operation.ID]
	claimed.DispatchLeaseUntil = clock().Add(-time.Second)
	st.operations[r.Operation.ID] = claimed
	st.mu.Unlock()
	p := &fakeProvider{}
	h, _ := NewHandler(st, p)
	op, err := h.Recover(context.Background(), r.Operation.ID)
	if err != nil || op.Status != OperationSucceeded || p.applied != 0 {
		t.Fatalf("op=%+v read recovery err=%v applied=%d", op, err, p.applied)
	}
	events, err := st.ListEvents(context.Background(), r.Operation.ID, 0)
	hasClaim, hasReadback := false, false
	for _, event := range events {
		hasClaim = hasClaim || event.Kind == "recovery_claim"
		hasReadback = hasReadback || event.Kind == "recovered_readback"
	}
	if err != nil || !hasClaim || !hasReadback {
		t.Fatalf("events=%+v err=%v", events, err)
	}
}

func TestWorkloadProviderErrorReconcilesByReadback(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	st := NewMemoryStore(clock)
	svc, _ := NewService(st, clock)
	pl, err := svc.CreatePlan(context.Background(), testPlanInput("00000000-0000-4000-8000-000000000007"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := svc.RequestApply(context.Background(), pl.ID, "", "00000000-0000-4000-8000-000000000008")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Confirm(context.Background(), r.Confirmation.ConfirmationID, 1); err != nil {
		t.Fatal(err)
	}
	p := &errorThenReadProvider{state: "ready"}
	h, _ := NewHandler(st, p)
	op, err := h.Handle(context.Background(), r.Operation.ID, pl.Digest, 1)
	if err != nil || op.Status != OperationSucceeded || p.applyCalls != 1 || p.readCalls != 1 {
		t.Fatalf("op=%+v err=%v apply=%d read=%d", op, err, p.applyCalls, p.readCalls)
	}
}

func TestWorkloadProviderReadFailureLeavesUncertain(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	st := NewMemoryStore(clock)
	svc, _ := NewService(st, clock)
	pl, err := svc.CreatePlan(context.Background(), testPlanInput("00000000-0000-4000-8000-000000000009"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := svc.RequestApply(context.Background(), pl.ID, "", "00000000-0000-4000-8000-00000000000a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Confirm(context.Background(), r.Confirmation.ConfirmationID, 1); err != nil {
		t.Fatal(err)
	}
	p := &errorThenReadProvider{readErr: errors.New("provider password=redact")}
	h, _ := NewHandler(st, p)
	op, err := h.Handle(context.Background(), r.Operation.ID, pl.Digest, 1)
	if err == nil || op.Status != OperationUncertain || p.applyCalls != 1 || p.readCalls != 1 {
		t.Fatalf("op=%+v err=%v apply=%d read=%d", op, err, p.applyCalls, p.readCalls)
	}
	if strings.Contains(op.FailureSummary, "password") {
		t.Fatalf("secret leaked: %q", op.FailureSummary)
	}
	replayed, recoverErr := h.Recover(context.Background(), r.Operation.ID)
	if recoverErr != nil || replayed.Status != OperationUncertain || p.readCalls != 1 {
		t.Fatalf("terminal uncertain mutated: op=%+v err=%v reads=%d", replayed, recoverErr, p.readCalls)
	}
}

func TestWorkloadRecoveryEventFailureRetainsLeaseForTakeover(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	base := NewMemoryStore(clock)
	svc, _ := NewService(base, clock)
	pl, err := svc.CreatePlan(context.Background(), testPlanInput("00000000-0000-4000-8000-00000000000b"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := svc.RequestApply(context.Background(), pl.ID, "", "00000000-0000-4000-8000-00000000000c")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Confirm(context.Background(), r.Confirmation.ConfirmationID, 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err = base.Consume(context.Background(), r.Operation.ID, r.Confirmation.ConfirmationID, pl.Digest, 1); err != nil {
		t.Fatal(err)
	}
	base.mu.Lock()
	claimed := base.operations[r.Operation.ID]
	claimed.DispatchLeaseUntil = now.Add(-time.Second)
	base.operations[r.Operation.ID] = claimed
	base.mu.Unlock()
	wrapped := &failEventStore{Store: base, fail: true}
	p := &fakeProvider{}
	h, _ := NewHandler(wrapped, p)
	if _, err = h.Recover(context.Background(), r.Operation.ID); err == nil {
		t.Fatal("transient event failure accepted")
	}
	now = now.Add(31 * time.Second)
	wrapped.fail = false
	op, err := h.Recover(context.Background(), r.Operation.ID)
	if err != nil || op.Status != OperationSucceeded || p.applied != 0 {
		t.Fatalf("recovery takeover op=%+v err=%v", op, err)
	}
}

func TestWorkloadRenewFailurePreventsCompletion(t *testing.T) {
	st := NewMemoryStore(time.Now)
	svc, _ := NewService(st, nil)
	pl, err := svc.CreatePlan(context.Background(), testPlanInput("00000000-0000-4000-8000-00000000000d"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := svc.RequestApply(context.Background(), pl.ID, "", "00000000-0000-4000-8000-00000000000e")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Confirm(context.Background(), r.Confirmation.ConfirmationID, 1); err != nil {
		t.Fatal(err)
	}
	wrapped := &failRenewStore{Store: st}
	h, _ := NewHandler(wrapped, &fakeProvider{})
	if _, err = h.Handle(context.Background(), r.Operation.ID, pl.Digest, 1); err == nil {
		t.Fatal("renew failure allowed completion")
	}
	op, _ := st.GetOperation(context.Background(), r.Operation.ID)
	if op.Status != OperationRunning {
		t.Fatalf("operation terminalized after renew failure: %+v", op)
	}
}
