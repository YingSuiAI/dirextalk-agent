package postgres

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

func TestCoreConfirmationPostgresConsumeReleaseAllowsNewRequest(t *testing.T) {
	f := newPGConfirmationFixture(t, time.Time{})
	defer f.cleanup()
	c, _ := createPGConfirmation(t, f, time.Time{})
	confirmed, err := f.service.Confirm(f.ctx, coreconfirmation.ConfirmCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: c.Revision, At: f.now})
	if err != nil {
		t.Fatal(err)
	}
	claimed, lease, err := f.tasks.ClaimNextDue(f.ctx, uuid.NewString(), time.Now().UTC(), time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	consumed, err := f.service.Consume(f.ctx, coreconfirmation.ConsumeCommand{ConfirmationID: confirmed.ConfirmationID, IdempotencyKey: uuid.NewString(), TaskID: claimed.ID, Attempt: lease.Attempt, LeaseEpoch: lease.Epoch, ExpectedRevision: confirmed.Revision, ExpectedTaskRevision: int64(claimed.Revision), At: f.now})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.tasks.FailTask(f.ctx, coretask.FailCommand{Fence: coretask.Fence{TaskID: claimed.ID, Attempt: lease.Attempt, LeaseEpoch: lease.Epoch, ExpectedRevision: claimed.Revision}, ErrorCode: "done", ErrorSummary: "done", At: f.now}); err != nil {
		t.Fatal(err)
	}
	rel, err := f.service.ReleaseReservation(f.ctx, coreconfirmation.ReleaseReservationCommand{ConfirmationID: consumed.ConfirmationID, IdempotencyKey: uuid.NewString(), TaskID: claimed.ID, AcquiredAttempt: lease.Attempt, AcquiredLeaseEpoch: lease.Epoch, TerminalAttempt: lease.Attempt, TerminalLeaseEpoch: lease.Epoch, ExpectedTaskRevision: int64(claimed.Revision)})
	if err != nil {
		t.Fatal(err)
	}
	if rel.State != coreconfirmation.StateConsumed {
		t.Fatalf("release state=%s", rel.State)
	}
	newTaskID := uuid.NewString()
	if _, err = f.store.pool.Exec(f.ctx, `INSERT INTO core_tasks(task_id,goal,model_profile_id,create_idempotency_key,status,progress_sequence,available_at,revision,created_at,updated_at) SELECT $1,'new',profile_id,$1,'waiting_user',1,$2,1,$2,$2 FROM core_model_profiles LIMIT 1`, newTaskID, f.now); err != nil {
		t.Fatal(err)
	}
	req := coreconfirmation.RequestCommand{IdempotencyKey: uuid.NewString(), Binding: consumed.Binding, TaskID: newTaskID, ExpiresAt: f.now.Add(time.Hour), At: f.now}
	if _, err = f.service.Request(f.ctx, req); err != nil {
		t.Fatalf("new request after release err=%v", err)
	}
	history, _ := f.confirmations.Get(f.ctx, consumed.ConfirmationID)
	if history.State != coreconfirmation.StateConsumed {
		t.Fatalf("history state=%s", history.State)
	}
}

func TestCoreConfirmationPostgresCancelCompensatesAndReleasesTarget(t *testing.T) {
	f := newPGConfirmationFixture(t, time.Time{})
	defer f.cleanup()
	c, req := createPGConfirmation(t, f, time.Time{})
	task, err := f.tasks.GetTask(f.ctx, c.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.tasks.CancelTask(f.ctx, coretask.CancelCommand{TaskID: task.ID, Reason: "cancel", At: f.now, Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("e", 64), ExpectedRevision: task.Revision}}); err != nil {
		t.Fatal(err)
	}
	got, err := f.confirmations.Get(f.ctx, c.ConfirmationID)
	if err != nil || got.State != coreconfirmation.StateExpired || got.TerminalReason != "task_canceled" {
		t.Fatalf("confirmation=%+v err=%v", got, err)
	}
	// Terminalized confirmations no longer reserve their target.
	key := uuid.NewString()
	spec := coretask.TaskSpec{Goal: "reuse", ModelProfileID: f.task.Spec.ModelProfileID, IdempotencyKey: key}
	digest, _ := spec.MutationDigest()
	next, err := f.tasks.CreateTask(f.ctx, coretask.CreateTaskCommand{Spec: spec, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.pool.Exec(f.ctx, `UPDATE core_tasks SET status='waiting_user' WHERE task_id=$1`, next.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.Request(f.ctx, coreconfirmation.RequestCommand{IdempotencyKey: uuid.NewString(), Binding: req.Binding, TaskID: next.ID, ExpiresAt: f.now.Add(time.Hour), At: f.now}); err != nil {
		t.Fatalf("target was not released: %v", err)
	}
}

func TestCoreConfirmationPostgresCancelVsConfirmHasOneOwner(t *testing.T) {
	f := newPGConfirmationFixture(t, time.Time{})
	defer f.cleanup()
	c, _ := createPGConfirmation(t, f, time.Time{})
	task, err := f.tasks.GetTask(f.ctx, c.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	confirmKey, cancelKey := uuid.NewString(), uuid.NewString()
	var wg sync.WaitGroup
	var confirmErr, cancelErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, confirmErr = f.service.Confirm(f.ctx, coreconfirmation.ConfirmCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: confirmKey, ExpectedRevision: c.Revision, At: f.now})
	}()
	go func() {
		defer wg.Done()
		_, cancelErr = f.tasks.CancelTask(f.ctx, coretask.CancelCommand{TaskID: task.ID, Reason: "race", At: f.now, Mutation: coretask.MutationCommand{IdempotencyKey: cancelKey, RequestDigest: strings.Repeat("f", 64), ExpectedRevision: task.Revision}})
	}()
	wg.Wait()
	if (confirmErr == nil) == (cancelErr == nil) {
		t.Fatalf("expected one owner confirm=%v cancel=%v", confirmErr, cancelErr)
	}
	// If confirmation won its CAS first, retry cancellation at the durable
	// revision; this proves the terminal hook compensates the confirmed state.
	if confirmErr == nil {
		current, e := f.tasks.GetTask(f.ctx, task.ID)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.tasks.CancelTask(f.ctx, coretask.CancelCommand{TaskID: task.ID, Reason: "settle", At: f.now.Add(time.Second), Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("1", 64), ExpectedRevision: current.Revision}}); e != nil {
			t.Fatal(e)
		}
	}
	got, err := f.confirmations.Get(f.ctx, c.ConfirmationID)
	if err != nil || got.State != coreconfirmation.StateExpired {
		t.Fatalf("confirmation=%+v err=%v", got, err)
	}
	if _, err = f.service.Confirm(f.ctx, coreconfirmation.ConfirmCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: confirmKey, ExpectedRevision: c.Revision, At: f.now}); !errors.Is(err, coreconfirmation.ErrConflict) && !errors.Is(err, coreconfirmation.ErrRevisionConflict) {
		t.Fatalf("late confirm=%v", err)
	}
}

func TestCoreConfirmationPostgresExpiryVsConsumeSingleOwner(t *testing.T) {
	f := newPGConfirmationFixture(t, time.Time{})
	defer f.cleanup()
	c, _ := createPGConfirmation(t, f, time.Time{})
	confirmed, err := f.service.Confirm(f.ctx, coreconfirmation.ConfirmCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: c.Revision, At: f.now})
	if err != nil {
		t.Fatal(err)
	}
	claimed, lease, err := f.tasks.ClaimNextDue(f.ctx, uuid.NewString(), f.now, time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var expireErr, consumeErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, expireErr = f.service.Expire(f.ctx, coreconfirmation.ExpireCommand{ConfirmationID: confirmed.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: confirmed.Revision, Reason: coreconfirmation.ReasonExpired, At: f.now})
	}()
	go func() {
		defer wg.Done()
		<-start
		_, consumeErr = f.service.Consume(f.ctx, coreconfirmation.ConsumeCommand{ConfirmationID: confirmed.ConfirmationID, TaskID: claimed.ID, IdempotencyKey: uuid.NewString(), Attempt: lease.Attempt, LeaseEpoch: lease.Epoch, ExpectedRevision: confirmed.Revision, ExpectedTaskRevision: int64(claimed.Revision), At: f.now})
	}()
	close(start)
	wg.Wait()
	if (expireErr == nil) == (consumeErr == nil) {
		t.Fatalf("expected one CAS owner expire=%v consume=%v", expireErr, consumeErr)
	}
	got, err := f.confirmations.Get(f.ctx, confirmed.ConfirmationID)
	if err != nil {
		t.Fatal(err)
	}
	if consumeErr == nil {
		if got.State != coreconfirmation.StateConsumed {
			t.Fatalf("consumed winner became %s", got.State)
		}
		if _, err = f.service.Expire(f.ctx, coreconfirmation.ExpireCommand{ConfirmationID: confirmed.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: got.Revision, Reason: coreconfirmation.ReasonExpired, At: f.now}); !errors.Is(err, coreconfirmation.ErrConflict) {
			t.Fatalf("consumed confirmation expired: %v", err)
		}
	} else if got.State != coreconfirmation.StateExpired {
		t.Fatalf("expired winner became %s", got.State)
	}
}

func TestCoreConfirmationPostgresWrongFenceReleaseRejected(t *testing.T) {
	f := newPGConfirmationFixture(t, time.Time{})
	defer f.cleanup()
	c, _ := createPGConfirmation(t, f, time.Time{})
	confirmed, _ := f.service.Confirm(f.ctx, coreconfirmation.ConfirmCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: c.Revision, At: f.now})
	claimed, lease, _ := f.tasks.ClaimNextDue(f.ctx, uuid.NewString(), time.Now().UTC(), time.Hour, 1)
	consumed, err := f.service.Consume(f.ctx, coreconfirmation.ConsumeCommand{ConfirmationID: confirmed.ConfirmationID, IdempotencyKey: uuid.NewString(), TaskID: claimed.ID, Attempt: lease.Attempt, LeaseEpoch: lease.Epoch, ExpectedRevision: confirmed.Revision, ExpectedTaskRevision: int64(claimed.Revision), At: f.now})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.ReleaseReservation(f.ctx, coreconfirmation.ReleaseReservationCommand{ConfirmationID: consumed.ConfirmationID, IdempotencyKey: uuid.NewString(), TaskID: claimed.ID, AcquiredAttempt: lease.Attempt, AcquiredLeaseEpoch: lease.Epoch, TerminalAttempt: lease.Attempt + 1, TerminalLeaseEpoch: lease.Epoch, ExpectedTaskRevision: int64(claimed.Revision)})
	if !errors.Is(err, coreconfirmation.ErrTaskFenceConflict) {
		t.Fatalf("wrong fence err=%v", err)
	}
}
