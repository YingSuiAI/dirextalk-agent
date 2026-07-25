package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

func TestCoreConfirmationPostgresReplayAndAtomicConfirm(t *testing.T) {
	ctx, store, profile, cleanup := corePG18Fixture(t)
	defer cleanup()
	key := uuid.NewString()
	taskSpec := coretask.TaskSpec{Goal: "confirm", ModelProfileID: profile, IdempotencyKey: key}
	digest, _ := taskSpec.MutationDigest()
	taskStore := NewCoreTaskStore(store)
	task, err := taskStore.CreateTask(ctx, coretask.CreateTaskCommand{Spec: taskSpec, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.pool.Exec(ctx, `UPDATE core_tasks SET status='waiting_user' WHERE task_id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	confirmationStore := NewCoreConfirmationStore(store)
	service, err := coreconfirmation.NewService(confirmationStore)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	binding := coreconfirmation.Binding{OperationDomain: "aws", TargetID: uuid.NewString(), TargetRevision: 1, SourceVersion: "v1", ContentDigest: coreconfirmation.Digest(strings.Repeat("a", 64)), ParameterDigest: coreconfirmation.Digest(strings.Repeat("b", 64)), NetworkDigest: coreconfirmation.Digest(strings.Repeat("c", 64)), SecretGrantDigest: coreconfirmation.Digest(strings.Repeat("d", 64))}
	if err = confirmationStore.UpsertCurrentTargetBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}
	req := coreconfirmation.RequestCommand{IdempotencyKey: uuid.NewString(), Binding: binding, TaskID: task.ID, ExpiresAt: now.Add(time.Hour), At: now}
	first, err := service.Request(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := service.Request(ctx, req)
	if err != nil || replay.ConfirmationID != first.ConfirmationID {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	confirmed, err := service.Confirm(ctx, coreconfirmation.ConfirmCommand{ConfirmationID: first.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: first.Revision, At: now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if confirmed.State != coreconfirmation.StateConfirmed {
		t.Fatalf("state=%s", confirmed.State)
	}
	changed := req
	changed.Binding.TargetRevision = 2
	if _, err = service.Request(ctx, changed); !errors.Is(err, coreconfirmation.ErrIdempotencyConflict) {
		t.Fatalf("changed replay err=%v", err)
	}
}

type pgConfirmationFixture struct {
	ctx           context.Context
	store         *Store
	tasks         *CoreTaskStore
	confirmations *CoreConfirmationStore
	service       *coreconfirmation.Service
	task          coretask.Task
	binding       coreconfirmation.Binding
	now           time.Time
	cleanup       func()
}

func newPGConfirmationFixture(t *testing.T, expires time.Time) pgConfirmationFixture {
	t.Helper()
	ctx, store, profile, cleanup := corePG18Fixture(t)
	tasks := NewCoreTaskStore(store)
	confirmations := NewCoreConfirmationStore(store)
	svc, err := coreconfirmation.NewService(confirmations)
	if err != nil {
		t.Fatal(err)
	}
	key := uuid.NewString()
	spec := coretask.TaskSpec{Goal: "confirmation", ModelProfileID: profile, IdempotencyKey: key}
	digest, _ := spec.MutationDigest()
	task, err := tasks.CreateTask(ctx, coretask.CreateTaskCommand{Spec: spec, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.pool.Exec(ctx, `UPDATE core_tasks SET status='waiting_user' WHERE task_id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if expires.IsZero() {
		expires = now.Add(time.Hour)
	}
	binding := pgBinding()
	if err = confirmations.UpsertCurrentTargetBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}
	req := coreconfirmation.RequestCommand{IdempotencyKey: uuid.NewString(), Binding: binding, TaskID: task.ID, ExpiresAt: expires, At: now}
	if _, err = svc.Request(ctx, req); err != nil {
		t.Fatal(err)
	}
	return pgConfirmationFixture{ctx: ctx, store: store, tasks: tasks, confirmations: confirmations, service: svc, task: task, binding: binding, now: now, cleanup: cleanup}
}

func pgBinding() coreconfirmation.Binding {
	d := coreconfirmation.Digest(strings.Repeat("a", 64))
	return coreconfirmation.Binding{OperationDomain: "aws", TargetID: uuid.NewString(), TargetRevision: 1, SourceVersion: "v1", ContentDigest: d, ParameterDigest: d, NetworkDigest: d, SecretGrantDigest: d}
}

func createPGConfirmation(t *testing.T, f pgConfirmationFixture, expires time.Time) (coreconfirmation.Confirmation, coreconfirmation.RequestCommand) {
	t.Helper()
	if expires.IsZero() {
		expires = f.now.Add(time.Hour)
	}
	if err := f.confirmations.UpsertCurrentTargetBinding(f.ctx, f.binding); err != nil {
		t.Fatal(err)
	}
	key := uuid.NewString()
	spec := coretask.TaskSpec{Goal: "confirmation", ModelProfileID: "", IdempotencyKey: key}
	var profile string
	if err := f.store.pool.QueryRow(f.ctx, `SELECT profile_id::text FROM core_model_profiles LIMIT 1`).Scan(&profile); err != nil {
		t.Fatal(err)
	}
	spec.ModelProfileID = profile
	digest, _ := spec.MutationDigest()
	task, err := f.tasks.CreateTask(f.ctx, coretask.CreateTaskCommand{Spec: spec, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.pool.Exec(f.ctx, `UPDATE core_tasks SET status='waiting_user' WHERE task_id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	b := f.binding
	b.TargetID = uuid.NewString()
	if err = f.confirmations.UpsertCurrentTargetBinding(f.ctx, b); err != nil {
		t.Fatal(err)
	}
	req := coreconfirmation.RequestCommand{IdempotencyKey: uuid.NewString(), Binding: b, TaskID: task.ID, ExpiresAt: expires, At: f.now}
	c, err := f.service.Request(f.ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	return c, req
}

func TestCoreConfirmationPostgresConcurrentConfirmReplayAndConflict(t *testing.T) {
	f := newPGConfirmationFixture(t, time.Time{})
	defer f.cleanup()
	c, req := createPGConfirmation(t, f, time.Time{})
	var wg sync.WaitGroup
	results := make([]coreconfirmation.Confirmation, 2)
	errs := make([]error, 2)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = f.service.Confirm(f.ctx, coreconfirmation.ConfirmCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: req.IdempotencyKey, ExpectedRevision: c.Revision, At: f.now.Add(time.Second)})
		}(i)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || results[0].ConfirmationID != results[1].ConfirmationID {
		t.Fatalf("concurrent replay results=%+v errs=%v", results, errs)
	}
	changed, err := f.service.Confirm(f.ctx, coreconfirmation.ConfirmCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: req.IdempotencyKey, ExpectedRevision: c.Revision + 1, At: f.now.Add(time.Second)})
	if !errors.Is(err, coreconfirmation.ErrIdempotencyConflict) {
		t.Fatalf("changed digest result=%+v err=%v", changed, err)
	}
}

func TestCoreConfirmationPostgresConsumeStaleBindingExpiresAndReplays(t *testing.T) {
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
	stale := confirmed.Binding
	stale.SourceVersion = "drifted"
	if err = f.confirmations.UpsertCurrentTargetBinding(f.ctx, stale); err != nil {
		t.Fatal(err)
	}
	consumeKey := uuid.NewString()
	cmd := coreconfirmation.ConsumeCommand{ConfirmationID: confirmed.ConfirmationID, IdempotencyKey: consumeKey, TaskID: claimed.ID, Attempt: lease.Attempt, LeaseEpoch: lease.Epoch, ExpectedRevision: confirmed.Revision, ExpectedTaskRevision: int64(claimed.Revision), At: f.now}
	if _, err = f.service.Consume(f.ctx, cmd); !errors.Is(err, coreconfirmation.ErrStale) {
		t.Fatalf("stale consume err=%v", err)
	}
	if _, err = f.service.Consume(f.ctx, cmd); !errors.Is(err, coreconfirmation.ErrStale) {
		t.Fatalf("stale replay err=%v", err)
	}
	got, _ := f.confirmations.Get(f.ctx, confirmed.ConfirmationID)
	if got.State != coreconfirmation.StateExpired {
		t.Fatalf("state=%s", got.State)
	}
	var status string
	if err = f.store.pool.QueryRow(f.ctx, `SELECT status FROM core_tasks WHERE task_id=$1`, claimed.ID).Scan(&status); err != nil || status != "failed" {
		t.Fatalf("task status=%s err=%v", status, err)
	}
}

func TestCoreConfirmationPostgresExpiredConfirmAndConsumeReplay(t *testing.T) {
	f := newPGConfirmationFixture(t, time.Time{})
	defer f.cleanup()
	c, _ := createPGConfirmation(t, f, f.now.Add(time.Second))
	key := uuid.NewString()
	cmd := coreconfirmation.ConfirmCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: key, ExpectedRevision: c.Revision, At: f.now.Add(2 * time.Second)}
	if _, err := f.service.Confirm(f.ctx, cmd); !errors.Is(err, coreconfirmation.ErrExpired) {
		t.Fatalf("expired confirm err=%v", err)
	}
	if _, err := f.service.Confirm(f.ctx, cmd); !errors.Is(err, coreconfirmation.ErrExpired) {
		t.Fatalf("expired confirm replay err=%v", err)
	}
	c2, _ := createPGConfirmation(t, f, f.now.Add(time.Second))
	confirmed, err := f.service.Confirm(f.ctx, coreconfirmation.ConfirmCommand{ConfirmationID: c2.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: c2.Revision, At: f.now})
	if err != nil {
		t.Fatal(err)
	}
	claimed, lease, err := f.tasks.ClaimNextDue(f.ctx, uuid.NewString(), time.Now().UTC(), time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	consume := coreconfirmation.ConsumeCommand{ConfirmationID: confirmed.ConfirmationID, IdempotencyKey: uuid.NewString(), TaskID: claimed.ID, Attempt: lease.Attempt, LeaseEpoch: lease.Epoch, ExpectedRevision: confirmed.Revision, ExpectedTaskRevision: int64(claimed.Revision), At: f.now.Add(2 * time.Second)}
	if _, err = f.service.Consume(f.ctx, consume); !errors.Is(err, coreconfirmation.ErrExpired) {
		t.Fatalf("expired consume err=%v", err)
	}
	if _, err = f.service.Consume(f.ctx, consume); !errors.Is(err, coreconfirmation.ErrExpired) {
		t.Fatalf("expired consume replay err=%v", err)
	}
}

func TestCoreConfirmationPostgresOverdueWaitingUserConvergesWithoutRunnableWork(t *testing.T) {
	f := newPGConfirmationFixture(t, time.Time{})
	defer f.cleanup()
	c, _ := createPGConfirmation(t, f, f.now.Add(time.Second))
	deadline := f.now.Add(2 * time.Second)
	if _, err := f.store.pool.Exec(f.ctx, `UPDATE core_tasks SET execution_started_at=$2,execution_deadline_at=$3 WHERE task_id=$1`, c.TaskID, f.now, deadline); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.tasks.ClaimNextDue(f.ctx, uuid.NewString(), deadline, time.Minute, 1); !errors.Is(err, coretask.ErrNotFound) {
		t.Fatalf("claim overdue waiting_user err=%v", err)
	}
	var taskStatus, confirmationState string
	if err := f.store.pool.QueryRow(f.ctx, `SELECT status FROM core_tasks WHERE task_id=$1`, c.TaskID).Scan(&taskStatus); err != nil {
		t.Fatal(err)
	}
	if err := f.store.pool.QueryRow(f.ctx, `SELECT state FROM core_confirmations WHERE confirmation_id=$1`, c.ConfirmationID).Scan(&confirmationState); err != nil {
		t.Fatal(err)
	}
	if taskStatus != "failed" || confirmationState != "expired" {
		t.Fatalf("task=%s confirmation=%s", taskStatus, confirmationState)
	}
}

func TestCoreConfirmationPostgresConfirmVsTimeoutRaceHasSingleTerminalOwner(t *testing.T) {
	f := newPGConfirmationFixture(t, time.Time{})
	defer f.cleanup()
	c, _ := createPGConfirmation(t, f, f.now.Add(time.Hour))
	deadline := f.now.Add(2 * time.Second)
	if _, err := f.store.pool.Exec(f.ctx, `UPDATE core_tasks SET execution_started_at=$2,execution_deadline_at=$3 WHERE task_id=$1`, c.TaskID, f.now, deadline); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var confirmErr, timeoutErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, confirmErr = f.service.Confirm(f.ctx, coreconfirmation.ConfirmCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: c.Revision, At: deadline})
	}()
	go func() {
		defer wg.Done()
		<-start
		_, _, timeoutErr = f.tasks.ClaimNextDue(f.ctx, uuid.NewString(), deadline, time.Minute, 1)
	}()
	close(start)
	wg.Wait()
	if confirmErr != nil && !errors.Is(confirmErr, coreconfirmation.ErrExpired) && !errors.Is(confirmErr, coreconfirmation.ErrConflict) && !errors.Is(confirmErr, coreconfirmation.ErrRevisionConflict) {
		t.Fatalf("confirm race err=%v", confirmErr)
	}
	if timeoutErr != nil && !errors.Is(timeoutErr, coretask.ErrNotFound) {
		t.Fatalf("timeout race err=%v", timeoutErr)
	}
	assertTimedOutConfirmationTask(t, f, c)
}

func TestCoreConfirmationPostgresRejectVsTimeoutRaceHasSingleTerminalOwner(t *testing.T) {
	f := newPGConfirmationFixture(t, time.Time{})
	defer f.cleanup()
	c, _ := createPGConfirmation(t, f, f.now.Add(time.Hour))
	deadline := f.now.Add(2 * time.Second)
	if _, err := f.store.pool.Exec(f.ctx, `UPDATE core_tasks SET execution_started_at=$2,execution_deadline_at=$3 WHERE task_id=$1`, c.TaskID, f.now, deadline); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var rejectErr, timeoutErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, rejectErr = f.service.Reject(f.ctx, coreconfirmation.RejectCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: c.Revision, At: deadline, Reason: "late"})
	}()
	go func() {
		defer wg.Done()
		<-start
		_, _, timeoutErr = f.tasks.ClaimNextDue(f.ctx, uuid.NewString(), deadline, time.Minute, 1)
	}()
	close(start)
	wg.Wait()
	if rejectErr != nil && !errors.Is(rejectErr, coreconfirmation.ErrExpired) && !errors.Is(rejectErr, coreconfirmation.ErrConflict) && !errors.Is(rejectErr, coreconfirmation.ErrRevisionConflict) {
		t.Fatalf("reject race err=%v", rejectErr)
	}
	if timeoutErr != nil && !errors.Is(timeoutErr, coretask.ErrNotFound) {
		t.Fatalf("timeout race err=%v", timeoutErr)
	}
	assertTimedOutConfirmationTask(t, f, c)
}

func assertTimedOutConfirmationTask(t *testing.T, f pgConfirmationFixture, c coreconfirmation.Confirmation) {
	t.Helper()
	var taskStatus, confirmationState string
	if err := f.store.pool.QueryRow(f.ctx, `SELECT status FROM core_tasks WHERE task_id=$1`, c.TaskID).Scan(&taskStatus); err != nil {
		t.Fatal(err)
	}
	if err := f.store.pool.QueryRow(f.ctx, `SELECT state FROM core_confirmations WHERE confirmation_id=$1`, c.ConfirmationID).Scan(&confirmationState); err != nil {
		t.Fatal(err)
	}
	if taskStatus != "failed" || confirmationState != "expired" {
		t.Fatalf("task=%s confirmation=%s", taskStatus, confirmationState)
	}
	var locks int
	if err := f.store.pool.QueryRow(f.ctx, `SELECT count(*) FROM core_confirmation_current_bindings WHERE operation_domain=$1 AND target_id=$2`, c.Binding.OperationDomain, c.Binding.TargetID).Scan(&locks); err != nil {
		t.Fatal(err)
	}
	if locks != 1 {
		t.Fatalf("target binding rows=%d, want retained single binding", locks)
	}
	var activeReservations int
	if err := f.store.pool.QueryRow(f.ctx, `SELECT count(*) FROM core_confirmation_reservations WHERE confirmation_id=$1 AND active`, c.ConfirmationID).Scan(&activeReservations); err != nil {
		t.Fatal(err)
	}
	if activeReservations != 0 {
		t.Fatalf("active reservations=%d, want 0", activeReservations)
	}
}

func TestCoreConfirmationPostgresListCursorFilterBinding(t *testing.T) {
	f := newPGConfirmationFixture(t, time.Time{})
	defer f.cleanup()
	_, _ = createPGConfirmation(t, f, time.Time{})
	f.binding.OperationDomain = "skill"
	_, _ = createPGConfirmation(t, f, time.Time{})
	page, err := f.service.List(f.ctx, coreconfirmation.ListQuery{PageSize: 1, Domain: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	if page.NextPageToken == "" {
		t.Fatal("expected cursor")
	}
	if _, err = f.service.List(f.ctx, coreconfirmation.ListQuery{PageSize: 1, Domain: "skill", PageToken: page.NextPageToken}); !errors.Is(err, coreconfirmation.ErrInvalid) {
		t.Fatalf("cross-filter cursor err=%v", err)
	}
	if _, err = f.service.List(f.ctx, coreconfirmation.ListQuery{PageSize: 1, Domain: "aws", PageToken: page.NextPageToken}); err != nil {
		t.Fatalf("same-filter cursor err=%v", err)
	}
}
