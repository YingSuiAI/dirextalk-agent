package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

type pgGenericRunHarness struct {
	ctx           context.Context
	store         *Store
	records       *coreexecutionv2.PostgresStore
	lifecycle     *CoreExecutionV2RunStore
	tasks         *CoreTaskStore
	confirmations *coreconfirmation.Service
	service       *coreexecutionv2.Service
	providerCalls *int
	authority     coreexecutionv2.Authority
	now           time.Time
	cleanup       func()
}

func newPGGenericRunHarness(t *testing.T) *pgGenericRunHarness {
	t.Helper()
	ctx, store, _, cleanup := corePG18Fixture(t)
	records, err := coreexecutionv2.NewPostgresStore(store.Pool())
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	lifecycle := NewCoreExecutionV2RunStore(store)
	providerCalls := 0
	service, err := coreexecutionv2.NewService(coreexecutionv2.Config{
		Store: records,
		Providers: coreexecutionv2.Providers{Reconcile: func(context.Context, string, map[string]any) (map[string]any, error) {
			providerCalls++
			return map[string]any{"status": "succeeded"}, nil
		}},
		RunLifecycle: lifecycle,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	confirmationService, err := coreconfirmation.NewService(NewCoreConfirmationStore(store), func() time.Time {
		return time.Now().UTC()
	})
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	return &pgGenericRunHarness{
		ctx: ctx, store: store, records: records, lifecycle: lifecycle, tasks: NewCoreTaskStore(store),
		confirmations: confirmationService, service: service, providerCalls: &providerCalls,
		authority: coreexecutionv2.Authority{OwnerID: "@generic-run-owner:example.test", AccountGeneration: 17},
		now:       now, cleanup: cleanup,
	}
}

func (h *pgGenericRunHarness) createPlan(t *testing.T) string {
	t.Helper()
	result, err := h.service.HandleWithAuthority(h.ctx, h.authority, "agent.execution.v2.plans.create", map[string]any{
		"project_id": uuid.NewString(), "analysis_id": uuid.NewString(), "target_id": uuid.NewString(),
		"target_revision": uint64(1), "intent": "deploy", "recipe_id": "generic-container-service",
		"purpose": "service", "idempotency_key": uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return result["plan"].(map[string]any)["plan_id"].(string)
}

func (h *pgGenericRunHarness) createRunForPlan(t *testing.T, planID, idempotencyKey string) coreexecutionv2.GenericRunEnvelope {
	t.Helper()
	result, err := h.service.HandleWithAuthority(h.ctx, h.authority, "agent.execution.v2.runs.create", map[string]any{
		"plan_id": planID, "plan_revision": uint64(1), "operation": "deploy", "trigger_kind": "manual",
		"idempotency_key": idempotencyKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	runView := result["run"].(map[string]any)
	runID := runView["run_id"].(string)
	run, err := h.records.Read(h.ctx, h.authority.OwnerID, "run", runID, 0)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := h.records.Read(h.ctx, h.authority.OwnerID, "stage", run.Payload["stage_id"].(string), 0)
	if err != nil {
		t.Fatal(err)
	}
	task, err := h.tasks.GetTask(h.ctx, run.Payload["task_id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	confirmation, err := h.lifecycle.ReadGenericRunConfirmation(h.ctx, h.authority.OwnerID, run.Payload["confirmation_id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return coreexecutionv2.GenericRunEnvelope{Run: run, Stage: stage, Task: task, Confirmation: confirmation}
}

func (h *pgGenericRunHarness) createRun(t *testing.T) coreexecutionv2.GenericRunEnvelope {
	t.Helper()
	return h.createRunForPlan(t, h.createPlan(t), uuid.NewString())
}

func (h *pgGenericRunHarness) confirm(t *testing.T, envelope coreexecutionv2.GenericRunEnvelope) coretask.Task {
	t.Helper()
	confirmed, err := h.confirmations.ConfirmAuthorized(h.ctx, coreconfirmation.Authority{
		OwnerID: h.authority.OwnerID, AccountGeneration: h.authority.AccountGeneration,
	}, coreconfirmation.ConfirmCommand{
		ConfirmationID: envelope.Confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(),
		ExpectedRevision: envelope.Confirmation.Revision, At: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if confirmed.State != coreconfirmation.StateConfirmed {
		t.Fatalf("confirmation state = %s", confirmed.State)
	}
	task, err := h.tasks.GetTask(h.ctx, envelope.Task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if task.Status != coretask.StatusQueued {
		t.Fatalf("confirmed task status = %s", task.Status)
	}
	run, err := h.records.Read(h.ctx, h.authority.OwnerID, "run", envelope.Run.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := h.records.Read(h.ctx, h.authority.OwnerID, "stage", envelope.Stage.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "queued" || stage.Status != "queued" {
		t.Fatalf("confirmed records run=%s stage=%s", run.Status, stage.Status)
	}
	return task
}

func (h *pgGenericRunHarness) claimAndBegin(t *testing.T, envelope coreexecutionv2.GenericRunEnvelope, holder string) coreexecutionv2.GenericRunEnvelope {
	t.Helper()
	h.confirm(t, envelope)
	claimed, _, err := h.tasks.ClaimNextDue(h.ctx, holder, time.Now().UTC(), time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.ID != envelope.Task.ID {
		t.Fatalf("claimed task = %s, want %s", claimed.ID, envelope.Task.ID)
	}
	begun, err := h.lifecycle.BeginGenericRun(h.ctx, claimed)
	if err != nil {
		t.Fatal(err)
	}
	return begun
}

func cloneGenericRunPayload(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var cloned map[string]any
	if err = json.Unmarshal(raw, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func TestCoreExecutionV2RunPostgresCreateAtomicReplayAndAuthority(t *testing.T) {
	h := newPGGenericRunHarness(t)
	defer h.cleanup()

	envelope := h.createRun(t)
	if envelope.Run.Status != "waiting_user" || envelope.Stage.Status != "waiting_user" ||
		envelope.Task.Status != coretask.StatusWaitingUser || envelope.Confirmation.State != coreconfirmation.StatePending {
		t.Fatalf("initial envelope = %+v", envelope)
	}
	var shadowConfirmations int
	if err := h.store.Pool().QueryRow(h.ctx, `SELECT count(*) FROM core_execution_v2_records WHERE resource_type='confirmation'`).Scan(&shadowConfirmations); err != nil {
		t.Fatal(err)
	}
	if shadowConfirmations != 0 {
		t.Fatalf("shadow confirmation records = %d", shadowConfirmations)
	}
	if _, err := h.store.Pool().Exec(h.ctx, `INSERT INTO core_execution_v2_records(
		owner_id,resource_type,resource_id,revision,status,digest,payload_json,created_at,updated_at)
		VALUES($1,'confirmation',$2,1,'pending',$3,'{}'::jsonb,$4,$4)`, h.authority.OwnerID, uuid.NewString(), envelope.Run.Digest, time.Now().UTC()); err == nil {
		t.Fatal("final schema accepted an Execution V2 shadow confirmation record")
	} else {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.ConstraintName != "core_execution_v2_records_resource_type_check" {
			t.Fatalf("shadow confirmation insert error = %v", err)
		}
	}
	if _, err := h.lifecycle.ReadGenericRunConfirmation(h.ctx, "@foreign:example.test", envelope.Confirmation.ConfirmationID); !errors.Is(err, coreexecutionv2.ErrNotFound) {
		t.Fatalf("foreign confirmation read err = %v", err)
	}

	command := coreexecutionv2.GenericRunCreateCommand{
		Run: envelope.Run, Stage: envelope.Stage, Task: envelope.Task, Confirmation: envelope.Confirmation,
	}
	// Simulate a retry after lifecycle commit but before the public action
	// replay was saved: the service rebuilds the same mutation with a fresh
	// clock and expiry, while the stable business digest must still replay the
	// originally committed response snapshot.
	retryAt := envelope.Run.CreatedAt.UTC().Add(time.Minute)
	command.At = retryAt
	command.Run.CreatedAt, command.Run.UpdatedAt = retryAt, retryAt
	command.Stage.CreatedAt, command.Stage.UpdatedAt = retryAt, retryAt
	command.Task.CreatedAt, command.Task.UpdatedAt, command.Task.AvailableAt = retryAt, retryAt, retryAt
	command.Task.Spec.AvailableAt = retryAt
	command.Confirmation.CreatedAt, command.Confirmation.UpdatedAt = retryAt, retryAt
	command.Confirmation.ExpiresAt = retryAt.Add(15 * time.Minute)
	replayed, err := h.lifecycle.CreateGenericRun(h.ctx, command)
	if err != nil || replayed.Run.ID != envelope.Run.ID || replayed.Task.ID != envelope.Task.ID {
		t.Fatalf("create replay = %+v err=%v", replayed, err)
	}
	changed := command
	changed.Task.Spec.Goal += " changed"
	if _, err = h.lifecycle.CreateGenericRun(h.ctx, changed); !errors.Is(err, coreexecutionv2.ErrConflict) {
		t.Fatalf("changed create err = %v", err)
	}

	planID := h.createPlan(t)
	var beforeRuns, beforeStages, beforeTasks, beforeConfirmations int
	if err = h.store.Pool().QueryRow(h.ctx, `SELECT
		(SELECT count(*) FROM core_execution_v2_records WHERE resource_type='run'),
		(SELECT count(*) FROM core_execution_v2_records WHERE resource_type='stage'),
		(SELECT count(*) FROM core_tasks WHERE task_kind='execution_v2_run'),
		(SELECT count(*) FROM core_confirmations WHERE operation_domain='execution_v2.run')`).Scan(
		&beforeRuns, &beforeStages, &beforeTasks, &beforeConfirmations); err != nil {
		t.Fatal(err)
	}
	if _, err = h.store.Pool().Exec(h.ctx, `CREATE FUNCTION reject_generic_run_binding() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'forced generic run binding failure'; END $$;
		CREATE TRIGGER reject_generic_run_binding BEFORE INSERT ON core_confirmation_current_bindings
		FOR EACH ROW EXECUTE FUNCTION reject_generic_run_binding()`); err != nil {
		t.Fatal(err)
	}
	_, err = h.service.HandleWithAuthority(h.ctx, h.authority, "agent.execution.v2.runs.create", map[string]any{
		"plan_id": planID, "plan_revision": uint64(1), "operation": "deploy", "trigger_kind": "manual",
		"idempotency_key": uuid.NewString(),
	})
	if err == nil {
		t.Fatal("forced late failure was accepted")
	}
	var afterRuns, afterStages, afterTasks, afterConfirmations int
	if scanErr := h.store.Pool().QueryRow(h.ctx, `SELECT
		(SELECT count(*) FROM core_execution_v2_records WHERE resource_type='run'),
		(SELECT count(*) FROM core_execution_v2_records WHERE resource_type='stage'),
		(SELECT count(*) FROM core_tasks WHERE task_kind='execution_v2_run'),
		(SELECT count(*) FROM core_confirmations WHERE operation_domain='execution_v2.run')`).Scan(
		&afterRuns, &afterStages, &afterTasks, &afterConfirmations); scanErr != nil {
		t.Fatal(scanErr)
	}
	if beforeRuns != afterRuns || beforeStages != afterStages || beforeTasks != afterTasks || beforeConfirmations != afterConfirmations {
		t.Fatalf("late failure leaked rows: before=%d/%d/%d/%d after=%d/%d/%d/%d",
			beforeRuns, beforeStages, beforeTasks, beforeConfirmations, afterRuns, afterStages, afterTasks, afterConfirmations)
	}
}

func TestCoreExecutionV2RunPostgresConfirmationTerminalProjection(t *testing.T) {
	tests := []struct {
		name              string
		confirmFirst      bool
		terminalState     coreconfirmation.State
		recordStatus      string
		taskStatus        coretask.Status
		expectedTaskError string
	}{
		{name: "reject pending", terminalState: coreconfirmation.StateRejected, recordStatus: "rejected", taskStatus: coretask.StatusCanceled, expectedTaskError: coreconfirmation.ReasonUserRejected},
		{name: "expire pending", terminalState: coreconfirmation.StateExpired, recordStatus: "expired", taskStatus: coretask.StatusFailed, expectedTaskError: coreconfirmation.ReasonExpired},
		{name: "expire confirmed", confirmFirst: true, terminalState: coreconfirmation.StateExpired, recordStatus: "expired", taskStatus: coretask.StatusFailed, expectedTaskError: coreconfirmation.ReasonExpired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newPGGenericRunHarness(t)
			defer h.cleanup()
			envelope := h.createRun(t)
			if test.confirmFirst {
				h.confirm(t, envelope)
				var err error
				envelope.Confirmation, err = h.lifecycle.ReadGenericRunConfirmation(h.ctx, h.authority.OwnerID, envelope.Confirmation.ConfirmationID)
				if err != nil {
					t.Fatal(err)
				}
			}

			var terminal coreconfirmation.Confirmation
			var err error
			if test.terminalState == coreconfirmation.StateRejected {
				terminal, err = h.confirmations.RejectAuthorized(h.ctx, coreconfirmation.Authority{
					OwnerID: h.authority.OwnerID, AccountGeneration: h.authority.AccountGeneration,
				}, coreconfirmation.RejectCommand{
					ConfirmationID: envelope.Confirmation.ConfirmationID, ExpectedRevision: envelope.Confirmation.Revision,
					IdempotencyKey: uuid.NewString(), Reason: "owner declined", At: time.Now().UTC(),
				})
			} else {
				terminal, err = h.confirmations.Expire(h.ctx, coreconfirmation.ExpireCommand{
					ConfirmationID: envelope.Confirmation.ConfirmationID, ExpectedRevision: envelope.Confirmation.Revision,
					IdempotencyKey: uuid.NewString(), Reason: coreconfirmation.ReasonExpired, At: time.Now().UTC(),
				})
			}
			if err != nil || terminal.State != test.terminalState {
				t.Fatalf("terminal confirmation=%+v err=%v", terminal, err)
			}
			run, err := h.records.Read(h.ctx, h.authority.OwnerID, "run", envelope.Run.ID, 0)
			if err != nil {
				t.Fatal(err)
			}
			stage, err := h.records.Read(h.ctx, h.authority.OwnerID, "stage", envelope.Stage.ID, 0)
			if err != nil {
				t.Fatal(err)
			}
			task, err := h.tasks.GetTask(h.ctx, envelope.Task.ID)
			if err != nil {
				t.Fatal(err)
			}
			if run.Status != test.recordStatus || stage.Status != test.recordStatus || task.Status != test.taskStatus ||
				task.FailureCode != test.expectedTaskError || task.Lease != nil {
				t.Fatalf("terminal projection run=%+v stage=%+v task=%+v", run, stage, task)
			}
			if _, _, err = h.tasks.ClaimNextDue(h.ctx, "must-not-dispatch", time.Now().UTC(), time.Minute, 1); !errors.Is(err, coretask.ErrNotFound) {
				t.Fatalf("terminal task remained claimable: %v", err)
			}
			if *h.providerCalls != 0 {
				t.Fatalf("provider calls = %d", *h.providerCalls)
			}
		})
	}
}

func TestCoreExecutionV2RunPostgresLeaseProjectionAndTerminalReplay(t *testing.T) {
	h := newPGGenericRunHarness(t)
	defer h.cleanup()

	envelope := h.createRun(t)
	begun := h.claimAndBegin(t, envelope, "generic-run-first")
	if begun.Run.Status != "running" || begun.Stage.Status != "running" || begun.Confirmation.State != coreconfirmation.StateConsumed {
		t.Fatalf("begun envelope = %+v", begun)
	}
	firstRunRevision, firstStageRevision := begun.Run.Revision, begun.Stage.Revision
	if _, err := h.store.Pool().Exec(h.ctx, `UPDATE core_tasks SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE task_id=$1`, begun.Task.ID); err != nil {
		t.Fatal(err)
	}
	reclaimed, _, err := h.tasks.ClaimNextDue(h.ctx, "generic-run-reclaimed", time.Now().UTC(), time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	if reclaimed.LeaseEpoch <= begun.Task.LeaseEpoch || reclaimed.Revision <= begun.Task.Revision {
		t.Fatalf("reclaim did not advance fence: before=%+v after=%+v", begun.Task, reclaimed)
	}
	rebound, err := h.lifecycle.BeginGenericRun(h.ctx, reclaimed)
	if err != nil {
		t.Fatal(err)
	}
	if rebound.Run.Revision != firstRunRevision || rebound.Stage.Revision != firstStageRevision {
		t.Fatalf("reclaim re-projected records: run=%d/%d stage=%d/%d", firstRunRevision, rebound.Run.Revision, firstStageRevision, rebound.Stage.Revision)
	}
	var reservationEpoch, reservationRevision int64
	if err = h.store.Pool().QueryRow(h.ctx, `SELECT acquired_lease_epoch,task_revision FROM core_confirmation_reservations WHERE confirmation_id=$1 AND active=true`, rebound.Confirmation.ConfirmationID).Scan(&reservationEpoch, &reservationRevision); err != nil {
		t.Fatal(err)
	}
	if reservationEpoch != int64(reclaimed.LeaseEpoch) || reservationRevision != int64(reclaimed.Revision) {
		t.Fatalf("reservation fence = %d/%d, want %d/%d", reservationEpoch, reservationRevision, reclaimed.LeaseEpoch, reclaimed.Revision)
	}

	nonterminal := coreexecutionv2.GenericRunProjectCommand{
		Task: rebound.Task, ExpectedRunRevision: rebound.Run.Revision, ExpectedStageRevision: rebound.Stage.Revision,
		Status: "uncertain", RunPayload: cloneGenericRunPayload(t, rebound.Run.Payload),
		StagePayload: cloneGenericRunPayload(t, rebound.Stage.Payload), At: time.Now().UTC(),
	}
	projected, err := h.lifecycle.ProjectGenericRun(h.ctx, nonterminal)
	if err != nil {
		t.Fatal(err)
	}
	if projected.Task.Revision != rebound.Task.Revision || projected.Task.LeaseEpoch != rebound.Task.LeaseEpoch || projected.Task.Lease == nil || projected.Task.Lease.Holder != rebound.Task.Lease.Holder {
		t.Fatalf("nonterminal projection changed task fence: before=%+v after=%+v", rebound.Task, projected.Task)
	}

	terminal := coreexecutionv2.GenericRunProjectCommand{
		Task: projected.Task, ExpectedRunRevision: projected.Run.Revision, ExpectedStageRevision: projected.Stage.Revision,
		Status: "succeeded", RunPayload: cloneGenericRunPayload(t, projected.Run.Payload),
		StagePayload: cloneGenericRunPayload(t, projected.Stage.Payload),
		Result:       coretask.Result{JSON: json.RawMessage(`{"verified":true}`), Summary: "verified"}, At: time.Now().UTC(),
	}
	completed, err := h.lifecycle.ProjectGenericRun(h.ctx, terminal)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Run.Status != "succeeded" || completed.Stage.Status != "succeeded" || completed.Task.Status != coretask.StatusSucceeded || completed.Task.Lease != nil {
		t.Fatalf("terminal envelope = %+v", completed)
	}
	replay, err := h.lifecycle.ProjectGenericRun(h.ctx, terminal)
	if err != nil || replay.Run.Revision != completed.Run.Revision || replay.Task.Revision != completed.Task.Revision {
		t.Fatalf("terminal replay = %+v err=%v", replay, err)
	}
	var runningCount, activeReservations int
	var released bool
	if err = h.store.Pool().QueryRow(h.ctx, `SELECT
		(SELECT running_count FROM core_task_runtime_concurrency WHERE singleton=true),
		(SELECT count(*) FROM core_confirmation_reservations WHERE confirmation_id=$1 AND active=true),
		(SELECT consumed_released FROM core_confirmations WHERE confirmation_id=$1)`, completed.Confirmation.ConfirmationID).Scan(
		&runningCount, &activeReservations, &released); err != nil {
		t.Fatal(err)
	}
	if runningCount != 0 || activeReservations != 0 || !released {
		t.Fatalf("terminal cleanup running=%d reservations=%d released=%v", runningCount, activeReservations, released)
	}
}

func TestCoreExecutionV2RunPostgresCancelStatesAndReplay(t *testing.T) {
	for _, state := range []string{"pending", "confirmed", "consumed"} {
		t.Run(state, func(t *testing.T) {
			h := newPGGenericRunHarness(t)
			defer h.cleanup()
			envelope := h.createRun(t)
			switch state {
			case "confirmed":
				h.confirm(t, envelope)
				var err error
				envelope.Run, err = h.records.Read(h.ctx, h.authority.OwnerID, "run", envelope.Run.ID, 0)
				if err != nil {
					t.Fatal(err)
				}
			case "consumed":
				envelope = h.claimAndBegin(t, envelope, "generic-run-cancel")
			}
			command := coreexecutionv2.GenericRunCancelCommand{
				Authority: h.authority, RunID: envelope.Run.ID, ExpectedRevision: envelope.Run.Revision,
				IdempotencyKey: uuid.NewString(), At: time.Now().UTC(),
			}
			canceled, err := h.lifecycle.CancelGenericRun(h.ctx, command)
			if err != nil {
				t.Fatal(err)
			}
			if canceled.Run.Status != "canceled" || canceled.Stage.Status != "canceled" || canceled.Task.Status != coretask.StatusCanceled {
				t.Fatalf("canceled envelope = %+v", canceled)
			}
			replay, err := h.lifecycle.CancelGenericRun(h.ctx, command)
			if err != nil || replay.Run.Revision != canceled.Run.Revision || replay.Task.Revision != canceled.Task.Revision {
				t.Fatalf("cancel replay = %+v err=%v", replay, err)
			}
			wrongGeneration := command
			wrongGeneration.IdempotencyKey = uuid.NewString()
			wrongGeneration.Authority.AccountGeneration++
			if _, err = h.lifecycle.CancelGenericRun(h.ctx, wrongGeneration); !errors.Is(err, coreexecutionv2.ErrConflict) {
				t.Fatalf("wrong generation cancel err = %v", err)
			}
		})
	}
}
