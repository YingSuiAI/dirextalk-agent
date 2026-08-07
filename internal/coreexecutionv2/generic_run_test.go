package coreexecutionv2

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

const (
	genericPlanID = "91919191-9191-4191-8191-919191919191"
	genericIdem   = "92929292-9292-4292-8292-929292929292"
)

func genericRunServiceFixture(t *testing.T, reconcile func(context.Context, string, map[string]any) (map[string]any, error)) (*Service, *MemoryStore, Authority, time.Time) {
	t.Helper()
	now := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	planPayload := ownedPayload(owner, map[string]any{"plan_id": genericPlanID, "status": "ready"})
	plan := Record{OwnerID: owner, Kind: "plan", ID: genericPlanID, Revision: 1, Status: "ready", Digest: strings.Repeat("a", 64), Payload: planPayload, CreatedAt: now, UpdatedAt: now}
	if _, err := store.Create(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(Config{Store: store, Providers: Providers{Reconcile: reconcile}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return service, store, Authority{OwnerID: owner, AccountGeneration: 7}, now
}

func createGenericRun(t *testing.T, service *Service, authority Authority) map[string]any {
	t.Helper()
	result, err := service.HandleWithAuthority(context.Background(), authority, "agent.execution.v2.runs.create", map[string]any{
		"plan_id": genericPlanID, "plan_revision": uint64(1), "operation": "deploy",
		"trigger_kind": "manual", "idempotency_key": genericIdem,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestGenericRunCreateIsAtomicReplayableAndHasNoShadowConfirmation(t *testing.T) {
	service, store, authority, _ := genericRunServiceFixture(t, func(context.Context, string, map[string]any) (map[string]any, error) {
		return map[string]any{"status": "succeeded"}, nil
	})
	first := createGenericRun(t, service, authority)
	run := first["run"].(map[string]any)
	if run["status"] != "waiting_user" || uintParam(run, "account_generation") != authority.AccountGeneration || stringParam(run, "plan_digest") != strings.Repeat("a", 64) {
		t.Fatalf("run=%v", run)
	}
	confirmationID := stringParam(run, "confirmation_id")
	confirmation, err := store.ReadGenericRunConfirmation(context.Background(), owner, confirmationID)
	if err != nil || confirmation.State != coreconfirmation.StatePending || confirmation.Binding.OperationDomain != "execution_v2.run" {
		t.Fatalf("confirmation=%+v err=%v", confirmation, err)
	}
	if _, err := store.Read(context.Background(), owner, "confirmation", confirmationID, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("shadow confirmation exists: %v", err)
	}
	replay := createGenericRun(t, service, authority)
	if !reflect.DeepEqual(canonicalJSON(first), canonicalJSON(replay)) {
		t.Fatalf("replay changed: first=%v replay=%v", first, replay)
	}
	_, err = service.HandleWithAuthority(context.Background(), authority, "agent.execution.v2.runs.create", map[string]any{
		"plan_id": genericPlanID, "plan_revision": uint64(1), "operation": "destroy",
		"trigger_kind": "manual", "idempotency_key": genericIdem,
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("changed replay err=%v", err)
	}
}

func TestGenericRunConfirmationAutomaticallyDispatchesAndProjectsTerminalState(t *testing.T) {
	calls := 0
	service, store, authority, now := genericRunServiceFixture(t, func(_ context.Context, gotOwner string, input map[string]any) (map[string]any, error) {
		calls++
		if gotOwner != owner || stringParam(input, "run_id") == "" || stringParam(input, "stage_id") == "" {
			t.Fatalf("provider input owner=%q input=%v", gotOwner, input)
		}
		return map[string]any{"status": "succeeded"}, nil
	})
	created := createGenericRun(t, service, authority)
	run := created["run"].(map[string]any)
	confirmed, err := store.confirmGenericRun(authority, stringParam(run, "confirmation_id"), 1, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	running := claimedGenericTask(confirmed.Task, now.Add(2*time.Second))
	outcome := service.handleGenericRunTask(context.Background(), running)
	if outcome.Err != nil || !outcome.TerminalOwned || calls != 1 {
		t.Fatalf("outcome=%+v calls=%d", outcome, calls)
	}
	final, err := store.genericRunEnvelope(owner, stringParam(run, "run_id"))
	if err != nil || final.Run.Status != "succeeded" || final.Stage.Status != "succeeded" || final.Task.Status != coretask.StatusSucceeded || final.Confirmation.State != coreconfirmation.StateConsumed {
		t.Fatalf("final=%+v err=%v", final, err)
	}
}

func TestGenericRunConfirmationRejectAndExpireTerminalizeBeforeProvider(t *testing.T) {
	tests := []struct {
		name          string
		confirmFirst  bool
		terminalState coreconfirmation.State
		runStatus     string
		taskStatus    coretask.Status
	}{
		{name: "reject pending", terminalState: coreconfirmation.StateRejected, runStatus: "rejected", taskStatus: coretask.StatusCanceled},
		{name: "expire pending", terminalState: coreconfirmation.StateExpired, runStatus: "expired", taskStatus: coretask.StatusFailed},
		{name: "expire confirmed", confirmFirst: true, terminalState: coreconfirmation.StateExpired, runStatus: "expired", taskStatus: coretask.StatusFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			providerCalls := 0
			service, store, authority, now := genericRunServiceFixture(t, func(context.Context, string, map[string]any) (map[string]any, error) {
				providerCalls++
				return map[string]any{"status": "succeeded"}, nil
			})
			created := createGenericRun(t, service, authority)
			run := created["run"].(map[string]any)
			confirmationID := stringParam(run, "confirmation_id")
			envelope, err := store.genericRunEnvelope(owner, stringParam(run, "run_id"))
			if err != nil {
				t.Fatal(err)
			}
			if test.confirmFirst {
				envelope, err = store.confirmGenericRun(authority, confirmationID, envelope.Confirmation.Revision, now.Add(time.Second))
				if err != nil || envelope.Run.Status != "queued" || envelope.Stage.Status != "queued" || envelope.Task.Status != coretask.StatusQueued {
					t.Fatalf("confirmed envelope=%+v err=%v", envelope, err)
				}
			}
			if test.terminalState == coreconfirmation.StateRejected {
				envelope, err = store.rejectGenericRun(authority, confirmationID, envelope.Confirmation.Revision, now.Add(2*time.Second))
			} else {
				envelope, err = store.expireGenericRun(authority, confirmationID, envelope.Confirmation.Revision, coreconfirmation.ReasonExpired, now.Add(2*time.Second))
			}
			if err != nil {
				t.Fatal(err)
			}
			if envelope.Confirmation.State != test.terminalState || envelope.Run.Status != test.runStatus ||
				envelope.Stage.Status != test.runStatus || envelope.Task.Status != test.taskStatus || envelope.Task.Lease != nil {
				t.Fatalf("terminal envelope=%+v", envelope)
			}
			outcome := service.handleGenericRunTask(context.Background(), claimedGenericTask(envelope.Task, now.Add(3*time.Second)))
			if outcome.Err == nil || providerCalls != 0 {
				t.Fatalf("terminal dispatch outcome=%+v provider_calls=%d", outcome, providerCalls)
			}
		})
	}
}

func TestGenericRunConsumedAuthorityDriftFailsBeforeProviderMutation(t *testing.T) {
	calls := 0
	service, store, authority, now := genericRunServiceFixture(t, func(context.Context, string, map[string]any) (map[string]any, error) {
		calls++
		return map[string]any{"status": "succeeded"}, nil
	})
	created := createGenericRun(t, service, authority)
	run := created["run"].(map[string]any)
	confirmed, err := store.confirmGenericRun(authority, stringParam(run, "confirmation_id"), 1, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	drift := store.genericConfirmations[confirmed.Confirmation.ConfirmationID]
	drift.Binding.AccountGeneration++
	store.genericConfirmations[drift.ConfirmationID] = drift
	store.mu.Unlock()
	outcome := service.handleGenericRunTask(context.Background(), claimedGenericTask(confirmed.Task, now.Add(2*time.Second)))
	if !errors.Is(outcome.Err, ErrConflict) || calls != 0 {
		t.Fatalf("outcome=%+v calls=%d", outcome, calls)
	}
}

func TestGenericRunCancelReplaysAndFencesRunningProjection(t *testing.T) {
	service, store, authority, now := genericRunServiceFixture(t, func(context.Context, string, map[string]any) (map[string]any, error) {
		return map[string]any{"status": "running"}, nil
	})
	created := createGenericRun(t, service, authority)
	run := created["run"].(map[string]any)
	confirmed, err := store.confirmGenericRun(authority, stringParam(run, "confirmation_id"), 1, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	running := claimedGenericTask(confirmed.Task, now.Add(2*time.Second))
	started, err := store.BeginGenericRun(context.Background(), running)
	if err != nil {
		t.Fatal(err)
	}
	cancelInput := map[string]any{"run_id": started.Run.ID, "expected_revision": started.Run.Revision, "idempotency_key": "93939393-9393-4393-8393-939393939393"}
	first, err := service.HandleWithAuthority(context.Background(), authority, "agent.execution.v2.runs.cancel", cancelInput)
	if err != nil || first["run"].(map[string]any)["status"] != "canceled" {
		t.Fatalf("cancel=%v err=%v", first, err)
	}
	replay, err := service.HandleWithAuthority(context.Background(), authority, "agent.execution.v2.runs.cancel", cancelInput)
	if err != nil || !reflect.DeepEqual(canonicalJSON(first), canonicalJSON(replay)) {
		t.Fatalf("cancel replay=%v err=%v", replay, err)
	}
	project := GenericRunProjectCommand{Task: started.Task, ExpectedRunRevision: started.Run.Revision, ExpectedStageRevision: started.Stage.Revision, Status: "succeeded", RunPayload: started.Run.Payload, StagePayload: started.Stage.Payload, At: now.Add(4 * time.Second)}
	if _, err := store.ProjectGenericRun(context.Background(), project); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale running projection err=%v", err)
	}
	foreign := cloneMap(cancelInput)
	foreign["idempotency_key"] = "94949494-9494-4494-8494-949494949494"
	if _, err := service.HandleWithAuthority(context.Background(), Authority{OwnerID: owner, AccountGeneration: authority.AccountGeneration + 1}, "agent.execution.v2.runs.cancel", foreign); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale generation cancel err=%v", err)
	}
}

func TestGenericRunRetryCreatesFreshTaskAndConfirmation(t *testing.T) {
	service, store, authority, now := genericRunServiceFixture(t, func(context.Context, string, map[string]any) (map[string]any, error) {
		return map[string]any{"status": "failed", "reason": "qualified_failure"}, nil
	})
	created := createGenericRun(t, service, authority)
	run := created["run"].(map[string]any)
	confirmed, err := store.confirmGenericRun(authority, stringParam(run, "confirmation_id"), 1, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if outcome := service.handleGenericRunTask(context.Background(), claimedGenericTask(confirmed.Task, now.Add(2*time.Second))); outcome.Err != nil || !outcome.TerminalOwned {
		t.Fatalf("terminal outcome=%+v", outcome)
	}
	failed, err := store.genericRunEnvelope(owner, stringParam(run, "run_id"))
	if err != nil || failed.Run.Status != "failed" {
		t.Fatalf("failed=%+v err=%v", failed, err)
	}
	retried, err := service.HandleWithAuthority(context.Background(), authority, "agent.execution.v2.runs.retry", map[string]any{
		"run_id": failed.Run.ID, "expected_revision": failed.Run.Revision,
		"idempotency_key": "95959595-9595-4595-8595-959595959595",
	})
	if err != nil {
		t.Fatal(err)
	}
	retryRun := retried["run"].(map[string]any)
	if retryRun["status"] != "waiting_user" || stringParam(retryRun, "retry_of_run_id") != failed.Run.ID || stringParam(retryRun, "task_id") == failed.Task.ID || stringParam(retryRun, "confirmation_id") == failed.Confirmation.ConfirmationID {
		t.Fatalf("retry=%v", retryRun)
	}
}

func TestCloudWorkerCreateAndRetryAreExplicitlyRejected(t *testing.T) {
	port := &cloudWorkerPortFake{calls: map[string]int{}}
	service, _ := newCloudRoutingService(t, port)
	authority := Authority{OwnerID: owner, AccountGeneration: cloudGeneration}
	tests := []struct {
		action string
		input  map[string]any
	}{
		{"agent.execution.v2.runs.create", map[string]any{"record_kind": RecordKindCloudWorker, "plan_id": cloudPlanID, "plan_revision": uint64(1), "operation": "execute", "idempotency_key": genericIdem}},
		{"agent.execution.v2.runs.retry", map[string]any{"record_kind": RecordKindCloudWorker, "run_id": cloudRunID, "expected_revision": uint64(1), "idempotency_key": genericIdem}},
	}
	for _, test := range tests {
		if _, err := service.HandleWithAuthority(context.Background(), authority, test.action, test.input); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s err=%v", test.action, err)
		}
	}
}

func claimedGenericTask(task coretask.Task, at time.Time) coretask.Task {
	task.Status = coretask.StatusRunning
	task.Revision++
	task.LeaseEpoch++
	task.UpdatedAt = at.UTC()
	task.Lease = &coretask.Lease{TaskID: task.ID, Attempt: task.Attempt, Epoch: task.LeaseEpoch, Holder: "generic-test-worker", ExpiresAt: at.Add(time.Minute).UTC()}
	return task
}

func (m *MemoryStore) genericRunEnvelope(ownerID, runID string) (GenericRunEnvelope, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.genericRunEnvelopeLocked(ownerID, runID)
}

func canonicalJSON(value any) any {
	raw, _ := json.Marshal(value)
	var out any
	_ = json.Unmarshal(raw, &out)
	return out
}
