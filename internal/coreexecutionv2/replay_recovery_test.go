package coreexecutionv2

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

type failCompleteReplayStore struct {
	Store
	failures atomic.Int32
}

type failProviderResponseStore struct {
	Store
	failures atomic.Int32
}

type failAppendEventStore struct {
	Store
	failures atomic.Int32
}

type failNthUpdateStore struct {
	Store
	failAt atomic.Int32
	calls  atomic.Int32
}

func (s *failNthUpdateStore) Update(ctx context.Context, record Record, expected uint64) (Record, error) {
	if s.calls.Add(1) == s.failAt.Load() {
		return Record{}, errors.New("injected graph update failure")
	}
	return s.Store.Update(ctx, record, expected)
}

func (s *failAppendEventStore) AppendEvent(ctx context.Context, event Event) (Event, error) {
	if s.failures.Add(1) == 1 {
		return Event{}, errors.New("injected event persistence failure")
	}
	return s.Store.AppendEvent(ctx, event)
}

func (s *failProviderResponseStore) StoreReplayProviderResponse(ctx context.Context, scope coretask.OwnerScope, action, id string, digest []byte, token string, response []byte, updatedAt time.Time) error {
	if s.failures.Add(1) == 1 {
		return errors.New("injected provider response persistence failure")
	}
	return s.Store.StoreReplayProviderResponse(ctx, scope, action, id, digest, token, response, updatedAt)
}

func (s *failCompleteReplayStore) CompleteReplay(ctx context.Context, scope coretask.OwnerScope, action, id string, digest []byte, token string, response []byte, completedAt time.Time) error {
	if s.failures.Add(1) == 1 {
		return errors.New("injected replay completion failure")
	}
	return s.Store.CompleteReplay(ctx, scope, action, id, digest, token, response, completedAt)
}

func TestServiceRecoversDomainWriteWhenReplayReceiptCompletionFails(t *testing.T) {
	ctx := context.Background()
	base := NewMemoryStore()
	store := &failCompleteReplayStore{Store: base}
	now := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	service, err := NewService(Config{
		Store: store,
		Now:   func() time.Time { return now },
		Providers: Providers{Analyze: func(_ context.Context, _ coretask.OwnerScope, _ map[string]any) (map[string]any, error) {
			calls.Add(1)
			return map[string]any{"analysis_id": analysisID, "status": "ready"}, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := replayRecoveryAnalyzeInput()
	if _, err = service.Handle(ctx, ownerScope, "agent.execution.v2.projects.analyze", input); err == nil || err.Error() != "injected replay completion failure" {
		t.Fatalf("first call err=%v", err)
	}

	now = now.Add(6 * time.Minute)
	result, err := service.Handle(ctx, ownerScope, "agent.execution.v2.projects.analyze", input)
	if err != nil {
		t.Fatalf("recover completed domain write: %v", err)
	}
	analysis, _ := result["analysis"].(map[string]any)
	if analysis["id"] != deterministicID(ownerScope, "agent.execution.v2.projects.analyze", targetID) {
		t.Fatalf("recovered analysis=%+v", analysis)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("provider calls=%d, want 1", got)
	}
}

func TestServiceDoesNotRedispatchProviderAfterUncertainOutcome(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	service, err := NewService(Config{
		Store: NewMemoryStore(),
		Now:   func() time.Time { return now },
		Providers: Providers{Analyze: func(_ context.Context, _ coretask.OwnerScope, _ map[string]any) (map[string]any, error) {
			if calls.Add(1) == 1 {
				return nil, errors.New("provider outcome is uncertain")
			}
			return map[string]any{"analysis_id": analysisID, "status": "ready"}, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := replayRecoveryAnalyzeInput()
	if _, err = service.Handle(ctx, ownerScope, "agent.execution.v2.projects.analyze", input); err == nil || err.Error() != "provider outcome is uncertain" {
		t.Fatalf("first call err=%v", err)
	}

	now = now.Add(6 * time.Minute)
	if _, err = service.Handle(ctx, ownerScope, "agent.execution.v2.projects.analyze", input); !errors.Is(err, ErrReplayInProgress) {
		t.Fatalf("uncertain retry err=%v, want ErrReplayInProgress", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("provider calls=%d, want 1", got)
	}
}

func TestServiceDoesNotRedispatchProviderWhenOutcomePersistenceFails(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	store := &failProviderResponseStore{Store: NewMemoryStore()}
	service, err := NewService(Config{
		Store: store,
		Now:   func() time.Time { return now },
		Providers: Providers{Analyze: func(_ context.Context, _ coretask.OwnerScope, _ map[string]any) (map[string]any, error) {
			calls.Add(1)
			return map[string]any{"analysis_id": analysisID, "status": "ready"}, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := replayRecoveryAnalyzeInput()
	if _, err = service.Handle(ctx, ownerScope, "agent.execution.v2.projects.analyze", input); err == nil || err.Error() != "injected provider response persistence failure" {
		t.Fatalf("first call err=%v", err)
	}

	now = now.Add(6 * time.Minute)
	if _, err = service.Handle(ctx, ownerScope, "agent.execution.v2.projects.analyze", input); !errors.Is(err, ErrReplayInProgress) {
		t.Fatalf("uncertain retry err=%v, want ErrReplayInProgress", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("provider calls=%d, want 1", got)
	}
}

func TestServiceRecoversEventJournalBeforeCompletingReplay(t *testing.T) {
	ctx := context.Background()
	base := NewMemoryStore()
	store := &failAppendEventStore{Store: base}
	now := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	service, err := NewService(Config{
		Store: store,
		Now:   func() time.Time { return now },
		Providers: Providers{Analyze: func(_ context.Context, _ coretask.OwnerScope, _ map[string]any) (map[string]any, error) {
			calls.Add(1)
			return map[string]any{"analysis_id": analysisID, "status": "ready"}, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := replayRecoveryAnalyzeInput()
	if _, err = service.Handle(ctx, ownerScope, "agent.execution.v2.projects.analyze", input); err == nil || err.Error() != "injected event persistence failure" {
		t.Fatalf("first call err=%v", err)
	}

	now = now.Add(6 * time.Minute)
	result, err := service.Handle(ctx, ownerScope, "agent.execution.v2.projects.analyze", input)
	if err != nil || result["analysis"] == nil {
		t.Fatalf("event recovery result=%+v err=%v", result, err)
	}
	recordID := deterministicID(ownerScope, "agent.execution.v2.projects.analyze", targetID)
	events, _, err := base.Events(ctx, ownerScope, "analysis", recordID, 0, 10)
	if err != nil || len(events) != 1 || events[0].Type != "analysis_created" {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("provider calls=%d, want 1", got)
	}
}

func TestServiceSecretRevokeRecoveryRequiresOriginalReplayIdentity(t *testing.T) {
	ctx := context.Background()
	base := NewMemoryStore()
	now := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	service, err := NewService(Config{Store: base, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Handle(ctx, ownerScope, "agent.execution.v2.secrets.create", map[string]any{
		"provider": "openrouter", "purpose": "ai_provider_api_key", "value": "sk-replay-recovery",
		"idempotency_key": "55555555-5555-4555-8555-555555555555",
	})
	if err != nil {
		t.Fatal(err)
	}
	ref := created["secret"].(map[string]any)["secret_ref"].(string)
	revoke := map[string]any{"secret_ref": ref, "expected_revision": 1.0, "idempotency_key": "66666666-6666-4666-8666-666666666666"}
	failing, err := NewService(Config{Store: &failCompleteReplayStore{Store: base}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = failing.Handle(ctx, ownerScope, "agent.execution.v2.secrets.revoke", revoke); err == nil || err.Error() != "injected replay completion failure" {
		t.Fatalf("first revoke err=%v", err)
	}

	now = now.Add(6 * time.Minute)
	recovered, err := failing.Handle(ctx, ownerScope, "agent.execution.v2.secrets.revoke", revoke)
	if err != nil || recovered["secret"].(map[string]any)["revision"] != uint64(2) {
		t.Fatalf("recovered revoke=%+v err=%v", recovered, err)
	}
	stale := map[string]any{"secret_ref": ref, "expected_revision": 1.0, "idempotency_key": "77777777-7777-4777-8777-777777777777"}
	if _, err = service.Handle(ctx, ownerScope, "agent.execution.v2.secrets.revoke", stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("different replay identity stale revoke err=%v", err)
	}
}

func TestServiceRunCreateRecoveryRejectsChangedRequestAfterReceiptFailure(t *testing.T) {
	ctx := context.Background()
	base := NewMemoryStore()
	now := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	service, err := NewService(Config{Store: base, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := service.Handle(ctx, ownerScope, "agent.execution.v2.plans.create", map[string]any{
		"project_id": projectID, "analysis_id": analysisID, "target_id": targetID, "target_revision": 1.0,
		"intent": "deploy", "recipe_id": "generic-container-service", "purpose": "service",
		"idempotency_key": "88888888-8888-4888-8888-888888888881",
	})
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{
		"plan_id": plan["plan"].(map[string]any)["plan_id"], "plan_revision": 1.0,
		"operation": "deploy", "trigger_kind": "manual",
		"idempotency_key": "88888888-8888-4888-8888-888888888882",
	}
	failing, err := NewService(Config{Store: &failCompleteReplayStore{Store: base}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = failing.Handle(ctx, ownerScope, "agent.execution.v2.runs.create", input); err == nil || err.Error() != "injected replay completion failure" {
		t.Fatalf("first run create err=%v", err)
	}
	changed := cloneMap(input)
	changed["trigger_kind"] = "schedule"
	if _, err = service.Handle(ctx, ownerScope, "agent.execution.v2.runs.create", changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed request recovered prior partial graph err=%v, want ErrConflict", err)
	}
}

func TestServiceConfirmationRecoversAfterPartialGraphUpdate(t *testing.T) {
	ctx := context.Background()
	base := NewMemoryStore()
	now := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	service, err := NewService(Config{Store: base, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := service.Handle(ctx, ownerScope, "agent.execution.v2.plans.create", map[string]any{
		"project_id": projectID, "analysis_id": analysisID, "target_id": targetID, "target_revision": 1.0,
		"intent": "deploy", "recipe_id": "generic-container-service", "purpose": "service",
		"idempotency_key": "99999999-9999-4999-8999-999999999991",
	})
	if err != nil {
		t.Fatal(err)
	}
	run, err := service.Handle(ctx, ownerScope, "agent.execution.v2.runs.create", map[string]any{
		"plan_id": plan["plan"].(map[string]any)["plan_id"], "plan_revision": 1.0, "operation": "deploy",
		"idempotency_key": "99999999-9999-4999-8999-999999999992",
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &failNthUpdateStore{Store: base}
	store.failAt.Store(3)
	failing, err := NewService(Config{Store: store, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	confirm := map[string]any{
		"confirmation_id": run["run"].(map[string]any)["confirmation_id"], "expected_revision": 1.0,
		"idempotency_key": "99999999-9999-4999-8999-999999999993",
	}
	if _, err = failing.Handle(ctx, ownerScope, "agent.execution.v2.confirmations.confirm", confirm); err == nil || err.Error() != "injected graph update failure" {
		t.Fatalf("first confirmation err=%v", err)
	}
	result, err := failing.Handle(ctx, ownerScope, "agent.execution.v2.confirmations.confirm", confirm)
	if err != nil {
		t.Fatalf("recover partial confirmation graph: %v", err)
	}
	if result["confirmation"].(map[string]any)["state"] != "confirmed" {
		t.Fatalf("recovered confirmation=%+v", result)
	}
}

func TestServiceRunCreateRecoversMissingConfirmationEvent(t *testing.T) {
	ctx := context.Background()
	base := NewMemoryStore()
	now := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	service, err := NewService(Config{Store: base, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := service.Handle(ctx, ownerScope, "agent.execution.v2.plans.create", map[string]any{
		"project_id": projectID, "analysis_id": analysisID, "target_id": targetID, "target_revision": 1.0,
		"intent": "deploy", "recipe_id": "generic-container-service", "purpose": "service",
		"idempotency_key": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &failAppendEventStore{Store: base}
	failing, err := NewService(Config{Store: store, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{
		"plan_id": plan["plan"].(map[string]any)["plan_id"], "plan_revision": 1.0, "operation": "deploy",
		"idempotency_key": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2",
	}
	if _, err = failing.Handle(ctx, ownerScope, "agent.execution.v2.runs.create", input); err == nil || err.Error() != "injected event persistence failure" {
		t.Fatalf("first run create err=%v", err)
	}
	result, err := failing.Handle(ctx, ownerScope, "agent.execution.v2.runs.create", input)
	if err != nil {
		t.Fatalf("recover run create events: %v", err)
	}
	run := result["run"].(map[string]any)
	confirmationID := stringParam(run, "confirmation_id")
	runID := stringParam(run, "run_id")
	confirmationEvents, _, err := base.Events(ctx, ownerScope, "confirmation", confirmationID, 0, 10)
	if err != nil || len(confirmationEvents) != 1 || confirmationEvents[0].Type != "confirmation_created" {
		t.Fatalf("confirmation events=%+v err=%v", confirmationEvents, err)
	}
	runEvents, _, err := base.Events(ctx, ownerScope, "run", runID, 0, 10)
	if err != nil || len(runEvents) != 1 || runEvents[0].Type != "run_created" {
		t.Fatalf("run events=%+v err=%v", runEvents, err)
	}
}

func replayRecoveryAnalyzeInput() map[string]any {
	return map[string]any{
		"project_id": projectID,
		"source": map[string]any{
			"kind":      "git_https",
			"location":  "https://github.com/example/project",
			"commit":    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"immutable": true,
		},
		"idempotency_key": targetID,
	}
}
