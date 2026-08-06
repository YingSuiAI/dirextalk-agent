package postgres

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

type failExecutionReplayCompletionStore struct {
	coreexecutionv2.Store
	failures atomic.Int32
}

func (s *failExecutionReplayCompletionStore) CompleteReplay(ctx context.Context, scope coretask.OwnerScope, action, id string, digest []byte, token string, response []byte, completedAt time.Time) error {
	if s.failures.Add(1) == 1 {
		return errors.New("injected PostgreSQL replay completion failure")
	}
	return s.Store.CompleteReplay(ctx, scope, action, id, digest, token, response, completedAt)
}

type failExecutionProviderResponseStore struct {
	coreexecutionv2.Store
	failures atomic.Int32
}

func (s *failExecutionProviderResponseStore) StoreReplayProviderResponse(ctx context.Context, scope coretask.OwnerScope, action, id string, digest []byte, token string, response []byte, updatedAt time.Time) error {
	if s.failures.Add(1) == 1 {
		return errors.New("injected PostgreSQL provider response failure")
	}
	return s.Store.StoreReplayProviderResponse(ctx, scope, action, id, digest, token, response, updatedAt)
}

func TestCoreExecutionV2PostgresRecoversReceiptFailureAcrossRestart(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_execution_v2_replay_recover_")
	if err := ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatal(err)
	}
	base, err := coreexecutionv2.NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	scope := coretask.OwnerScope{OwnerID: "@execution-replay-owner:example.test", AccountGeneration: 7}
	now := time.Date(2035, 3, 4, 5, 6, 7, 0, time.UTC)
	var calls atomic.Int32
	provider := func(_ context.Context, _ coretask.OwnerScope, _ map[string]any) (map[string]any, error) {
		calls.Add(1)
		return map[string]any{"analysis_id": "22222222-2222-4222-8222-222222222222", "status": "ready"}, nil
	}
	first, err := coreexecutionv2.NewService(coreexecutionv2.Config{Store: &failExecutionReplayCompletionStore{Store: base}, Now: func() time.Time { return now }, Providers: coreexecutionv2.Providers{Analyze: provider}})
	if err != nil {
		t.Fatal(err)
	}
	input := postgresExecutionAnalyzeInput()
	if _, err = first.Handle(ctx, scope, "agent.execution.v2.projects.analyze", input); err == nil || err.Error() != "injected PostgreSQL replay completion failure" {
		t.Fatalf("first call err=%v", err)
	}

	now = now.Add(6 * time.Minute)
	restarted, err := coreexecutionv2.NewService(coreexecutionv2.Config{Store: base, Now: func() time.Time { return now }, Providers: coreexecutionv2.Providers{Analyze: provider}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Handle(ctx, scope, "agent.execution.v2.projects.analyze", input); err != nil {
		t.Fatalf("restart recovery: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("provider calls=%d, want 1", got)
	}
	var state string
	var hasProviderResponse bool
	if err = pool.QueryRow(ctx, `SELECT state,provider_response_json IS NOT NULL FROM core_execution_v2_replays WHERE owner_id=$1 AND account_generation=$2 AND action='agent.execution.v2.projects.analyze' AND idempotency_key=$3`, scope.OwnerID, scope.AccountGeneration, input["idempotency_key"]).Scan(&state, &hasProviderResponse); err != nil {
		t.Fatal(err)
	}
	if state != "completed" || !hasProviderResponse {
		t.Fatalf("replay state=%q provider_response=%t", state, hasProviderResponse)
	}
}

func TestCoreExecutionV2PostgresDoesNotRedispatchUnknownProviderOutcomeAcrossRestart(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_execution_v2_replay_uncertain_")
	if err := ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatal(err)
	}
	base, err := coreexecutionv2.NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	scope := coretask.OwnerScope{OwnerID: "@execution-replay-owner:example.test", AccountGeneration: 8}
	now := time.Date(2035, 3, 4, 5, 6, 7, 0, time.UTC)
	var calls atomic.Int32
	provider := func(_ context.Context, _ coretask.OwnerScope, _ map[string]any) (map[string]any, error) {
		calls.Add(1)
		return map[string]any{"analysis_id": "22222222-2222-4222-8222-222222222222", "status": "ready"}, nil
	}
	first, err := coreexecutionv2.NewService(coreexecutionv2.Config{Store: &failExecutionProviderResponseStore{Store: base}, Now: func() time.Time { return now }, Providers: coreexecutionv2.Providers{Analyze: provider}})
	if err != nil {
		t.Fatal(err)
	}
	input := postgresExecutionAnalyzeInput()
	if _, err = first.Handle(ctx, scope, "agent.execution.v2.projects.analyze", input); err == nil || err.Error() != "injected PostgreSQL provider response failure" {
		t.Fatalf("first call err=%v", err)
	}

	now = now.Add(6 * time.Minute)
	restarted, err := coreexecutionv2.NewService(coreexecutionv2.Config{Store: base, Now: func() time.Time { return now }, Providers: coreexecutionv2.Providers{Analyze: provider}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Handle(ctx, scope, "agent.execution.v2.projects.analyze", input); !errors.Is(err, coreexecutionv2.ErrReplayInProgress) {
		t.Fatalf("uncertain restart err=%v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("provider calls=%d, want 1", got)
	}
	var state string
	var hasProviderResponse bool
	if err = pool.QueryRow(ctx, `SELECT state,provider_response_json IS NOT NULL FROM core_execution_v2_replays WHERE owner_id=$1 AND account_generation=$2 AND action='agent.execution.v2.projects.analyze' AND idempotency_key=$3`, scope.OwnerID, scope.AccountGeneration, input["idempotency_key"]).Scan(&state, &hasProviderResponse); err != nil {
		t.Fatal(err)
	}
	if state != "dispatched" || hasProviderResponse {
		t.Fatalf("replay state=%q provider_response=%t", state, hasProviderResponse)
	}
}

func TestCoreExecutionV2PostgresSecretRecoveryRejectsDifferentReplayIdentity(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_execution_v2_secret_replay_")
	if err := ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatal(err)
	}
	base, err := coreexecutionv2.NewPostgresStore(pool, testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	scope := coretask.OwnerScope{OwnerID: "@execution-secret-replay:example.test", AccountGeneration: 9}
	now := time.Date(2035, 3, 4, 5, 6, 7, 0, time.UTC)
	service, err := coreexecutionv2.NewService(coreexecutionv2.Config{Store: base, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Handle(ctx, scope, "agent.execution.v2.secrets.create", map[string]any{
		"provider": "openrouter", "purpose": "ai_provider_api_key", "value": "sk-postgres-recovery",
		"idempotency_key": "55555555-5555-4555-8555-555555555555",
	})
	if err != nil {
		t.Fatal(err)
	}
	ref := created["secret"].(map[string]any)["secret_ref"].(string)
	revoke := map[string]any{"secret_ref": ref, "expected_revision": 1.0, "idempotency_key": "66666666-6666-4666-8666-666666666666"}
	failing, err := coreexecutionv2.NewService(coreexecutionv2.Config{Store: &failExecutionReplayCompletionStore{Store: base}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = failing.Handle(ctx, scope, "agent.execution.v2.secrets.revoke", revoke); err == nil || err.Error() != "injected PostgreSQL replay completion failure" {
		t.Fatalf("first revoke err=%v", err)
	}

	now = now.Add(6 * time.Minute)
	restarted, err := coreexecutionv2.NewService(coreexecutionv2.Config{Store: base, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Handle(ctx, scope, "agent.execution.v2.secrets.revoke", revoke); err != nil {
		t.Fatalf("same replay recovery: %v", err)
	}
	stale := map[string]any{"secret_ref": ref, "expected_revision": 1.0, "idempotency_key": "77777777-7777-4777-8777-777777777777"}
	if _, err = restarted.Handle(ctx, scope, "agent.execution.v2.secrets.revoke", stale); !errors.Is(err, coreexecutionv2.ErrConflict) {
		t.Fatalf("different replay identity err=%v", err)
	}
}

func postgresExecutionAnalyzeInput() map[string]any {
	return map[string]any{
		"project_id": "11111111-1111-4111-8111-111111111111",
		"source": map[string]any{
			"kind": "git_https", "location": "https://github.com/example/project",
			"commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "immutable": true,
		},
		"idempotency_key": "33333333-3333-4333-8333-333333333333",
	}
}
