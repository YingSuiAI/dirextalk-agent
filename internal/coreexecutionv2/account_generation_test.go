package coreexecutionv2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
)

func TestMemoryStoreAccountGenerationIsolation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()
	scope1 := coretask.OwnerScope{OwnerID: owner, AccountGeneration: 1}
	scope2 := coretask.OwnerScope{OwnerID: owner, AccountGeneration: 2}
	now := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		scope  coretask.OwnerScope
		status string
	}{
		{scope: scope1, status: "generation-1"},
		{scope: scope2, status: "generation-2"},
	} {
		if _, err := store.Create(ctx, Record{OwnerID: tc.scope.OwnerID, AccountGeneration: tc.scope.AccountGeneration, Kind: "run", ID: projectID, Revision: 1, Status: tc.status, Payload: map[string]any{"generation": tc.scope.AccountGeneration}, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatalf("create generation %d: %v", tc.scope.AccountGeneration, err)
		}
		if _, err := store.AppendEvent(ctx, Event{OwnerID: tc.scope.OwnerID, AccountGeneration: tc.scope.AccountGeneration, Kind: "run", ResourceID: projectID, EventID: analysisID, Type: tc.status, Payload: map[string]any{"generation": tc.scope.AccountGeneration}, CreatedAt: now}); err != nil {
			t.Fatalf("append event generation %d: %v", tc.scope.AccountGeneration, err)
		}
		if _, err := store.SaveSecret(ctx, Secret{OwnerID: tc.scope.OwnerID, AccountGeneration: tc.scope.AccountGeneration, Ref: targetID, Revision: 1, Provider: "test", Purpose: tc.status, Value: tc.status, BindingDigest: tc.status, Status: "active", CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatalf("save secret generation %d: %v", tc.scope.AccountGeneration, err)
		}
	}

	record1, err := store.Read(ctx, scope1, "run", projectID, 0)
	if err != nil || record1.Status != "generation-1" || record1.AccountGeneration != 1 {
		t.Fatalf("generation 1 record=%+v err=%v", record1, err)
	}
	record2, err := store.Read(ctx, scope2, "run", projectID, 0)
	if err != nil || record2.Status != "generation-2" || record2.AccountGeneration != 2 {
		t.Fatalf("generation 2 record=%+v err=%v", record2, err)
	}
	record1.Status = "generation-1-revised"
	if _, err := store.Update(ctx, record1, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(ctx, scope2, "run", projectID, 2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("generation 2 read generation 1 revision: %v", err)
	}
	for _, tc := range []struct {
		scope coretask.OwnerScope
		want  string
	}{
		{scope: scope1, want: "generation-1"},
		{scope: scope2, want: "generation-2"},
	} {
		items, _, err := store.List(ctx, tc.scope, "run", nil, "", 10)
		if err != nil || len(items) != 1 || items[0].AccountGeneration != tc.scope.AccountGeneration {
			t.Fatalf("list generation %d items=%+v err=%v", tc.scope.AccountGeneration, items, err)
		}
		events, _, err := store.Events(ctx, tc.scope, "run", projectID, 0, 10)
		if err != nil || len(events) != 1 || events[0].Type != tc.want || events[0].Sequence != 1 {
			t.Fatalf("events generation %d=%+v err=%v", tc.scope.AccountGeneration, events, err)
		}
		secret, err := store.ReadSecret(ctx, tc.scope, targetID, 0)
		if err != nil || secret.Purpose != tc.want || secret.AccountGeneration != tc.scope.AccountGeneration {
			t.Fatalf("secret generation %d=%+v err=%v", tc.scope.AccountGeneration, secret, err)
		}
	}
}

func TestExecutionSecretAADPreservesLegacyAndScopesNewWrites(t *testing.T) {
	t.Parallel()
	legacy, err := executionSecretAAD(owner, 7, targetID, 3, executionSecretAADLegacy)
	if err != nil {
		t.Fatal(err)
	}
	wantLegacy, err := secretbox.BindAAD("core_execution_v2_secrets", owner+"/"+targetID, 3, "secret_value")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(legacy, wantLegacy) {
		t.Fatal("legacy AAD contract changed")
	}
	gen7, err := executionSecretAAD(owner, 7, targetID, 3, executionSecretAADScoped)
	if err != nil {
		t.Fatal(err)
	}
	gen8, err := executionSecretAAD(owner, 8, targetID, 3, executionSecretAADScoped)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(gen7, legacy) || bytes.Equal(gen7, gen8) {
		t.Fatal("scoped AAD does not bind account generation")
	}
}

func TestMemoryStoreReplayAdmissionIsGenerationScoped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()
	scope1 := coretask.OwnerScope{OwnerID: owner, AccountGeneration: 1}
	scope2 := coretask.OwnerScope{OwnerID: owner, AccountGeneration: 2}
	digest := []byte("request-digest")
	now := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)

	claim1, err := store.BeginReplay(ctx, scope1, "action", projectID, digest, now, time.Minute)
	if err != nil || claim1.Token == "" || claim1.Completed {
		t.Fatalf("first admission=%+v err=%v", claim1, err)
	}
	claim2, err := store.BeginReplay(ctx, scope2, "action", projectID, digest, now, time.Minute)
	if err != nil || claim2.Token == "" || claim2.Token == claim1.Token || claim2.Completed {
		t.Fatalf("other generation admission=%+v err=%v", claim2, err)
	}
	if _, err := store.BeginReplay(ctx, scope1, "action", projectID, digest, now, time.Minute); !errors.Is(err, ErrReplayInProgress) {
		t.Fatalf("duplicate concurrent admission err=%v", err)
	}
	if err := store.CompleteReplay(ctx, scope1, "action", projectID, digest, claim1.Token, []byte(`{"generation":1}`), now); err != nil {
		t.Fatal(err)
	}
	replay, err := store.BeginReplay(ctx, scope1, "action", projectID, digest, now, time.Minute)
	if err != nil || !replay.Completed || string(replay.Response) != `{"generation":1}` {
		t.Fatalf("completed replay=%+v err=%v", replay, err)
	}
}

func TestServiceConcurrentReplayAdmissionCallsProviderOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	scope := coretask.OwnerScope{OwnerID: owner, AccountGeneration: 7}
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	service, err := NewService(Config{Store: NewMemoryStore(), Providers: Providers{Analyze: func(_ context.Context, got coretask.OwnerScope, _ map[string]any) (map[string]any, error) {
		if got != scope {
			t.Fatalf("provider scope=%+v, want %+v", got, scope)
		}
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return map[string]any{"analysis_id": analysisID, "status": "ready"}, nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"project_id": projectID, "source": map[string]any{"kind": "git_https", "location": "https://github.com/example/project", "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "immutable": true}, "idempotency_key": targetID}
	type result struct {
		value map[string]any
		err   error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			value, callErr := service.Handle(ctx, scope, "agent.execution.v2.projects.analyze", input)
			results <- result{value: value, err: callErr}
		}()
	}
	<-started
	time.Sleep(25 * time.Millisecond)
	close(release)
	wg.Wait()
	close(results)
	var encoded string
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		raw, _ := json.Marshal(result.value)
		if encoded != "" && encoded != string(raw) {
			t.Fatalf("concurrent replay changed: %s != %s", encoded, raw)
		}
		encoded = string(raw)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("provider calls=%d, want 1", got)
	}
}
