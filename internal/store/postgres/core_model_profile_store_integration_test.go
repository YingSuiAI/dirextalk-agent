package postgres

import (
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCoreModelProfileStoreIntegration(t *testing.T) {
	dsn := os.Getenv("AGENT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AGENT_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminConfig, err := pgxpool.ParseConfig(strings.TrimSpace(dsn))
	if err != nil {
		t.Fatalf("parse AGENT_TEST_POSTGRES_DSN: %v", err)
	}
	adminConfig.MaxConns = 2
	adminPool, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("open PostgreSQL administration pool: %v", err)
	}
	schema := "dtx_agent_profile_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		adminPool.Close()
		t.Fatalf("create isolated PostgreSQL schema: %v", err)
	}
	config, err := pgxpool.ParseConfig(strings.TrimSpace(dsn))
	if err != nil {
		_ = dropProfileIntegrationSchema(adminPool, quotedSchema)
		adminPool.Close()
		t.Fatalf("parse AGENT_TEST_POSTGRES_DSN: %v", err)
	}
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.ConnConfig.RuntimeParams["application_name"] = "dirextalk-agent-profile-test"
	config.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_ = dropProfileIntegrationSchema(adminPool, quotedSchema)
		adminPool.Close()
		t.Fatalf("open isolated PostgreSQL pool: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if err := dropProfileIntegrationSchemaWithContext(cleanupCtx, adminPool, quotedSchema); err != nil {
			t.Errorf("drop isolated PostgreSQL schema: %v", err)
		}
		adminPool.Close()
	})
	instanceID := uuid.NewString()
	if err := ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatal(err)
	}
	store, err := New(pool, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	key := "integration-secret"
	profile := coremodel.Profile{ID: uuid.NewString(), DisplayName: "integration", Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://example.com", Model: "test", APIKey: key, ContextWindow: 32768, ReasoningEffort: "medium", Revision: 1, CreatedAt: nowUTC(), UpdatedAt: nowUTC()}
	createKey := uuid.NewString()
	createDigest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	snap, err := store.CreateProfile(ctx, profile, createKey, createDigest)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Profile.APIKeyConfigured != true {
		t.Fatal("profile not configured")
	}
	if snap.Profile.ContextWindow != profile.ContextWindow || snap.Profile.ReasoningEffort != profile.ReasoningEffort {
		t.Fatalf("snapshot parameters = (%d,%q), want (%d,%q)", snap.Profile.ContextWindow, snap.Profile.ReasoningEffort, profile.ContextWindow, profile.ReasoningEffort)
	}
	loaded, err := store.ResolveProfile(ctx, profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.APIKey != key {
		t.Fatal("secret did not persist")
	}
	if loaded.ContextWindow != profile.ContextWindow || loaded.ReasoningEffort != profile.ReasoningEffort {
		t.Fatalf("stored parameters = (%d,%q), want (%d,%q)", loaded.ContextWindow, loaded.ReasoningEffort, profile.ContextWindow, profile.ReasoningEffort)
	}
	replay, err := store.CreateProfile(ctx, profile, createKey, createDigest)
	if err != nil || !replay.Replay {
		t.Fatalf("create replay = %#v, err=%v", replay, err)
	}
	concurrentProfile := profile
	concurrentProfile.ID = uuid.NewString()
	concurrentProfile.DisplayName = "concurrent"
	concurrentKey := uuid.NewString()
	concurrentDigest := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	results := make(chan coremodel.MutationSnapshot, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snapshot, callErr := store.CreateProfile(ctx, concurrentProfile, concurrentKey, concurrentDigest)
			results <- snapshot
			errs <- callErr
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	var replayCount int
	for snapshot := range results {
		if snapshot.Replay {
			replayCount++
		}
	}
	for callErr := range errs {
		if callErr != nil {
			t.Fatalf("concurrent create error: %v", callErr)
		}
	}
	if replayCount != 1 {
		t.Fatalf("concurrent create replay count=%d, want 1", replayCount)
	}
	concurrentProfile.DisplayName = "concurrent-updated"
	concurrentProfile.Revision = 2
	concurrentProfile.UpdatedAt = nowUTC()
	updateKey := uuid.NewString()
	updateDigest := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	updateResults := make(chan coremodel.MutationSnapshot, 2)
	updateErrs := make(chan error, 2)
	wg = sync.WaitGroup{}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snapshot, callErr := store.UpdateProfile(ctx, concurrentProfile, updateKey, updateDigest, 1)
			updateResults <- snapshot
			updateErrs <- callErr
		}()
	}
	wg.Wait()
	close(updateResults)
	close(updateErrs)
	replayCount = 0
	for snapshot := range updateResults {
		if snapshot.Replay {
			replayCount++
		}
	}
	for callErr := range updateErrs {
		if callErr != nil {
			t.Fatalf("concurrent update error: %v", callErr)
		}
	}
	if replayCount != 1 {
		t.Fatalf("concurrent update replay count=%d, want 1", replayCount)
	}
	deleteKey := uuid.NewString()
	deleteDigest := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	deleteResults := make(chan coremodel.MutationSnapshot, 2)
	deleteErrs := make(chan error, 2)
	wg = sync.WaitGroup{}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snapshot, callErr := store.DeleteProfile(ctx, concurrentProfile.ID, deleteKey, deleteDigest, 2)
			deleteResults <- snapshot
			deleteErrs <- callErr
		}()
	}
	wg.Wait()
	close(deleteResults)
	close(deleteErrs)
	replayCount = 0
	for snapshot := range deleteResults {
		if snapshot.Replay {
			replayCount++
		}
	}
	for callErr := range deleteErrs {
		if callErr != nil {
			t.Fatalf("concurrent delete error: %v", callErr)
		}
	}
	if replayCount != 1 {
		t.Fatalf("concurrent delete replay count=%d, want 1", replayCount)
	}
	var connectionCalls int32
	connectionKey := uuid.NewString()
	connectionDigest := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	connectionResults := make(chan coremodel.ConnectionTestResult, 2)
	connectionErrs := make(chan error, 2)
	wg = sync.WaitGroup{}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, _, callErr := store.RunConnectionTest(ctx, connectionKey, connectionDigest, profile.ID, func(coremodel.Profile) coremodel.ConnectionTestResult {
				atomic.AddInt32(&connectionCalls, 1)
				return coremodel.ConnectionTestResult{OK: true}
			})
			connectionResults <- result
			connectionErrs <- callErr
		}()
	}
	wg.Wait()
	close(connectionResults)
	close(connectionErrs)
	for callErr := range connectionErrs {
		if callErr != nil {
			t.Fatalf("concurrent connection test error: %v", callErr)
		}
	}
	for result := range connectionResults {
		if !result.OK {
			t.Fatalf("connection result=%#v", result)
		}
	}
	if got := atomic.LoadInt32(&connectionCalls); got != 1 {
		t.Fatalf("connection callback calls=%d, want 1", got)
	}
	profile.DisplayName = "integration-updated"
	profile.ContextWindow = 65536
	profile.ReasoningEffort = "high"
	profile.Revision = 2
	profile.UpdatedAt = nowUTC()
	updated, err := store.UpdateProfile(ctx, profile, uuid.NewString(), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1)
	if err != nil || updated.Profile.ContextWindow != 65536 || updated.Profile.ReasoningEffort != "high" {
		t.Fatalf("update parameters = %#v, err=%v", updated, err)
	}
}

func nowUTC() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

func dropProfileIntegrationSchema(pool *pgxpool.Pool, quotedSchema string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return dropProfileIntegrationSchemaWithContext(ctx, pool, quotedSchema)
}

func dropProfileIntegrationSchemaWithContext(ctx context.Context, pool *pgxpool.Pool, quotedSchema string) error {
	_, err := pool.Exec(ctx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	return err
}
