package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
	store, err := New(pool, instanceID, testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	key := "integration-secret"
	profile := coremodel.Profile{ID: uuid.NewString(), DisplayName: "integration", Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindConversation, BaseURL: "https://example.com", Model: "test", APIKey: key, ContextWindow: 32768, ReasoningEffort: "medium", Revision: 1, CreatedAt: nowUTC(), UpdatedAt: nowUTC()}
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
			var replayRows int
			var storedRevision int64
			_ = pool.QueryRow(ctx, `SELECT count(*) FROM core_mutation_replays WHERE operation=$1 AND idempotency_key=$2`, profileUpdateOp, updateKey).Scan(&replayRows)
			_ = pool.QueryRow(ctx, `SELECT revision FROM core_model_profiles WHERE profile_id=$1`, concurrentProfile.ID).Scan(&storedRevision)
			t.Fatalf("concurrent update error: %v (replays=%d revision=%d)", callErr, replayRows, storedRevision)
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

func TestCoreModelProfileStoreSyncIntegration(t *testing.T) {
	dsn := os.Getenv("AGENT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AGENT_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	adminConfig, err := pgxpool.ParseConfig(strings.TrimSpace(dsn))
	if err != nil {
		t.Fatal(err)
	}
	adminConfig.MaxConns = 2
	adminPool, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	schema := "dtx_agent_profile_sync_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err = adminPool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(strings.TrimSpace(dsn))
	if err != nil {
		_ = dropProfileIntegrationSchema(adminPool, quotedSchema)
		adminPool.Close()
		t.Fatal(err)
	}
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_ = dropProfileIntegrationSchema(adminPool, quotedSchema)
		adminPool.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if err := dropProfileIntegrationSchemaWithContext(cleanupCtx, adminPool, quotedSchema); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		adminPool.Close()
	})
	instanceID := uuid.NewString()
	if err := ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatal(err)
	}
	store, err := New(pool, instanceID, testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.SyncProfiles(ctx, uuid.NewString(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", coremodel.SyncProfileCommand{
		DefaultClientProfileID: "one",
		Entries:                []coremodel.SyncProfileEntry{syncStoreEntry("one", "One", "one-secret"), syncStoreEntry("two", "Two", "two-secret")},
	})
	if err != nil || len(created.Profiles) != 2 || created.Profiles[0].ClientProfileID != "one" || created.Profiles[1].ClientProfileID != "two" {
		t.Fatalf("create sync=%+v err=%v", created, err)
	}
	if strings.Contains(fmt.Sprint(created), "one-secret") || strings.Contains(fmt.Sprint(created), "two-secret") {
		t.Fatal("sync response leaked API key")
	}
	updated, err := store.SyncProfiles(ctx, uuid.NewString(), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", coremodel.SyncProfileCommand{DefaultClientProfileID: "two", Entries: []coremodel.SyncProfileEntry{{ClientProfileID: "two", ExpectedRevision: int64PtrStore(1), DisplayName: "Two rotated", Provider: coremodel.ProviderOpenAICompatible, Model: "model", APIKey: stringPtrStore("rotated")}}})
	if err != nil || len(updated.Profiles) != 1 || updated.Profiles[0].Revision != 2 {
		t.Fatalf("update sync=%+v err=%v", updated, err)
	}
	resolved, err := store.ResolveProfile(ctx, updated.Profiles[0].ID)
	if err != nil || resolved.APIKey != "rotated" {
		t.Fatalf("rotated key=%q err=%v", resolved.APIKey, err)
	}
	_, err = store.SyncProfiles(ctx, uuid.NewString(), "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", coremodel.SyncProfileCommand{DefaultClientProfileID: "missing", Entries: []coremodel.SyncProfileEntry{{ClientProfileID: "two", ExpectedRevision: int64PtrStore(2), DisplayName: "should rollback", Provider: coremodel.ProviderOpenAICompatible, Model: "model", APIKey: nil}}})
	if !errors.Is(err, coremodel.ErrProfileNotFound) {
		t.Fatalf("invalid default err=%v", err)
	}
	var defaultID string
	modelOwnerID := internalEntityOwnerID("model", instanceID)
	if err = pool.QueryRow(ctx, `SELECT default_client_profile_id FROM core_model_profile_defaults WHERE owner_id=$1 AND account_generation=1`, modelOwnerID).Scan(&defaultID); err != nil || defaultID != "two" {
		t.Fatalf("default changed after failed batch: default=%q err=%v", defaultID, err)
	}
	_, err = store.SyncProfiles(ctx, uuid.NewString(), "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", coremodel.SyncProfileCommand{DefaultClientProfileID: "one", Entries: []coremodel.SyncProfileEntry{{ClientProfileID: "one", ExpectedRevision: int64PtrStore(1), DisplayName: "should rollback", Provider: coremodel.ProviderOpenAICompatible, Model: "model", APIKey: nil}, {ClientProfileID: "two", ExpectedRevision: int64PtrStore(99), DisplayName: "stale", Provider: coremodel.ProviderOpenAICompatible, Model: "model", APIKey: nil}}})
	if !errors.Is(err, coremodel.ErrRevisionConflict) {
		t.Fatalf("stale sync err=%v", err)
	}
	if err = pool.QueryRow(ctx, `SELECT default_client_profile_id FROM core_model_profile_defaults WHERE owner_id=$1 AND account_generation=1`, modelOwnerID).Scan(&defaultID); err != nil || defaultID != "two" {
		t.Fatalf("default changed after stale batch: default=%q err=%v", defaultID, err)
	}
	one, _ := store.GetProfile(ctx, created.Profiles[0].ID)
	if one.Revision != 1 || one.DisplayName != "One" {
		t.Fatalf("stale batch changed one=%+v", one)
	}
	replayCommand := coremodel.SyncProfileCommand{DefaultClientProfileID: "two", Entries: []coremodel.SyncProfileEntry{{ClientProfileID: "two", ExpectedRevision: int64PtrStore(2), DisplayName: "Two rotated", Provider: coremodel.ProviderOpenAICompatible, Model: "model", APIKey: nil}}}
	replayKey := uuid.NewString()
	replay, err := store.SyncProfiles(ctx, replayKey, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", replayCommand)
	if err != nil {
		t.Fatal(err)
	}
	replay, err = store.SyncProfiles(ctx, replayKey, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", replayCommand)
	if err != nil || !replay.Replay {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	keyChanged := replayCommand
	keyChanged.Entries = append([]coremodel.SyncProfileEntry(nil), replayCommand.Entries...)
	keyChanged.Entries[0].APIKey = stringPtrStore("changed-secret")
	if _, err = store.SyncProfiles(ctx, replayKey, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", keyChanged); !errors.Is(err, coremodel.ErrIdempotencyConflict) {
		t.Fatalf("API-key-only digest conflict err=%v", err)
	}
	replayCommand.Entries[0].DisplayName = "different"
	if _, err = store.SyncProfiles(ctx, replayKey, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", replayCommand); !errors.Is(err, coremodel.ErrIdempotencyConflict) {
		t.Fatalf("digest conflict err=%v", err)
	}
	var replayJSON []byte
	if err = pool.QueryRow(ctx, `SELECT response_json FROM core_mutation_replays WHERE operation=$1 AND idempotency_key=$2`, profileSyncOp, replayKey).Scan(&replayJSON); err != nil {
		t.Fatalf("read replay response: %v", err)
	}
	// "Two rotated" is an intentionally public display name in this replay;
	// only the exact fixture secrets (and an API-key field) prove a leak.
	if bytes.Contains(replayJSON, []byte("one-secret")) || bytes.Contains(replayJSON, []byte("two-secret")) || bytes.Contains(replayJSON, []byte("changed-secret")) || bytes.Contains(replayJSON, []byte(`"api_key":`)) {
		t.Fatalf("replay response contains secret material: %s", replayJSON)
	}
	left, right := replayCommand, replayCommand
	left.IdempotencyKey, right.IdempotencyKey = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	left.Entries = append([]coremodel.SyncProfileEntry(nil), replayCommand.Entries...)
	right.Entries = append([]coremodel.SyncProfileEntry(nil), replayCommand.Entries...)
	left.Entries[0].ExpectedRevision, right.Entries[0].ExpectedRevision = int64PtrStore(3), int64PtrStore(3)
	left.Entries[0].DisplayName, right.Entries[0].DisplayName = "left", "right"
	results := make(chan error, 2)
	go func() {
		_, e := store.SyncProfiles(ctx, left.IdempotencyKey, "1111111111111111111111111111111111111111111111111111111111111111", left)
		results <- e
	}()
	go func() {
		_, e := store.SyncProfiles(ctx, right.IdempotencyKey, "2222222222222222222222222222222222222222222222222222222222222222", right)
		results <- e
	}()
	var success, conflict int
	for i := 0; i < 2; i++ {
		e := <-results
		if e == nil {
			success++
		} else if errors.Is(e, coremodel.ErrRevisionConflict) {
			conflict++
		} else {
			t.Errorf("overlap error=%v", e)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("overlap success=%d conflict=%d", success, conflict)
	}
	profiles, _, err := store.ListProfiles(ctx, "", 10)
	if err != nil || len(profiles) != 2 {
		t.Fatalf("missing profile lost: len=%d err=%v", len(profiles), err)
	}
}

func syncStoreEntry(id, name, key string) coremodel.SyncProfileEntry {
	return coremodel.SyncProfileEntry{ClientProfileID: id, DisplayName: name, Provider: coremodel.ProviderOpenAICompatible, Model: "model", APIKey: stringPtrStore(key)}
}
func stringPtrStore(v string) *string { return &v }
func int64PtrStore(v int64) *int64    { return &v }

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
