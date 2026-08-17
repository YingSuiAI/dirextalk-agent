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

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
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
	profile := coremodel.Profile{ID: uuid.NewString(), ClientProfileID: uuid.NewString(), DisplayName: "integration", Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindConversation, ProviderSecrets: map[string]string{"organization": "historical-secret"}, BaseURL: "https://example.com", Model: "test", APIKey: key, ContextWindow: 32768, ReasoningEffort: "medium", Revision: 1, CreatedAt: nowUTC(), UpdatedAt: nowUTC()}
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
	concurrentProfile.ClientProfileID = uuid.NewString()
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
	conversationID := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO core_conversations(conversation_id,title) VALUES($1,'historical')`, conversationID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_model_profile_active_refs(owner_kind,owner_id,profile_id) VALUES('conversation',$1,$2)`, conversationID, profile.ID); err != nil {
		t.Fatal(err)
	}
	updated, err := store.UpdateProfile(ctx, profile, uuid.NewString(), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1)
	if err != nil || updated.Profile.ContextWindow != 65536 || updated.Profile.ReasoningEffort != "high" {
		t.Fatalf("update parameters = %#v, err=%v", updated, err)
	}
	lifecycleDeleteKey := uuid.NewString()
	lifecycleDeleteDigest := strings.Repeat("d", 64)
	deleted, err := store.DeleteProfile(ctx, profile.ID, lifecycleDeleteKey, lifecycleDeleteDigest, 2)
	if err != nil || !deleted.Deleted {
		t.Fatalf("delete with historical conversation ref=%#v err=%v", deleted, err)
	}
	replayedDelete, err := store.DeleteProfile(ctx, profile.ID, lifecycleDeleteKey, lifecycleDeleteDigest, 2)
	if err != nil || !replayedDelete.Replay || !replayedDelete.Deleted {
		t.Fatalf("delete replay=%#v err=%v", replayedDelete, err)
	}
	if _, err = store.GetProfile(ctx, profile.ID); !errors.Is(err, coremodel.ErrProfileNotFound) {
		t.Fatalf("deleted profile readback err=%v", err)
	}
	var clientID *string
	var apiConfigured bool
	var apiNonce, apiCipher, providerNonce, providerCipher []byte
	var deletedAt *time.Time
	if err = pool.QueryRow(ctx, `SELECT client_profile_id,api_key_configured,api_key_nonce,api_key_ciphertext,provider_secrets_nonce,provider_secrets_ciphertext,deleted_at FROM core_model_profiles WHERE profile_id=$1`, profile.ID).Scan(&clientID, &apiConfigured, &apiNonce, &apiCipher, &providerNonce, &providerCipher, &deletedAt); err != nil {
		t.Fatal(err)
	}
	if clientID != nil || apiConfigured || apiNonce != nil || apiCipher != nil || providerNonce != nil || providerCipher != nil || deletedAt == nil {
		t.Fatalf("profile was not credential-free tombstone: client=%v configured=%v deleted=%v", clientID, apiConfigured, deletedAt)
	}
	executionSnapshot := coretask.ModelProfileSnapshot{
		ProfileID: profile.ID, Revision: 1, SecretRef: fmt.Sprintf("model-profile:%s:1", profile.ID),
		Provider: string(profile.Provider), BaseURL: profile.BaseURL, Model: profile.Model,
		ContextWindow: profile.ContextWindow, ReasoningEffort: profile.ReasoningEffort,
	}
	executionSnapshot.Digest = coreTaskModelSnapshotDigest(executionSnapshot)
	resolvedHistoricalProfile, resolveErr := store.ResolveExecutionProfile(ctx, executionSnapshot)
	if resolveErr != nil || resolvedHistoricalProfile.APIKey != key {
		t.Fatalf("historical revision secret was not preserved: profile=%#v err=%v", resolvedHistoricalProfile.Public(), resolveErr)
	}
	var conversationRefs int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM core_model_profile_active_refs WHERE profile_id=$1 AND owner_kind='conversation'`, profile.ID).Scan(&conversationRefs); err != nil || conversationRefs != 1 {
		t.Fatalf("conversation refs=%d err=%v", conversationRefs, err)
	}

	staleTaskProfile := coremodel.Profile{ID: uuid.NewString(), DisplayName: "stale-task", Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindConversation, BaseURL: "https://example.com", Model: "test", APIKey: key, Revision: 1, CreatedAt: nowUTC(), UpdatedAt: nowUTC()}
	if _, err = store.CreateProfile(ctx, staleTaskProfile, uuid.NewString(), strings.Repeat("e", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_model_profile_active_refs(owner_kind,owner_id,profile_id) VALUES('task',$1,$2)`, uuid.NewString(), staleTaskProfile.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.DeleteProfile(ctx, staleTaskProfile.ID, uuid.NewString(), strings.Repeat("f", 64), 1); err != nil {
		t.Fatalf("stale terminal task ref blocked delete: %v", err)
	}

	liveScheduleProfile := coremodel.Profile{ID: uuid.NewString(), DisplayName: "live-schedule", Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindConversation, BaseURL: "https://example.com", Model: "test", APIKey: key, Revision: 1, CreatedAt: nowUTC(), UpdatedAt: nowUTC()}
	if _, err = store.CreateProfile(ctx, liveScheduleProfile, uuid.NewString(), strings.Repeat("1", 64)); err != nil {
		t.Fatal(err)
	}
	now := nowUTC()
	runAt := now.Add(time.Hour)
	schedule := coretask.Schedule{ID: uuid.NewString(), Name: "live profile consumer", Spec: coretask.TaskTemplate{Goal: "future task", ModelProfileID: liveScheduleProfile.ID}, RunAt: &runAt, Timezone: "UTC", Revision: 1, CreatedAt: now, UpdatedAt: now}
	scheduleDigest, _ := coretask.CanonicalMutationDigest(schedule)
	if _, err = NewCoreScheduleStore(store).CreateSchedule(ctx, coretask.CreateScheduleCommand{Schedule: schedule, Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: scheduleDigest}}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.DeleteProfile(ctx, liveScheduleProfile.ID, uuid.NewString(), strings.Repeat("2", 64), 1); !errors.Is(err, coremodel.ErrProfileInUse) {
		t.Fatalf("live schedule delete err=%v", err)
	}
}

func TestKnowledgeIndexAdmissionFencesProfileDeletionUntilCancelPostgres(t *testing.T) {
	ctx, store, _, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()
	profileID := uuid.NewString()
	createTestEmbeddingProfile(ctx, t, store, profileID, "embedding", "secret")
	sourceID := uuid.NewString()
	if _, err := store.pool.Exec(ctx, `INSERT INTO core_knowledge_sources(source_id,kind,status,title,digest,size_bytes,media_type,revision) VALUES($1,'mount','ready','admission source',$2,1,'text/plain',1)`, sourceID, strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	indexer, err := NewKnowledgeIndexer(store, profileID, strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := indexer.RequestIndex(ctx, coreknowledge.IndexRequest{IdempotencyKey: uuid.NewString(), SourceIDs: []string{sourceID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.DeleteProfile(ctx, profileID, uuid.NewString(), strings.Repeat("e", 64), 1); !errors.Is(err, coremodel.ErrProfileInUse) {
		t.Fatalf("queued generation delete err=%v", err)
	}
	tasks := NewCoreTaskStore(store)
	claimed, _, err := tasks.ClaimNextDue(ctx, "knowledge-ref-test", time.Now().UTC().Add(time.Second), time.Minute, 1)
	if err != nil || claimed.ID != ref.TaskID {
		t.Fatalf("claimed=%+v ref=%+v err=%v", claimed, ref, err)
	}
	if _, err = store.DeleteProfile(ctx, profileID, uuid.NewString(), strings.Repeat("f", 64), 1); !errors.Is(err, coremodel.ErrProfileInUse) {
		t.Fatalf("running generation delete err=%v", err)
	}
	if _, err = tasks.CancelTask(ctx, coretask.CancelCommand{TaskID: claimed.ID, Reason: "test terminal", Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("1", 64), ExpectedRevision: claimed.Revision}, At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	var admissionRefs int
	if err = store.pool.QueryRow(ctx, `SELECT count(*) FROM core_model_profile_active_refs ref JOIN core_knowledge_index_jobs job ON job.job_id=ref.owner_id WHERE ref.owner_kind='knowledge_generation' AND ref.profile_id=$1`, profileID).Scan(&admissionRefs); err != nil || admissionRefs != 0 {
		t.Fatalf("terminal admission refs=%d err=%v", admissionRefs, err)
	}
	if _, err = store.DeleteProfile(ctx, profileID, uuid.NewString(), strings.Repeat("2", 64), 1); err != nil {
		t.Fatalf("terminal generation blocked delete: %v", err)
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
		DefaultConversationProfileID: "one",
		DefaultToolProfileID:         "two",
		Entries:                      []coremodel.SyncProfileEntry{syncStoreEntry("one", "One", "one-secret"), syncStoreEntry("two", "Two", "two-secret")},
	})
	if err != nil || len(created.Profiles) != 2 || created.Profiles[0].ClientProfileID != "one" || created.Profiles[1].ClientProfileID != "two" {
		t.Fatalf("create sync=%+v err=%v", created, err)
	}
	if strings.Contains(fmt.Sprint(created), "one-secret") || strings.Contains(fmt.Sprint(created), "two-secret") {
		t.Fatal("sync response leaked API key")
	}
	defaults, err := store.GetProfileDefaults(ctx)
	if err != nil || defaults.ToolClientProfileID != "two" {
		t.Fatalf("durable tool default=%+v err=%v", defaults, err)
	}
	beforeNoOp, err := store.GetProfile(ctx, created.Profiles[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := store.SyncProfiles(ctx, uuid.NewString(), strings.Repeat("a1", 32), coremodel.SyncProfileCommand{
		DefaultConversationProfileID: "one",
		DefaultToolProfileID:         "two",
		Entries: []coremodel.SyncProfileEntry{{
			ClientProfileID: "one", ExpectedRevision: int64PtrStore(1), DisplayName: "One",
			Provider: coremodel.ProviderOpenAICompatible, Model: "model",
		}},
	})
	if err != nil || len(unchanged.Profiles) != 1 || unchanged.Profiles[0].Revision != 1 || unchanged.Profiles[0].CredentialVersion != 1 || !unchanged.Profiles[0].UpdatedAt.Equal(beforeNoOp.UpdatedAt) {
		t.Fatalf("PostgreSQL no-op sync changed profile: before=%+v after=%+v err=%v", beforeNoOp.Public(), unchanged, err)
	}
	_, err = store.SyncProfiles(ctx, uuid.NewString(), strings.Repeat("a2", 32), coremodel.SyncProfileCommand{Entries: []coremodel.SyncProfileEntry{{
		ClientProfileID: "one", ExpectedRevision: int64PtrStore(2), DisplayName: "One",
		Provider: coremodel.ProviderOpenAICompatible, Model: "model",
	}}})
	if !errors.Is(err, coremodel.ErrRevisionConflict) {
		t.Fatalf("PostgreSQL stale no-op sync err=%v", err)
	}
	_, err = store.SyncProfiles(ctx, uuid.NewString(), "abababababababababababababababababababababababababababababababab", coremodel.SyncProfileCommand{DefaultToolProfileID: "embed", Entries: []coremodel.SyncProfileEntry{{ClientProfileID: "embed", DisplayName: "Embed", Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindEmbedding, Model: "embed", APIKey: stringPtrStore("embed-secret")}}})
	if !errors.Is(err, coremodel.ErrInvalidProfile) {
		t.Fatalf("PostgreSQL accepted embedding tool default: %v", err)
	}
	updated, err := store.SyncProfiles(ctx, uuid.NewString(), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", coremodel.SyncProfileCommand{DefaultConversationProfileID: "two", Entries: []coremodel.SyncProfileEntry{{ClientProfileID: "two", ExpectedRevision: int64PtrStore(1), DisplayName: "Two rotated", Provider: coremodel.ProviderOpenAICompatible, Model: "model", APIKey: stringPtrStore("rotated")}}})
	if err != nil || len(updated.Profiles) != 1 || updated.Profiles[0].Revision != 2 {
		t.Fatalf("update sync=%+v err=%v", updated, err)
	}
	resolved, err := store.ResolveProfile(ctx, updated.Profiles[0].ID)
	if err != nil || resolved.APIKey != "rotated" {
		t.Fatalf("rotated key=%q err=%v", resolved.APIKey, err)
	}
	_, err = store.SyncProfiles(ctx, uuid.NewString(), "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", coremodel.SyncProfileCommand{DefaultConversationProfileID: "missing", Entries: []coremodel.SyncProfileEntry{{ClientProfileID: "two", ExpectedRevision: int64PtrStore(2), DisplayName: "should rollback", Provider: coremodel.ProviderOpenAICompatible, Model: "model", APIKey: nil}}})
	if !errors.Is(err, coremodel.ErrProfileNotFound) {
		t.Fatalf("invalid default err=%v", err)
	}
	var defaultID string
	if err = pool.QueryRow(ctx, `SELECT default_conversation_client_profile_id FROM core_model_profile_defaults WHERE singleton=true`).Scan(&defaultID); err != nil || defaultID != "two" {
		t.Fatalf("default changed after failed batch: default=%q err=%v", defaultID, err)
	}
	_, err = store.SyncProfiles(ctx, uuid.NewString(), "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", coremodel.SyncProfileCommand{DefaultConversationProfileID: "one", Entries: []coremodel.SyncProfileEntry{{ClientProfileID: "one", ExpectedRevision: int64PtrStore(1), DisplayName: "should rollback", Provider: coremodel.ProviderOpenAICompatible, Model: "model", APIKey: nil}, {ClientProfileID: "two", ExpectedRevision: int64PtrStore(99), DisplayName: "stale", Provider: coremodel.ProviderOpenAICompatible, Model: "model", APIKey: nil}}})
	if !errors.Is(err, coremodel.ErrRevisionConflict) {
		t.Fatalf("stale sync err=%v", err)
	}
	if err = pool.QueryRow(ctx, `SELECT default_conversation_client_profile_id FROM core_model_profile_defaults WHERE singleton=true`).Scan(&defaultID); err != nil || defaultID != "two" {
		t.Fatalf("default changed after stale batch: default=%q err=%v", defaultID, err)
	}
	one, _ := store.GetProfile(ctx, created.Profiles[0].ID)
	if one.Revision != 1 || one.DisplayName != "One" {
		t.Fatalf("stale batch changed one=%+v", one)
	}
	replayCommand := coremodel.SyncProfileCommand{DefaultConversationProfileID: "two", Entries: []coremodel.SyncProfileEntry{{ClientProfileID: "two", ExpectedRevision: int64PtrStore(2), DisplayName: "Two rotated", Provider: coremodel.ProviderOpenAICompatible, Model: "model", APIKey: nil}}}
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
	left.Entries[0].ExpectedRevision, right.Entries[0].ExpectedRevision = int64PtrStore(2), int64PtrStore(2)
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
