package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/corememory"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCoreMemoryPostgresConflictTimelineOptIn(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set AGENT_TEST_POSTGRES_DSN for PG18 memory integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "dtx_memory_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE")
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	instanceID := uuid.NewString()
	if err = ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatal(err)
	}
	store, err := New(pool, instanceID, testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	profile := coremodel.Profile{ID: uuid.NewString(), DisplayName: "memory", Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindConversation, BaseURL: "https://example.invalid", Model: "test", APIKey: "integration-secret", ContextWindow: 32768, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if _, err = store.CreateProfile(ctx, profile, uuid.NewString(), strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	conversationID := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO core_conversations(conversation_id,revision,created_at,updated_at) VALUES($1,1,$2,$2)`, conversationID, now); err != nil {
		t.Fatal(err)
	}
	memoryStore, err := NewCoreMemoryStore(store)
	if err != nil {
		t.Fatal(err)
	}
	configState, err := memoryStore.GetConfig(ctx)
	if err != nil || configState.Enabled || configState.EmbeddingConfigured || configState.Revision != 0 {
		t.Fatalf("default config=%+v err=%v", configState, err)
	}
	if _, err = memoryStore.UpdateConfig(ctx, corememory.ConfigMutation{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("b", 64), ExpectedRevision: 0, Enabled: true, Now: now}); !errors.Is(err, corememory.ErrEmbeddingNotConfigured) {
		t.Fatalf("enable without embedding error=%v", err)
	}
	embeddingProfile := coremodel.Profile{ID: uuid.NewString(), DisplayName: "embedding", Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindEmbedding, BaseURL: "https://example.invalid", Model: "embed-test", APIKey: "integration-secret", ContextWindow: 32768, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if _, err = store.CreateProfile(ctx, embeddingProfile, uuid.NewString(), strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	knowledgeStore, err := NewCoreKnowledgeStore(store, CoreKnowledgeStoreConfig{Content: coreknowledge.NewMemoryContentPort(1 << 20)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = knowledgeStore.EnsureEmbeddingConfig(ctx, coreknowledge.EmbeddingConfig{EmbeddingProfileID: embeddingProfile.ID, Dimension: 2, Collection: "core_knowledge_vectors", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	configState, err = memoryStore.UpdateConfig(ctx, corememory.ConfigMutation{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("d", 64), ExpectedRevision: 0, Enabled: true, Now: now})
	if err != nil || !configState.Enabled || !configState.EmbeddingConfigured || configState.EmbeddingProfileID != embeddingProfile.ID || configState.Revision != 1 {
		t.Fatalf("enabled config=%+v err=%v", configState, err)
	}
	apply := func(value string, at time.Time, effectiveAt string) {
		observationID := uuid.NewString()
		if _, insertErr := pool.Exec(ctx, `INSERT INTO core_memory_observations(observation_id,conversation_id,profile_id,user_text,assistant_text,observed_at,next_attempt_at) VALUES($1,$2,$3,$4,'ok',$5,$5)`, observationID, conversationID, profile.ID, "I live in "+value, at); insertErr != nil {
			t.Fatal(insertErr)
		}
		lease, ok, claimErr := memoryStore.ClaimObservation(ctx, at, time.Minute)
		if claimErr != nil || !ok || lease.ID != observationID {
			t.Fatalf("claim=%+v ok=%v err=%v", lease, ok, claimErr)
		}
		if applyErr := memoryStore.ApplyObservation(ctx, lease, []corememory.Candidate{{Operation: "upsert", Subject: "user", Predicate: "home_city", Value: value, Kind: "context", Confidence: .95, EffectiveAt: effectiveAt}}, at); applyErr != nil {
			t.Fatal(applyErr)
		}
	}
	apply("Shanghai", now, "")
	effectiveAt := now.Add(-365 * 24 * time.Hour).Truncate(time.Second)
	apply("Beijing", now.Add(time.Second), effectiveAt.Format(time.RFC3339))
	snapshot, err := memoryStore.Recall(ctx, 10, 10)
	if err != nil || len(snapshot.Facts) != 1 || snapshot.Facts[0].Value != "Beijing" || !snapshot.Facts[0].ValidFrom.Equal(effectiveAt) || len(snapshot.Events) != 2 || snapshot.Events[0].Kind != "replaced" || !snapshot.Events[0].EffectiveAt.Equal(effectiveAt) {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	var oldState string
	var validTo *time.Time
	if err = pool.QueryRow(ctx, `SELECT state,valid_to FROM core_memory_facts WHERE value='Shanghai'`).Scan(&oldState, &validTo); err != nil || oldState != "superseded" || validTo == nil {
		t.Fatalf("old fact state=%q valid_to=%v err=%v", oldState, validTo, err)
	}
	if _, err = knowledgeStore.DisableEmbeddingProfile(ctx, embeddingProfile.ID); err != nil {
		t.Fatal(err)
	}
	configState, err = memoryStore.GetConfig(ctx)
	if err != nil || configState.Enabled || configState.EmbeddingConfigured || configState.Revision != 2 {
		t.Fatalf("config after embedding disable=%+v err=%v", configState, err)
	}
	status, err := memoryStore.Status(ctx, 10, 10)
	if err != nil || status.ActiveFactCount != 1 || len(status.Facts) != 1 || len(status.Timeline) != 2 {
		t.Fatalf("preserved status=%+v err=%v", status, err)
	}
	if disabledSnapshot, recallErr := memoryStore.Recall(ctx, 10, 10); recallErr != nil || len(disabledSnapshot.Facts) != 0 || len(disabledSnapshot.Events) != 0 {
		t.Fatalf("disabled recall=%+v err=%v", disabledSnapshot, recallErr)
	}
}
