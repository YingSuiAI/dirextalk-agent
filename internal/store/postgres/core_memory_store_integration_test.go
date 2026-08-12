package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

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
	apply := func(value string, at time.Time) {
		observationID := uuid.NewString()
		if _, insertErr := pool.Exec(ctx, `INSERT INTO core_memory_observations(observation_id,conversation_id,profile_id,user_text,assistant_text,observed_at,next_attempt_at) VALUES($1,$2,$3,$4,'ok',$5,$5)`, observationID, conversationID, profile.ID, "I live in "+value, at); insertErr != nil {
			t.Fatal(insertErr)
		}
		lease, ok, claimErr := memoryStore.ClaimObservation(ctx, at, time.Minute)
		if claimErr != nil || !ok || lease.ID != observationID {
			t.Fatalf("claim=%+v ok=%v err=%v", lease, ok, claimErr)
		}
		if applyErr := memoryStore.ApplyObservation(ctx, lease, []corememory.Candidate{{Operation: "upsert", Subject: "user", Predicate: "home_city", Value: value, Kind: "context", Confidence: .95}}, at); applyErr != nil {
			t.Fatal(applyErr)
		}
	}
	apply("Shanghai", now)
	apply("Beijing", now.Add(time.Second))
	snapshot, err := memoryStore.Recall(ctx, 10, 10)
	if err != nil || len(snapshot.Facts) != 1 || snapshot.Facts[0].Value != "Beijing" || len(snapshot.Events) != 2 || snapshot.Events[0].Kind != "replaced" {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	var oldState string
	var validTo *time.Time
	if err = pool.QueryRow(ctx, `SELECT state,valid_to FROM core_memory_facts WHERE value='Shanghai'`).Scan(&oldState, &validTo); err != nil || oldState != "superseded" || validTo == nil {
		t.Fatalf("old fact state=%q valid_to=%v err=%v", oldState, validTo, err)
	}
}
