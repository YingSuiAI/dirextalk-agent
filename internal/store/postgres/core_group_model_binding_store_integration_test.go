package postgres

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestCoreGroupModelBindingStoreIntegration pins the per-group model choice
// against PG18: absent means inherit, a set binding is per room, revisions are
// CAS-fenced, a foreign or unknown profile is refused, and deleting the binding
// returns the group to inheriting the owner's default.
func TestCoreGroupModelBindingStoreIntegration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set AGENT_TEST_POSTGRES_DSN for PG18 integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	adminPool, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	schema := "dtx_agent_group_model_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = map[string]string{}
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.ConnConfig.RuntimeParams["application_name"] = "dirextalk-group-model-binding-integration"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+quotedSchema+" CASCADE")
		adminPool.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE")
		adminPool.Close()
	})
	sid := uuid.NewString()
	if err := ApplyMigrations(ctx, pool, sid); err != nil {
		t.Fatal(err)
	}
	keyring, err := secretbox.New(secretbox.KeyVersionMin, bytes.Repeat([]byte{0x4d}, secretbox.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(pool, sid, keyring)
	if err != nil {
		t.Fatal(err)
	}
	store := NewCoreGroupModelBindingStore(s)

	const owner = "@owner:example.test"
	const generation = uint64(9)
	const roomID = "!group-room:example.test"
	groupProfile := uuid.NewString()
	personalProfile := uuid.NewString()
	for _, profileID := range []string{groupProfile, personalProfile} {
		createTestProfile(ctx, t, s, profileID, "model-"+profileID[:8], "test-key")
	}

	// Absent binding = inherit.
	if _, ok, err := store.ResolveGroupConversationModel(ctx, owner, generation, roomID); err != nil || ok {
		t.Fatalf("empty store resolved ok=%v err=%v", ok, err)
	}
	// A created binding is per room and CAS-fenced.
	created, err := store.SetGroupConversationModel(ctx, owner, generation, roomID, groupProfile, 0)
	if err != nil || created.ProfileID != groupProfile || created.Revision != 1 {
		t.Fatalf("create binding=%+v err=%v", created, err)
	}
	if _, err := store.SetGroupConversationModel(ctx, owner, generation, roomID, personalProfile, 0); !errors.Is(err, ErrGroupModelBindingConflict) {
		t.Fatalf("stale create was accepted: %v", err)
	}
	resolved, ok, err := store.ResolveGroupConversationModel(ctx, owner, generation, roomID)
	if err != nil || !ok || resolved != groupProfile {
		t.Fatalf("resolve=%q ok=%v err=%v", resolved, ok, err)
	}
	if _, ok, err := store.ResolveGroupConversationModel(ctx, owner, generation, "!another-room:example.test"); err != nil || ok {
		t.Fatalf("another room inherited a foreign binding: ok=%v err=%v", ok, err)
	}
	if _, ok, err := store.ResolveGroupConversationModel(ctx, "@other:example.test", generation, roomID); err != nil || ok {
		t.Fatalf("another owner inherited a foreign binding: ok=%v err=%v", ok, err)
	}
	// An unknown profile is refused by the durable reference.
	if _, err := store.SetGroupConversationModel(ctx, owner, generation, roomID, uuid.NewString(), 1); !errors.Is(err, ErrGroupModelBindingInvalid) {
		t.Fatalf("unknown profile was accepted: %v", err)
	}
	// Rotation keeps the CAS honest and deleting returns to inheritance.
	updated, err := store.SetGroupConversationModel(ctx, owner, generation, roomID, personalProfile, 1)
	if err != nil || updated.ProfileID != personalProfile || updated.Revision != 2 {
		t.Fatalf("update binding=%+v err=%v", updated, err)
	}
	if err := store.DeleteGroupConversationModel(ctx, owner, generation, roomID, 1); !errors.Is(err, ErrGroupModelBindingConflict) {
		t.Fatalf("stale delete was accepted: %v", err)
	}
	if err := store.DeleteGroupConversationModel(ctx, owner, generation, roomID, 2); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.ResolveGroupConversationModel(ctx, owner, generation, roomID); err != nil || ok {
		t.Fatalf("deleted binding still resolved: ok=%v err=%v", ok, err)
	}
}
