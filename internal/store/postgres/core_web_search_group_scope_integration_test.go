package postgres

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/corewebsearch"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestCoreWebSearchGroupScopeDispatchFenceIntegration pins the group search
// credential fence against PG18: one owner keeps independent personal and
// per-room search credentials, the dispatch reload carries the scope it was
// resolved for, another scope is refused, and an unconfigured group resolves
// nothing so the resolver can inherit the owner's provider explicitly.
func TestCoreWebSearchGroupScopeDispatchFenceIntegration(t *testing.T) {
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
	schema := "dtx_agent_websearch_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	config.ConnConfig.RuntimeParams["application_name"] = "dirextalk-core-websearch-group-integration"
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
	keyring, err := secretbox.New(secretbox.KeyVersionMin, bytes.Repeat([]byte{0x6b}, secretbox.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(pool, sid, keyring)
	if err != nil {
		t.Fatal(err)
	}
	store := NewCoreWebSearchStore(s)
	// The searcher is never reached: this test exercises resolution and the
	// credential fence, not the provider call.
	service, err := corewebsearch.NewService(store, noopWebSearcher{})
	if err != nil {
		t.Fatal(err)
	}

	const owner = "@owner:example.test"
	const generation = int64(6)
	const roomID = "!search-room:example.test"
	personal := corewebsearch.PersonalScope(owner, generation)
	group := corewebsearch.GroupScope(owner, generation, roomID)
	otherGroup := corewebsearch.GroupScope(owner, generation, "!other-room:example.test")

	enabled := true
	personalKey := "tvly-personal-only"
	if _, err := service.Update(ctx, corewebsearch.UpdateCommand{
		Scope: personal, IdempotencyKey: uuid.NewString(), ExpectedRevision: 0,
		Enabled: &enabled, APIKey: &personalKey,
	}); err != nil {
		t.Fatalf("personal update: %v", err)
	}
	groupKey := "tvly-group-only"
	if _, err := service.Update(ctx, corewebsearch.UpdateCommand{
		Scope: group, IdempotencyKey: uuid.NewString(), ExpectedRevision: 0,
		Enabled: &enabled, APIKey: &groupKey,
	}); err != nil {
		t.Fatalf("group update: %v", err)
	}

	// The group credential is its own row: writing it must not disturb the
	// owner's personal credential.
	personalConfig, err := service.Get(ctx, personal)
	if err != nil || personalConfig.Revision != 1 {
		t.Fatalf("personal config was disturbed by the group write: %+v err=%v", personalConfig, err)
	}

	resolvedGroup, err := service.Resolve(ctx, group)
	if err != nil {
		t.Fatalf("group resolve: %v", err)
	}
	if resolvedGroup.RoomID != roomID || resolvedGroup.APIKey != groupKey {
		t.Fatalf("group resolve lost its scope or credential: room=%q", resolvedGroup.RoomID)
	}
	current, release, err := store.ResolveForDispatch(ctx, group, resolvedGroup)
	if err != nil {
		t.Fatalf("group dispatch fence rejected the group's own credential: %v", err)
	}
	if release == nil || current.RoomID != roomID || current.APIKey != groupKey || current.OwnerID != owner || current.AccountGeneration != generation {
		t.Fatalf("dispatch snapshot=%+v", current)
	}
	if err := release(); err != nil {
		t.Fatalf("release dispatch fence: %v", err)
	}

	resolvedPersonal, err := service.Resolve(ctx, personal)
	if err != nil || resolvedPersonal.APIKey != personalKey {
		t.Fatalf("personal resolve=%+v err=%v", resolvedPersonal, err)
	}

	// A snapshot resolved for one scope is never dispatched under another, and
	// an unconfigured group resolves nothing (the resolver then inherits the
	// owner's provider explicitly).
	if _, _, err := store.ResolveForDispatch(ctx, personal, resolvedGroup); !errors.Is(err, corewebsearch.ErrRevisionConflict) && !errors.Is(err, corewebsearch.ErrInvalid) {
		t.Fatalf("cross-scope dispatch was not refused: %v", err)
	}
	if _, err := service.Resolve(ctx, otherGroup); !errors.Is(err, corewebsearch.ErrNotConfigured) {
		t.Fatalf("unconfigured group resolved a credential: %v", err)
	}
}

type noopWebSearcher struct{}

func (noopWebSearcher) Search(context.Context, string, string, int) (corewebsearch.SearchResult, error) {
	return corewebsearch.SearchResult{}, corewebsearch.ErrProvider
}
