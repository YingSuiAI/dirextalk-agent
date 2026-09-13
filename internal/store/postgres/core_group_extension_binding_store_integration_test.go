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

// TestCoreGroupExtensionBindingStoreIntegration pins the third-party plugin
// binding: an installation is shared only with the group the owner bound it to,
// clearing the binding shares it with no group, and an unknown installation is
// refused by the durable reference.
func TestCoreGroupExtensionBindingStoreIntegration(t *testing.T) {
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
	schema := "dtx_agent_group_ext_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	config.ConnConfig.RuntimeParams["application_name"] = "dirextalk-group-extension-binding-integration"
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
	keyring, err := secretbox.New(secretbox.KeyVersionMin, bytes.Repeat([]byte{0x2a}, secretbox.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(pool, sid, keyring)
	if err != nil {
		t.Fatal(err)
	}
	store := NewCoreGroupExtensionBindingStore(s)

	now := time.Now().UTC().Truncate(time.Microsecond)
	installationID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO core_extension_installations(installation_id,candidate_json,kind,source,candidate_id,name,transport,state,enabled,created_at,updated_at)
		VALUES($1,'{}'::jsonb,'mcp','third-party','candidate','Weather MCP','http','installed',true,$2,$2)`, installationID, now); err != nil {
		t.Fatal(err)
	}
	const owner = "@owner:example.test"
	const generation = uint64(9)
	const roomID = "!group-room:example.test"

	if _, err := store.ListGroupExtensionBindings(ctx, owner, generation, roomID); err != nil {
		t.Fatalf("empty list: %v", err)
	}
	if bound, err := store.GroupExtensionBound(ctx, owner, generation, roomID, installationID); err != nil || bound {
		t.Fatalf("unbound installation reported bound=%v err=%v", bound, err)
	}
	if err := store.SetGroupExtensionBinding(ctx, owner, generation, roomID, installationID); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := store.SetGroupExtensionBinding(ctx, owner, generation, roomID, installationID); err != nil {
		t.Fatalf("bind was not idempotent: %v", err)
	}
	bound, err := store.ListGroupExtensionBindings(ctx, owner, generation, roomID)
	if err != nil || len(bound) != 1 || bound[0] != installationID {
		t.Fatalf("bound=%v err=%v", bound, err)
	}
	// Another room and another owner never see this binding.
	for _, other := range []struct {
		owner, room string
	}{
		{owner, "!another-room:example.test"},
		{"@other:example.test", roomID},
	} {
		listed, err := store.ListGroupExtensionBindings(ctx, other.owner, generation, other.room)
		if err != nil || len(listed) != 0 {
			t.Fatalf("scope %s/%s saw a foreign binding: %v err=%v", other.owner, other.room, listed, err)
		}
	}
	if err := store.SetGroupExtensionBinding(ctx, owner, generation, roomID, uuid.NewString()); !errors.Is(err, ErrGroupExtensionBindingInvalid) {
		t.Fatalf("unknown installation was accepted: %v", err)
	}
	if err := store.ClearGroupExtensionBinding(ctx, owner, generation, roomID, installationID); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if bound, err := store.GroupExtensionBound(ctx, owner, generation, roomID, installationID); err != nil || bound {
		t.Fatalf("cleared installation still bound=%v err=%v", bound, err)
	}
}
