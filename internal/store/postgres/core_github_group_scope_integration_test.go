package postgres

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coregithub"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type githubScopeIdentityTester struct{}

func (githubScopeIdentityTester) Identity(context.Context, string) error { return nil }

// TestCoreGitHubGroupScopeDispatchFenceIntegration pins the group credential
// fence end to end against PG18: one owner keeps independent personal and
// per-room credentials, the dispatch reload carries the same scope it was
// resolved for, and a dispatch for another scope is refused.
func TestCoreGitHubGroupScopeDispatchFenceIntegration(t *testing.T) {
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
	schema := "dtx_agent_github_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	config.ConnConfig.RuntimeParams["application_name"] = "dirextalk-core-github-group-integration"
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
	keyring, err := secretbox.New(secretbox.KeyVersionMin, bytes.Repeat([]byte{0x3c}, secretbox.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(pool, sid, keyring)
	if err != nil {
		t.Fatal(err)
	}
	store := NewCoreGitHubStore(s)
	service, err := coregithub.NewService(store, githubScopeIdentityTester{})
	if err != nil {
		t.Fatal(err)
	}

	const owner = "@owner:example.test"
	const generation = int64(4)
	const roomID = "!group-room:example.test"
	const otherRoomID = "!other-room:example.test"
	personal := coregithub.PersonalScope(owner, generation)
	group := coregithub.GroupScope(owner, generation, roomID)
	otherGroup := coregithub.GroupScope(owner, generation, otherRoomID)

	personalToken := "ghp_personal_only_token"
	enabled := true
	if _, err := service.Update(ctx, coregithub.UpdateCommand{
		Scope: personal, IdempotencyKey: uuid.NewString(), ExpectedRevision: 0,
		Enabled: &enabled, GitHubToken: &personalToken,
	}); err != nil {
		t.Fatalf("personal update: %v", err)
	}
	groupToken := "ghp_group_only_token"
	groupRevision := int64(0)
	created, err := service.Update(ctx, coregithub.UpdateCommand{
		Scope: group, IdempotencyKey: uuid.NewString(), ExpectedRevision: groupRevision,
		Enabled: &enabled, GitHubToken: &groupToken,
	})
	if err != nil {
		t.Fatalf("group update: %v", err)
	}

	// The group credential is its own row: enabling it must not touch the
	// owner's personal credential.
	personalConfig, err := service.Get(ctx, personal)
	if err != nil {
		t.Fatalf("personal config: %v", err)
	}
	if personalConfig.Revision != 1 {
		t.Fatalf("personal revision was disturbed by the group write: %+v", personalConfig)
	}
	if created.Revision != 1 || !created.Enabled {
		t.Fatalf("group config: %+v", created)
	}

	resolvedGroup, err := service.Resolve(ctx, group)
	if err != nil {
		t.Fatalf("group resolve: %v", err)
	}
	if resolvedGroup.RoomID != roomID || resolvedGroup.OwnerID != owner || resolvedGroup.AccountGeneration != generation {
		t.Fatalf("group resolve lost its scope: %+v", resolvedGroup)
	}
	var dispatched string
	if err := service.WithTokenResolved(ctx, group, resolvedGroup, func(token string) error {
		dispatched = token
		return nil
	}); err != nil {
		t.Fatalf("group dispatch fence rejected the group's own credential: %v", err)
	}
	if dispatched != groupToken {
		t.Fatalf("group dispatch returned %q", dispatched)
	}

	resolvedPersonal, err := service.Resolve(ctx, personal)
	if err != nil {
		t.Fatalf("personal resolve: %v", err)
	}
	var dispatchedPersonal string
	if err := service.WithTokenResolved(ctx, personal, resolvedPersonal, func(token string) error {
		dispatchedPersonal = token
		return nil
	}); err != nil {
		t.Fatalf("personal dispatch fence rejected the personal credential: %v", err)
	}
	if dispatchedPersonal != personalToken {
		t.Fatalf("personal dispatch returned a foreign credential")
	}

	// A snapshot resolved for one scope may never be dispatched under another.
	if err := service.WithTokenResolved(ctx, personal, resolvedGroup, func(string) error { return nil }); !errors.Is(err, coregithub.ErrInvalid) {
		t.Fatalf("cross-scope dispatch was not refused: %v", err)
	}
	if err := service.WithTokenResolved(ctx, otherGroup, resolvedGroup, func(string) error { return nil }); !errors.Is(err, coregithub.ErrInvalid) {
		t.Fatalf("cross-room dispatch was not refused: %v", err)
	}
	if _, err := service.Resolve(ctx, otherGroup); !errors.Is(err, coregithub.ErrNotConfigured) {
		t.Fatalf("unconfigured room resolved a credential: %v", err)
	}
}
