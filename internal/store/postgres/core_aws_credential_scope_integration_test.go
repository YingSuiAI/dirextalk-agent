package postgres

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestCoreAWSCredentialScopeListingIntegration pins the cloud credential scope
// read against PG18: the owner's credential set and one group's are separate
// lists, a room never sees another room's credential, and the durable single
// active credential invariant is enforced per scope.
func TestCoreAWSCredentialScopeListingIntegration(t *testing.T) {
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
	schema := "dtx_agent_aws_scope_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	config.ConnConfig.RuntimeParams["application_name"] = "dirextalk-aws-credential-scope-integration"
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
	keyring, err := secretbox.New(secretbox.KeyVersionMin, bytes.Repeat([]byte{0x7e}, secretbox.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(pool, sid, keyring)
	if err != nil {
		t.Fatal(err)
	}
	store := NewCoreAWSStore(s)
	service := coreaws.NewService(store, nil, func() time.Time { return time.Now().UTC() })

	const roomID = "!group-room:example.test"
	create := func(scope coreaws.Scope, name string) coreaws.CredentialView {
		view, err := service.SaveCredential(ctx, scope, coreaws.CredentialInput{
			IdempotencyKey: uuid.NewString(), Name: name, Region: "us-east-1",
			AccessKeyID: "access", SecretAccessKey: "secret",
		})
		if err != nil {
			t.Fatalf("create %s credential: %v", name, err)
		}
		return view
	}
	// One active credential per scope: the owner's own set and each group keep
	// their own row, created through the owner-facing service path.
	personal := create(coreaws.PersonalScope(), "personal")
	group := create(coreaws.GroupScope(roomID), "group")

	personalPage, err := service.ListCredentials(ctx, coreaws.PersonalScope(), 10, "")
	if err != nil || len(personalPage.Items) != 1 || personalPage.Items[0].ID != personal.ID {
		t.Fatalf("personal scope page=%+v err=%v", personalPage, err)
	}
	groupPage, err := service.ListCredentials(ctx, coreaws.GroupScope(roomID), 10, "")
	if err != nil || len(groupPage.Items) != 1 || groupPage.Items[0].ID != group.ID {
		t.Fatalf("group scope page=%+v err=%v", groupPage, err)
	}
	for _, other := range []string{"!another-room:example.test", "!third-room:example.test"} {
		page, err := service.ListCredentials(ctx, coreaws.GroupScope(other), 10, "")
		if err != nil || len(page.Items) != 0 {
			t.Fatalf("room %q saw another scope's credential: %+v err=%v", other, page, err)
		}
	}
	// Another scope can neither read nor mutate this group's credential.
	if _, err := service.GetCredential(ctx, coreaws.PersonalScope(), group.ID); !errors.Is(err, coreaws.ErrNotFound) {
		t.Fatalf("personal scope read the group credential: %v", err)
	}
	if err := service.DeleteCredential(ctx, coreaws.PersonalScope(), group.ID, group.Revision, uuid.NewString()); !errors.Is(err, coreaws.ErrNotFound) {
		t.Fatalf("personal scope deleted the group credential: %v", err)
	}
	if _, err := service.GetCredential(ctx, coreaws.GroupScope("!other-room:example.test"), group.ID); !errors.Is(err, coreaws.ErrNotFound) {
		t.Fatalf("another room read the group credential: %v", err)
	}
	// The group disables its own credential without touching the owner's.
	if err := service.DeleteCredential(ctx, coreaws.GroupScope(roomID), group.ID, group.Revision, uuid.NewString()); err != nil {
		t.Fatalf("group delete: %v", err)
	}
	if page, err := service.ListCredentials(ctx, coreaws.GroupScope(roomID), 10, ""); err != nil || len(page.Items) != 0 {
		t.Fatalf("group scope still lists its credential: %+v err=%v", page, err)
	}
	if view, err := service.GetCredential(ctx, coreaws.PersonalScope(), personal.ID); err != nil || view.ID != personal.ID {
		t.Fatalf("personal credential changed: %+v err=%v", view, err)
	}
	// Deleting the owner's credential is still possible in its own scope, and
	// then that scope may hold a new active credential again.
	if err := service.DeleteCredential(ctx, coreaws.PersonalScope(), personal.ID, personal.Revision, uuid.NewString()); err != nil {
		t.Fatalf("personal delete: %v", err)
	}
	_ = create(coreaws.PersonalScope(), "personal-again")
}
