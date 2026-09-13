package postgres

import (
	"bytes"
	"context"
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
	now := time.Now().UTC().Truncate(time.Microsecond)
	personal := coreaws.RehydrateCredentials(uuid.NewString(), "scope-test", "us-east-1",
		"123456789012", "arn:aws:iam::123456789012:user/scope-test",
		[]byte("access"), []byte("secret"), nil, 1, 1, now, now)
	personal.TestedAt = now
	if _, err := store.CreateCredential(ctx, personal); err != nil {
		t.Fatalf("create personal credential: %v", err)
	}
	// One durable row per scope: the group credential is the same envelope in a
	// different scope, which the listing boundary must keep separate.
	const roomID = "!group-room:example.test"
	groupID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO core_aws_credentials(credential_id,name,region,secret_key_version,access_key_id_nonce,access_key_id_ciphertext,secret_access_key_nonce,secret_access_key_ciphertext,session_token_nonce,session_token_ciphertext,session_token_configured,account_id,user_arn,verified_revision,revision,tested_at,created_at,updated_at,scope,room_id)
		SELECT $1,name,region,secret_key_version,access_key_id_nonce,access_key_id_ciphertext,secret_access_key_nonce,secret_access_key_ciphertext,session_token_nonce,session_token_ciphertext,session_token_configured,account_id,user_arn,verified_revision,revision,tested_at,created_at,updated_at,'group',$2
		FROM core_aws_credentials WHERE credential_id=$3`, groupID, roomID, personal.ID); err != nil {
		t.Fatalf("insert group credential: %v", err)
	}

	personalPage, err := store.ListCredentialsScoped(ctx, "", 10, "")
	if err != nil || len(personalPage.Items) != 1 || personalPage.Items[0].ID != personal.ID {
		t.Fatalf("personal scope page=%+v err=%v", personalPage, err)
	}
	groupPage, err := store.ListCredentialsScoped(ctx, roomID, 10, "")
	if err != nil || len(groupPage.Items) != 1 || groupPage.Items[0].ID != groupID {
		t.Fatalf("group scope page=%+v err=%v", groupPage, err)
	}
	for _, other := range []string{"!another-room:example.test", "!third-room:example.test"} {
		page, err := store.ListCredentialsScoped(ctx, other, 10, "")
		if err != nil || len(page.Items) != 0 {
			t.Fatalf("room %q saw another scope's credential: %+v err=%v", other, page, err)
		}
	}
	// The default listing stays the owner's own scope.
	legacy, err := store.ListCredentials(ctx, 10, "")
	if err != nil || len(legacy.Items) != 1 || legacy.Items[0].ID != personal.ID {
		t.Fatalf("default listing=%+v err=%v", legacy, err)
	}
	// One active credential per scope is a durable invariant.
	if _, err := pool.Exec(ctx, `INSERT INTO core_aws_credentials(credential_id,name,region,secret_key_version,access_key_id_nonce,access_key_id_ciphertext,secret_access_key_nonce,secret_access_key_ciphertext,session_token_nonce,session_token_ciphertext,session_token_configured,account_id,user_arn,verified_revision,revision,tested_at,created_at,updated_at,scope,room_id)
		SELECT $1,name,region,secret_key_version,access_key_id_nonce,access_key_id_ciphertext,secret_access_key_nonce,secret_access_key_ciphertext,session_token_nonce,session_token_ciphertext,session_token_configured,account_id,user_arn,verified_revision,revision,tested_at,created_at,updated_at,'group',$2
		FROM core_aws_credentials WHERE credential_id=$3`, uuid.NewString(), roomID, personal.ID); err == nil {
		t.Fatal("a second active credential in the same group scope was accepted")
	}
}
