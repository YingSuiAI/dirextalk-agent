package postgres

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const corePG18DSN = "postgres://postgres:dtx_corev1_test_only@127.0.0.1:46509/postgres?sslmode=disable"

func TestCorePostgresUnsupportedTaskDurableFailure(t *testing.T) {
	ctx, store, profile, cleanup := corePG18Fixture(t)
	defer cleanup()
	tasks := NewCoreTaskStore(store)
	key := uuid.NewString()
	spec := coretask.TaskSpec{Goal: "unsupported", ModelProfileID: profile, IdempotencyKey: key, Extensions: []coretask.ExtensionSelection{{Kind: coretask.ExtensionMCP, ID: uuid.NewString(), Version: "1", Digest: strings.Repeat("a", 64)}}}
	digest, err := spec.MutationDigest()
	if err != nil {
		t.Fatal(err)
	}
	_, err = tasks.CreateTask(ctx, coretask.CreateTaskCommand{Spec: spec, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest}})
	if !errors.Is(err, coretask.ErrNotFound) {
		t.Fatalf("unresolved extension selection err=%v", err)
	}
}

func corePG18Fixture(t *testing.T) (context.Context, *Store, string, func()) {
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		dsn = corePG18DSN
	}
	return corePGFixture(t, dsn)
}

func corePGFixture(t *testing.T, dsn string) (context.Context, *Store, string, func()) {
	t.Helper()
	strictDSN := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN")) != ""
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		if strictDSN {
			t.Fatalf("Postgres DSN parse failed: %v", err)
		}
		t.Skipf("PG18 unavailable: %v", err)
	}
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	pingErr := error(nil)
	if err == nil {
		pingErr = admin.Ping(ctx)
	}
	if err != nil || pingErr != nil {
		if admin != nil {
			admin.Close()
		}
		cancel()
		if strictDSN {
			t.Fatalf("Postgres DSN unavailable: %v", firstNonNil(err, pingErr))
		}
		t.Skipf("PG18 unavailable: %v", firstNonNil(err, pingErr))
	}
	schema := "dtx_core_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		cancel()
		t.Skipf("PG18 schema unavailable: %v", err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.ConnConfig.RuntimeParams["application_name"] = "dirextalk-core-integration"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		cancel()
		t.Fatal(err)
	}
	instance := uuid.NewString()
	if err = ApplyMigrations(ctx, pool, instance); err != nil {
		pool.Close()
		admin.Close()
		cancel()
		if !strictDSN && strings.Contains(err.Error(), `extension "vector" is not available`) {
			t.Skipf("pgvector unavailable: %v", err)
		}
		t.Fatal(err)
	}
	keyring, err := secretbox.New(secretbox.KeyVersionMin, bytes.Repeat([]byte{0x5a}, secretbox.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(pool, instance, keyring)
	if err != nil {
		t.Fatal(err)
	}
	profile := uuid.NewString()
	createTestProfile(ctx, t, store, profile, "test", "test")
	return ctx, store, profile, func() {
		pool.Close()
		cancel()
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_, _ = admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE")
		admin.Close()
	}
}

func testSecretKeyring(t *testing.T) *secretbox.Keyring {
	t.Helper()
	keyring, err := secretbox.New(secretbox.KeyVersionMin, bytes.Repeat([]byte{0x5a}, secretbox.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}

func createTestProfile(ctx context.Context, t *testing.T, store *Store, id, model, apiKey string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := store.CreateProfile(ctx, coremodel.Profile{ID: id, DisplayName: "test", Provider: coremodel.ProviderOpenAICompatible, RequestDialect: coremodel.DialectOpenAICompatibleChatV1, ModelKind: coremodel.ModelKindConversation, BaseURL: "https://example.invalid", Model: model, APIKey: apiKey, ContextWindow: 32768, Revision: 1, CreatedAt: now, UpdatedAt: now}, uuid.NewString(), strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
}

func firstNonNil(first, second error) error {
	if first != nil {
		return first
	}
	return second
}

var _ coremodel.ProfileRepository = (*Store)(nil)
