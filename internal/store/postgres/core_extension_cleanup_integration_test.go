package postgres

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCoreExtensionArtifactCleanupPostgresReplayKeepsStableGenerationFence(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("AGENT_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "dtx_ext_cleanup_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
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
	if err := ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatal(err)
	}
	if err := ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatalf("reapply immutable migration checksum: %v", err)
	}
	store, err := New(pool, instanceID, testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	extensions := NewCoreExtensionStore(store)
	candidate, inspection := extensionFixture()
	digest := strings.Repeat("a", 64)
	result, err := extensions.CreateMutation(ctx, coreextension.Mutation{IdempotencyKey: uuid.NewString(), Candidate: candidate, Inspection: inspection, ArtifactPath: digest, ArtifactDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	version := result.Installation.Versions[0]
	root := t.TempDir()
	target := filepath.Join(root, digest)
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "manifest.json"), []byte("{}"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0500); err != nil {
		t.Fatal(err)
	}
	cleaner, err := NewCoreExtensionArtifactCleaner(store, root, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := cleaner.Enqueue(ctx, version, result.Installation.ID, "failure"); err != nil {
		t.Fatal(err)
	}
	wantCleanupID := extensionArtifactCleanupID(result.Installation.ID, version.VersionID, digest)
	if completed, err := cleaner.Sweep(ctx, 8); err != nil || completed != 1 {
		t.Fatalf("first sweep completed=%d err=%v", completed, err)
	}
	var cleanupID, state string
	if err := pool.QueryRow(ctx, `SELECT cleanup_id::text,state FROM core_extension_artifact_cleanup WHERE installation_id=$1 AND version_id=$2 AND artifact_digest=$3`, result.Installation.ID, version.VersionID, digest).Scan(&cleanupID, &state); err != nil {
		t.Fatal(err)
	}
	if cleanupID != wantCleanupID || state != "succeeded" {
		t.Fatalf("cleanup row id=%q state=%q want_id=%q", cleanupID, state, wantCleanupID)
	}
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(target, "replacement")
	if err := os.WriteFile(replacement, []byte("new generation"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := cleaner.Enqueue(ctx, version, result.Installation.ID, "failure"); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM core_extension_artifact_cleanup WHERE installation_id=$1 AND version_id=$2 AND artifact_digest=$3`, result.Installation.ID, version.VersionID, digest).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("replayed enqueue created %d cleanup rows", rows)
	}
	if completed, err := cleaner.Sweep(ctx, 8); err != nil || completed != 0 {
		t.Fatalf("replay sweep completed=%d err=%v", completed, err)
	}
	if got, err := os.ReadFile(replacement); err != nil || string(got) != "new generation" {
		t.Fatalf("replayed cleanup crossed into replacement: %q err=%v", got, err)
	}
	orphanCleanupID := uuid.NewString()
	orphanTombstone := filepath.Join(root, ".remove-"+orphanCleanupID)
	if err := os.Mkdir(orphanTombstone, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphanTombstone, "remaining"), []byte("partial compensation"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(orphanTombstone, 0500); err != nil {
		t.Fatal(err)
	}
	if completed, err := cleaner.Sweep(ctx, 8); err != nil || completed != 0 {
		t.Fatalf("orphan compensation recovery completed=%d err=%v", completed, err)
	}
	for _, marker := range []string{".remove-" + orphanCleanupID, ".removed-" + orphanCleanupID} {
		if _, err := os.Stat(filepath.Join(root, marker)); !os.IsNotExist(err) {
			t.Fatalf("orphan compensation marker %q was not reclaimed: %v", marker, err)
		}
	}
	if got, err := os.ReadFile(replacement); err != nil || string(got) != "new generation" {
		t.Fatalf("orphan compensation recovery crossed into replacement: %q err=%v", got, err)
	}
	completedOrphanID := uuid.NewString()
	completedOrphan := filepath.Join(root, ".removed-"+completedOrphanID)
	if err := os.Mkdir(completedOrphan, 0500); err != nil {
		t.Fatal(err)
	}
	if completed, err := cleaner.Sweep(ctx, 8); err != nil || completed != 0 {
		t.Fatalf("completed orphan marker recovery completed=%d err=%v", completed, err)
	}
	if _, err := os.Stat(completedOrphan); !os.IsNotExist(err) {
		t.Fatalf("successful compensation marker was not reclaimed: %v", err)
	}
	if got, err := os.ReadFile(replacement); err != nil || string(got) != "new generation" {
		t.Fatalf("successful compensation marker GC crossed into replacement: %q err=%v", got, err)
	}
}
