package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/source"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCoreExtensionBuiltinMCPSeedIsOneTimeAndRemovalSurvivesRestart(t *testing.T) {
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
	schema := "dtx_builtin_mcp_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
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
	repository := NewCoreExtensionStore(store)
	catalog, err := source.NewBuiltinMCPs([]byte("ELF fixture"), []byte("shell fixture"))
	if err != nil {
		t.Fatal(err)
	}
	artifact := catalog.Artifacts()[0]
	artifactDigest := strings.Repeat("a", 64)
	installed, err := repository.EnsureBuiltinMCP(ctx, artifact, artifactDigest)
	if err != nil {
		t.Fatal(err)
	}
	if installed.State != coreextension.StateInstalled || !installed.Enabled || installed.Source != coreextension.SourceBuiltin || installed.Kind != coreextension.KindMCP || installed.ActiveVersionID == "" || len(installed.Versions) != 1 || installed.Versions[0].ArtifactDigest != artifactDigest {
		t.Fatalf("installed=%#v", installed)
	}
	replayed, err := repository.EnsureBuiltinMCP(ctx, artifact, artifactDigest)
	if err != nil || replayed.ID != installed.ID || replayed.Revision != installed.Revision {
		t.Fatalf("replayed=%#v err=%v", replayed, err)
	}
	repackedDigest := strings.Repeat("c", 64)
	repacked, err := repository.EnsureBuiltinMCP(ctx, artifact, repackedDigest)
	if err != nil || repacked.ID != installed.ID || repacked.Revision != installed.Revision+1 || len(repacked.Versions) != 2 || repacked.ActiveVersionID == installed.ActiveVersionID {
		t.Fatalf("repacked=%#v err=%v", repacked, err)
	}
	var repackedActive coreextension.VersionRecord
	for _, version := range repacked.Versions {
		if version.VersionID == repacked.ActiveVersionID {
			repackedActive = version
			break
		}
	}
	if repackedActive.VersionID == "" || repackedActive.ContentDigest != artifact.ContentDigest || repackedActive.ArtifactDigest != repackedDigest {
		t.Fatalf("active repacked version=%#v", repackedActive)
	}
	updatedCatalog, err := source.NewBuiltinMCPs([]byte("ELF fixture v2"), []byte("shell fixture"))
	if err != nil {
		t.Fatal(err)
	}
	updatedArtifact := updatedCatalog.Artifacts()[0]
	updatedDigest := strings.Repeat("b", 64)
	updated, err := repository.EnsureBuiltinMCP(ctx, updatedArtifact, updatedDigest)
	if err != nil || updated.ID != installed.ID || updated.Revision != installed.Revision+2 || len(updated.Versions) != 3 || updated.ActiveVersionID == repacked.ActiveVersionID {
		t.Fatalf("updated=%#v err=%v", updated, err)
	}
	var active coreextension.VersionRecord
	for _, version := range updated.Versions {
		if version.VersionID == updated.ActiveVersionID {
			active = version
			break
		}
	}
	if active.VersionID != updated.ActiveVersionID || active.ArtifactDigest != updatedDigest {
		t.Fatalf("active updated version=%#v", active)
	}
	if _, err = pool.Exec(ctx, `UPDATE core_extension_installations SET state='removed',enabled=false,active_version_id=NULL,revision=revision+1 WHERE installation_id=$1`, installed.ID); err != nil {
		t.Fatal(err)
	}
	seeded, err := repository.BuiltinMCPSeeded(ctx, artifact.Candidate.ID)
	if err != nil || !seeded {
		t.Fatalf("seeded=%v err=%v", seeded, err)
	}
	afterRestart, err := repository.EnsureBuiltinMCP(ctx, updatedArtifact, updatedDigest)
	if err != nil || afterRestart.State != coreextension.StateRemoved || afterRestart.Enabled || afterRestart.ActiveVersionID != "" {
		t.Fatalf("removed default resurrected: %#v err=%v", afterRestart, err)
	}
}
