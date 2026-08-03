package postgres

import (
	"io/fs"
	"sort"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/migrations"
)

func TestCurrentSchemaVersionMatchesEmbeddedMigrations(t *testing.T) {
	entries, err := fs.Glob(migrations.Files, "*.up.sql")
	if err != nil {
		t.Fatalf("list embedded migrations: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("embedded migration set is empty")
	}
	sort.Strings(entries)

	var latest int64
	for _, entry := range entries {
		version, err := migrationVersion(entry)
		if err != nil {
			t.Fatalf("parse %q: %v", entry, err)
		}
		if version != latest+1 {
			t.Fatalf("migration sequence jumps from %d to %d at %q", latest, version, entry)
		}
		latest = version
	}
	if latest != currentSchemaVersion {
		t.Fatalf("latest embedded migration is %d, current schema version is %d", latest, currentSchemaVersion)
	}
}
