package migrations

import (
	"strings"
	"testing"
)

func TestTeamArtifactsMigrationKeepsObjectCoordinatesInternalAndImmutable(
	t *testing.T,
) {
	raw, err := Files.ReadFile("000061_team_artifacts.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	migration := string(raw)
	for _, expected := range []string{
		"CREATE TABLE team_artifacts",
		"object_ref text NOT NULL",
		"verification='passed'",
		"retention_expires_at",
		"Team artifact metadata is immutable",
		"dispatch.result_evidence_json IS NULL",
		"final->>'artifact_sha256' <> NEW.sha256",
		"worker.state='finished'",
		"worker.outcome='succeeded'",
	} {
		if !strings.Contains(migration, expected) {
			t.Fatalf("artifact migration missing %q", expected)
		}
	}
}
