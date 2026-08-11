package migrations

import (
	"strings"
	"testing"
)

func TestTeamArtifactNameMigrationSupportsSafeUnicodeNames(t *testing.T) {
	t.Parallel()
	raw, err := Files.ReadFile("000066_team_artifact_names.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.Join(strings.Fields(string(raw)), " ")
	for _, required := range []string{
		"DROP CONSTRAINT team_artifacts_name_check",
		"ADD CONSTRAINT team_artifacts_name_check CHECK",
		"octet_length(name) BETWEEN 1 AND 255",
		"name = btrim(name)",
		"name NOT IN ('.', '..')",
		"position('/' IN name) = 0",
		"position(chr(92) IN name) = 0",
		"name !~ '[[:cntrl:]<>:\"|?*]'",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("artifact name migration missing %q", required)
		}
	}
}
