package migrations

import (
	"strings"
	"testing"
)

func TestTeamPPTXArtifactMigrationKeepsClosedMediaTypeSet(t *testing.T) {
	t.Parallel()
	raw, err := Files.ReadFile("000065_team_pptx_artifacts.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.Join(strings.Fields(string(raw)), " ")
	for _, required := range []string{
		"DROP CONSTRAINT team_artifacts_media_type_check",
		"ADD CONSTRAINT team_artifacts_media_type_check CHECK",
		"'application/json'",
		"'text/plain; charset=utf-8'",
		"'application/vnd.openxmlformats-officedocument.presentationml.presentation'",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("PPTX artifact migration missing %q", required)
		}
	}
}
