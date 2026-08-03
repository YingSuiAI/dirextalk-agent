package migrations

import (
	"strings"
	"testing"
)

func TestTeamExecutionMarketplaceMigrationBindsApprovedRelease(t *testing.T) {
	t.Parallel()
	raw, err := Files.ReadFile(
		"000057_team_execution_marketplace_binding.up.sql",
	)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"CREATE OR REPLACE FUNCTION validate_team_execution_insert()",
		"'marketplace'",
		"assignment.value->'marketplace' IS NOT DISTINCT FROM",
		"role.value->'marketplace'",
		"Team execution JSON contains unknown or missing fields",
		"Team execution is not bound to the approved Team Plan",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("Team execution Marketplace migration missing %q", fragment)
		}
	}
	for _, forbidden := range []string{
		"DROP TRIGGER",
		"DISABLE TRIGGER",
		"session_replication_role",
	} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf(
				"Team execution Marketplace migration weakens validation with %q",
				forbidden,
			)
		}
	}
}
