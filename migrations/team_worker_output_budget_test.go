package migrations

import (
	"strings"
	"testing"
)

func TestTeamWorkerOutputBudgetMigrationExtendsRuntimeTaskAllowlist(t *testing.T) {
	t.Parallel()
	raw, err := Files.ReadFile("000063_team_worker_output_budget.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"CREATE OR REPLACE FUNCTION validate_team_worker_input_insert()",
		"FROM jsonb_object_keys(runtime_task)",
		") <> 18",
		"'max_output_tokens'",
		"jsonb_typeof(runtime_task->'max_output_tokens') <> 'number'",
		"NOT BETWEEN 1 AND 100000000",
		"credential_grant->>'maximum_output_tokens'",
		"Team Worker input JSON contains unknown or missing fields",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("Team Worker output budget migration missing %q", fragment)
		}
	}
}
