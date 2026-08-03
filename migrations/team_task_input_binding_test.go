package migrations

import (
	"strings"
	"testing"
)

func TestTeamTaskInputMigrationBindsApprovedSourceWithoutCredentials(
	t *testing.T,
) {
	t.Parallel()
	raw, err := Files.ReadFile(
		"000055_team_task_input_binding.up.sql",
	)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"CREATE TABLE team_task_inputs",
		"PRIMARY KEY (input_id, input_digest)",
		"UNIQUE (input_id, input_digest, source_digest)",
		"repository_connection_id uuid",
		"repository_id text",
		"repository_base_commit_sha text",
		"workspace_snapshot_digest text",
		"input_cbor bytea NOT NULL",
		"CREATE TRIGGER team_task_inputs_validated",
		"CREATE TRIGGER team_task_inputs_immutable",
		"ADD CONSTRAINT team_plans_task_input_reference",
		"ADD CONSTRAINT team_executions_task_input_reference",
		"CREATE TRIGGER team_plans_task_input_immutable",
		"CREATE TRIGGER team_executions_task_input_immutable",
		"NEW.execution_json->'task_input' =",
		"plan.plan_json->'task_input'",
		"NEW.task_input_source_digest =",
		"plan.task_input_source_digest",
		"Team execution is not bound to the approved Team Plan",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("Team TaskInput migration missing %q", fragment)
		}
	}
	lower := strings.ToLower(sql)
	for _, forbidden := range []string{
		"installation_token",
		"personal_access_token",
		"private_key",
		"clone_url",
		"github_pat_",
		"ghs_",
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf(
				"Team TaskInput migration persists forbidden material %q",
				forbidden,
			)
		}
	}
}
