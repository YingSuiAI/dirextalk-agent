package migrations

import (
	"strings"
	"testing"
)

func TestTeamExecutionMigrationPreservesApprovedImmutableWorkerGraph(
	t *testing.T,
) {
	t.Parallel()
	raw, err := Files.ReadFile(
		"000047_team_execution_materialization.up.sql",
	)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	required := []string{
		"CREATE TABLE team_executions",
		"CREATE TABLE team_execution_roles",
		"CREATE TABLE team_execution_role_dependencies",
		"UNIQUE (plan_id, plan_revision)",
		"approval_id uuid NOT NULL UNIQUE",
		"execution_cbor bytea NOT NULL",
		"role_cbor bytea NOT NULL",
		"model_credential_slot text NOT NULL",
		"CREATE UNIQUE INDEX team_executions_one_active_task_idx",
		"CREATE TRIGGER team_executions_approved_binding",
		"CREATE TRIGGER team_executions_state_only",
		"CREATE CONSTRAINT TRIGGER team_executions_complete_graph",
		"CREATE TRIGGER team_execution_roles_bound_insert",
		"CREATE TRIGGER team_execution_roles_immutable",
		"CREATE TRIGGER team_execution_role_dependencies_bound_insert",
		"CREATE TRIGGER team_execution_role_dependencies_immutable",
		"CREATE TRIGGER team_task_step_dependencies_bound",
		"Team execution is not bound to the approved Team Plan",
		"Team execution role graph is incomplete",
		"Task dependency is not present in the immutable Team execution",
		"materialized Team execution fields are immutable",
		"plan.status = 'approved'",
		"minimum_cost_micros",
		"max_concurrent_workers",
		"Team execution JSON contains unknown or missing fields",
		"plan.plan_json->'assignments'",
		"assignment.value->>'runtime_image_digest'",
		"assignment.value->'resources'",
	}
	for _, fragment := range required {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("Team execution migration missing %q", fragment)
		}
	}
	forbidden := []string{
		"model_credential_ref",
		"private_key",
		"secret_access_key",
		"session_token",
		"model_api_key",
	}
	for _, fragment := range forbidden {
		if strings.Contains(strings.ToLower(sql), fragment) {
			t.Fatalf(
				"Team execution migration persists forbidden material %q",
				fragment,
			)
		}
	}
}
