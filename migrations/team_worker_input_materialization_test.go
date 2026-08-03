package migrations

import (
	"strings"
	"testing"
)

func TestTeamWorkerInputMigrationPersistsOnlyImmutableSecretFreeBindings(
	t *testing.T,
) {
	t.Parallel()
	raw, err := Files.ReadFile(
		"000049_team_worker_input_materialization.up.sql",
	)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	required := []string{
		"CREATE TABLE team_worker_inputs",
		"PRIMARY KEY",
		"UNIQUE (execution_id, role_id)",
		"REFERENCES team_execution_roles(execution_id, role_id)",
		"materialization_json jsonb NOT NULL",
		"manifest_json jsonb NOT NULL",
		"manifest_raw bytea NOT NULL",
		"execution_bundle_json jsonb NOT NULL",
		"execution_bundle_raw bytea NOT NULL",
		"execution_bundle_digest text NOT NULL",
		"credential_grant_digest text NOT NULL",
		"Team Worker input JSON contains unknown or missing fields",
		"convert_from(NEW.manifest_raw, 'UTF8')::jsonb",
		"input_action->>'kind' <> 'worker.input.materialize'",
		"runtime_action->'runtime'->'task' <> runtime_task",
		"context_object->>'sha256' <> NEW.context_digest",
		"workspace_object->>'sha256' <> NEW.workspace_digest",
		"execution.status IN ('dispatching', 'running')",
		"pg_column_size(materialization_json) <= 8388608",
		"octet_length(execution_bundle_raw) BETWEEN 1 AND 8388608",
		"role.role_digest = NEW.role_digest",
		"role.role_json->>'runtime_image_digest'",
		"Team Worker input contains credential material",
		"materialized Team Worker input fields are immutable",
		"CREATE TRIGGER team_worker_inputs_bound_insert",
		"CREATE TRIGGER team_worker_inputs_immutable",
	}
	for _, fragment := range required {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("Team Worker input migration missing %q", fragment)
		}
	}
	forbidden := []string{
		"context_bytes",
		"model_api_key text",
		"model_api_key bytea",
		"secret_value text",
		"secret_value bytea",
		"credential_payload",
	}
	lowerSQL := strings.ToLower(sql)
	for _, fragment := range forbidden {
		if strings.Contains(lowerSQL, fragment) {
			t.Fatalf(
				"Team Worker input migration persists forbidden material %q",
				fragment,
			)
		}
	}
}
