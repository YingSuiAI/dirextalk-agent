package migrations

import (
	"strings"
	"testing"
)

func TestTurnControllerMigrationKeepsControlFactsFenced(t *testing.T) {
	t.Parallel()
	raw, err := Files.ReadFile("000045_turn_controller.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	required := []string{
		"CREATE TABLE agent_turns",
		"CREATE TABLE agent_turn_events",
		"UNIQUE (\n        agent_instance_id,\n        caller_client_id,\n        caller_credential_id,\n        request_id",
		"FOREIGN KEY (plan_id, plan_revision)",
		"REFERENCES team_plan_approvals(approval_id)",
		"REFERENCES tasks(task_id)",
		"CREATE INDEX agent_turns_recovery_idx",
		"CREATE TRIGGER agent_turns_controlled_transition",
		"CREATE TRIGGER agent_turn_events_valid_insert",
		"CREATE TRIGGER agent_turn_events_immutable",
		"Turn identity is immutable",
		"invalid Turn route decision",
		"invalid Turn approval binding",
		"invalid Turn response binding",
		"invalid Turn event authority or artifact",
	}
	for _, fragment := range required {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("Turn Controller migration missing %q", fragment)
		}
	}
	forbidden := []string{
		"message_content",
		"reasoning_content",
		"tool_arguments",
		"tool_result_content",
		"private_key",
		"secret_access_key",
		"session_token",
		"model_api_key",
	}
	lower := strings.ToLower(sql)
	for _, fragment := range forbidden {
		if strings.Contains(lower, fragment) {
			t.Fatalf("Turn Controller migration persists forbidden field %q", fragment)
		}
	}
}
