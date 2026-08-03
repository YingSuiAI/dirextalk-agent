package migrations

import (
	"strings"
	"testing"
)

func TestTeamRoleDispatchMigrationFencesConcurrencyReservationInputs(
	t *testing.T,
) {
	t.Parallel()
	raw, err := Files.ReadFile("000050_team_role_dispatches.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	required := []string{
		"CREATE TABLE team_role_dispatches",
		"UNIQUE (execution_id, role_id)",
		"REFERENCES team_launch_authorizations",
		"execution.status IN ('dispatching', 'running')",
		"plan.status='executing'",
		"step.execution_status='queued'",
		"required_step.outcome_status='succeeded'",
		"maximum_approved_cost_micros",
		"model_credential_ref",
		"Team role dispatch is not bound to a ready signed role",
		"Team role dispatch intent is immutable",
		"invalid Team role dispatch retry",
		"CREATE TRIGGER team_role_dispatches_bound_insert",
		"CREATE TRIGGER team_role_dispatches_state_guard",
	}
	for _, fragment := range required {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("Team role dispatch migration missing %q", fragment)
		}
	}
}
