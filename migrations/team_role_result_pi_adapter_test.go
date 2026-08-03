package migrations

import (
	"strings"
	"testing"
)

func TestTeamRoleResultPiAdapterMigrationExtendsExistingValidator(
	t *testing.T,
) {
	t.Parallel()
	raw, err := Files.ReadFile(
		"000062_team_role_result_pi_adapter.up.sql",
	)
	if err != nil {
		t.Fatal(err)
	}
	migration := string(raw)
	for _, expected := range []string{
		"CREATE OR REPLACE FUNCTION validate_team_role_result_evidence()",
		"'pi_json_task_v1'",
		"deployment.state='finished'",
		"deployment.outcome='succeeded'",
		"untrusted_worker_claim",
		"NOT BETWEEN 1 AND 8388608",
	} {
		if !strings.Contains(migration, expected) {
			t.Fatalf("Pi result migration missing %q", expected)
		}
	}
}
