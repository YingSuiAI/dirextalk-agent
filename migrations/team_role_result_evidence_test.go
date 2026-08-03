package migrations

import (
	"strings"
	"testing"
)

func TestTeamRoleResultEvidenceMigrationFreezesVerifiedBoundedOutput(
	t *testing.T,
) {
	t.Parallel()
	raw, err := Files.ReadFile(
		"000053_team_role_result_evidence.up.sql",
	)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	required := []string{
		"result_evidence_digest",
		"result_evidence_json",
		"result_verified_at",
		"team_role_success_requires_result",
		"dirextalk.agent.team-role-result/v1",
		"deployment.state='finished'",
		"deployment.outcome='succeeded'",
		"untrusted_worker_claim",
		"must be frozen at result_ready",
		"result evidence is immutable",
		"CREATE TRIGGER team_role_dispatches_result_bound",
		"CREATE TRIGGER team_role_dispatches_result_guard",
	}
	for _, fragment := range required {
		if !strings.Contains(sql, fragment) {
			t.Fatalf(
				"Team result evidence migration missing %q",
				fragment,
			)
		}
	}
	lowerSQL := strings.ToLower(sql)
	for _, forbidden := range []string{
		"model_api_key",
		"credential_payload",
		"raw_output",
	} {
		if strings.Contains(lowerSQL, forbidden) {
			t.Fatalf(
				"Team result migration persists forbidden field %q",
				forbidden,
			)
		}
	}
}
