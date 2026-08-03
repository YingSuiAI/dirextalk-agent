package migrations

import (
	"strings"
	"testing"
)

func TestTeamExecutionReportMigrationFreezesSafeVerifiedProjection(
	t *testing.T,
) {
	t.Parallel()
	raw, err := Files.ReadFile(
		"000054_team_execution_report.up.sql",
	)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"report_digest",
		"report_json",
		"report_generated_at",
		"dirextalk.agent.team-execution-report/v1",
		"completed Team execution requires a final report",
		"result_evidence_digest",
		"result_evidence_json",
		"Team execution report projection differs from evidence",
		"Team execution report usage differs from evidence",
		"Team execution report is immutable",
		"CREATE TRIGGER team_executions_report_guard",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("Team report migration missing %q", fragment)
		}
	}
	lowerSQL := strings.ToLower(sql)
	for _, forbidden := range []string{
		"model_api_key",
		"credential_payload",
		"secret_access_key",
		"session_token",
		"raw_output",
	} {
		if strings.Contains(lowerSQL, forbidden) {
			t.Fatalf(
				"Team report migration persists forbidden field %q",
				forbidden,
			)
		}
	}
}
