package migrations

import (
	"strings"
	"testing"
)

func TestTeamRoleProvisioningQuoteMigrationFreezesProviderEvidence(
	t *testing.T,
) {
	t.Parallel()
	raw, err := Files.ReadFile(
		"000051_team_role_provisioning_quote.up.sql",
	)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	required := []string{
		"provisioning_quote_digest",
		"provisioning_quote_json",
		"provisioning_quote_valid_until",
		"provisioning_started_at",
		"provisioning_worker_revision",
		"provisioning_enrollment_expires_at",
		"team_role_provisioning_quote_complete",
		"team_role_provisioning_quote_required",
		"dirextalk.agent.team-fresh-launch-quote/v1",
		"team_launch_authorizations",
		"maximum_approved_cost_micros",
		"must be frozen at provisioning",
		"fresh quote is immutable",
		"CREATE TRIGGER team_role_dispatches_quote_bound",
		"CREATE TRIGGER team_role_dispatches_quote_guard",
		"DROP CONSTRAINT worker_installer_capability_shape",
	}
	for _, fragment := range required {
		if !strings.Contains(sql, fragment) {
			t.Fatalf(
				"Team provisioning quote migration missing %q",
				fragment,
			)
		}
	}
}
