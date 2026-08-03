package migrations_test

import (
	"os"
	"strings"
	"testing"
)

func TestTeamProvisioningQuoteRefreshMigrationRetainsAuditHistory(t *testing.T) {
	raw, err := os.ReadFile("000058_team_provisioning_quote_refresh.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, required := range []string{
		"team_role_provisioning_quote_history",
		"Team role quote history is append-only",
		"Team role fresh quote refresh is not authorized",
		"record_team_role_provisioning_quote",
		"deployment.provider_instance_id IS NULL",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration is missing %q", required)
		}
	}
}
