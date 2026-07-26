package migrations

import (
	"strings"
	"testing"
)

func TestPlanningSourceClaimsMigrationIsUpgradeCompatible(t *testing.T) {
	raw, err := Files.ReadFile("000042_planning_source_claims.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	if !strings.Contains(sql, "add column source_claim jsonb") ||
		!strings.Contains(sql, "source_claim is null") ||
		strings.Contains(sql, "source_claim jsonb not null") {
		t.Fatalf("source-claim migration must preserve pre-upgrade evidence rows: %s", sql)
	}
}
