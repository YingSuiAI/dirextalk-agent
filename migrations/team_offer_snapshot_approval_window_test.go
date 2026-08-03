package migrations

import (
	"strings"
	"testing"
)

func TestTeamOfferSnapshotApprovalWindowMigration(t *testing.T) {
	t.Parallel()
	raw, err := Files.ReadFile(
		"000060_team_offer_snapshot_approval_window.up.sql",
	)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"ALTER TABLE team_offer_snapshots",
		"DROP CONSTRAINT team_offer_snapshots_check",
		"ADD CONSTRAINT team_offer_snapshots_validity_window_check",
		"valid_until > captured_at",
		"valid_until <= captured_at + interval '24 hours'",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("Team offer approval-window migration missing %q", fragment)
		}
	}
	for _, forbidden := range []string{
		"DROP TABLE",
		"TRUNCATE",
		"DELETE FROM",
		"DISABLE TRIGGER",
		"session_replication_role",
	} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf(
				"Team offer approval-window migration uses %q",
				forbidden,
			)
		}
	}
}
