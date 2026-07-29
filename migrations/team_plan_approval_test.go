package migrations

import (
	"strings"
	"testing"
)

func TestTeamPlanApprovalMigrationPreservesImmutableSignedDocuments(
	t *testing.T,
) {
	t.Parallel()
	raw, err := Files.ReadFile("000044_team_plan_approval.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	required := []string{
		"CREATE TABLE team_offer_snapshots",
		"CREATE TABLE team_plans",
		"PRIMARY KEY (plan_id, plan_revision)",
		"CREATE UNIQUE INDEX team_plans_one_active_revision_idx",
		"CREATE TABLE team_plan_approval_challenges",
		"CREATE TABLE team_plan_approvals",
		"snapshot_cbor bytea NOT NULL",
		"plan_cbor bytea NOT NULL",
		"signing_payload bytea NOT NULL",
		"signature bytea NOT NULL",
		"connection_revision bigint NOT NULL",
		"account_id text NOT NULL",
		"record_revision bigint NOT NULL",
		"CREATE TRIGGER team_offer_snapshots_immutable",
		"CREATE TRIGGER team_plans_state_only",
		"CREATE TRIGGER team_plan_challenges_consume_only",
		"CREATE TRIGGER team_plan_approvals_immutable",
		"signed Team Plan fields are immutable",
		"new Team Plan must start ready at record revision 1",
		"new Team Plan challenge must be pending at record revision 1",
	}
	for _, fragment := range required {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("Team Plan migration missing %q", fragment)
		}
	}
	forbidden := []string{
		"private_key",
		"secret_access_key",
		"session_token",
		"model_api_key",
	}
	for _, fragment := range forbidden {
		if strings.Contains(strings.ToLower(sql), fragment) {
			t.Fatalf("Team Plan migration persists forbidden material %q", fragment)
		}
	}
}
