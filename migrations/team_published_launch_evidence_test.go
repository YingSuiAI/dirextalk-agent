package migrations

import (
	"strings"
	"testing"
)

func TestTeamPublishedLaunchEvidenceMigrationFreezesNonSecretIdentityInputs(
	t *testing.T,
) {
	t.Parallel()
	raw, err := Files.ReadFile(
		"000052_team_published_launch_evidence.up.sql",
	)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	required := []string{
		"published_evidence_digest",
		"published_evidence_json",
		"published_at",
		"team_role_published_evidence_complete",
		"team_role_published_evidence_required",
		"dirextalk.agent.team-published-evidence/v1",
		"installer_root_trust",
		"installer_secrets",
		"model_credential_ref",
		"must be frozen at artifacts_ready",
		"publication evidence is immutable",
		"CREATE TRIGGER team_role_dispatches_publication_bound",
		"CREATE TRIGGER team_role_dispatches_publication_guard",
	}
	for _, fragment := range required {
		if !strings.Contains(sql, fragment) {
			t.Fatalf(
				"Team publication evidence migration missing %q",
				fragment,
			)
		}
	}
	lowerSQL := strings.ToLower(sql)
	for _, forbidden := range []string{
		"model_api_key",
		"secret_value",
		"credential_payload",
	} {
		if strings.Contains(lowerSQL, forbidden) {
			t.Fatalf(
				"Team publication migration persists forbidden field %q",
				forbidden,
			)
		}
	}
}
