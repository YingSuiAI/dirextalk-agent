package migrations

import (
	"strings"
	"testing"
)

func TestPairingResumeSignatureIsIsolatedFromChallengeAndReplay(t *testing.T) {
	raw, err := Files.ReadFile("000035_pairing_resume_approval.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	script := strings.ToLower(string(raw))
	approvalAt := strings.Index(script, "create table pairing_resume_approvals")
	replayAt := strings.Index(script, "create table pairing_resume_replays")
	if approvalAt < 0 || replayAt <= approvalAt {
		t.Fatal("pairing resume approval migration sections are missing")
	}
	challengeSection := script[:approvalAt]
	approvalSection := script[approvalAt:replayAt]
	replaySection := script[replayAt:]
	if strings.Contains(challengeSection, "\n    signature ") {
		t.Fatal("challenge table must not persist approval signatures")
	}
	if !strings.Contains(approvalSection, "\n    signature bytea") {
		t.Fatal("approval table must be the signature authority")
	}
	for _, forbidden := range []string{"\n    signature ", "response_json", "approval_json"} {
		if strings.Contains(replaySection, forbidden) {
			t.Fatalf("replay table persists forbidden approval material %q", forbidden)
		}
	}
}
