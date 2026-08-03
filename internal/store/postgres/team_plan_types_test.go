package postgres

import (
	"testing"
	"time"
)

func TestTeamApprovalChallengeDigestExcludesGeneratedAuthorization(t *testing.T) {
	t.Parallel()
	command := CreateTeamApprovalChallengeCommand{
		IdempotencyKey:             "11111111-1111-4111-8111-111111111111",
		OwnerID:                    "owner-team",
		PlanID:                     "22222222-2222-4222-8222-222222222222",
		PlanRevision:               1,
		ExpectedPlanRecordRevision: 1,
		ApprovalID:                 "33333333-3333-4333-8333-333333333333",
		ChallengeID:                "44444444-4444-4444-8444-444444444444",
		SignerKeyID:                "cloud-device-stable",
	}
	command.Authorization.AuthorizationID =
		"55555555-5555-4555-8555-555555555555"
	command.Authorization.LaunchNotBefore = time.Date(
		2026,
		8,
		3,
		12,
		0,
		0,
		0,
		time.UTC,
	)
	first, err := command.digest()
	if err != nil {
		t.Fatal(err)
	}

	changed := command
	changed.Authorization.AuthorizationID =
		"66666666-6666-4666-8666-666666666666"
	changed.Authorization.LaunchNotBefore =
		command.Authorization.LaunchNotBefore.Add(30 * time.Second)
	second, err := changed.digest()
	if err != nil {
		t.Fatal(err)
	}
	find, err := (FindTeamApprovalChallengeCommand{
		IdempotencyKey:             command.IdempotencyKey,
		OwnerID:                    command.OwnerID,
		PlanID:                     command.PlanID,
		PlanRevision:               command.PlanRevision,
		ExpectedPlanRecordRevision: command.ExpectedPlanRecordRevision,
		ApprovalID:                 command.ApprovalID,
		ChallengeID:                command.ChallengeID,
		SignerKeyID:                command.SignerKeyID,
	}).digest()
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first != find {
		t.Fatal("challenge intent digest changed with generated authorization")
	}
}
