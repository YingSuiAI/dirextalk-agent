package cloudapp

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
)

type launcherFacts struct {
	*coordinatorFacts
	persistedApproval cloudapproval.ApprovalV1
	persistedKey      string
	persisted         bool
}

func (facts *launcherFacts) PersistApproval(_ context.Context, _ MutationScope, key string, _, _ uint64, approval cloudapproval.ApprovalV1) (cloudapproval.PlanV1, error) {
	if facts.persisted {
		if key != facts.persistedKey || approval.Signature != facts.persistedApproval.Signature || approval.ApprovalID != facts.persistedApproval.ApprovalID {
			return cloudapproval.PlanV1{}, ErrRevisionConflict
		}
		return facts.plan, nil
	}
	facts.persistedApproval = approval
	facts.persistedKey = key
	facts.persisted = true
	facts.approval = approval
	facts.challenge.Revision++
	consumedAt := approval.ExpiresAt.Add(-time.Minute)
	facts.challenge.ConsumedAt = &consumedAt
	approved := facts.plan
	approved.Status = cloudapproval.PlanApproved
	approved.Revision++
	facts.plan = approved
	return approved, nil
}

type recordingDeploymentLauncher struct {
	facts                 *launcherFacts
	commands              []SubmitApprovedPlanCommand
	scopes                []MutationScope
	persistedBeforeSubmit []bool
	err                   error
}

func (launcher *recordingDeploymentLauncher) SubmitApprovedPlan(_ context.Context, scope MutationScope, command SubmitApprovedPlanCommand) error {
	launcher.scopes = append(launcher.scopes, scope)
	launcher.commands = append(launcher.commands, command)
	launcher.persistedBeforeSubmit = append(launcher.persistedBeforeSubmit, launcher.facts.persisted)
	return launcher.err
}

type recordingConnectionEstablisher struct {
	command EstablishConnectionCommand
	calls   int
}

func (establisher *recordingConnectionEstablisher) EstablishAWSConnection(_ context.Context, _ MutationScope, command EstablishConnectionCommand) (Connection, error) {
	if err := command.Validate(); err != nil {
		return Connection{}, err
	}
	establisher.command = command
	establisher.calls++
	return Connection{ConnectionID: "019b2d57-b3c0-7e65-a1d2-10c43de26717", OwnerID: command.OwnerID, Status: "active", Revision: 1}, nil
}

func TestApprovePlanPersistsApprovalBeforeSubmittingDeployment(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	plan := coordinatorPlan(now)
	command, challenge := launcherApprovalCommand(plan, now)
	facts := &launcherFacts{coordinatorFacts: &coordinatorFacts{plan: plan, challenge: challenge}}
	submitErr := errors.New("durable launch queue unavailable")
	launcher := &recordingDeploymentLauncher{facts: facts, err: submitErr}
	service, err := NewService(
		testAgentID, facts, coordinatorRecipes{}, coordinatorQuotes{}, &coordinatorApprovals{}, nil, nil,
		Capabilities{}, func() time.Time { return now }, WithDeploymentLauncher(launcher),
	)
	if err != nil {
		t.Fatal(err)
	}

	approved, err := service.ApprovePlan(context.Background(), MutationScope{ClientID: "message-server", CredentialID: testCredentialID}, command)
	if !errors.Is(err, submitErr) {
		t.Fatalf("ApprovePlan error=%v, want launcher error", err)
	}
	if approved.Status != cloudapproval.PlanApproved || approved.Revision != plan.Revision+1 || !facts.persisted {
		t.Fatalf("approval was not durably persisted before launch: approved=%#v persisted=%t", approved, facts.persisted)
	}
	if len(launcher.commands) != 1 || len(launcher.persistedBeforeSubmit) != 1 || !launcher.persistedBeforeSubmit[0] {
		t.Fatalf("launcher observations: commands=%#v persisted=%#v", launcher.commands, launcher.persistedBeforeSubmit)
	}
	if launcher.commands[0].ApprovalID != facts.persistedApproval.ApprovalID {
		t.Fatalf("launcher approval=%q persisted approval=%q", launcher.commands[0].ApprovalID, facts.persistedApproval.ApprovalID)
	}
}

func TestApprovePlanExactRetryAfterLauncherFailureReplaysDurableApproval(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	currentTime := now
	plan := coordinatorPlan(now)
	command, challenge := launcherApprovalCommand(plan, now)
	facts := &launcherFacts{coordinatorFacts: &coordinatorFacts{plan: plan, challenge: challenge}}
	launcherErr := errors.New("connection is not established yet")
	launcher := &recordingDeploymentLauncher{facts: facts, err: launcherErr}
	service, err := NewService(
		testAgentID, facts, coordinatorRecipes{}, coordinatorQuotes{}, &coordinatorApprovals{}, nil, nil,
		Capabilities{}, func() time.Time { return currentTime }, WithDeploymentLauncher(launcher),
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := MutationScope{ClientID: "message-server", CredentialID: testCredentialID}
	first, err := service.ApprovePlan(context.Background(), scope, command)
	if !errors.Is(err, launcherErr) || first.Status != cloudapproval.PlanApproved || first.Revision != plan.Revision+1 {
		t.Fatalf("first approval=%#v err=%v", first, err)
	}
	launcher.err = nil
	replayed, err := service.ApprovePlan(context.Background(), scope, command)
	if err != nil || replayed.PlanID != first.PlanID || replayed.Revision != first.Revision || replayed.Status != first.Status {
		t.Fatalf("exact approval retry=%#v err=%v, want %#v", replayed, err, first)
	}
	if len(launcher.commands) != 2 || launcher.commands[0] != launcher.commands[1] {
		t.Fatalf("launcher retry changed approved command: %#v", launcher.commands)
	}
	currentTime = command.Approval.ExpiresAt.Add(time.Minute)
	replayed, err = service.ApprovePlan(context.Background(), scope, command)
	if err != nil || replayed.PlanID != first.PlanID || replayed.Revision != first.Revision || replayed.Status != first.Status {
		t.Fatalf("expired exact approval replay=%#v err=%v, want durable %#v", replayed, err, first)
	}
	if len(launcher.commands) != 2 {
		t.Fatalf("expired read-only replay resubmitted launcher: %#v", launcher.commands)
	}
	otherKey := command
	otherKey.IdempotencyKey = "019b2d57-b3c0-7e65-a1d2-10c43de26729"
	if _, err = service.ApprovePlan(context.Background(), scope, otherKey); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("different idempotency key error=%v, want revision conflict", err)
	}
	changedApproval := command
	changedApproval.Approval.Signature = append([]byte(nil), command.Approval.Signature...)
	changedApproval.Approval.Signature[0] ^= 1
	if _, err = service.ApprovePlan(context.Background(), scope, changedApproval); !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("changed approval under same idempotency key error=%v, want approval required", err)
	}
}

func TestEstablishAWSConnectionResubmitsTheSameApprovedPlan(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	plan := coordinatorPlan(now)
	approveCommand, challenge := launcherApprovalCommand(plan, now)
	facts := &launcherFacts{coordinatorFacts: &coordinatorFacts{plan: plan, challenge: challenge}}
	launcher := &recordingDeploymentLauncher{facts: facts}
	connections := &recordingConnectionEstablisher{}
	service, err := NewService(
		testAgentID, facts, coordinatorRecipes{}, coordinatorQuotes{}, &coordinatorApprovals{}, nil, connections,
		Capabilities{}, func() time.Time { return now }, WithDeploymentLauncher(launcher),
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := MutationScope{ClientID: "message-server", CredentialID: testCredentialID}
	approved, err := service.ApprovePlan(context.Background(), scope, approveCommand)
	if err != nil {
		t.Fatal(err)
	}
	establishCommand := EstablishConnectionCommand{
		IdempotencyKey:          "019b2d57-b3c0-7e65-a1d2-10c43de26724",
		OwnerID:                 plan.OwnerID,
		BootstrapSessionID:      "019b2d57-b3c0-7e65-a1d2-10c43de26725",
		ExpectedSessionRevision: 2,
		PlanID:                  plan.PlanID,
		ExpectedPlanRevision:    approved.Revision,
		Approval:                approveCommand.Approval,
	}
	connection, err := service.EstablishAWSConnection(context.Background(), scope, establishCommand)
	if err != nil {
		t.Fatal(err)
	}
	if connection.Status != "active" || connections.calls != 1 || connections.command.PlanID != plan.PlanID {
		t.Fatalf("connection=%#v establisher calls=%d command=%#v", connection, connections.calls, connections.command)
	}
	if len(launcher.commands) != 2 || launcher.commands[0] != launcher.commands[1] {
		t.Fatalf("approved plan was not resubmitted unchanged: %#v", launcher.commands)
	}
	if launcher.commands[1] != (SubmitApprovedPlanCommand{OwnerID: plan.OwnerID, PlanID: plan.PlanID, ApprovalID: approveCommand.Approval.ApprovalID}) {
		t.Fatalf("unexpected resubmitted plan: %#v", launcher.commands[1])
	}
}

func launcherApprovalCommand(plan cloudapproval.PlanV1, now time.Time) (ApprovePlanCommand, cloudapproval.ChallengeV1) {
	challenge := cloudapproval.ChallengeV1{ChallengeID: "challenge_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Revision: 1}
	return ApprovePlanCommand{
		IdempotencyKey:   "019b2d57-b3c0-7e65-a1d2-10c43de26721",
		OwnerID:          plan.OwnerID,
		PlanID:           plan.PlanID,
		ExpectedRevision: plan.Revision,
		Approval: ApprovalSignature{
			ApprovalID:  "019b2d57-b3c0-7e65-a1d2-10c43de26722",
			ChallengeID: challenge.ChallengeID,
			SignerKeyID: "device-key-1",
			ExpiresAt:   now.Add(5 * time.Minute),
			Signature:   make([]byte, ed25519.SignatureSize),
		},
	}, challenge
}
