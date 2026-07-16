package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
)

type pendingFoundationLaunches struct {
	handoffs []cloudapp.FoundationLaunchHandoff
}

func (source *pendingFoundationLaunches) ListPendingFoundationLaunchHandoffs(context.Context, int) ([]cloudapp.FoundationLaunchHandoff, error) {
	return append([]cloudapp.FoundationLaunchHandoff(nil), source.handoffs...), nil
}

type compensatingLauncher struct {
	source   *pendingFoundationLaunches
	scopes   []cloudapp.MutationScope
	commands []cloudapp.SubmitApprovedPlanCommand
	err      error
}

func (launcher *compensatingLauncher) SubmitApprovedPlan(_ context.Context, scope cloudapp.MutationScope, command cloudapp.SubmitApprovedPlanCommand) error {
	launcher.scopes = append(launcher.scopes, scope)
	launcher.commands = append(launcher.commands, command)
	if launcher.err == nil {
		launcher.source.handoffs = nil
	}
	return launcher.err
}

func TestFoundationLaunchCompensatorRetriesExactDurableHandoffUntilIntentExists(t *testing.T) {
	handoff := cloudapp.FoundationLaunchHandoff{
		Caller:     cloudapp.MutationScope{ClientID: "message-server", CredentialID: "019b2d57-b3c0-7e65-a1d2-10c43de26721"},
		OwnerID:    "owner-foundation-handoff",
		PlanID:     "019b2d57-b3c0-7e65-a1d2-10c43de26722",
		ApprovalID: "019b2d57-b3c0-7e65-a1d2-10c43de26723",
	}
	source := &pendingFoundationLaunches{handoffs: []cloudapp.FoundationLaunchHandoff{handoff}}
	launcher := &compensatingLauncher{source: source, err: errors.New("launch intent store temporarily unavailable")}
	compensator, err := newFoundationLaunchCompensator(source, launcher, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	if err := compensator.RunOnce(context.Background()); err == nil {
		t.Fatal("first compensation unexpectedly succeeded")
	}
	launcher.err = nil
	if err := compensator.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := compensator.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	wantCommand := cloudapp.SubmitApprovedPlanCommand{OwnerID: handoff.OwnerID, PlanID: handoff.PlanID, ApprovalID: handoff.ApprovalID}
	if len(launcher.commands) != 2 || launcher.commands[0] != wantCommand || launcher.commands[1] != wantCommand {
		t.Fatalf("compensated commands=%#v, want two exact retries of %#v", launcher.commands, wantCommand)
	}
	if len(launcher.scopes) != 2 || launcher.scopes[0] != handoff.Caller || launcher.scopes[1] != handoff.Caller {
		t.Fatalf("compensated scopes=%#v, want caller-bound retries", launcher.scopes)
	}
}
