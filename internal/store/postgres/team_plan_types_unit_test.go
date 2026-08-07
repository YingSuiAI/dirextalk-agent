package postgres

import (
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/runtimebounds"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
)

func TestTeamPlanIntentAcceptsDeterministicPiTokenBound(t *testing.T) {
	t.Parallel()
	proposedTokens := teamplan.TokenEstimate{
		InputMinimum:   100_000,
		InputExpected:  500_000,
		InputMaximum:   1_000_000,
		OutputMinimum:  100_000,
		OutputExpected: 500_000,
		OutputMaximum:  1_000_000,
	}
	assignedTokens := proposedTokens
	assignedTokens.OutputExpected =
		runtimebounds.PiDeepSeekMaximumRequestOutputTokens
	assignedTokens.OutputMaximum =
		runtimebounds.PiDeepSeekMaximumRequestOutputTokens
	duration := teamplan.DurationEstimate{
		Minimum:  10 * time.Minute,
		Expected: 30 * time.Minute,
		Maximum:  50 * time.Minute,
	}
	assignment := teamplan.WorkerAssignment{
		RoleID:               "logscope",
		Title:                "LogScope",
		Objective:            "Build and verify LogScope.",
		WorkClass:            teamplan.WorkSoftwareImplementation,
		RequiredCapabilities: []teamplan.Capability{teamplan.CapabilityShell},
		Workspace:            teamplan.WorkspaceIsolated,
		Duration:             duration,
		Tokens:               assignedTokens,
		RuntimeAdapter:       teamplan.AdapterPiV1,
		ModelProvider:        "deepseek",
		Resources: teamplan.ResourceEnvelope{
			VCPU: 2, MemoryMiB: 2048, DiskGiB: 20,
		},
	}
	role := teamplan.RoleProposal{
		RoleID:               assignment.RoleID,
		Title:                assignment.Title,
		Objective:            assignment.Objective,
		WorkClass:            assignment.WorkClass,
		RequiredCapabilities: assignment.RequiredCapabilities,
		Workspace:            assignment.Workspace,
		Duration:             duration,
		Tokens:               proposedTokens,
		MinimumResources:     assignment.Resources,
	}
	plan := teamplan.Plan{
		WorkerCount: 1,
		Assignments: []teamplan.WorkerAssignment{assignment},
	}
	intent := TeamPlanPreparationIntent{
		Proposal: teamplan.TeamProposal{Roles: []teamplan.RoleProposal{role}},
	}
	if !teamPlanMatchesPreparationIntent(plan, intent) {
		t.Fatal("deterministically bounded Pi assignment was rejected")
	}
	intent.Proposal.Roles[0].Tokens.InputMaximum++
	if teamPlanMatchesPreparationIntent(plan, intent) {
		t.Fatal("changed proposal tokens were accepted")
	}
}
