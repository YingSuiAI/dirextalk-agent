package app

import (
	"reflect"
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
)

func TestTeamPlanServiceScopesSeparateReadWriteAndApproval(t *testing.T) {
	t.Parallel()
	want := map[string]string{
		agentv1.TeamPlanService_PrepareTeamPlanV3_FullMethodName:                  "team.plan.write",
		agentv1.TeamPlanService_GetTeamPlanV3_FullMethodName:                      "team.plan.read",
		agentv1.TeamPlanService_GetTeamExecutionV3_FullMethodName:                 "team.plan.read",
		agentv1.TeamPlanService_DownloadTeamArtifactV3_FullMethodName:             "team.artifact.read",
		agentv1.TeamPlanService_BootstrapFirstTeamApprovalDeviceV3_FullMethodName: "team.approval_device.bootstrap",
		agentv1.TeamPlanService_CreateTeamApprovalChallengeV3_FullMethodName:      "team.plan.approve",
		agentv1.TeamPlanService_ApproveTeamPlanV3_FullMethodName:                  "team.plan.approve",
	}
	if got := teamPlanServiceScopes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Team Plan scopes=%#v, want %#v", got, want)
	}
}
