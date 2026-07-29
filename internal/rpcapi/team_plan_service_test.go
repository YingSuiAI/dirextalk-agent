package rpcapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamapproval"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestTeamPlanServiceMapsTrustedPreparationAndRedactsCredentialReference(
	t *testing.T,
) {
	t.Parallel()
	fact := rpcTeamPlanFact(t, teamorchestration.PlanReadyForConfirmation)
	stub := &teamPlanRPCStub{plan: fact}
	service := NewTeamPlanService(stub, stub)
	principal := auth.Principal{
		ClientID:     "message-server",
		CredentialID: uuid.NewString(),
	}
	request := rpcPrepareTeamPlanRequest(fact)
	response, err := service.PrepareTeamPlanV3(
		auth.ContextWithPrincipal(context.Background(), principal),
		request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if stub.prepareCalls != 1 ||
		stub.scope != (task.MutationScope{
			ClientID:     principal.ClientID,
			CredentialID: principal.CredentialID,
		}) ||
		stub.prepare.ConnectionID != request.GetCloudConnectionId() ||
		stub.prepare.Proposal.Roles[0].PreferredFamilies[0] !=
			teamplan.RuntimeCodex {
		t.Fatalf(
			"scope=%#v command=%#v calls=%d",
			stub.scope,
			stub.prepare,
			stub.prepareCalls,
		)
	}
	projected := response.GetPlan()
	if projected.GetPlanDigest() != fact.PlanDigest ||
		projected.GetProviderScope().GetAccountId() !=
			fact.Plan.ProviderScope.AccountID ||
		projected.GetAssignments()[0].GetRuntimeFamily() !=
			agentv1.TeamRuntimeFamilyV3_TEAM_RUNTIME_FAMILY_V3_CODEX ||
		projected.GetCost().GetExpectedMicros() !=
			fact.Plan.Cost.ExpectedMicros {
		t.Fatalf("projected Team Plan=%#v", projected)
	}
	encoded, err := protojson.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("secret_ref:")) ||
		bytes.Contains(bytes.ToLower(encoded), []byte("credential")) {
		t.Fatalf("Team Plan response leaked credential material: %s", encoded)
	}
}

func TestTeamPlanProjectionAllowsZeroColdStart(t *testing.T) {
	t.Parallel()
	fact := rpcTeamPlanFact(t, teamorchestration.PlanReadyForConfirmation)
	fact.Plan.Assignments[0].ColdStart = 0
	digest, err := fact.Plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	fact.PlanDigest = digest
	projected, err := teamPlanToProto(fact)
	if err != nil {
		t.Fatal(err)
	}
	if projected.GetAssignments()[0].GetColdStartSeconds() != 0 {
		t.Fatalf(
			"cold_start_seconds=%d, want 0",
			projected.GetAssignments()[0].GetColdStartSeconds(),
		)
	}
}

func TestTeamPlanServiceChallengeIDsAreStableAndPayloadIsComplete(
	t *testing.T,
) {
	t.Parallel()
	fact := rpcTeamPlanFact(t, teamorchestration.PlanReadyForConfirmation)
	stub := &teamPlanRPCStub{plan: fact}
	service := NewTeamPlanService(stub, stub)
	request := &agentv1.CreateTeamApprovalChallengeV3Request{
		IdempotencyKey:             uuid.NewString(),
		OwnerId:                    fact.Plan.OwnerID,
		PlanId:                     fact.Plan.PlanID,
		PlanRevision:               int64(fact.Plan.Revision),
		ExpectedPlanRecordRevision: int64(fact.RecordRevision),
		SignerKeyId:                "owner-device-1",
	}
	ctx := rpcTeamPrincipalContext()
	first, err := service.CreateTeamApprovalChallengeV3(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	firstCommand := stub.challenge
	second, err := service.CreateTeamApprovalChallengeV3(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if firstCommand.ApprovalID != stub.challenge.ApprovalID ||
		firstCommand.ChallengeID != stub.challenge.ChallengeID ||
		firstCommand.ApprovalID == firstCommand.ChallengeID ||
		first.GetChallenge().GetApprovalId() != firstCommand.ApprovalID ||
		second.GetChallenge().GetChallengeId() != firstCommand.ChallengeID {
		t.Fatalf(
			"unstable challenge IDs first=%#v second=%#v",
			firstCommand,
			stub.challenge,
		)
	}
	expectedPayload, err := stub.challengeFact.Challenge.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	projected := first.GetChallenge()
	if !bytes.Equal(projected.GetSigningPayloadCbor(), expectedPayload) ||
		projected.GetPlanDigest() != fact.PlanDigest ||
		projected.GetProviderScope().GetCloudConnectionId() !=
			fact.Plan.ProviderScope.ConnectionID ||
		projected.GetHardBudgetMicros() !=
			fact.Plan.Cost.HardBudgetMicros {
		t.Fatalf("challenge projection lost signed facts: %#v", projected)
	}
}

func TestTeamPlanServiceMapsRawDeviceSignatureAndReadsApprovedPlan(
	t *testing.T,
) {
	t.Parallel()
	fact := rpcTeamPlanFact(t, teamorchestration.PlanReadyForConfirmation)
	stub := &teamPlanRPCStub{plan: fact}
	service := NewTeamPlanService(stub, stub)
	signature := bytes.Repeat([]byte{0x5a}, 64)
	response, err := service.ApproveTeamPlanV3(
		rpcTeamPrincipalContext(),
		&agentv1.ApproveTeamPlanV3Request{
			IdempotencyKey:                  uuid.NewString(),
			OwnerId:                         fact.Plan.OwnerID,
			ExpectedPlanRecordRevision:      int64(fact.RecordRevision),
			ExpectedChallengeRecordRevision: 1,
			Approval: &agentv1.TeamApprovalSignatureV3{
				ApprovalId:  uuid.NewString(),
				ChallengeId: uuid.NewString(),
				PlanId:      fact.Plan.PlanID,
				PlanRevision: int64(
					fact.Plan.Revision,
				),
				PlanDigest:  fact.PlanDigest,
				SignerKeyId: "owner-device-1",
				Signature:   signature,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if stub.approveCalls != 1 ||
		stub.approval.Signature.SchemaVersion !=
			teamapproval.SignatureSchemaV1 ||
		stub.approval.Signature.SignatureBase64URL !=
			base64.RawURLEncoding.EncodeToString(signature) ||
		response.GetPlan().GetStatus() !=
			agentv1.TeamPlanStatusV3_TEAM_PLAN_STATUS_V3_APPROVED {
		t.Fatalf(
			"approval=%#v response=%#v calls=%d",
			stub.approval,
			response,
			stub.approveCalls,
		)
	}
	read, err := service.GetTeamPlanV3(
		context.Background(),
		&agentv1.GetTeamPlanV3Request{
			OwnerId:      fact.Plan.OwnerID,
			PlanId:       fact.Plan.PlanID,
			PlanRevision: int64(fact.Plan.Revision),
		},
	)
	if err != nil ||
		read.GetPlan().GetStatus() !=
			agentv1.TeamPlanStatusV3_TEAM_PLAN_STATUS_V3_APPROVED {
		t.Fatalf("GetTeamPlanV3() response=%#v error=%v", read, err)
	}
}

func TestTeamPlanServiceRejectsUnknownProposalEnumsAndUnsignedApproval(
	t *testing.T,
) {
	t.Parallel()
	fact := rpcTeamPlanFact(t, teamorchestration.PlanReadyForConfirmation)
	stub := &teamPlanRPCStub{plan: fact}
	service := NewTeamPlanService(stub, stub)
	request := rpcPrepareTeamPlanRequest(fact)
	request.Proposal.Roles[0].WorkClass =
		agentv1.TeamWorkClassV3_TEAM_WORK_CLASS_V3_UNSPECIFIED
	if _, err := service.PrepareTeamPlanV3(
		rpcTeamPrincipalContext(),
		request,
	); status.Code(err) != codes.InvalidArgument ||
		stub.prepareCalls != 0 {
		t.Fatalf(
			"unknown enum error=%v calls=%d",
			err,
			stub.prepareCalls,
		)
	}
	if _, err := service.ApproveTeamPlanV3(
		rpcTeamPrincipalContext(),
		&agentv1.ApproveTeamPlanV3Request{
			IdempotencyKey:                  uuid.NewString(),
			OwnerId:                         fact.Plan.OwnerID,
			ExpectedPlanRecordRevision:      1,
			ExpectedChallengeRecordRevision: 1,
			Approval: &agentv1.TeamApprovalSignatureV3{
				PlanRevision: 1,
				Signature:    make([]byte, 63),
			},
		},
	); status.Code(err) != codes.InvalidArgument ||
		stub.approveCalls != 0 {
		t.Fatalf(
			"unsigned approval error=%v calls=%d",
			err,
			stub.approveCalls,
		)
	}
}

func TestTeamPlanServiceFailsClosedWhenNotConfigured(t *testing.T) {
	t.Parallel()
	service := NewTeamPlanService(nil, nil)
	if _, err := service.GetTeamPlanV3(
		context.Background(),
		&agentv1.GetTeamPlanV3Request{},
	); status.Code(err) != codes.Unavailable {
		t.Fatalf("GetTeamPlanV3() code=%v", status.Code(err))
	}
	if _, err := service.PrepareTeamPlanV3(
		rpcTeamPrincipalContext(),
		&agentv1.PrepareTeamPlanV3Request{},
	); status.Code(err) != codes.Unavailable {
		t.Fatalf("PrepareTeamPlanV3() code=%v", status.Code(err))
	}
}

func TestTeamPlanPublicErrorsHaveStableRecoverySemantics(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		err     error
		code    codes.Code
		message string
	}{
		{
			name:    "requote",
			err:     teamplan.ErrPricingChanged,
			code:    codes.FailedPrecondition,
			message: "Team Plan must be requoted and approved again",
		},
		{
			name:    "not found",
			err:     teamorchestration.ErrNotFound,
			code:    codes.NotFound,
			message: "requested entity was not found",
		},
		{
			name:    "record revision",
			err:     teamorchestration.ErrRevision,
			code:    codes.Aborted,
			message: "Team Plan record revision does not match",
		},
		{
			name:    "signature",
			err:     teamapproval.ErrSignatureInvalid,
			code:    codes.PermissionDenied,
			message: "Team Plan device approval signature is invalid",
		},
		{
			name:    "pricing unavailable",
			err:     teamorchestration.ErrOfferVerificationUnavailable,
			code:    codes.Unavailable,
			message: "trusted Team pricing is unavailable",
		},
		{
			name:    "scope changed",
			err:     teamorchestration.ErrScopeChanged,
			code:    codes.FailedPrecondition,
			message: "Team Plan cloud scope changed",
		},
		{
			name:    "challenge consumed",
			err:     teamorchestration.ErrChallengeConsumed,
			code:    codes.FailedPrecondition,
			message: "Team Plan is not ready for this operation",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			mapped := status.Convert(publicError(test.err))
			if mapped.Code() != test.code ||
				mapped.Message() != test.message {
				t.Fatalf(
					"publicError(%v)=%s/%q, want %s/%q",
					test.err,
					mapped.Code(),
					mapped.Message(),
					test.code,
					test.message,
				)
			}
		})
	}
}

type teamPlanRPCStub struct {
	plan           teamorchestration.PlanFact
	scope          task.MutationScope
	prepare        teamorchestration.PreparePlanRequest
	challenge      teamorchestration.ChallengeRequest
	challengeFact  teamorchestration.ChallengeFact
	approval       teamorchestration.ApprovalRequest
	prepareCalls   int
	challengeCalls int
	approveCalls   int
}

func (stub *teamPlanRPCStub) PreparePlan(
	_ context.Context,
	scope task.MutationScope,
	request teamorchestration.PreparePlanRequest,
) (teamorchestration.PlanFact, error) {
	stub.scope = scope
	stub.prepare = request
	stub.prepareCalls++
	return stub.plan, nil
}

func (stub *teamPlanRPCStub) GetPlan(
	context.Context,
	string,
	string,
	uint64,
) (teamorchestration.PlanFact, error) {
	return stub.plan, nil
}

func (stub *teamPlanRPCStub) CreateChallenge(
	_ context.Context,
	scope task.MutationScope,
	request teamorchestration.ChallengeRequest,
) (teamorchestration.ChallengeFact, error) {
	stub.scope = scope
	stub.challenge = request
	stub.challengeCalls++
	challenge, err := teamapproval.NewChallengeV1(
		stub.plan.Plan,
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		request.ApprovalID,
		request.ChallengeID,
		request.SignerKeyID,
		stub.plan.Plan.QuotedAt.Add(time.Minute),
	)
	if err != nil {
		return teamorchestration.ChallengeFact{}, err
	}
	stub.challengeFact = teamorchestration.ChallengeFact{
		Challenge:      challenge,
		RecordRevision: 1,
		CreatedAt:      challenge.IssuedAt,
		UpdatedAt:      challenge.IssuedAt,
	}
	return stub.challengeFact, nil
}

func (stub *teamPlanRPCStub) ApprovePlan(
	_ context.Context,
	scope task.MutationScope,
	request teamorchestration.ApprovalRequest,
) (teamorchestration.PlanFact, error) {
	stub.scope = scope
	stub.approval = request
	stub.approveCalls++
	stub.plan.Status = teamorchestration.PlanApproved
	stub.plan.RecordRevision++
	stub.plan.UpdatedAt = stub.plan.UpdatedAt.Add(time.Second)
	return stub.plan, nil
}

func rpcTeamPrincipalContext() context.Context {
	return auth.ContextWithPrincipal(
		context.Background(),
		auth.Principal{
			ClientID:     "message-server",
			CredentialID: uuid.NewString(),
		},
	)
}

func rpcPrepareTeamPlanRequest(
	fact teamorchestration.PlanFact,
) *agentv1.PrepareTeamPlanV3Request {
	assignment := fact.Plan.Assignments[0]
	return &agentv1.PrepareTeamPlanV3Request{
		IdempotencyKey:    uuid.NewString(),
		OwnerId:           fact.Plan.OwnerID,
		TaskId:            fact.TaskID,
		CloudConnectionId: fact.Plan.ProviderScope.ConnectionID,
		PlanId:            fact.Plan.PlanID,
		PlanRevision:      int64(fact.Plan.Revision),
		GoalDigest:        fact.Plan.GoalDigest,
		Proposal: &agentv1.TeamProposalV3{
			Confidence: fact.Plan.ProposalConfidence,
			Rationale:  fact.Plan.ProposalRationale,
			Roles: []*agentv1.TeamRoleProposalV3{{
				RoleId:    assignment.RoleID,
				Title:     assignment.Title,
				Objective: assignment.Objective,
				WorkClass: agentv1.TeamWorkClassV3_TEAM_WORK_CLASS_V3_SOFTWARE_IMPLEMENTATION,
				RequiredCapabilities: []agentv1.TeamCapabilityV3{
					agentv1.TeamCapabilityV3_TEAM_CAPABILITY_V3_GIT,
				},
				PreferredRuntimeFamilies: []agentv1.TeamRuntimeFamilyV3{
					agentv1.TeamRuntimeFamilyV3_TEAM_RUNTIME_FAMILY_V3_CODEX,
				},
				WorkspaceMode: agentv1.TeamWorkspaceModeV3_TEAM_WORKSPACE_MODE_V3_ISOLATED,
				Duration: &agentv1.TeamDurationEstimateV3{
					MinimumSeconds:  60,
					ExpectedSeconds: 120,
					MaximumSeconds:  180,
				},
				Tokens: &agentv1.TeamTokenEstimateV3{
					InputMinimum:   1_000,
					InputExpected:  2_000,
					InputMaximum:   3_000,
					OutputMinimum:  100,
					OutputExpected: 200,
					OutputMaximum:  300,
				},
				ModelNeed: &agentv1.TeamModelNeedV3{
					MinimumQuality:       agentv1.TeamQualityTierV3_TEAM_QUALITY_TIER_V3_BALANCED,
					MinimumContextTokens: 1_024,
				},
				MinimumResources: &agentv1.TeamMinimumResourcesV3{
					Vcpu:      2,
					MemoryMib: 8_192,
					DiskGib:   40,
				},
			}},
		},
	}
}

func rpcTeamPlanFact(
	t *testing.T,
	statusValue teamorchestration.PlanStatus,
) teamorchestration.PlanFact {
	t.Helper()
	quotedAt := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	planID := uuid.NewString()
	assignment := teamplan.WorkerAssignment{
		RoleID:    "implementation",
		Title:     "Implementation",
		Objective: "Implement and verify the bounded change.",
		WorkClass: teamplan.WorkSoftwareImplementation,
		RequiredCapabilities: []teamplan.Capability{
			teamplan.CapabilityGit,
		},
		Workspace:          teamplan.WorkspaceIsolated,
		RuntimeReleaseID:   uuid.NewSHA1(uuid.MustParse(planID), []byte("runtime")).String(),
		RuntimeFamily:      teamplan.RuntimeCodex,
		RuntimeVersion:     "1.0.0",
		RuntimeImageDigest: "sha256:" + strings.Repeat("a", 64),
		RuntimeAdapter:     teamplan.AdapterCodexV1,
		ModelProfileID:     "model-balanced",
		ModelProvider:      "openai_compatible",
		Model:              "code-model",
		ModelInterface:     teamplan.ModelOpenAIResponses,
		ModelCredentialRef: "secret_ref:model/worker-balanced",
		ComputeOfferID:     uuid.NewString(),
		InstanceType:       "m7i.large",
		Resources: teamplan.ResourceEnvelope{
			VCPU:      2,
			MemoryMiB: 8_192,
			DiskGiB:   40,
			Arch:      recipe.ArchitectureAMD64,
		},
		Duration: teamplan.DurationEstimate{
			Minimum:  time.Minute,
			Expected: 2 * time.Minute,
			Maximum:  3 * time.Minute,
		},
		Tokens: teamplan.TokenEstimate{
			InputMinimum:   1_000,
			InputExpected:  2_000,
			InputMaximum:   3_000,
			OutputMinimum:  100,
			OutputExpected: 200,
			OutputMaximum:  300,
		},
		ColdStart: 30 * time.Second,
	}
	plan := teamplan.Plan{
		SchemaVersion: teamplan.SchemaV1,
		PlanID:        planID,
		Revision:      1,
		OwnerID:       "owner-team-rpc",
		GoalDigest:    "sha256:" + strings.Repeat("d", 64),
		ProviderScope: teamplan.ProviderScope{
			Provider:           teamplan.CloudProviderAWS,
			ConnectionID:       uuid.NewString(),
			ConnectionRevision: 3,
			AccountID:          "123456789012",
		},
		Region:                "us-east-1",
		CatalogRevision:       "sha256:" + strings.Repeat("c", 64),
		PolicyRevision:        "sha256:" + strings.Repeat("b", 64),
		PricingSnapshotID:     uuid.NewString(),
		PricingSnapshotDigest: "sha256:" + strings.Repeat("e", 64),
		QuotedAt:              quotedAt,
		ValidUntil:            quotedAt.Add(15 * time.Minute),
		ProposalConfidence:    90,
		ProposalRationale:     "One isolated implementation Worker is sufficient.",
		WorkerCount:           1,
		MaxConcurrentWorkers:  1,
		Assignments:           []teamplan.WorkerAssignment{assignment},
		Schedule: teamplan.ScheduleEstimate{
			MinimumWallTime:  time.Minute,
			ExpectedWallTime: 2 * time.Minute,
			MaximumWallTime:  3 * time.Minute,
		},
		Cost: teamplan.CostEstimate{
			Currency:         "USD",
			MinimumMicros:    71_200,
			ExpectedMicros:   132_400,
			MaximumMicros:    193_600,
			HardBudgetMicros: 232_320,
			Roles: []teamplan.RoleCostEstimate{{
				RoleID:                assignment.RoleID,
				ComputeMinimumMicros:  60_000,
				ComputeExpectedMicros: 120_000,
				ComputeMaximumMicros:  180_000,
				ModelMinimumMicros:    1_200,
				ModelExpectedMicros:   2_400,
				ModelMaximumMicros:    3_600,
				TotalMinimumMicros:    71_200,
				TotalExpectedMicros:   132_400,
				TotalMaximumMicros:    193_600,
			}},
			Assumptions: []string{"on_demand_compute"},
			Exclusions:  []string{"third_party_paid_tools"},
		},
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	digest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return teamorchestration.PlanFact{
		TaskID:         uuid.NewString(),
		Plan:           plan,
		PlanDigest:     digest,
		Status:         statusValue,
		RecordRevision: 1,
		CreatedAt:      quotedAt,
		UpdatedAt:      quotedAt,
	}
}

var _ TeamPlanPreparationCoordinator = (*teamPlanRPCStub)(nil)
var _ TeamPlanCoordinator = (*teamPlanRPCStub)(nil)
