package rpcapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamapproval"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamlaunch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamreport"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
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
		!taskinput.IsEmptyInput(stub.prepare.TaskInput) ||
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
		projected.GetTaskInput().GetInputDigest() !=
			fact.Plan.TaskInput.InputDigest ||
		projected.GetTaskInput().GetWorkspace().GetWorkspaceDigest() !=
			fact.Plan.TaskInput.Workspace.WorkspaceDigest ||
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

func TestTeamRuntimeCodecSupportsPi(t *testing.T) {
	t.Parallel()
	family, err := teamRuntimeFamilyFromProto(
		agentv1.TeamRuntimeFamilyV3_TEAM_RUNTIME_FAMILY_V3_PI,
	)
	if err != nil || family != teamplan.RuntimePi {
		t.Fatalf("Pi family decode = %q, %v", family, err)
	}
	projectedFamily, err := teamRuntimeFamilyToProto(
		teamplan.RuntimePi,
	)
	if err != nil ||
		projectedFamily !=
			agentv1.TeamRuntimeFamilyV3_TEAM_RUNTIME_FAMILY_V3_PI {
		t.Fatalf(
			"Pi family projection = %s, %v",
			projectedFamily,
			err,
		)
	}
	projectedAdapter, err := teamRuntimeAdapterToProto(
		teamplan.AdapterPiV1,
	)
	if err != nil ||
		projectedAdapter !=
			agentv1.TeamRuntimeAdapterV3_TEAM_RUNTIME_ADAPTER_V3_PI_JSON_TASK_V1 {
		t.Fatalf(
			"Pi adapter projection = %s, %v",
			projectedAdapter,
			err,
		)
	}
}

func TestTeamPlanServiceBootstrapsCanonicalFirstApprovalDevice(
	t *testing.T,
) {
	t.Parallel()
	publicKey := bytes.Repeat([]byte{0x37}, ed25519.PublicKeySize)
	digest := sha256.Sum256(publicKey)
	keyID := "cloud-device-" +
		hex.EncodeToString(digest[:])[:24]
	now := time.Now().UTC()
	bootstrapper := &teamApprovalDeviceBootstrapRPCStub{
		device: cloudapproval.DeviceKeyV1{
			KeyID:           keyID,
			AgentInstanceID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			OwnerID:         "owner-team-bootstrap",
			Revision:        1,
			Status:          cloudapproval.DeviceKeyActive,
			PublicKey: append(
				ed25519.PublicKey(nil),
				publicKey...,
			),
			NotBefore: now.Add(-time.Minute),
			ExpiresAt: now.Add(24 * time.Hour),
		},
	}
	service := NewTeamPlanService(nil, nil).
		WithApprovalDeviceBootstrap(bootstrapper)
	request := &agentv1.BootstrapFirstTeamApprovalDeviceV3Request{
		IdempotencyKey: uuid.NewString(),
		OwnerId:        bootstrapper.device.OwnerID,
		KeyId:          keyID,
		PublicKey:      publicKey,
	}
	response, err := service.BootstrapFirstTeamApprovalDeviceV3(
		rpcTeamPrincipalContext(),
		request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if bootstrapper.calls != 1 ||
		bootstrapper.command.IdempotencyKey != request.GetIdempotencyKey() ||
		bootstrapper.command.OwnerID != request.GetOwnerId() ||
		bootstrapper.command.KeyID != keyID ||
		!bytes.Equal(bootstrapper.command.PublicKey, publicKey) ||
		response.GetKeyId() != keyID ||
		response.GetRevision() != 1 ||
		!response.GetExpiresAt().AsTime().Equal(
			bootstrapper.device.ExpiresAt,
		) {
		t.Fatalf(
			"command=%#v response=%#v calls=%d",
			bootstrapper.command,
			response,
			bootstrapper.calls,
		)
	}
}

func TestTeamPlanServiceRejectsMismatchedApprovalDeviceIdentity(
	t *testing.T,
) {
	t.Parallel()
	bootstrapper := &teamApprovalDeviceBootstrapRPCStub{}
	service := NewTeamPlanService(nil, nil).
		WithApprovalDeviceBootstrap(bootstrapper)
	_, err := service.BootstrapFirstTeamApprovalDeviceV3(
		rpcTeamPrincipalContext(),
		&agentv1.BootstrapFirstTeamApprovalDeviceV3Request{
			IdempotencyKey: uuid.NewString(),
			OwnerId:        "owner-team-bootstrap",
			KeyId:          "cloud-device-mismatched",
			PublicKey: bytes.Repeat(
				[]byte{0x48},
				ed25519.PublicKeySize,
			),
		},
	)
	if status.Code(err) != codes.InvalidArgument ||
		bootstrapper.calls != 0 {
		t.Fatalf("error=%v calls=%d", err, bootstrapper.calls)
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
			fact.Plan.Cost.HardBudgetMicros ||
		first.GetAuthorization().GetAuthorizationId() !=
			projected.GetLaunchAuthorizationId() ||
		first.GetAuthorization().GetPlanDigest() != fact.PlanDigest ||
		first.GetAuthorization().GetNetwork().GetPublicInbound() ||
		!first.GetAuthorization().GetRetention().GetAutoDestroy() ||
		first.GetAuthorization().GetRoles()[0].
			GetWorkerImage().GetImageId() == "" {
		t.Fatalf("challenge projection lost signed facts: %#v", projected)
	}
	encoded, err := protojson.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("secret_ref:")) ||
		bytes.Contains(bytes.ToLower(encoded), []byte("credential")) {
		t.Fatalf("launch authorization leaked secret material: %s", encoded)
	}
}

func TestTeamPlanServiceMapsRawDeviceSignatureAndReadsApprovedPlan(
	t *testing.T,
) {
	t.Parallel()
	fact := rpcTeamPlanFact(t, teamorchestration.PlanReadyForConfirmation)
	stub := &teamPlanRPCStub{plan: fact}
	executions := &teamExecutionRPCStub{}
	service := NewTeamPlanService(stub, stub, executions)
	signature := bytes.Repeat([]byte{0x5a}, 64)
	approvalID := uuid.NewString()
	response, err := service.ApproveTeamPlanV3(
		rpcTeamPrincipalContext(),
		&agentv1.ApproveTeamPlanV3Request{
			IdempotencyKey:                  uuid.NewString(),
			OwnerId:                         fact.Plan.OwnerID,
			ExpectedPlanRecordRevision:      int64(fact.RecordRevision),
			ExpectedChallengeRecordRevision: 1,
			Approval: &agentv1.TeamApprovalSignatureV3{
				ApprovalId:  approvalID,
				ChallengeId: uuid.NewString(),
				PlanId:      fact.Plan.PlanID,
				PlanRevision: int64(
					fact.Plan.Revision,
				),
				PlanDigest:                fact.PlanDigest,
				SignerKeyId:               "owner-device-1",
				Signature:                 signature,
				SchemaVersion:             teamapproval.SignatureSchemaV2,
				LaunchAuthorizationId:     uuid.NewString(),
				LaunchAuthorizationDigest: "sha256:" + strings.Repeat("f", 64),
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if stub.approveCalls != 1 ||
		stub.approval.Signature.SchemaVersion !=
			teamapproval.SignatureSchemaV2 ||
		stub.approval.Signature.SignatureBase64URL !=
			base64.RawURLEncoding.EncodeToString(signature) ||
		response.GetPlan().GetStatus() !=
			agentv1.TeamPlanStatusV3_TEAM_PLAN_STATUS_V3_APPROVED ||
		response.GetExecutionId() != mustTeamExecutionID(
			t,
			fact.Plan.PlanID,
			fact.Plan.Revision,
			approvalID,
		) ||
		executions.calls != 1 ||
		executions.request.OwnerID != fact.Plan.OwnerID ||
		executions.request.PlanID != fact.Plan.PlanID ||
		executions.request.PlanRevision != fact.Plan.Revision ||
		executions.request.IdempotencyKey == "" ||
		executions.scope != stub.scope {
		t.Fatalf(
			"approval=%#v response=%#v calls=%d materialization=%#v",
			stub.approval,
			response,
			stub.approveCalls,
			executions,
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

func TestTeamPlanServiceReturnsDurableApprovalWhenMaterializationIsPending(
	t *testing.T,
) {
	t.Parallel()
	fact := rpcTeamPlanFact(t, teamorchestration.PlanReadyForConfirmation)
	stub := &teamPlanRPCStub{plan: fact}
	executions := &teamExecutionRPCStub{err: teamexecution.ErrNotReady}
	service := NewTeamPlanService(stub, stub, executions)
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
				PlanDigest:                fact.PlanDigest,
				SignerKeyId:               "owner-device-1",
				Signature:                 bytes.Repeat([]byte{0x5a}, 64),
				SchemaVersion:             teamapproval.SignatureSchemaV2,
				LaunchAuthorizationId:     uuid.NewString(),
				LaunchAuthorizationDigest: "sha256:" + strings.Repeat("f", 64),
			},
		},
	)
	if err != nil ||
		response.GetPlan().GetStatus() !=
			agentv1.TeamPlanStatusV3_TEAM_PLAN_STATUS_V3_APPROVED ||
		response.GetExecutionId() == "" ||
		executions.calls != 1 {
		t.Fatalf(
			"approval response=%#v error=%v materialization_calls=%d",
			response,
			err,
			executions.calls,
		)
	}
}

func TestTeamPlanServiceRecoversExecutionIDFromApprovedPlan(
	t *testing.T,
) {
	t.Parallel()
	fact := rpcTeamPlanFact(t, teamorchestration.PlanApproved)
	executionID := uuid.NewString()
	reader := &teamExecutionReadRPCStub{
		execution: teamexecution.Fact{
			Execution: teamexecution.ExecutionV1{
				ExecutionID:  executionID,
				OwnerID:      fact.Plan.OwnerID,
				PlanID:       fact.Plan.PlanID,
				PlanRevision: fact.Plan.Revision,
				PlanDigest:   fact.PlanDigest,
			},
		},
		findFound: true,
	}
	service := NewTeamPlanService(
		&teamPlanRPCStub{plan: fact},
		&teamPlanRPCStub{plan: fact},
	).WithExecutionReads(reader, reader)

	response, err := service.GetTeamPlanV3(
		context.Background(),
		&agentv1.GetTeamPlanV3Request{
			OwnerId:      fact.Plan.OwnerID,
			PlanId:       fact.Plan.PlanID,
			PlanRevision: int64(fact.Plan.Revision),
		},
	)
	if err != nil ||
		response.GetExecutionId() != executionID ||
		reader.findCalls != 1 {
		t.Fatalf(
			"GetTeamPlanV3() response=%#v reads=%d error=%v",
			response,
			reader.findCalls,
			err,
		)
	}

	reader.findFound = false
	response, err = service.GetTeamPlanV3(
		context.Background(),
		&agentv1.GetTeamPlanV3Request{
			OwnerId:      fact.Plan.OwnerID,
			PlanId:       fact.Plan.PlanID,
			PlanRevision: int64(fact.Plan.Revision),
		},
	)
	if err != nil || response.GetExecutionId() != "" {
		t.Fatalf(
			"pending materialization response=%#v error=%v",
			response,
			err,
		)
	}
}

func mustTeamExecutionID(
	t *testing.T,
	planID string,
	planRevision uint64,
	approvalID string,
) string {
	t.Helper()
	value, err := teamexecution.DeriveExecutionID(
		planID,
		planRevision,
		approvalID,
	)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestTeamPlanServiceReturnsCompletedExecutionReportWithoutObjectRefs(
	t *testing.T,
) {
	t.Parallel()
	execution, report, artifacts := rpcCompletedTeamExecution(t)
	reader := &teamExecutionReadRPCStub{
		execution: execution,
		report:    report,
		artifacts: artifacts,
	}
	service := NewTeamPlanService(
		&teamPlanRPCStub{},
		&teamPlanRPCStub{},
		&teamExecutionRPCStub{},
	).WithExecutionReads(reader, reader).WithArtifactReads(reader)
	response, err := service.GetTeamExecutionV3(
		context.Background(),
		&agentv1.GetTeamExecutionV3Request{
			OwnerId:     execution.Execution.OwnerID,
			ExecutionId: execution.Execution.ExecutionID,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	projected := response.GetExecution()
	if projected.GetStatus() !=
		agentv1.TeamExecutionStatusV3_TEAM_EXECUTION_STATUS_V3_COMPLETED ||
		projected.GetTaskInput().GetInputDigest() !=
			execution.Execution.TaskInput.InputDigest ||
		projected.GetReport().GetReportDigest() !=
			report.ReportDigest ||
		projected.GetReport().GetRoles()[0].
			GetFinals()[0].GetSummary() !=
			"Implementation completed and verified." ||
		projected.GetReport().GetTotalUsage().GetInputTokens() != 100 ||
		len(projected.GetArtifacts()) != 1 ||
		projected.GetArtifacts()[0].GetName() != "final.json" ||
		projected.GetArtifacts()[0].GetSha256() !=
			artifacts[0].SHA256 ||
		reader.executionCalls != 1 ||
		reader.reportCalls != 1 ||
		reader.artifactCalls != 1 {
		t.Fatalf(
			"execution response=%#v reads=%#v",
			projected,
			reader,
		)
	}
	encoded, err := protojson.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		[]byte("s3://"),
		[]byte("secret_ref:"),
		[]byte("credential"),
		[]byte("artifactRef"),
	} {
		if bytes.Contains(bytes.ToLower(encoded), bytes.ToLower(forbidden)) {
			t.Fatalf(
				"Team execution report leaked %q: %s",
				forbidden,
				encoded,
			)
		}
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
			name: "launch authorization unavailable",
			err: teamorchestration.
				ErrLaunchAuthorizationUnavailable,
			code: codes.Unavailable,
			message: "trusted Team launch authorization " +
				"is unavailable",
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
		{
			name: "approval device already bootstrapped",
			err: errors.Join(
				errors.New("bootstrap failed"),
				ErrTeamApprovalDeviceAlreadyBootstrapped,
			),
			code:    codes.FailedPrecondition,
			message: "another approval device is already linked",
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

type teamExecutionRPCStub struct {
	scope   task.MutationScope
	request teamexecution.MaterializeRequest
	calls   int
	err     error
}

type teamExecutionReadRPCStub struct {
	execution      teamexecution.Fact
	report         teamreport.Fact
	artifacts      []teamartifact.ArtifactV1
	findFound      bool
	findCalls      int
	executionCalls int
	reportCalls    int
	artifactCalls  int
}

type teamApprovalDeviceBootstrapRPCStub struct {
	device  cloudapproval.DeviceKeyV1
	command TeamApprovalDeviceBootstrapCommand
	calls   int
	err     error
}

func (stub *teamApprovalDeviceBootstrapRPCStub) RegisterTeamApprovalSigner(
	_ context.Context,
	_ task.MutationScope,
	command TeamApprovalDeviceBootstrapCommand,
) (cloudapproval.DeviceKeyV1, error) {
	stub.calls++
	stub.command = command
	stub.command.PublicKey = append(
		ed25519.PublicKey(nil),
		command.PublicKey...,
	)
	device := stub.device
	device.PublicKey = append(
		ed25519.PublicKey(nil),
		device.PublicKey...,
	)
	return device, stub.err
}

func (stub *teamExecutionReadRPCStub) FindTeamExecutionByPlan(
	context.Context,
	string,
	string,
	uint64,
) (teamexecution.Fact, bool, error) {
	stub.findCalls++
	return stub.execution, stub.findFound, nil
}

func (stub *teamExecutionReadRPCStub) GetTeamExecution(
	context.Context,
	string,
	string,
) (teamexecution.Fact, error) {
	stub.executionCalls++
	return stub.execution, nil
}

func (stub *teamExecutionReadRPCStub) GetTeamExecutionReport(
	context.Context,
	string,
	string,
) (teamreport.Fact, error) {
	stub.reportCalls++
	return stub.report, nil
}

func (stub *teamExecutionReadRPCStub) ListTeamArtifacts(
	context.Context,
	string,
	string,
) ([]teamartifact.ArtifactV1, error) {
	stub.artifactCalls++
	return append([]teamartifact.ArtifactV1(nil), stub.artifacts...), nil
}

func (stub *teamExecutionRPCStub) Materialize(
	_ context.Context,
	scope task.MutationScope,
	request teamexecution.MaterializeRequest,
) (teamexecution.Fact, error) {
	stub.scope = scope
	stub.request = request
	stub.calls++
	return teamexecution.Fact{}, stub.err
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
	authorization, err := rpcTeamLaunchAuthorization(
		stub.plan.Plan,
		request.ApprovalID,
	)
	if err != nil {
		return teamorchestration.ChallengeFact{}, err
	}
	challenge, err := teamapproval.NewChallengeV2(
		stub.plan.Plan,
		authorization,
		authorization.AgentInstanceID,
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
		Authorization:  &authorization,
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

func rpcCompletedTeamExecution(
	t *testing.T,
) (teamexecution.Fact, teamreport.Fact, []teamartifact.ArtifactV1) {
	t.Helper()
	planFact := rpcTeamPlanFact(
		t,
		teamorchestration.PlanApproved,
	)
	approvalID := uuid.NewString()
	authorization, err := rpcTeamLaunchAuthorization(
		planFact.Plan,
		approvalID,
	)
	if err != nil {
		t.Fatal(err)
	}
	authorizationDigest, err := authorization.Digest()
	if err != nil {
		t.Fatal(err)
	}
	approvedAt := planFact.Plan.QuotedAt.
		Add(2 * time.Minute).
		UTC().
		Truncate(time.Microsecond)
	approved := teamorchestration.ApprovedPlanFact{
		Plan: planFact,
		Approval: teamorchestration.ApprovalFact{
			Signature: teamapproval.SignatureV1{
				SchemaVersion:             teamapproval.SignatureSchemaV2,
				ApprovalID:                approvalID,
				ChallengeID:               uuid.NewString(),
				PlanID:                    planFact.Plan.PlanID,
				PlanRevision:              planFact.Plan.Revision,
				PlanDigest:                planFact.PlanDigest,
				LaunchAuthorizationID:     authorization.AuthorizationID,
				LaunchAuthorizationDigest: authorizationDigest,
				SignerKeyID:               "owner-device-report",
				SignatureBase64URL: base64.RawURLEncoding.EncodeToString(
					bytes.Repeat([]byte{0x5a}, 64),
				),
			},
			Authorization: &authorization,
			ApprovedAt:    approvedAt,
			CreatedAt:     approvedAt,
		},
	}
	execution, err := teamexecution.Materialize(approved)
	if err != nil {
		t.Fatal(err)
	}
	executionDigest, err := execution.Digest()
	if err != nil {
		t.Fatal(err)
	}
	executionFact := teamexecution.Fact{
		Execution:       execution,
		ExecutionDigest: executionDigest,
		Status:          teamexecution.StatusCompleted,
		RecordRevision:  5,
		CreatedAt:       approvedAt,
		UpdatedAt:       approvedAt.Add(time.Minute),
	}
	role := execution.Roles[0]
	reportValue := teamreport.ReportV1{
		SchemaVersion: teamreport.SchemaV1,
		ExecutionID:   execution.ExecutionID,
		OwnerID:       execution.OwnerID,
		TaskID:        execution.TaskID,
		PlanID:        execution.PlanID,
		PlanRevision:  execution.PlanRevision,
		PlanDigest:    execution.PlanDigest,
		Roles: []teamreport.RoleV1{{
			RoleID:               role.RoleID,
			Title:                role.Title,
			RuntimeFamily:        role.RuntimeFamily,
			RuntimeAdapter:       workerruntime.Adapter(role.RuntimeAdapter),
			Outcome:              task.OutcomeSucceeded,
			ResultEvidenceDigest: "sha256:" + strings.Repeat("8", 64),
			Finals: []teamreport.FinalV1{{
				ActionID: "execute",
				Adapter:  workerruntime.AdapterCodexV1,
				Usage: workerruntime.Usage{
					InputTokens: 100, OutputTokens: 20,
				},
				Status:         "completed",
				Summary:        "Implementation completed and verified.",
				Deliverables:   []string{"Implementation"},
				Tests:          []string{"Focused tests passed."},
				Risks:          []string{},
				ArtifactSHA256: "sha256:" + strings.Repeat("9", 64),
			}},
		}},
		TotalUsage: workerruntime.Usage{
			InputTokens: 100, OutputTokens: 20,
		},
	}
	reportDigest, err := reportValue.Digest()
	if err != nil {
		t.Fatal(err)
	}
	reportFact := teamreport.Fact{
		Report:       reportValue,
		ReportDigest: reportDigest,
		GeneratedAt:  executionFact.UpdatedAt,
	}
	if reportFact.Validate() != nil {
		t.Fatal("invalid Team report RPC fixture")
	}
	artifact, err := teamartifact.NewVerified(teamartifact.BuildRequest{
		AgentInstanceID:  uuid.NewString(),
		OwnerID:          execution.OwnerID,
		ExecutionID:      execution.ExecutionID,
		OperationID:      uuid.NewString(),
		TaskID:           execution.TaskID,
		PlanID:           execution.PlanID,
		PlanRevision:     execution.PlanRevision,
		ConnectionID:     execution.ProviderScope.ConnectionID,
		RoleID:           role.RoleID,
		ActionID:         "execute",
		DeploymentID:     uuid.NewString(),
		Name:             "final.json",
		MediaType:        "application/json",
		SizeBytes:        128,
		SHA256:           "sha256:" + strings.Repeat("9", 64),
		ObjectRef:        "s3://artifact-test/executions/" + execution.ExecutionID + "/final.json",
		CreatedAt:        executionFact.UpdatedAt,
		RetentionExpires: executionFact.UpdatedAt.Add(90 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return executionFact, reportFact, []teamartifact.ArtifactV1{artifact}
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

func rpcTeamLaunchAuthorization(
	plan teamplan.Plan,
	approvalID string,
) (teamlaunch.AuthorizationV1, error) {
	const agentInstanceID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if len(plan.Assignments) != 1 || len(plan.Cost.Roles) != 1 {
		return teamlaunch.AuthorizationV1{}, teamlaunch.ErrInvalid
	}
	planDigest, err := plan.Digest()
	if err != nil {
		return teamlaunch.AuthorizationV1{}, err
	}
	authorizationID, err := teamlaunch.AuthorizationID(
		plan.PlanID,
		plan.Revision,
		approvalID,
	)
	if err != nil {
		return teamlaunch.AuthorizationV1{}, err
	}
	foundation, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{
		AgentInstanceID: agentInstanceID,
		Partition:       "aws",
		AccountID:       plan.ProviderScope.AccountID,
		Region:          plan.Region,
	})
	if err != nil {
		return teamlaunch.AuthorizationV1{}, err
	}
	kmsAlias, err := awsfoundation.KMSAliasForAgent(agentInstanceID)
	if err != nil {
		return teamlaunch.AuthorizationV1{}, err
	}
	assignment := plan.Assignments[0]
	cost := plan.Cost.Roles[0]
	authorization := teamlaunch.AuthorizationV1{
		SchemaVersion:   teamlaunch.SchemaV1,
		AuthorizationID: authorizationID,
		AgentInstanceID: agentInstanceID,
		OwnerID:         plan.OwnerID,
		PlanID:          plan.PlanID,
		PlanRevision:    plan.Revision,
		PlanDigest:      planDigest,
		ApprovalID:      approvalID,
		ProviderScope:   plan.ProviderScope,
		Region:          plan.Region,
		Network: teamlaunch.NetworkV1{
			ConnectivityMode:     teamlaunch.ConnectivityDirectPublicTLSV1,
			VPCID:                "vpc-0123456789abcdef0",
			SubnetID:             "subnet-0123456789abcdef0",
			AvailabilityZone:     plan.Region + "a",
			SecurityGroupMode:    teamlaunch.SecurityGroupDedicatedNoIngress,
			PublicIPv4:           true,
			ControlPlaneEndpoint: "grpcs://worker-control.demo2.dirextalk.ai:7443",
			Egress: []teamlaunch.EgressRuleV1{
				{
					Protocol: "tcp",
					FromPort: 443,
					ToPort:   443,
					CIDRv4:   "0.0.0.0/0",
				},
				{
					Protocol: "tcp",
					FromPort: 7443,
					ToPort:   7443,
					CIDRv4:   "0.0.0.0/0",
				},
				{
					Protocol: "udp",
					FromPort: 53,
					ToPort:   53,
					CIDRv4:   "169.254.169.253/32",
				},
			},
		},
		Retention: teamlaunch.RetentionV1{
			Class:                  teamlaunch.RetentionEphemeralAutoDestroy,
			AutoDestroy:            true,
			MaximumLifetimeSeconds: 2 * 60 * 60,
			DestroyGraceSeconds:    5 * 60,
		},
		WorkerCount:                  plan.WorkerCount,
		MaxConcurrentBillableWorkers: plan.MaxConcurrentWorkers,
		Currency:                     plan.Cost.Currency,
		HardBudgetMicros:             plan.Cost.HardBudgetMicros,
		RequiresFreshQuote:           true,
		MaximumQuoteAgeSeconds:       15 * 60,
		LaunchNotBefore:              plan.QuotedAt,
		LaunchNotAfter:               plan.ValidUntil,
		Roles: []teamlaunch.RoleLaunchV1{{
			RoleID:                    assignment.RoleID,
			RuntimeReleaseID:          assignment.RuntimeReleaseID,
			RuntimeImageDigest:        assignment.RuntimeImageDigest,
			RuntimeInstallationDigest: "sha256:" + strings.Repeat("6", 64),
			RuntimeExecutableDigest:   "sha256:" + strings.Repeat("7", 64),
			ComputeOfferID:            assignment.ComputeOfferID,
			InstanceType:              assignment.InstanceType,
			Architecture:              assignment.Resources.Arch,
			VCPU:                      assignment.Resources.VCPU,
			MemoryMiB:                 assignment.Resources.MemoryMiB,
			PurchaseOption:            teamlaunch.PurchaseOnDemand,
			InstanceProfileName:       foundation.WorkerProfileName,
			EBSOptimized:              true,
			RequireIMDSv2:             true,
			MetadataResponseHopLimit:  1,
			ShutdownBehavior:          teamlaunch.ShutdownTerminate,
			RootStorage: teamlaunch.RootStorageV1{
				DeviceName:          "/dev/sda1",
				SizeGiB:             assignment.Resources.DiskGiB,
				VolumeType:          "gp3",
				IOPS:                3000,
				ThroughputMiBPS:     125,
				KMSKeyID:            kmsAlias,
				Encrypted:           true,
				DeleteOnTermination: true,
			},
			WorkerImage: teamlaunch.WorkerImageV1{
				PublicationDigest:     "sha256:" + strings.Repeat("8", 64),
				AgentInstanceID:       agentInstanceID,
				AccountID:             plan.ProviderScope.AccountID,
				Region:                plan.Region,
				Architecture:          assignment.Resources.Arch,
				ImageID:               "ami-0123456789abcdef0",
				ImageDigest:           "sha256:" + strings.Repeat("9", 64),
				RootSnapshotID:        "snap-0123456789abcdef0",
				ReleaseManifestDigest: "sha256:" + strings.Repeat("a", 64),
				WorkerRootFSDigest:    "sha256:" + strings.Repeat("b", 64),
				WorkerBinaryDigest:    "sha256:" + strings.Repeat("c", 64),
				ObservedAt: plan.QuotedAt.
					Add(-time.Hour).
					UTC().
					Truncate(time.Microsecond),
			},
			MaximumApprovedCostMicros: cost.TotalMaximumMicros,
		}},
	}
	if err := authorization.ValidateAgainst(plan); err != nil {
		return teamlaunch.AuthorizationV1{}, err
	}
	return authorization, nil
}

func rpcTeamPlanFact(
	t *testing.T,
	statusValue teamorchestration.PlanStatus,
) teamorchestration.PlanFact {
	t.Helper()
	quotedAt := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	planID := uuid.NewString()
	taskID := uuid.NewString()
	ownerID := "owner-team-rpc"
	goalDigest := "sha256:" + strings.Repeat("d", 64)
	taskInput, err := taskinput.NewEmptyInput(
		ownerID,
		taskID,
		goalDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	inputBinding, err := taskInput.Binding()
	if err != nil {
		t.Fatal(err)
	}
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
		ModelProvider:      "openai",
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
		SchemaVersion: teamplan.SchemaV3,
		PlanID:        planID,
		Revision:      1,
		OwnerID:       ownerID,
		GoalDigest:    goalDigest,
		TaskInput:     inputBinding,
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
		TaskID:         taskID,
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
