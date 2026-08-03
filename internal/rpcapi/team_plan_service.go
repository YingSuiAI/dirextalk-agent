package rpcapi

import (
	"context"
	"strconv"
	"strings"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamreport"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type TeamPlanPreparationCoordinator interface {
	PreparePlan(
		context.Context,
		task.MutationScope,
		teamorchestration.PreparePlanRequest,
	) (teamorchestration.PlanFact, error)
}

type TeamPlanCoordinator interface {
	GetPlan(
		context.Context,
		string,
		string,
		uint64,
	) (teamorchestration.PlanFact, error)
	CreateChallenge(
		context.Context,
		task.MutationScope,
		teamorchestration.ChallengeRequest,
	) (teamorchestration.ChallengeFact, error)
	ApprovePlan(
		context.Context,
		task.MutationScope,
		teamorchestration.ApprovalRequest,
	) (teamorchestration.PlanFact, error)
}

type TeamExecutionCoordinator interface {
	Materialize(
		context.Context,
		task.MutationScope,
		teamexecution.MaterializeRequest,
	) (teamexecution.Fact, error)
}

type TeamExecutionReader interface {
	GetTeamExecution(
		context.Context,
		string,
		string,
	) (teamexecution.Fact, error)
	FindTeamExecutionByPlan(
		context.Context,
		string,
		string,
		uint64,
	) (teamexecution.Fact, bool, error)
}

type TeamExecutionReportReader interface {
	GetTeamExecutionReport(
		context.Context,
		string,
		string,
	) (teamreport.Fact, error)
}

type TeamExecutionArtifactReader interface {
	ListTeamArtifacts(
		context.Context,
		string,
		string,
	) ([]teamartifact.ArtifactV1, error)
}

type TeamPlanService struct {
	agentv1.UnimplementedTeamPlanServiceServer
	preparation     TeamPlanPreparationCoordinator
	plans           TeamPlanCoordinator
	executions      TeamExecutionCoordinator
	executionReads  TeamExecutionReader
	reports         TeamExecutionReportReader
	artifacts       TeamExecutionArtifactReader
	deviceBootstrap TeamApprovalDeviceBootstrapper
}

func (service *TeamPlanService) WithArtifactReads(
	artifacts TeamExecutionArtifactReader,
) *TeamPlanService {
	if service != nil {
		service.artifacts = artifacts
	}
	return service
}

func (service *TeamPlanService) WithExecutionReads(
	executions TeamExecutionReader,
	reports TeamExecutionReportReader,
) *TeamPlanService {
	if service != nil {
		service.executionReads = executions
		service.reports = reports
	}
	return service
}

func NewTeamPlanService(
	preparation TeamPlanPreparationCoordinator,
	plans TeamPlanCoordinator,
	executions ...TeamExecutionCoordinator,
) *TeamPlanService {
	service := &TeamPlanService{
		preparation: preparation,
		plans:       plans,
	}
	if len(executions) == 1 {
		service.executions = executions[0]
	}
	return service
}

func (service *TeamPlanService) PrepareTeamPlanV3(
	ctx context.Context,
	request *agentv1.PrepareTeamPlanV3Request,
) (*agentv1.PrepareTeamPlanV3Response, error) {
	scope, err := mutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service == nil || service.preparation == nil {
		return nil, teamPlanUnavailable()
	}
	command, err := teamPrepareRequestFromProto(request)
	if err != nil {
		return nil, err
	}
	prepared, err := service.preparation.PreparePlan(
		ctx,
		scope,
		command,
	)
	if err != nil {
		return nil, publicError(err)
	}
	projected, err := teamPlanToProto(prepared)
	if err != nil {
		return nil, invalidTeamProjection()
	}
	return &agentv1.PrepareTeamPlanV3Response{Plan: projected}, nil
}

func (service *TeamPlanService) GetTeamPlanV3(
	ctx context.Context,
	request *agentv1.GetTeamPlanV3Request,
) (*agentv1.GetTeamPlanV3Response, error) {
	if service == nil || service.plans == nil {
		return nil, teamPlanUnavailable()
	}
	if request == nil || request.GetPlanRevision() < 1 {
		return nil, invalidTeamRequest(
			"owner_id, plan_id, and positive plan_revision are required",
		)
	}
	plan, err := service.plans.GetPlan(
		ctx,
		request.GetOwnerId(),
		request.GetPlanId(),
		uint64(request.GetPlanRevision()),
	)
	if err != nil {
		return nil, publicError(err)
	}
	projected, err := teamPlanToProto(plan)
	if err != nil {
		return nil, invalidTeamProjection()
	}
	executionID := ""
	if service.executionReads != nil &&
		plan.Status != teamorchestration.PlanReadyForConfirmation &&
		plan.Status != teamorchestration.PlanExpired &&
		plan.Status != teamorchestration.PlanSuperseded {
		execution, found, readErr :=
			service.executionReads.FindTeamExecutionByPlan(
				ctx,
				request.GetOwnerId(),
				request.GetPlanId(),
				uint64(request.GetPlanRevision()),
			)
		if readErr != nil {
			return nil, publicError(readErr)
		}
		if found {
			parsedExecutionID, parseErr := uuid.Parse(
				execution.Execution.ExecutionID,
			)
			if parseErr != nil ||
				parsedExecutionID == uuid.Nil ||
				parsedExecutionID.String() !=
					execution.Execution.ExecutionID ||
				execution.Execution.OwnerID != request.GetOwnerId() ||
				execution.Execution.PlanID != request.GetPlanId() ||
				execution.Execution.PlanRevision !=
					uint64(request.GetPlanRevision()) ||
				execution.Execution.PlanDigest != plan.PlanDigest {
				return nil, invalidTeamProjection()
			}
			executionID = execution.Execution.ExecutionID
		}
	}
	return &agentv1.GetTeamPlanV3Response{
		Plan:        projected,
		ExecutionId: executionID,
	}, nil
}

func (service *TeamPlanService) CreateTeamApprovalChallengeV3(
	ctx context.Context,
	request *agentv1.CreateTeamApprovalChallengeV3Request,
) (*agentv1.CreateTeamApprovalChallengeV3Response, error) {
	scope, err := mutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service == nil || service.plans == nil {
		return nil, teamPlanUnavailable()
	}
	if request == nil ||
		request.GetPlanRevision() < 1 ||
		request.GetExpectedPlanRecordRevision() < 1 {
		return nil, invalidTeamRequest(
			"positive Plan and record revisions are required",
		)
	}
	approvalID, challengeID, err := deterministicTeamChallengeIDs(
		request,
	)
	if err != nil {
		return nil, err
	}
	challenge, err := service.plans.CreateChallenge(
		ctx,
		scope,
		teamorchestration.ChallengeRequest{
			IdempotencyKey: request.GetIdempotencyKey(),
			OwnerID:        request.GetOwnerId(),
			PlanID:         request.GetPlanId(),
			PlanRevision:   uint64(request.GetPlanRevision()),
			ExpectedPlanRecordRevision: uint64(
				request.GetExpectedPlanRecordRevision(),
			),
			ApprovalID:  approvalID,
			ChallengeID: challengeID,
			SignerKeyID: request.GetSignerKeyId(),
		},
	)
	if err != nil {
		return nil, publicError(err)
	}
	projected, err := teamChallengeToProto(challenge)
	if err != nil {
		return nil, invalidTeamProjection()
	}
	authorization, err := teamLaunchAuthorizationToProto(
		challenge.Authorization,
	)
	if err != nil {
		return nil, invalidTeamProjection()
	}
	return &agentv1.CreateTeamApprovalChallengeV3Response{
		Challenge:     projected,
		Authorization: authorization,
	}, nil
}

func (service *TeamPlanService) ApproveTeamPlanV3(
	ctx context.Context,
	request *agentv1.ApproveTeamPlanV3Request,
) (*agentv1.ApproveTeamPlanV3Response, error) {
	scope, err := mutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service == nil || service.plans == nil {
		return nil, teamPlanUnavailable()
	}
	if request == nil ||
		request.GetExpectedPlanRecordRevision() < 1 ||
		request.GetExpectedChallengeRecordRevision() < 1 {
		return nil, invalidTeamRequest(
			"positive Plan and challenge record revisions are required",
		)
	}
	signature, err := teamApprovalFromProto(request.GetApproval())
	if err != nil {
		return nil, err
	}
	approved, err := service.plans.ApprovePlan(
		ctx,
		scope,
		teamorchestration.ApprovalRequest{
			IdempotencyKey: request.GetIdempotencyKey(),
			OwnerID:        request.GetOwnerId(),
			ExpectedPlanRecordRevision: uint64(
				request.GetExpectedPlanRecordRevision(),
			),
			ExpectedChallengeRecordRevision: uint64(
				request.GetExpectedChallengeRecordRevision(),
			),
			Signature: signature,
		},
	)
	if err != nil {
		return nil, publicError(err)
	}
	executionID, err := teamexecution.DeriveExecutionID(
		approved.Plan.PlanID,
		approved.Plan.Revision,
		signature.ApprovalID,
	)
	if err != nil {
		return nil, invalidTeamProjection()
	}
	if service.executions != nil {
		planID, parseErr := uuid.Parse(approved.Plan.PlanID)
		if parseErr != nil || planID == uuid.Nil {
			return nil, invalidTeamProjection()
		}
		materializationKey := uuid.NewSHA1(
			planID,
			[]byte(
				"team-execution-materialize/v1\x00"+
					signature.ApprovalID,
			),
		).String()
		// Approval is already durable. A transient materialization failure
		// leaves the Plan truthfully approved and is recovered from the
		// durable approved-without-Execution relation.
		_, _ = service.executions.Materialize(
			ctx,
			scope,
			teamexecution.MaterializeRequest{
				IdempotencyKey: materializationKey,
				OwnerID:        approved.Plan.OwnerID,
				PlanID:         approved.Plan.PlanID,
				PlanRevision:   approved.Plan.Revision,
			},
		)
	}
	projected, err := teamPlanToProto(approved)
	if err != nil {
		return nil, invalidTeamProjection()
	}
	return &agentv1.ApproveTeamPlanV3Response{
		Plan:        projected,
		ExecutionId: executionID,
	}, nil
}

func (service *TeamPlanService) GetTeamExecutionV3(
	ctx context.Context,
	request *agentv1.GetTeamExecutionV3Request,
) (*agentv1.GetTeamExecutionV3Response, error) {
	if service == nil ||
		service.executions == nil ||
		service.executionReads == nil ||
		service.reports == nil ||
		service.artifacts == nil {
		return nil, teamPlanUnavailable()
	}
	if request == nil ||
		request.GetOwnerId() == "" ||
		request.GetExecutionId() == "" {
		return nil, invalidTeamRequest(
			"owner_id and execution_id are required",
		)
	}
	execution, err := service.executionReads.GetTeamExecution(
		ctx,
		request.GetOwnerId(),
		request.GetExecutionId(),
	)
	if err != nil {
		return nil, publicError(err)
	}
	var report *teamreport.Fact
	var artifacts []teamartifact.ArtifactV1
	if execution.Status == teamexecution.StatusCompleted {
		value, readErr := service.reports.GetTeamExecutionReport(
			ctx,
			request.GetOwnerId(),
			request.GetExecutionId(),
		)
		if readErr != nil {
			return nil, invalidTeamProjection()
		}
		report = &value
		artifacts, readErr = service.artifacts.ListTeamArtifacts(
			ctx,
			request.GetOwnerId(),
			request.GetExecutionId(),
		)
		if readErr != nil || len(artifacts) == 0 {
			return nil, invalidTeamProjection()
		}
	}
	projected, err := teamExecutionToProto(execution, report, artifacts)
	if err != nil {
		return nil, invalidTeamProjection()
	}
	return &agentv1.GetTeamExecutionV3Response{
		Execution: projected,
	}, nil
}

func teamPrepareRequestFromProto(
	request *agentv1.PrepareTeamPlanV3Request,
) (teamorchestration.PreparePlanRequest, error) {
	if request == nil ||
		request.GetPlanRevision() < 1 ||
		request.GetExpectedPreviousPlanRevision() < 0 ||
		request.GetTaskId() == "" {
		return teamorchestration.PreparePlanRequest{}, invalidTeamRequest(
			"Task identity and valid Plan revisions are required",
		)
	}
	proposal, err := teamProposalFromProto(request.GetProposal())
	if err != nil {
		return teamorchestration.PreparePlanRequest{}, err
	}
	taskInput, err := taskinput.NewEmptyInput(
		request.GetOwnerId(),
		request.GetTaskId(),
		request.GetGoalDigest(),
	)
	if err != nil {
		return teamorchestration.PreparePlanRequest{}, invalidTeamRequest(
			"owner_id, task_id, and goal_digest must identify a valid task input",
		)
	}
	inputBinding, err := taskInput.Binding()
	if err != nil {
		return teamorchestration.PreparePlanRequest{}, invalidTeamRequest(
			"task input snapshot could not be bound",
		)
	}
	return teamorchestration.PreparePlanRequest{
		IdempotencyKey: request.GetIdempotencyKey(),
		OwnerID:        request.GetOwnerId(),
		TaskID:         request.GetTaskId(),
		ConnectionID:   request.GetCloudConnectionId(),
		PlanID:         request.GetPlanId(),
		Revision:       uint64(request.GetPlanRevision()),
		ExpectedPreviousRevision: uint64(
			request.GetExpectedPreviousPlanRevision(),
		),
		GoalDigest: request.GetGoalDigest(),
		TaskInput:  inputBinding,
		Proposal:   proposal,
	}, nil
}

func deterministicTeamChallengeIDs(
	request *agentv1.CreateTeamApprovalChallengeV3Request,
) (string, string, error) {
	if request == nil {
		return "", "", invalidTeamRequest(
			"Team Plan challenge request is required",
		)
	}
	planID, err := uuid.Parse(request.GetPlanId())
	if err != nil ||
		planID == uuid.Nil ||
		planID.String() != request.GetPlanId() {
		return "", "", invalidTeamRequest(
			"plan_id must be a canonical UUID",
		)
	}
	idempotencyID, err := uuid.Parse(request.GetIdempotencyKey())
	if err != nil ||
		idempotencyID == uuid.Nil ||
		idempotencyID.String() != request.GetIdempotencyKey() {
		return "", "", invalidTeamRequest(
			"idempotency_key must be a canonical UUID",
		)
	}
	seed := strings.Join([]string{
		"dirextalk.agent.team-plan-challenge/v3",
		idempotencyID.String(),
		request.GetOwnerId(),
		strconv.FormatInt(request.GetPlanRevision(), 10),
		request.GetSignerKeyId(),
	}, "\x00")
	approvalID := uuid.NewSHA1(
		planID,
		[]byte("approval\x00"+seed),
	).String()
	challengeID := uuid.NewSHA1(
		planID,
		[]byte("challenge\x00"+seed),
	).String()
	return approvalID, challengeID, nil
}

func teamPlanUnavailable() error {
	return status.Error(
		codes.Unavailable,
		"Team Plan v3 is not configured",
	)
}

func invalidTeamProjection() error {
	return status.Error(
		codes.Internal,
		"stored Team Plan projection is invalid",
	)
}

var _ TeamPlanPreparationCoordinator = (*teamorchestration.PreparationService)(nil)
var _ TeamPlanCoordinator = (*teamorchestration.Service)(nil)
var _ TeamExecutionCoordinator = (*teamexecution.Service)(nil)
