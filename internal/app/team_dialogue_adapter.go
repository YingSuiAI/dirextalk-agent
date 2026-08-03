package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/agent/teamskill"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/google/uuid"
)

type teamDialogueTaskStore interface {
	Create(
		context.Context,
		task.MutationScope,
		task.CreateCommand,
	) (task.Task, error)
	Get(context.Context, string) (task.Task, error)
	Cancel(
		context.Context,
		task.MutationScope,
		task.CancelCommand,
	) (task.Task, error)
}

type teamDialoguePlanPreparer interface {
	PreparePlan(
		context.Context,
		task.MutationScope,
		teamorchestration.PreparePlanRequest,
	) (teamorchestration.PlanFact, error)
}

type teamDialogueAdapter struct {
	tasks       teamDialogueTaskStore
	preparation teamDialoguePlanPreparer
}

func newTeamDialogueAdapter(
	tasks teamDialogueTaskStore,
	preparation teamDialoguePlanPreparer,
) (*teamDialogueAdapter, error) {
	if tasks == nil || preparation == nil {
		return nil, teamskill.ErrInvalidDependencies
	}
	return &teamDialogueAdapter{
		tasks:       tasks,
		preparation: preparation,
	}, nil
}

func (adapter *teamDialogueAdapter) PrepareTeamPlan(
	ctx context.Context,
	request teamskill.PrepareRequest,
) (teamorchestration.PlanFact, error) {
	if adapter == nil ||
		adapter.tasks == nil ||
		adapter.preparation == nil ||
		ctx == nil {
		return teamorchestration.PlanFact{},
			teamskill.ErrInvalidDependencies
	}
	scope, requestID, goal, err := trustedTeamDialogueRequest(ctx, request)
	if err != nil {
		return teamorchestration.PlanFact{},
			err
	}
	taskIdempotencyKey := uuid.NewSHA1(
		requestID,
		[]byte("team-plan-task-create"),
	).String()
	created, err := adapter.tasks.Create(
		ctx,
		scope,
		task.CreateCommand{
			IdempotencyKey: taskIdempotencyKey,
			OwnerID:        request.OwnerID,
			Goal:           goal,
			Retention:      task.RetentionEphemeralAutoDestroy,
		},
	)
	if err != nil {
		return teamorchestration.PlanFact{}, err
	}
	if created.TaskID == "" ||
		created.OwnerID != request.OwnerID ||
		created.Goal != goal ||
		created.RetentionPolicy != task.RetentionEphemeralAutoDestroy {
		return teamorchestration.PlanFact{},
			teamskill.ErrInvalidPortResponse
	}
	goalHash := sha256.Sum256([]byte(goal))
	goalDigest := "sha256:" + hex.EncodeToString(goalHash[:])
	taskInput, err := taskinput.NewEmptyInput(
		request.OwnerID,
		created.TaskID,
		goalDigest,
	)
	if err != nil {
		return teamorchestration.PlanFact{}, err
	}
	inputBinding, err := taskInput.Binding()
	if err != nil {
		return teamorchestration.PlanFact{}, err
	}
	planID := uuid.NewSHA1(
		requestID,
		[]byte("team-plan\x00"+request.OwnerID),
	).String()
	prepared, err := adapter.preparation.PreparePlan(
		ctx,
		scope,
		teamorchestration.PreparePlanRequest{
			IdempotencyKey: uuid.NewSHA1(
				requestID,
				[]byte("team-plan-prepare"),
			).String(),
			OwnerID:                  request.OwnerID,
			TaskID:                   created.TaskID,
			ConnectionID:             request.ConnectionID,
			PlanID:                   planID,
			Revision:                 1,
			ExpectedPreviousRevision: 0,
			GoalDigest:               goalDigest,
			TaskInput:                inputBinding,
			Proposal:                 request.Proposal,
		},
	)
	if err != nil {
		return teamorchestration.PlanFact{}, err
	}
	if prepared.TaskID != created.TaskID ||
		prepared.Plan.PlanID != planID ||
		prepared.Plan.OwnerID != request.OwnerID ||
		prepared.Plan.TaskInput != inputBinding ||
		prepared.Plan.ProviderScope.ConnectionID != request.ConnectionID {
		return teamorchestration.PlanFact{},
			teamskill.ErrInvalidPortResponse
	}
	return prepared, nil
}

func (adapter *teamDialogueAdapter) CloseUnplannedTeamTask(
	ctx context.Context,
	request teamskill.PrepareRequest,
	reasonCode string,
) error {
	if adapter == nil || adapter.tasks == nil || ctx == nil {
		return teamskill.ErrInvalidDependencies
	}
	scope, requestID, goal, err := trustedTeamDialogueRequest(ctx, request)
	if err != nil {
		return err
	}
	if !validTeamPlanningFailureReason(reasonCode) {
		return teamskill.ErrInvocationScopeMismatch
	}
	created, err := adapter.tasks.Create(
		ctx,
		scope,
		task.CreateCommand{
			IdempotencyKey: uuid.NewSHA1(
				requestID,
				[]byte("team-plan-task-create"),
			).String(),
			OwnerID:   request.OwnerID,
			Goal:      goal,
			Retention: task.RetentionEphemeralAutoDestroy,
		},
	)
	if err != nil {
		return err
	}
	current, err := adapter.tasks.Get(ctx, created.TaskID)
	if err != nil {
		return err
	}
	if current.TaskID != created.TaskID ||
		current.OwnerID != request.OwnerID ||
		current.Goal != goal ||
		current.RetentionPolicy != task.RetentionEphemeralAutoDestroy {
		return teamskill.ErrInvalidPortResponse
	}
	if current.ExecutionStatus == task.ExecutionFinished ||
		current.ExecutionStatus != task.ExecutionPlanning ||
		current.OutcomeStatus != task.OutcomePending ||
		current.ApprovedPlanID != "" {
		return nil
	}
	if current.Revision != 1 {
		return teamskill.ErrInvalidPortResponse
	}
	canceled, err := adapter.tasks.Cancel(
		ctx,
		scope,
		task.CancelCommand{
			IdempotencyKey: uuid.NewSHA1(
				requestID,
				[]byte("team-plan-task-close"),
			).String(),
			TaskID:           current.TaskID,
			ExpectedRevision: current.Revision,
			Reason: "Team Plan preparation ended without a plan: " +
				reasonCode,
		},
	)
	if errors.Is(err, task.ErrRevisionConflict) {
		latest, readErr := adapter.tasks.Get(ctx, current.TaskID)
		if readErr != nil {
			return errors.Join(err, readErr)
		}
		if latest.ExecutionStatus == task.ExecutionFinished ||
			latest.ExecutionStatus != task.ExecutionPlanning ||
			latest.OutcomeStatus != task.OutcomePending ||
			latest.ApprovedPlanID != "" {
			return nil
		}
		return err
	}
	if err != nil {
		return err
	}
	if canceled.TaskID != current.TaskID ||
		canceled.OwnerID != request.OwnerID ||
		canceled.ExecutionStatus != task.ExecutionFinished ||
		canceled.OutcomeStatus != task.OutcomeCanceled ||
		canceled.Revision != current.Revision+1 {
		return teamskill.ErrInvalidPortResponse
	}
	return nil
}

func trustedTeamDialogueRequest(
	ctx context.Context,
	request teamskill.PrepareRequest,
) (task.MutationScope, uuid.UUID, string, error) {
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok {
		return task.MutationScope{}, uuid.Nil, "",
			teamskill.ErrInvocationScopeMismatch
	}
	scope := task.MutationScope{
		ClientID:     strings.TrimSpace(principal.ClientID),
		CredentialID: principal.CredentialID,
	}
	requestID, err := uuid.Parse(request.RequestID)
	goal := strings.TrimSpace(request.Goal)
	connectionID, connectionErr := uuid.Parse(request.ConnectionID)
	if scope.Validate() != nil ||
		err != nil ||
		requestID == uuid.Nil ||
		requestID.String() != request.RequestID ||
		connectionErr != nil ||
		connectionID == uuid.Nil ||
		connectionID.String() != request.ConnectionID ||
		strings.TrimSpace(request.OwnerID) != request.OwnerID ||
		request.OwnerID == "" ||
		goal == "" {
		return task.MutationScope{}, uuid.Nil, "",
			teamskill.ErrInvocationScopeMismatch
	}
	return scope, requestID, goal, nil
}

func validTeamPlanningFailureReason(reasonCode string) bool {
	switch reasonCode {
	case "retry_exhausted",
		"proposal_outside_policy",
		"runtime_registry_unavailable",
		"no_qualified_runtime",
		"no_qualified_model",
		"no_qualified_compute",
		"budget_exceeded",
		"preparation_failed":
		return true
	default:
		return false
	}
}

type scopedTeamProvider struct {
	provider runtimeapi.ToolProvider
}

func (provider *scopedTeamProvider) Tools(
	ctx context.Context,
	request runtimeapi.ToolRequest,
) ([]runtimeapi.Tool, error) {
	if provider == nil || provider.provider == nil {
		return nil, teamskill.ErrInvalidDependencies
	}
	if request.CloudDialogue == nil ||
		strings.TrimSpace(request.ConversationID) == "" {
		return nil, nil
	}
	cloudScope, err := runtimeapi.NewCloudDialogueScope(
		request.CloudDialogue.ConnectionID,
	)
	if err != nil {
		return nil, teamskill.ErrInvalidCallScope
	}
	scoped, err := teamskill.BindCallScope(
		ctx,
		teamskill.CallScope{
			OwnerID:      request.OwnerID,
			ConnectionID: cloudScope.ConnectionID,
			Goal:         request.LatestUserMessage,
		},
	)
	if err != nil {
		return nil, err
	}
	return provider.provider.Tools(scoped, request)
}

var _ teamskill.PreparationPort = (*teamDialogueAdapter)(nil)
var _ runtimeapi.ToolProvider = (*scopedTeamProvider)(nil)
