package app

import (
	"context"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/agent/teamtaskskill"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamreport"
	"github.com/google/uuid"
)

type teamTaskDialogueStore interface {
	Get(context.Context, string) (task.Task, error)
	Cancel(
		context.Context,
		task.MutationScope,
		task.CancelCommand,
	) (task.Task, error)
	FindTeamExecutionReportByTask(
		context.Context,
		string,
		string,
	) (teamreport.Fact, bool, error)
	FindTeamPlanByTask(
		context.Context,
		string,
		string,
	) (teamorchestration.PlanFact, bool, error)
}

type teamTaskDialogueAdapter struct {
	tasks teamTaskDialogueStore
}

func newTeamTaskDialogueAdapter(
	tasks teamTaskDialogueStore,
) (*teamTaskDialogueAdapter, error) {
	if tasks == nil {
		return nil, teamtaskskill.ErrInvalidDependencies
	}
	return &teamTaskDialogueAdapter{tasks: tasks}, nil
}

func (adapter *teamTaskDialogueAdapter) GetTeamTask(
	ctx context.Context,
	request teamtaskskill.StatusRequest,
) (task.Task, error) {
	if adapter == nil || adapter.tasks == nil || ctx == nil {
		return task.Task{}, teamtaskskill.ErrInvalidDependencies
	}
	if _, err := teamTaskDialogueMutationScope(ctx); err != nil {
		return task.Task{}, err
	}
	if !validTeamTaskDialogueRequest(request.OwnerID, request.TaskID) {
		return task.Task{}, teamtaskskill.ErrInvocationScopeMismatch
	}
	current, err := adapter.tasks.Get(ctx, request.TaskID)
	if err != nil {
		return task.Task{}, err
	}
	if current.TaskID != request.TaskID || current.OwnerID != request.OwnerID {
		return task.Task{}, teamtaskskill.ErrInvocationScopeMismatch
	}
	return current, nil
}

func (adapter *teamTaskDialogueAdapter) FindTeamTaskReport(
	ctx context.Context,
	request teamtaskskill.StatusRequest,
) (teamreport.Fact, bool, error) {
	if adapter == nil || adapter.tasks == nil || ctx == nil {
		return teamreport.Fact{}, false,
			teamtaskskill.ErrInvalidDependencies
	}
	if _, err := teamTaskDialogueMutationScope(ctx); err != nil {
		return teamreport.Fact{}, false, err
	}
	if !validTeamTaskDialogueRequest(request.OwnerID, request.TaskID) {
		return teamreport.Fact{}, false,
			teamtaskskill.ErrInvocationScopeMismatch
	}
	fact, found, err := adapter.tasks.FindTeamExecutionReportByTask(
		ctx,
		request.OwnerID,
		request.TaskID,
	)
	if err != nil {
		return teamreport.Fact{}, false, err
	}
	if found &&
		(fact.Validate() != nil ||
			fact.Report.OwnerID != request.OwnerID ||
			fact.Report.TaskID != request.TaskID) {
		return teamreport.Fact{}, false,
			teamtaskskill.ErrInvalidPortResponse
	}
	return fact, found, nil
}

func (adapter *teamTaskDialogueAdapter) FindTeamTaskPlan(
	ctx context.Context,
	request teamtaskskill.StatusRequest,
) (teamorchestration.PlanFact, bool, error) {
	if adapter == nil || adapter.tasks == nil || ctx == nil {
		return teamorchestration.PlanFact{}, false,
			teamtaskskill.ErrInvalidDependencies
	}
	if _, err := teamTaskDialogueMutationScope(ctx); err != nil {
		return teamorchestration.PlanFact{}, false, err
	}
	if !validTeamTaskDialogueRequest(request.OwnerID, request.TaskID) {
		return teamorchestration.PlanFact{}, false,
			teamtaskskill.ErrInvocationScopeMismatch
	}
	fact, found, err := adapter.tasks.FindTeamPlanByTask(
		ctx,
		request.OwnerID,
		request.TaskID,
	)
	if err != nil {
		return teamorchestration.PlanFact{}, false, err
	}
	if found &&
		(fact.TaskID != request.TaskID ||
			fact.Plan.OwnerID != request.OwnerID ||
			fact.Plan.PlanID == "" ||
			fact.Plan.Revision == 0 ||
			fact.RecordRevision == 0) {
		return teamorchestration.PlanFact{}, false,
			teamtaskskill.ErrInvalidPortResponse
	}
	return fact, found, nil
}

func (adapter *teamTaskDialogueAdapter) CancelTeamTask(
	ctx context.Context,
	request teamtaskskill.CancelRequest,
) (teamtaskskill.CancelFact, error) {
	if adapter == nil || adapter.tasks == nil || ctx == nil {
		return teamtaskskill.CancelFact{},
			teamtaskskill.ErrInvalidDependencies
	}
	scope, err := teamTaskDialogueMutationScope(ctx)
	if err != nil {
		return teamtaskskill.CancelFact{}, err
	}
	idempotencyID, idempotencyErr := uuid.Parse(request.IdempotencyKey)
	if !validTeamTaskDialogueRequest(request.OwnerID, request.TaskID) ||
		idempotencyErr != nil ||
		idempotencyID == uuid.Nil ||
		idempotencyID.String() != request.IdempotencyKey {
		return teamtaskskill.CancelFact{},
			teamtaskskill.ErrInvocationScopeMismatch
	}

	for attempt := 0; attempt < 2; attempt++ {
		current, readErr := adapter.tasks.Get(ctx, request.TaskID)
		if readErr != nil {
			return teamtaskskill.CancelFact{}, readErr
		}
		if current.TaskID != request.TaskID ||
			current.OwnerID != request.OwnerID ||
			current.Revision < 1 {
			return teamtaskskill.CancelFact{},
				teamtaskskill.ErrInvocationScopeMismatch
		}
		if current.ExecutionStatus == task.ExecutionFinished {
			state := teamtaskskill.CancelNotApplicableTerminal
			if current.OutcomeStatus == task.OutcomeCanceled {
				state = teamtaskskill.CancelAlreadyCanceled
			}
			return teamtaskskill.CancelFact{
				Task:  current,
				State: state,
			}, nil
		}
		canceled, cancelErr := adapter.tasks.Cancel(
			ctx,
			scope,
			task.CancelCommand{
				IdempotencyKey:   request.IdempotencyKey,
				TaskID:           request.TaskID,
				ExpectedRevision: current.Revision,
				Reason:           "Owner explicitly requested cancellation in Native Agent chat.",
			},
		)
		if errors.Is(cancelErr, task.ErrRevisionConflict) ||
			errors.Is(cancelErr, task.ErrTerminal) {
			continue
		}
		if cancelErr != nil {
			return teamtaskskill.CancelFact{}, cancelErr
		}
		if canceled.TaskID != request.TaskID ||
			canceled.OwnerID != request.OwnerID ||
			canceled.ExecutionStatus != task.ExecutionFinished ||
			canceled.OutcomeStatus != task.OutcomeCanceled ||
			canceled.Revision <= current.Revision {
			return teamtaskskill.CancelFact{},
				teamtaskskill.ErrInvalidPortResponse
		}
		return teamtaskskill.CancelFact{
			Task:  canceled,
			State: teamtaskskill.CancelCommitted,
		}, nil
	}
	return teamtaskskill.CancelFact{},
		teamtaskskill.ErrInvalidPortResponse
}

func teamTaskDialogueMutationScope(
	ctx context.Context,
) (task.MutationScope, error) {
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok {
		return task.MutationScope{},
			teamtaskskill.ErrInvocationScopeMismatch
	}
	scope := task.MutationScope{
		ClientID:     strings.TrimSpace(principal.ClientID),
		CredentialID: principal.CredentialID,
	}
	if scope.Validate() != nil {
		return task.MutationScope{},
			teamtaskskill.ErrInvocationScopeMismatch
	}
	return scope, nil
}

func validTeamTaskDialogueRequest(ownerID, taskID string) bool {
	parsed, err := uuid.Parse(taskID)
	return ownerID != "" &&
		strings.TrimSpace(ownerID) == ownerID &&
		len(ownerID) <= 255 &&
		err == nil &&
		parsed != uuid.Nil &&
		parsed.String() == taskID
}

type scopedTeamTaskProvider struct {
	provider runtimeapi.ToolProvider
}

func (provider *scopedTeamTaskProvider) Tools(
	ctx context.Context,
	request runtimeapi.ToolRequest,
) ([]runtimeapi.Tool, error) {
	if provider == nil || provider.provider == nil {
		return nil, teamtaskskill.ErrInvalidDependencies
	}
	if request.CloudDialogue == nil ||
		strings.TrimSpace(request.ConversationID) == "" {
		return nil, nil
	}
	if _, err := runtimeapi.NewCloudDialogueScope(
		request.CloudDialogue.ConnectionID,
	); err != nil {
		return nil, teamtaskskill.ErrInvalidCallScope
	}
	scoped, err := teamtaskskill.BindCallScope(
		ctx,
		teamtaskskill.CallScope{OwnerID: request.OwnerID},
	)
	if err != nil {
		return nil, err
	}
	return provider.provider.Tools(scoped, request)
}

var _ teamtaskskill.LifecyclePort = (*teamTaskDialogueAdapter)(nil)
var _ runtimeapi.ToolProvider = (*scopedTeamTaskProvider)(nil)
