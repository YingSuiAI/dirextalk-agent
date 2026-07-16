package rpcapi

import (
	"context"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type TaskService struct {
	agentv1.UnimplementedTaskServiceServer
	store        task.Store
	pollInterval time.Duration
}

func NewTaskService(store task.Store) *TaskService {
	return &TaskService{store: store, pollInterval: 250 * time.Millisecond}
}

func (service *TaskService) CreateTask(ctx context.Context, request *agentv1.CreateTaskRequest) (*agentv1.CreateTaskResponse, error) {
	scope, err := mutationScope(ctx)
	if err != nil {
		return nil, err
	}
	retention, err := retentionFromProto(request.GetRetentionPolicy())
	if err != nil {
		return nil, err
	}
	created, createErr := service.store.Create(ctx, scope, task.CreateCommand{
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: request.GetOwnerId(), Goal: request.GetGoal(), Retention: retention,
	})
	if createErr != nil {
		return nil, publicError(createErr)
	}
	return &agentv1.CreateTaskResponse{Task: taskToProto(created)}, nil
}

func (service *TaskService) GetTask(ctx context.Context, request *agentv1.GetTaskRequest) (*agentv1.GetTaskResponse, error) {
	item, err := service.store.Get(ctx, request.GetTaskId())
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.GetTaskResponse{Task: taskToProto(item)}, nil
}

func (service *TaskService) ListTasks(ctx context.Context, request *agentv1.ListTasksRequest) (*agentv1.ListTasksResponse, error) {
	result, err := service.store.List(ctx, task.ListQuery{
		OwnerID: request.GetOwnerId(), PageSize: int(request.GetPageSize()), Cursor: request.GetPageToken(),
	})
	if err != nil {
		return nil, publicError(err)
	}
	response := &agentv1.ListTasksResponse{Tasks: make([]*agentv1.Task, 0, len(result.Tasks)), NextPageToken: result.NextCursor}
	for _, item := range result.Tasks {
		response.Tasks = append(response.Tasks, taskToProto(item))
	}
	return response, nil
}

func (service *TaskService) CancelTask(ctx context.Context, request *agentv1.CancelTaskRequest) (*agentv1.CancelTaskResponse, error) {
	scope, err := mutationScope(ctx)
	if err != nil {
		return nil, err
	}
	canceled, err := service.store.Cancel(ctx, scope, task.CancelCommand{
		IdempotencyKey: request.GetIdempotencyKey(), TaskID: request.GetTaskId(),
		ExpectedRevision: request.GetExpectedRevision(), Reason: request.GetReason(),
	})
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.CancelTaskResponse{Task: taskToProto(canceled)}, nil
}

func mutationScope(ctx context.Context) (task.MutationScope, error) {
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok {
		return task.MutationScope{}, status.Error(codes.Unauthenticated, "authenticated caller is required")
	}
	scope := task.MutationScope{ClientID: principal.ClientID, CredentialID: principal.CredentialID}
	if err := scope.Validate(); err != nil {
		return task.MutationScope{}, status.Error(codes.Unauthenticated, "authenticated caller identity is invalid")
	}
	return scope, nil
}

func (service *TaskService) ListSteps(ctx context.Context, request *agentv1.ListStepsRequest) (*agentv1.ListStepsResponse, error) {
	steps, err := service.store.ListSteps(ctx, request.GetTaskId())
	if err != nil {
		return nil, publicError(err)
	}
	response := &agentv1.ListStepsResponse{Steps: make([]*agentv1.Step, 0, len(steps))}
	for _, step := range steps {
		response.Steps = append(response.Steps, stepToProto(step))
	}
	return response, nil
}

func (service *TaskService) WatchEvents(request *agentv1.WatchEventsRequest, stream agentv1.TaskService_WatchEventsServer) error {
	if request.GetAfterSeq() < 0 {
		return status.Error(codes.InvalidArgument, "after_seq cannot be negative")
	}
	afterSeq := request.GetAfterSeq()
	ticker := time.NewTicker(service.pollInterval)
	defer ticker.Stop()
	for {
		events, err := service.store.EventsAfter(stream.Context(), afterSeq, 100)
		if err != nil {
			if stream.Context().Err() != nil {
				return stream.Context().Err()
			}
			return publicError(err)
		}
		for _, event := range events {
			if err := stream.Send(&agentv1.WatchEventsResponse{Event: eventToProto(event)}); err != nil {
				return err
			}
			afterSeq = event.Seq
		}
		if len(events) == 100 {
			continue
		}
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-ticker.C:
		}
	}
}

func retentionFromProto(value agentv1.RetentionPolicy) (task.RetentionPolicy, error) {
	switch value {
	case agentv1.RetentionPolicy_RETENTION_POLICY_EPHEMERAL_AUTO_DESTROY:
		return task.RetentionEphemeralAutoDestroy, nil
	case agentv1.RetentionPolicy_RETENTION_POLICY_MANAGED_RETAINED:
		return task.RetentionManaged, nil
	default:
		return "", status.Error(codes.InvalidArgument, "retention_policy is required")
	}
}

func taskToProto(item task.Task) *agentv1.Task {
	return &agentv1.Task{
		TaskId: item.TaskID, OwnerId: item.OwnerID, Goal: item.Goal,
		ExecutionStatus: executionToProto(item.ExecutionStatus), OutcomeStatus: outcomeToProto(item.OutcomeStatus),
		RetentionPolicy: retentionToProto(item.RetentionPolicy), CurrentStepId: item.CurrentStepID,
		ApprovedPlanId: item.ApprovedPlanID, Revision: item.Revision,
		CreatedAt: timestamppb.New(item.CreatedAt), UpdatedAt: timestamppb.New(item.UpdatedAt),
	}
}

func stepToProto(item task.Step) *agentv1.Step {
	return &agentv1.Step{
		StepId: item.StepID, TaskId: item.TaskID, Name: item.Name, DependsOnStepIds: append([]string(nil), item.DependsOnStepIDs...),
		ExecutorKind: executorToProto(item.ExecutorKind), ExecutionStatus: executionToProto(item.ExecutionStatus),
		OutcomeStatus: outcomeToProto(item.OutcomeStatus), Attempt: item.Attempt, LeaseEpoch: item.LeaseEpoch,
		CheckpointRef: item.CheckpointRef, ResultRef: item.ResultRef, Revision: item.Revision,
		CreatedAt: timestamppb.New(item.CreatedAt), UpdatedAt: timestamppb.New(item.UpdatedAt),
	}
}

func eventToProto(item task.Event) *agentv1.Event {
	return &agentv1.Event{
		Seq: item.Seq, EventId: item.EventID, EventType: item.EventType, AggregateType: item.AggregateType,
		AggregateId: item.AggregateID, Revision: item.Revision, SummaryJson: append([]byte(nil), item.SummaryJSON...),
		OccurredAt: timestamppb.New(item.OccurredAt),
	}
}

func executionToProto(value task.ExecutionStatus) agentv1.ExecutionStatus {
	switch value {
	case task.ExecutionDraft:
		return agentv1.ExecutionStatus_EXECUTION_STATUS_DRAFT
	case task.ExecutionPlanning:
		return agentv1.ExecutionStatus_EXECUTION_STATUS_PLANNING
	case task.ExecutionAwaitingApproval:
		return agentv1.ExecutionStatus_EXECUTION_STATUS_AWAITING_APPROVAL
	case task.ExecutionQueued:
		return agentv1.ExecutionStatus_EXECUTION_STATUS_QUEUED
	case task.ExecutionRunning:
		return agentv1.ExecutionStatus_EXECUTION_STATUS_RUNNING
	case task.ExecutionWaitingUser:
		return agentv1.ExecutionStatus_EXECUTION_STATUS_WAITING_USER
	case task.ExecutionVerifying:
		return agentv1.ExecutionStatus_EXECUTION_STATUS_VERIFYING
	case task.ExecutionFinished:
		return agentv1.ExecutionStatus_EXECUTION_STATUS_FINISHED
	default:
		return agentv1.ExecutionStatus_EXECUTION_STATUS_UNSPECIFIED
	}
}

func outcomeToProto(value task.OutcomeStatus) agentv1.OutcomeStatus {
	switch value {
	case task.OutcomePending:
		return agentv1.OutcomeStatus_OUTCOME_STATUS_PENDING
	case task.OutcomeSucceeded:
		return agentv1.OutcomeStatus_OUTCOME_STATUS_SUCCEEDED
	case task.OutcomeFailed:
		return agentv1.OutcomeStatus_OUTCOME_STATUS_FAILED
	case task.OutcomeCanceled:
		return agentv1.OutcomeStatus_OUTCOME_STATUS_CANCELED
	case task.OutcomeTimedOut:
		return agentv1.OutcomeStatus_OUTCOME_STATUS_TIMED_OUT
	case task.OutcomeInterrupted:
		return agentv1.OutcomeStatus_OUTCOME_STATUS_INTERRUPTED
	default:
		return agentv1.OutcomeStatus_OUTCOME_STATUS_UNSPECIFIED
	}
}

func retentionToProto(value task.RetentionPolicy) agentv1.RetentionPolicy {
	if value == task.RetentionManaged {
		return agentv1.RetentionPolicy_RETENTION_POLICY_MANAGED_RETAINED
	}
	if value == task.RetentionEphemeralAutoDestroy {
		return agentv1.RetentionPolicy_RETENTION_POLICY_EPHEMERAL_AUTO_DESTROY
	}
	return agentv1.RetentionPolicy_RETENTION_POLICY_UNSPECIFIED
}

func executorToProto(value task.ExecutorKind) agentv1.ExecutorKind {
	if value == task.ExecutorControlPlane {
		return agentv1.ExecutorKind_EXECUTOR_KIND_CONTROL_PLANE
	}
	if value == task.ExecutorCloudWorker {
		return agentv1.ExecutorKind_EXECUTOR_KIND_CLOUD_WORKER
	}
	return agentv1.ExecutorKind_EXECUTOR_KIND_UNSPECIFIED
}
