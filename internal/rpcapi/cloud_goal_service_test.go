package rpcapi

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/agent/cloudskill"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type cloudGoalPlannerStub struct {
	principal auth.Principal
	request   cloudskill.ResearchRequest
	created   task.Task
	calls     int
}

func (stub *cloudGoalPlannerStub) CreateResearch(ctx context.Context, request cloudskill.ResearchRequest) (task.Task, error) {
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok {
		return task.Task{}, planning.ErrScopeMismatch
	}
	stub.calls++
	if stub.calls > 1 && !reflect.DeepEqual(stub.request, request) {
		return task.Task{}, planning.ErrIdempotencyConflict
	}
	stub.principal = principal
	stub.request = request
	return stub.created, nil
}

func TestCreateCloudGoalIsOwnerBoundPlanningOnlyAndIdempotent(t *testing.T) {
	now := time.Date(2026, time.July, 17, 9, 0, 0, 0, time.UTC)
	ownerID := "project-owner-a"
	connectionID := uuid.NewString()
	taskID := uuid.NewString()
	principal := auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()}
	planner := &cloudGoalPlannerStub{created: task.Task{
		TaskID: taskID, OwnerID: ownerID, Goal: "Deploy an official knowledge service.",
		ExecutionStatus: task.ExecutionQueued, OutcomeStatus: task.OutcomePending,
		RetentionPolicy: task.RetentionEphemeralAutoDestroy, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}}
	reader := &cloudStatusReaderStub{ownerID: ownerID, connection: cloudstatus.Connection{
		ConnectionID: connectionID, OwnerID: ownerID, Status: "active", Revision: 1,
	}}
	service := NewCloudControlServiceWithGoals(nil, uuid.NewString(), reader, nil, planner)
	ctx := auth.ContextWithPrincipal(context.Background(), principal)
	request := &agentv1.CreateCloudGoalRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: ownerID, CloudConnectionId: connectionID,
		Goal: planner.created.Goal, RetentionPolicy: agentv1.RetentionPolicy_RETENTION_POLICY_EPHEMERAL_AUTO_DESTROY,
	}

	created, err := service.CreateCloudGoal(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if created.GetTask().GetTaskId() != taskID || created.GetPlanning().GetTaskId() != taskID ||
		created.GetPlanning().GetOwnerId() != ownerID || created.GetPlanning().GetCloudConnectionId() != connectionID ||
		created.GetPlanning().GetRecipeId() == "" || created.GetPlanning().GetRelatedPlanId() != "" ||
		created.GetPlanning().GetState() != agentv1.CloudGoalPlanningState_CLOUD_GOAL_PLANNING_STATE_RESEARCH_QUEUED ||
		!reflect.DeepEqual(planner.principal, principal) || planner.calls != 1 {
		t.Fatalf("created goal lost its durable/caller binding: response=%#v planner=%#v", created, planner)
	}
	if planner.request.ConnectionID != connectionID || planner.request.Create.OwnerID != ownerID ||
		planner.request.Create.IdempotencyKey != request.GetIdempotencyKey() || len(planner.request.Create.Steps) != 3 {
		t.Fatalf("planning request was not fixed and owner-bound: %#v", planner.request)
	}
	for _, step := range planner.request.Create.Steps {
		if step.ExecutorKind != task.ExecutorControlPlane {
			t.Fatalf("cloud Goal reached a provider-capable executor: %#v", step)
		}
	}

	replayed, err := service.CreateCloudGoal(ctx, request)
	if err != nil || !reflect.DeepEqual(created, replayed) || planner.calls != 2 {
		t.Fatalf("exact replay changed result: replay=%#v calls=%d err=%v", replayed, planner.calls, err)
	}
	conflict := *request
	conflict.Goal = "Deploy a different service."
	if _, err := service.CreateCloudGoal(ctx, &conflict); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("changed idempotent payload code=%s err=%v", status.Code(err), err)
	}
}

func TestCreateCloudGoalRejectsCrossOwnerConnectionAndSensitiveGoal(t *testing.T) {
	ownerID := "project-owner-a"
	connectionID := uuid.NewString()
	planner := &cloudGoalPlannerStub{created: task.Task{TaskID: uuid.NewString()}}
	reader := &cloudStatusReaderStub{ownerID: ownerID, connection: cloudstatus.Connection{ConnectionID: connectionID, OwnerID: ownerID}}
	service := NewCloudControlServiceWithGoals(nil, uuid.NewString(), reader, nil, planner)
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
	base := &agentv1.CreateCloudGoalRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: ownerID, CloudConnectionId: connectionID, Goal: "Research an official service.",
		RetentionPolicy: agentv1.RetentionPolicy_RETENTION_POLICY_EPHEMERAL_AUTO_DESTROY,
	}

	crossOwner := *base
	crossOwner.OwnerId = "project-owner-b"
	if _, err := service.CreateCloudGoal(ctx, &crossOwner); status.Code(err) != codes.NotFound || planner.calls != 0 {
		t.Fatalf("cross-owner connection code=%s calls=%d err=%v", status.Code(err), planner.calls, err)
	}
	sensitive := *base
	sensitive.IdempotencyKey = uuid.NewString()
	sensitive.Goal = "Use sk-" + strings.Repeat("Z", 40) + " to deploy it."
	if _, err := service.CreateCloudGoal(ctx, &sensitive); status.Code(err) != codes.InvalidArgument || planner.calls != 0 || strings.Contains(err.Error(), sensitive.Goal) {
		t.Fatalf("sensitive goal rejection code=%s calls=%d err=%v", status.Code(err), planner.calls, err)
	}
}
