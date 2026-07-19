package rpcapi

import (
	"context"
	"strings"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/agent/cloudskill"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CloudGoalPlanner is deliberately limited to the planning/research port. It
// has no approval, provider, credential, network, or Worker mutation method.
type CloudGoalPlanner interface {
	CreateResearch(context.Context, cloudskill.ResearchRequest) (task.Task, error)
}

func (service *CloudControlService) CreateCloudGoal(ctx context.Context, request *agentv1.CreateCloudGoalRequest) (*agentv1.CreateCloudGoalResponse, error) {
	if _, err := mutationScope(ctx); err != nil {
		return nil, err
	}
	if err := service.requireWorkerControlPrivateLink(ctx); err != nil {
		return nil, err
	}
	if service == nil || service.goalPlanner == nil || service.statusReader == nil {
		return nil, cloudStatusUnavailable()
	}
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "cloud Goal request is required")
	}
	retention, err := retentionFromProto(request.GetRetentionPolicy())
	if err != nil {
		return nil, err
	}
	ownerID := strings.TrimSpace(request.GetOwnerId())
	connectionID := strings.TrimSpace(request.GetCloudConnectionId())
	parsedConnection, parseErr := uuid.Parse(connectionID)
	if parseErr != nil || parsedConnection == uuid.Nil || parsedConnection.String() != connectionID {
		return nil, status.Error(codes.InvalidArgument, "cloud_connection_id must be a canonical UUID")
	}
	recipeID, err := cloudGoalRecipeID(request.GetIdempotencyKey(), request.GetRecipeId())
	if err != nil {
		return nil, err
	}
	command := task.CreateCommand{
		IdempotencyKey: request.GetIdempotencyKey(), OwnerID: ownerID, Goal: request.GetGoal(), Retention: retention,
		Steps: cloudskill.PlanningSteps(request.GetIdempotencyKey()),
	}
	if err := command.Validate(); err != nil {
		return nil, publicError(err)
	}

	connection, err := service.statusReader.GetConnection(ctx, ownerID, connectionID)
	if err != nil {
		return nil, publicError(err)
	}
	if connection.ConnectionID != connectionID || connection.OwnerID != ownerID {
		return nil, status.Error(codes.Internal, "cloud connection ownership read-back is invalid")
	}
	created, err := service.goalPlanner.CreateResearch(ctx, cloudskill.ResearchRequest{
		Create: command, ConversationID: cloudGoalConversationID(request.GetIdempotencyKey()),
		ConnectionID: connectionID, RecipeID: recipeID,
	})
	if err != nil {
		return nil, publicError(err)
	}
	if !validCreatedCloudGoalTask(created, command) {
		return nil, status.Error(codes.Internal, "persisted cloud Goal task is invalid")
	}
	return &agentv1.CreateCloudGoalResponse{
		Task: taskToProto(created),
		Planning: &agentv1.CloudGoalPlanning{
			TaskId: created.TaskID, OwnerId: created.OwnerID, CloudConnectionId: connectionID, RecipeId: recipeID,
			State: agentv1.CloudGoalPlanningState_CLOUD_GOAL_PLANNING_STATE_RESEARCH_QUEUED,
		},
	}, nil
}

func cloudGoalRecipeID(idempotencyKey, requested string) (string, error) {
	parsed, err := uuid.Parse(idempotencyKey)
	if err != nil || parsed == uuid.Nil {
		return "", status.Error(codes.InvalidArgument, "idempotency_key must be a UUID")
	}
	value := strings.TrimSpace(requested)
	if value == "" {
		return "recipe-cloud-goal-" + strings.ReplaceAll(parsed.String(), "-", ""), nil
	}
	if len(value) > 128 || security.ContainsLikelySecret(value) {
		return "", status.Error(codes.InvalidArgument, "recipe_id is invalid")
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return "", status.Error(codes.InvalidArgument, "recipe_id is invalid")
		}
	}
	return value, nil
}

func cloudGoalConversationID(idempotencyKey string) string {
	parsed := uuid.MustParse(idempotencyKey)
	return "cloud-goal-" + strings.ReplaceAll(parsed.String(), "-", "")
}

func validCreatedCloudGoalTask(created task.Task, command task.CreateCommand) bool {
	parsed, err := uuid.Parse(created.TaskID)
	return err == nil && parsed != uuid.Nil && created.OwnerID == strings.TrimSpace(command.OwnerID) && created.Goal == strings.TrimSpace(command.Goal) &&
		created.ExecutionStatus == task.ExecutionQueued && created.OutcomeStatus == task.OutcomePending && created.RetentionPolicy == command.Retention &&
		created.CurrentStepID == "" && created.ApprovedPlanID == "" && created.Revision == 1 && !created.CreatedAt.IsZero() && !created.UpdatedAt.IsZero() &&
		!created.UpdatedAt.Before(created.CreatedAt)
}
