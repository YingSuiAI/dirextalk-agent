package postgres

import (
	"context"
	"errors"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
)

// CloudAdapter keeps PostgreSQL command types out of the public application
// boundary while preserving the Store's atomic, caller-scoped mutations.
type CloudAdapter struct{ store *Store }

func NewCloudAdapter(store *Store) (*CloudAdapter, error) {
	if store == nil {
		return nil, cloudapp.ErrInvalid
	}
	return &CloudAdapter{store: store}, nil
}

func (adapter *CloudAdapter) PersistQuote(ctx context.Context, scope cloudapp.MutationScope, key string, requestDigest [32]byte, value cloudquote.QuoteV1) (cloudquote.QuoteV1, error) {
	result, err := adapter.store.CreateQuote(ctx, taskScope(scope), CreateQuoteCommand{IdempotencyKey: key, RequestDigest: requestDigest, Quote: value})
	return result, mapCloudFactError(err)
}

func (adapter *CloudAdapter) LoadQuote(ctx context.Context, ownerID, quoteID string) (cloudquote.QuoteV1, error) {
	result, err := adapter.store.GetQuote(ctx, ownerID, quoteID)
	return result, mapCloudFactError(err)
}

func (adapter *CloudAdapter) PersistPlan(ctx context.Context, scope cloudapp.MutationScope, key string, value cloudapproval.PlanV1) (cloudapproval.PlanV1, error) {
	result, err := adapter.store.CreatePlan(ctx, taskScope(scope), CreatePlanCommand{IdempotencyKey: key, Plan: value})
	return result, mapCloudFactError(err)
}

// PersistCloudGoalPlan adds the exact durable Task binding required for a
// server-created Cloud Goal. Generic CloudFactRepository callers continue to
// use PersistPlan and cannot accidentally manufacture a task association.
func (adapter *CloudAdapter) PersistCloudGoalPlan(ctx context.Context, scope cloudapp.MutationScope, key, taskID string, value cloudapproval.PlanV1) (cloudapproval.PlanV1, error) {
	result, err := adapter.store.CreatePlan(ctx, taskScope(scope), CreatePlanCommand{IdempotencyKey: key, TaskID: taskID, Plan: value})
	return result, mapCloudFactError(err)
}

func (adapter *CloudAdapter) LoadPlan(ctx context.Context, ownerID, planID string) (cloudapproval.PlanV1, error) {
	result, err := adapter.store.GetPlan(ctx, ownerID, planID)
	return result, mapCloudFactError(err)
}

func (adapter *CloudAdapter) PersistChallenge(ctx context.Context, scope cloudapp.MutationScope, key string, value cloudapproval.ChallengeV1) (cloudapproval.ChallengeV1, error) {
	result, err := adapter.store.CreateApprovalChallenge(ctx, taskScope(scope), CreateApprovalChallengeCommand{
		IdempotencyKey: key, Challenge: value,
	})
	return result, mapCloudFactError(err)
}

func (adapter *CloudAdapter) LoadChallenge(ctx context.Context, challengeID string) (cloudapproval.ChallengeV1, error) {
	result, err := adapter.store.GetChallenge(ctx, challengeID)
	return result, mapCloudFactError(err)
}

func (adapter *CloudAdapter) PersistApproval(ctx context.Context, scope cloudapp.MutationScope, key string, challengeRevision, planRevision uint64, value cloudapproval.ApprovalV1) (cloudapproval.PlanV1, error) {
	result, err := adapter.store.ApprovePlan(ctx, taskScope(scope), ApprovePlanCommand{
		IdempotencyKey: key, ExpectedChallengeRevision: challengeRevision,
		ExpectedPlanRevision: planRevision, Approval: value,
	})
	return result, mapCloudFactError(err)
}

func (adapter *CloudAdapter) LoadApproval(ctx context.Context, ownerID, approvalID string) (cloudapproval.ApprovalV1, error) {
	result, err := adapter.store.GetApproval(ctx, ownerID, approvalID)
	return result, mapCloudFactError(err)
}

func (adapter *CloudAdapter) RegisterApprovalDevice(ctx context.Context, scope cloudapp.MutationScope, command cloudapp.RegisterApprovalDeviceCommand) (cloudapproval.DeviceKeyV1, error) {
	result, err := adapter.store.RegisterApprovalDevice(ctx, taskScope(scope), RegisterApprovalDeviceCommand{
		IdempotencyKey: command.IdempotencyKey,
		Device: cloudapproval.DeviceKeyV1{
			KeyID: command.KeyID, AgentInstanceID: adapter.store.instanceID.String(), OwnerID: command.OwnerID,
			Revision: 1, Status: cloudapproval.DeviceKeyActive, PublicKey: append([]byte(nil), command.PublicKey...),
			NotBefore: command.NotBefore.UTC(), ExpiresAt: command.ExpiresAt.UTC(),
		},
	})
	return result, mapCloudFactError(err)
}

func (adapter *CloudAdapter) RevokeApprovalDevice(ctx context.Context, scope cloudapp.MutationScope, command cloudapp.RevokeApprovalDeviceCommand) (cloudapproval.DeviceKeyV1, error) {
	result, err := adapter.store.RevokeApprovalDevice(ctx, taskScope(scope), RevokeApprovalDeviceCommand{
		IdempotencyKey: command.IdempotencyKey, KeyID: command.KeyID, ExpectedRevision: command.ExpectedRevision,
	})
	return result, mapCloudFactError(err)
}

func taskScope(scope cloudapp.MutationScope) task.MutationScope {
	return task.MutationScope{ClientID: scope.ClientID, CredentialID: scope.CredentialID}
}

func mapCloudFactError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrCloudFactNotFound), errors.Is(err, cloudapproval.ErrDeviceNotFound), errors.Is(err, cloudapproval.ErrChallengeNotFound):
		return cloudapp.ErrNotFound
	case errors.Is(err, ErrCloudFactRevision), errors.Is(err, ErrCloudChallengeConsumed), errors.Is(err, cloudapproval.ErrRevisionConflict), errors.Is(err, cloudapproval.ErrChallengeConsumed):
		return cloudapp.ErrRevisionConflict
	case errors.Is(err, ErrCloudFactScope):
		return cloudapp.ErrApprovalRequired
	case errors.Is(err, idempotency.ErrConflict):
		return idempotency.ErrConflict
	case errors.Is(err, ErrCloudFactInvalid), errors.Is(err, task.ErrInvalidMutationScope):
		return cloudapp.ErrInvalid
	default:
		return cloudapp.ErrUnavailable
	}
}
