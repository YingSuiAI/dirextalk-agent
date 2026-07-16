package app

import (
	"context"
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/google/uuid"
)

type cloudLaunchAdapter struct {
	dispatcher *cloudexecution.Dispatcher
	target     string
}

func (adapter cloudLaunchAdapter) SubmitApprovedPlan(ctx context.Context, scope cloudapp.MutationScope, command cloudapp.SubmitApprovedPlanCommand) error {
	planID, err := uuid.Parse(command.PlanID)
	if adapter.dispatcher == nil || err != nil || planID == uuid.Nil {
		return cloudapp.ErrInvalid
	}
	idempotencyKey := uuid.NewSHA1(planID, []byte("cloud-launch-submit/v1")).String()
	_, err = adapter.dispatcher.Submit(ctx, scope, cloudexecution.LaunchRequest{
		IdempotencyKey: idempotencyKey, OwnerID: command.OwnerID, PlanID: command.PlanID,
		ApprovalID: command.ApprovalID, ControlPlaneTarget: adapter.target,
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, cloudexecution.ErrInvalid):
		return cloudapp.ErrInvalid
	case errors.Is(err, cloudexecution.ErrNotReady), errors.Is(err, cloudexecution.ErrRevisionConflict):
		return cloudapp.ErrRevisionConflict
	default:
		return cloudapp.ErrUnavailable
	}
}
