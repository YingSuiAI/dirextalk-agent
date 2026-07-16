package app

import (
	"context"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
)

const foundationLaunchBatchSize = 32

// foundationLaunchCompensator closes the crash window between committing an
// active Foundation Connection and persisting the matching cloud launch
// intent. The Foundation row remains the durable outbox; SubmitApprovedPlan is
// idempotent and the row stops being selected only after the exact launch
// intent exists.
type foundationLaunchCompensator struct {
	source   cloudapp.FoundationLaunchHandoffRepository
	launcher cloudapp.DeploymentLauncher
	interval time.Duration
}

func newFoundationLaunchCompensator(source cloudapp.FoundationLaunchHandoffRepository, launcher cloudapp.DeploymentLauncher, interval time.Duration) (*foundationLaunchCompensator, error) {
	if source == nil || launcher == nil || interval < time.Second || interval > 5*time.Minute {
		return nil, errors.New("Foundation launch compensation is unavailable")
	}
	return &foundationLaunchCompensator{source: source, launcher: launcher, interval: interval}, nil
}

func (compensator *foundationLaunchCompensator) RunOnce(ctx context.Context) error {
	if compensator == nil || ctx == nil {
		return errors.New("Foundation launch compensation is unavailable")
	}
	handoffs, err := compensator.source.ListPendingFoundationLaunchHandoffs(ctx, foundationLaunchBatchSize)
	if err != nil {
		return err
	}
	var batchErr error
	for _, handoff := range handoffs {
		if handoff.Caller.Validate() != nil || handoff.OwnerID == "" || handoff.PlanID == "" || handoff.ApprovalID == "" {
			batchErr = errors.Join(batchErr, cloudapp.ErrInvalid)
			continue
		}
		err := compensator.launcher.SubmitApprovedPlan(ctx, handoff.Caller, cloudapp.SubmitApprovedPlanCommand{
			OwnerID: handoff.OwnerID, PlanID: handoff.PlanID, ApprovalID: handoff.ApprovalID,
		})
		batchErr = errors.Join(batchErr, err)
	}
	return batchErr
}

func (compensator *foundationLaunchCompensator) Run(ctx context.Context) error {
	if compensator == nil || ctx == nil {
		return errors.New("Foundation launch compensation is unavailable")
	}
	ticker := time.NewTicker(compensator.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// A failed handoff remains represented by the succeeded Foundation
			// row and is retried on the next bounded tick.
			_ = compensator.RunOnce(ctx)
		}
	}
}
