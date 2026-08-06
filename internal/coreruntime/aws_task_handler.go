package coreruntime

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

// AWSChangeService is the narrow Core AWS surface used by the generic task
// runtime. Implementations must keep provider credentials and calls inside the
// typed coreaws service.
type AWSChangeService interface {
	GetChangeForExecution(context.Context, string) (coreaws.Change, error)
	ConsumeChange(context.Context, coreaws.ConsumeChangeCommand) (coreaws.Reservation, error)
	ExecuteChange(context.Context, string) (coreaws.Change, error)
}

// NewAWSChangeTaskHandler binds an already-claimed generic Task to the
// durable AWS change fence. The handler never creates a second task lease;
// ConsumeChange receives the exact worker attempt/lease epoch/revision.
func NewAWSChangeTaskHandler(service AWSChangeService, coordinator coreaws.ChangeCoordinator) (TaskHandler, error) {
	if service == nil || coordinator == nil {
		return nil, errors.New("invalid AWS task handler dependencies")
	}
	return func(ctx context.Context, task coretask.Task) ManagedOutcome {
		return runAWSChangeTask(ctx, task, service, coordinator)
	}, nil
}

func runAWSChangeTask(ctx context.Context, task coretask.Task, service AWSChangeService, coordinator coreaws.ChangeCoordinator) ManagedOutcome {
	if ctx == nil || task.Spec.Kind != coretask.TaskKindAWSChange || task.Lease == nil || task.Attempt == 0 || task.LeaseEpoch == 0 {
		return ManagedOutcome{Err: coretask.ErrLeaseConflict, TerminalOwned: true}
	}
	payload := task.Spec.Payload.AWSChange
	if payload == nil || !coretask.ValidUUID(payload.ChangeID) {
		return ManagedOutcome{Err: coretask.ErrInvalid, TerminalOwned: true}
	}
	change, err := service.GetChangeForExecution(ctx, payload.ChangeID)
	if err != nil {
		return ManagedOutcome{Err: err}
	}
	if change.TaskID != task.ID || !coretask.ValidUUID(change.ConfirmationID) {
		return ManagedOutcome{Err: coretask.ErrRevisionConflict, TerminalOwned: true}
	}
	taskRevision, ok := taskRevisionInt64(task.Revision)
	if !ok {
		return ManagedOutcome{Err: coretask.ErrInvalid, TerminalOwned: true}
	}
	fence, err := coordinator.ExecutionFence(ctx, change.ConfirmationID)
	if err != nil {
		return ManagedOutcome{Err: err}
	}
	if !sameTaskFence(task, fence) {
		return ManagedOutcome{Err: coretask.ErrLeaseConflict, TerminalOwned: true}
	}
	if isTerminalChange(fence.Change.Status) {
		return ManagedOutcome{TerminalOwned: true}
	}

	// A confirmed change is consumed by the generic worker's existing lease.
	// If the confirmation was consumed by a previous attempt, the persisted
	// reservation is resumed exactly as-is.
	if fence.Confirmation.State == coreconfirmation.StateConfirmed {
		reservation, consumeErr := service.ConsumeChange(ctx, coreaws.ConsumeChangeCommand{
			ChangeID: change.ID, ConfirmationID: change.ConfirmationID, TaskID: task.ID,
			IdempotencyKey: task.Spec.IdempotencyKey, Attempt: task.Attempt, LeaseEpoch: task.LeaseEpoch,
			ExpectedChangeRevision: fence.Change.Revision, ExpectedConfirmationRevision: fence.Confirmation.Revision,
			ExpectedTaskRevision: taskRevision, Binding: fence.Confirmation.Binding,
		})
		if consumeErr != nil {
			// ConsumeChange owns stale/expired terminalization atomically.
			return ManagedOutcome{Err: consumeErr, TerminalOwned: true}
		}
		if !reservation.Active || reservation.TaskID != task.ID || reservation.Attempt != task.Attempt || reservation.LeaseEpoch != task.LeaseEpoch || reservation.TaskRevision != taskRevision {
			return ManagedOutcome{Err: coretask.ErrLeaseConflict, TerminalOwned: true}
		}
	} else if fence.Confirmation.State == coreconfirmation.StateConsumed && fence.Reservation.Active && fence.Reservation.TaskID == task.ID {
		// A reclaimed generic lease may atomically promote an expired consumed
		// reservation.  ConsumeChange performs the old-expiry/current-fence CAS.
		reservation, consumeErr := service.ConsumeChange(ctx, coreaws.ConsumeChangeCommand{
			ChangeID: change.ID, ConfirmationID: change.ConfirmationID, TaskID: task.ID,
			IdempotencyKey: uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("%s:reclaim:%d:%d", task.Spec.IdempotencyKey, task.Attempt, task.LeaseEpoch))).String(), Attempt: task.Attempt, LeaseEpoch: task.LeaseEpoch,
			ExpectedChangeRevision: fence.Change.Revision, ExpectedConfirmationRevision: fence.Confirmation.Revision,
			ExpectedTaskRevision: taskRevision, Binding: fence.Confirmation.Binding,
		})
		if consumeErr != nil || !reservation.Active || reservation.Attempt != task.Attempt || reservation.LeaseEpoch != task.LeaseEpoch || reservation.TaskRevision != taskRevision {
			if consumeErr == nil {
				consumeErr = coretask.ErrLeaseConflict
			}
			return ManagedOutcome{Err: consumeErr, TerminalOwned: true}
		}
	} else if fence.Confirmation.State != coreconfirmation.StateConsumed || !fence.Reservation.Active || fence.Reservation.TaskID != task.ID || fence.Reservation.Attempt != task.Attempt || fence.Reservation.LeaseEpoch != task.LeaseEpoch || fence.Reservation.TaskRevision != taskRevision {
		// Unconfirmed, expired, canceled, or stale reservations never reach a
		// provider. The coordinator's consume boundary records terminal state.
		_, consumeErr := service.ConsumeChange(ctx, coreaws.ConsumeChangeCommand{
			ChangeID: change.ID, ConfirmationID: change.ConfirmationID, TaskID: task.ID,
			IdempotencyKey: task.Spec.IdempotencyKey, Attempt: task.Attempt, LeaseEpoch: task.LeaseEpoch,
			ExpectedChangeRevision: fence.Change.Revision, ExpectedConfirmationRevision: fence.Confirmation.Revision,
			ExpectedTaskRevision: taskRevision, Binding: fence.Confirmation.Binding,
		})
		if consumeErr == nil {
			return ManagedOutcome{Err: coreaws.ErrUnconfirmed, TerminalOwned: true}
		}
		return ManagedOutcome{Err: consumeErr, TerminalOwned: true}
	}
	// Consumption may promote an expired reservation to this reclaimed lease.
	// Do not carry the pre-promotion fence into the provider/reconciliation
	// boundary: every subsequent CAS must use the current durable fence.
	fence, err = coordinator.ExecutionFence(ctx, change.ConfirmationID)
	if err != nil {
		return ManagedOutcome{Err: err, TerminalOwned: true}
	}
	if !sameTaskFence(task, fence) || !fence.Reservation.Active || fence.Reservation.TaskID != task.ID || fence.Reservation.Attempt != task.Attempt || fence.Reservation.LeaseEpoch != task.LeaseEpoch || fence.Reservation.TaskRevision != taskRevision {
		return ManagedOutcome{Err: coretask.ErrLeaseConflict, TerminalOwned: true}
	}

	result, execErr := service.ExecuteChange(ctx, change.ConfirmationID)
	if execErr != nil {
		// Response uncertainty is deliberately left non-terminal for lease
		// reclamation/restart reconciliation. Provider/domain failures are
		// terminalized by ExecuteChange through CompleteChange.
		if errors.Is(execErr, coreaws.ErrResponseUncertain) {
			return ManagedOutcome{Err: execErr, TerminalOwned: true}
		}
		return ManagedOutcome{Err: execErr, TerminalOwned: true}
	}
	if isTerminalChange(result.Status) {
		return ManagedOutcome{Result: coretask.Result{Summary: string(result.Status)}, TerminalOwned: true}
	}
	return ManagedOutcome{Err: coreaws.ErrResponseUncertain, TerminalOwned: true}
}

func sameTaskFence(task coretask.Task, fence coreaws.ExecutionFence) bool {
	tr, ok := taskRevisionInt64(task.Revision)
	return ok && fence.Task.ID == task.ID && fence.Task.Status == "running" && fence.Task.Attempt == task.Attempt && fence.Task.LeaseEpoch == task.LeaseEpoch && fence.Task.Revision == tr
}

func taskRevisionInt64(v uint64) (int64, bool) {
	if v > math.MaxInt64 {
		return 0, false
	}
	return int64(v), true
}

func isTerminalChange(status coreaws.ChangeStatus) bool {
	return status == coreaws.ChangeSucceeded || status == coreaws.ChangeFailed || status == coreaws.ChangeCanceled
}
