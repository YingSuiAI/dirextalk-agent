package cloudexecution

import (
	"context"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
)

const dispatcherBatchSize = 32

// Dispatcher is the single-process durable execution pump. Submit persists an
// intent before acknowledging the caller; Run resumes it after disconnect or
// restart. PostgreSQL and provider idempotency remain the fencing authority.
type Dispatcher struct {
	service    *Service
	repository Repository
	interval   time.Duration
	wake       chan struct{}
}

func NewDispatcher(service *Service, repository Repository, interval time.Duration) (*Dispatcher, error) {
	if service == nil || repository == nil || interval < time.Second || interval > 5*time.Minute {
		return nil, ErrInvalid
	}
	return &Dispatcher{service: service, repository: repository, interval: interval, wake: make(chan struct{}, 1)}, nil
}

func (dispatcher *Dispatcher) Submit(ctx context.Context, caller cloudapp.MutationScope, request LaunchRequest) (Operation, error) {
	if dispatcher == nil {
		return Operation{}, ErrInvalid
	}
	operation, err := dispatcher.service.PrepareApprovedPlan(ctx, caller, request)
	if err != nil {
		return Operation{}, err
	}
	select {
	case dispatcher.wake <- struct{}{}:
	default:
	}
	return operation, nil
}

func (dispatcher *Dispatcher) Run(ctx context.Context) error {
	if dispatcher == nil || ctx == nil {
		return ErrInvalid
	}
	ticker := time.NewTicker(dispatcher.interval)
	defer ticker.Stop()
	for {
		if err := dispatcher.RunOnce(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			// A failed batch remains durable and is retried on the next bounded
			// tick. Do not terminate the control process for provider downtime.
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		case <-dispatcher.wake:
		}
	}
}

func (dispatcher *Dispatcher) RunOnce(ctx context.Context) error {
	operations, err := dispatcher.repository.ListRecoverable(ctx, dispatcherBatchSize)
	if err != nil {
		return err
	}
	var batchErr error
	for _, operation := range operations {
		_, launchErr := dispatcher.service.LaunchApprovedPlan(ctx, operation.Caller, operation.Launch)
		if launchErr != nil {
			batchErr = errors.Join(batchErr, launchErr)
		}
	}
	return batchErr
}
