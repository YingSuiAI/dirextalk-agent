package foundation

import (
	"context"
	"errors"
	"strings"
	"time"
)

var ErrProviderDestroyBlocked = errors.New("Foundation teardown requires remediation")
var ErrProviderAuthorizationExpired = errors.New("Foundation operation requires a fresh bootstrap approval")

type ExecutionRepository interface {
	ListExecutable(context.Context, int) ([]OperationV1, error)
	MarkRunning(context.Context, string, int64) (OperationV1, error)
	MarkSucceeded(context.Context, string, int64, ExecutionResult) (OperationV1, error)
	MarkFailed(context.Context, string, int64, bool, bool, string) (OperationV1, error)
}

// Provider executes only the immutable scope already approved and persisted.
// Implementations may consume the bound bootstrap secret but receive no
// caller-supplied provider request or operator credential chain.
type Provider interface {
	ExecuteFoundation(context.Context, OperationV1) (ExecutionResult, error)
}

type ExecutionResult struct {
	ConnectionStatus     string
	FoundationStackID    string
	ControlRoleARN       string
	CredentialGeneration uint64
}

type Executor struct {
	repository ExecutionRepository
	provider   Provider
	wake       chan struct{}
}

func NewExecutor(repository ExecutionRepository, provider Provider) (*Executor, error) {
	if repository == nil || provider == nil {
		return nil, ErrInvalid
	}
	return &Executor{repository: repository, provider: provider, wake: make(chan struct{}, 1)}, nil
}

func (executor *Executor) RunOnce(ctx context.Context) error {
	if executor == nil || ctx == nil {
		return ErrInvalid
	}
	operations, err := executor.repository.ListExecutable(ctx, 32)
	if err != nil {
		return err
	}
	for _, operation := range operations {
		if operation.Status != StatusApproved && operation.Status != StatusRunning && operation.Status != StatusFailedRetriable {
			return ErrInvalid
		}
		recovery := operation.Status == StatusRunning || operation.Status == StatusFailedRetriable
		operation.Recovery = recovery
		if operation.Status != StatusRunning {
			adoptExisting := operation.AdoptExisting
			operation, err = executor.repository.MarkRunning(ctx, operation.Challenge.OperationID, operation.Revision)
			if err != nil {
				return err
			}
			operation.AdoptExisting = adoptExisting
			operation.Recovery = recovery || adoptExisting || operation.Recovery
		}
		result, executeErr := executor.provider.ExecuteFoundation(ctx, operation)
		if executeErr != nil {
			blocked := errors.Is(executeErr, ErrProviderDestroyBlocked)
			terminal := errors.Is(executeErr, ErrProviderAuthorizationExpired)
			reason := strings.TrimSpace(executeErr.Error())
			if len(reason) > 512 {
				reason = reason[:512]
			}
			if _, saveErr := executor.repository.MarkFailed(ctx, operation.Challenge.OperationID, operation.Revision, blocked, terminal, reason); saveErr != nil {
				return saveErr
			}
			continue
		}
		if _, err := executor.repository.MarkSucceeded(ctx, operation.Challenge.OperationID, operation.Revision, result); err != nil {
			return err
		}
	}
	return nil
}

func (executor *Executor) NotifyFoundationOperation() {
	if executor == nil {
		return
	}
	select {
	case executor.wake <- struct{}{}:
	default:
	}
}

func (executor *Executor) Run(ctx context.Context) error {
	if executor == nil || ctx == nil {
		return ErrInvalid
	}
	if err := executor.RunOnce(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-executor.wake:
		case <-ticker.C:
		}
		if err := executor.RunOnce(ctx); err != nil {
			return err
		}
	}
}
