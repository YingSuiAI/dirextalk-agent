package managed

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
)

const (
	defaultExecutionBatch = 32
	scopeChangedCode      = "managed_scope_changed"
	scopeChangedSummary   = "managed acceptance facts no longer match the approved scope"
)

type ExecutionRepository interface {
	ListExecutableManagedAcceptances(context.Context, int) ([]OperationV1, error)
	TransitionManagedAcceptance(context.Context, string, int64, Status, string, string) (OperationV1, error)
}

type Executor struct {
	repository   ExecutionRepository
	scopes       ScopeBuilder
	acceptor     Acceptor
	pollInterval time.Duration
	wake         chan struct{}
	now          func() time.Time
}

func NewExecutor(repository ExecutionRepository, scopes ScopeBuilder, acceptor Acceptor, pollInterval time.Duration) (*Executor, error) {
	if repository == nil || scopes == nil || acceptor == nil || pollInterval < time.Second || pollInterval > time.Hour {
		return nil, ErrInvalid
	}
	return &Executor{repository: repository, scopes: scopes, acceptor: acceptor, pollInterval: pollInterval, wake: make(chan struct{}, 1), now: time.Now}, nil
}

func (e *Executor) NotifyManagedAcceptance() {
	if e == nil {
		return
	}
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

func (e *Executor) ExecuteManagedAcceptance(ctx context.Context, operation OperationV1) (OperationV1, error) {
	if e == nil || ctx == nil || operation.OperationID != operation.Challenge.ApprovalID ||
		operation.Revision < 2 || operation.ApprovedAt == nil {
		return OperationV1{}, ErrInvalid
	}
	if operation.Status == StatusApproved {
		var err error
		operation, err = e.repository.TransitionManagedAcceptance(ctx, operation.OperationID, operation.Revision, StatusRunning, "", "")
		if err != nil {
			return OperationV1{}, err
		}
	}
	if operation.Status != StatusRunning {
		return operation, nil
	}
	if _, replayed, err := e.acceptor.ReplayManaged(ctx, operation.Challenge.Scope, operation.OperationID, operation.ApprovedAt.UTC()); err != nil {
		if terminalManagedExecutionError(err) {
			return e.failScope(ctx, operation)
		}
		return OperationV1{}, err
	} else if replayed {
		return e.repository.TransitionManagedAcceptance(ctx, operation.OperationID, operation.Revision, StatusSucceeded, "", "")
	}
	current, err := e.scopes.BuildManagedAcceptanceSnapshot(ctx, operation.Challenge.Scope.OwnerID, operation.Challenge.Scope.DeploymentID, operation.OperationID)
	if err != nil {
		if terminalManagedExecutionError(err) {
			return e.failScope(ctx, operation)
		}
		return OperationV1{}, err
	}
	current.Scope.AgentInstanceID, current.Scope.AcceptanceID = operation.Challenge.Scope.AgentInstanceID, operation.OperationID
	now := e.now().UTC()
	if current.Scope.HealthObservedAt.After(now) || now.Sub(current.Scope.HealthObservedAt) > maxManagedHealthAge {
		return e.failScope(ctx, operation)
	}
	currentDigest, currentErr := ScopeDigest(current.Scope)
	approvedDigest, approvedErr := ScopeDigest(operation.Challenge.Scope)
	if currentErr != nil || approvedErr != nil || currentDigest != approvedDigest ||
		!reflect.DeepEqual(current.Service, operation.Challenge.Service) || !reflect.DeepEqual(current.Recipe, operation.Challenge.Recipe) {
		return e.failScope(ctx, operation)
	}
	if _, err := e.acceptor.AcceptManaged(ctx, operation.Challenge.Scope, operation.OperationID, operation.ApprovedAt.UTC()); err != nil {
		if terminalManagedExecutionError(err) {
			return e.failScope(ctx, operation)
		}
		return OperationV1{}, err
	}
	return e.repository.TransitionManagedAcceptance(ctx, operation.OperationID, operation.Revision, StatusSucceeded, "", "")
}

func (e *Executor) failScope(ctx context.Context, operation OperationV1) (OperationV1, error) {
	return e.repository.TransitionManagedAcceptance(ctx, operation.OperationID, operation.Revision, StatusFailedTerminal, scopeChangedCode, scopeChangedSummary)
}

func terminalManagedExecutionError(err error) bool {
	return errors.Is(err, ErrInvalid) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrRevisionConflict) ||
		errors.Is(err, resource.ErrInvalid) || errors.Is(err, resource.ErrNotFound) ||
		errors.Is(err, resource.ErrRevisionConflict) || errors.Is(err, resource.ErrManaged)
}

func (e *Executor) RunOnce(ctx context.Context) error {
	if e == nil || ctx == nil {
		return ErrInvalid
	}
	operations, err := e.repository.ListExecutableManagedAcceptances(ctx, defaultExecutionBatch)
	if err != nil {
		return err
	}
	for _, operation := range operations {
		if _, err := e.ExecuteManagedAcceptance(ctx, operation); err != nil {
			if errors.Is(err, ErrRevisionConflict) || errors.Is(err, ErrNotFound) {
				continue
			}
			return err
		}
	}
	return nil
}

func (e *Executor) Run(ctx context.Context) error {
	if e == nil || ctx == nil {
		return ErrInvalid
	}
	ticker := time.NewTicker(e.pollInterval)
	defer ticker.Stop()
	for {
		_ = e.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-e.wake:
		case <-ticker.C:
		}
	}
}
