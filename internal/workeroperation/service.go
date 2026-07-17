package workeroperation

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	minLease = 5 * time.Second
	maxLease = 30 * time.Minute
)

type Repository interface {
	CreateIdempotent(context.Context, Operation, Mutation) (Operation, error)
	Get(context.Context, string) (Operation, error)
	MutateIdempotent(context.Context, string, string, Mutation, func(*Operation) error) (Operation, error)
	AcquireNext(context.Context, AcquireSelection) (Operation, error)
}

type Service struct {
	repository Repository
	verifier   ReceiptVerifier
	now        func() time.Time
}

func NewService(repository Repository, verifier ReceiptVerifier, now func() time.Time) (*Service, error) {
	if repository == nil || verifier == nil || now == nil {
		return nil, ErrInvalid
	}
	return &Service{repository: repository, verifier: verifier, now: now}, nil
}

type CreateRestartRequest struct {
	OperationID                     string
	DeploymentID                    string
	OwnerID                         string
	LifecycleRestartRef             string
	ExecutionBundleDigest           string
	ExpectedInstalledManifestDigest string
	IdempotencyKey                  string
}

func (service *Service) CreateRestart(ctx context.Context, request CreateRestartRequest) (Operation, error) {
	mutation, err := NewMutation(request.IdempotencyKey, 0, fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\nrestart",
		request.OperationID, request.DeploymentID, request.OwnerID, request.LifecycleRestartRef,
		request.ExecutionBundleDigest, request.ExpectedInstalledManifestDigest))
	if err != nil {
		return Operation{}, err
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	operation := Operation{
		SchemaVersion: SchemaV1, OperationID: strings.TrimSpace(request.OperationID),
		DeploymentID: strings.TrimSpace(request.DeploymentID), OwnerID: strings.TrimSpace(request.OwnerID),
		Action: ActionRestart, LifecycleRestartRef: strings.TrimSpace(request.LifecycleRestartRef),
		ExecutionBundleDigest:           strings.TrimSpace(request.ExecutionBundleDigest),
		ExpectedInstalledManifestDigest: strings.TrimSpace(request.ExpectedInstalledManifestDigest),
		State:                           StatePending, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := operation.Validate(); err != nil {
		return Operation{}, err
	}
	return service.repository.CreateIdempotent(ctx, operation, mutation)
}

func (service *Service) Get(ctx context.Context, operationID string) (Operation, error) {
	value, err := service.repository.Get(ctx, operationID)
	if err != nil {
		return Operation{}, err
	}
	if value.Receipt != nil && service.verifier.Verify(ctx, *value.Receipt) != nil {
		return Operation{}, ErrInvalid
	}
	return value, nil
}

type ClaimRequest struct {
	OperationID      string
	DeploymentID     string
	WorkerID         string
	IdempotencyKey   string
	ExpectedRevision int64
	LeaseDuration    time.Duration
}

// AcquireRequest discovers and leases deployment work without trusting a
// Worker-supplied operation ID. This is the only claim path used by a polling
// Worker.
type AcquireRequest struct {
	DeploymentID   string
	WorkerID       string
	IdempotencyKey string
	LeaseDuration  time.Duration
}

// AcquireSelection is executed atomically by the repository. The repository
// first recovers an unexpired lease already owned by this Worker, then selects
// the oldest pending or expired operation in the authenticated deployment.
type AcquireSelection struct {
	DeploymentID  string
	WorkerID      string
	Mutation      Mutation
	Now           time.Time
	LeaseDuration time.Duration
}

func (service *Service) AcquireNext(ctx context.Context, request AcquireRequest) (Assignment, error) {
	if request.LeaseDuration < minLease || request.LeaseDuration > maxLease ||
		!validUUID(request.DeploymentID) || !validUUID(request.WorkerID) {
		return Assignment{}, ErrInvalid
	}
	mutation, err := NewMutation(request.IdempotencyKey, 0, fmt.Sprintf("%s\n%s\n%d",
		request.DeploymentID, request.WorkerID, request.LeaseDuration))
	if err != nil {
		return Assignment{}, err
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	value, err := service.repository.AcquireNext(ctx, AcquireSelection{
		DeploymentID: request.DeploymentID, WorkerID: request.WorkerID,
		Mutation: mutation, Now: now, LeaseDuration: request.LeaseDuration,
	})
	if err != nil {
		return Assignment{}, err
	}
	if value.DeploymentID != request.DeploymentID || value.WorkerID != request.WorkerID ||
		value.State != StateLeased || !now.Before(value.LeaseExpiresAt) {
		return Assignment{}, ErrInvalid
	}
	return assignment(value), nil
}

func (service *Service) Claim(ctx context.Context, request ClaimRequest) (Assignment, error) {
	if request.LeaseDuration < minLease || request.LeaseDuration > maxLease {
		return Assignment{}, ErrInvalid
	}
	mutation, err := NewMutation(request.IdempotencyKey, request.ExpectedRevision, fmt.Sprintf("%s\n%s\n%s\n%d",
		request.OperationID, request.DeploymentID, request.WorkerID, request.LeaseDuration))
	if err != nil {
		return Assignment{}, err
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	operation, err := service.repository.MutateIdempotent(ctx, request.OperationID, "claim", mutation, func(operation *Operation) error {
		if operation.DeploymentID != request.DeploymentID {
			return ErrNotFound
		}
		switch operation.State {
		case StatePending:
		case StateLeased:
			if now.Before(operation.LeaseExpiresAt) {
				return ErrLeaseActive
			}
		default:
			return ErrTerminal
		}
		operation.State = StateLeased
		operation.WorkerID = request.WorkerID
		operation.LeaseEpoch++
		operation.LeaseExpiresAt = now.Add(request.LeaseDuration)
		operation.Revision++
		operation.UpdatedAt = now
		return nil
	})
	if err != nil {
		return Assignment{}, err
	}
	return assignment(operation), nil
}

type CompleteRequest struct {
	OperationID      string
	DeploymentID     string
	WorkerID         string
	LeaseEpoch       int64
	IdempotencyKey   string
	ExpectedRevision int64
	Receipt          RootHelperReceipt
	FailureCode      string
}

func (service *Service) Complete(ctx context.Context, request CompleteRequest) (Operation, error) {
	outcome := request.FailureCode
	if outcome == "" {
		outcome = "succeeded"
	}
	mutation, err := NewMutation(request.IdempotencyKey, request.ExpectedRevision, fmt.Sprintf("%s\n%s\n%s\n%d\n%s\n%x",
		request.OperationID, request.DeploymentID, request.WorkerID, request.LeaseEpoch, outcome, request.Receipt.Signature))
	if err != nil {
		return Operation{}, err
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	return service.repository.MutateIdempotent(ctx, request.OperationID, "complete", mutation, func(operation *Operation) error {
		if operation.DeploymentID != request.DeploymentID || operation.WorkerID != request.WorkerID ||
			operation.State != StateLeased || operation.LeaseEpoch != request.LeaseEpoch {
			return ErrStaleLease
		}
		if !now.Before(operation.LeaseExpiresAt) {
			return ErrLeaseExpired
		}
		if request.FailureCode != "" {
			if !identifierPattern.MatchString(request.FailureCode) {
				return ErrInvalid
			}
			operation.State = StateFailed
			operation.FailureCode = request.FailureCode
		} else {
			if request.Receipt.ValidateFor(*operation) != nil ||
				request.Receipt.ObservedAt.Before(operation.UpdatedAt) || request.Receipt.ObservedAt.After(now) ||
				service.verifier.Verify(ctx, request.Receipt) != nil {
				return ErrInvalid
			}
			receipt := request.Receipt
			operation.State = StateSucceeded
			operation.Receipt = &receipt
		}
		operation.LeaseExpiresAt = time.Time{}
		operation.Revision++
		operation.UpdatedAt = now
		return nil
	})
}

func assignment(operation Operation) Assignment {
	return Assignment{
		OperationID: operation.OperationID, DeploymentID: operation.DeploymentID, OwnerID: operation.OwnerID,
		Action: operation.Action, LifecycleRestartRef: operation.LifecycleRestartRef,
		ExecutionBundleDigest: operation.ExecutionBundleDigest, WorkerID: operation.WorkerID,
		ExpectedInstalledManifestDigest: operation.ExpectedInstalledManifestDigest,
		LeaseEpoch:                      operation.LeaseEpoch, LeaseExpiresAt: operation.LeaseExpiresAt, Revision: operation.Revision,
	}
}
