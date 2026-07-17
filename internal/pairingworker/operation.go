package pairingworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound         = errors.New("pairing Worker operation not found")
	ErrRevisionConflict = errors.New("pairing Worker operation revision conflict")
	ErrLease            = errors.New("pairing Worker operation lease conflict")
	ErrUnavailable      = errors.New("pairing Worker operation is temporarily unavailable")
)

type State string

const (
	StatePending   State = "pending"
	StateLeased    State = "leased"
	StateSucceeded State = "succeeded"
	StateFailed    State = "failed"
)

type Operation struct {
	Command
	State          State
	WorkerID       string
	LeaseEpoch     int64
	LeaseExpiresAt time.Time
	Result         *Result
	FailureCode    string
	Revision       int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (value Operation) Validate() error {
	if _, err := commandHash(value.Command); err != nil || value.Revision < 1 ||
		value.CreatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) ||
		!value.PairingExpiresAt.After(value.CreatedAt) {
		return ErrInvalid
	}
	switch value.State {
	case StatePending:
		if value.WorkerID != "" || value.LeaseEpoch != 0 || value.ExecutionEpoch != 0 || value.Result != nil || value.FailureCode != "" {
			return ErrInvalid
		}
	case StateLeased:
		if value.WorkerID == "" || value.LeaseEpoch < 1 || value.ExecutionEpoch < 1 || value.LeaseExpiresAt.IsZero() || value.Result != nil || value.FailureCode != "" {
			return ErrInvalid
		}
	case StateSucceeded:
		if value.WorkerID == "" || value.LeaseEpoch < 1 || value.ExecutionEpoch < 1 || !value.LeaseExpiresAt.IsZero() || value.Result == nil || value.FailureCode != "" {
			return ErrInvalid
		}
		if value.Action == ActionBegin && (value.Result.Begin == nil || value.Result.Resume != nil || !sameBegin(*value.Result.Begin, value.Command)) ||
			value.Action == ActionResume && (value.Result.Resume == nil || value.Result.Begin != nil || !sameResume(*value.Result.Resume, value.Command)) {
			return ErrInvalid
		}
	case StateFailed:
		if value.WorkerID == "" || value.LeaseEpoch < 1 || value.ExecutionEpoch < 1 || !value.LeaseExpiresAt.IsZero() || value.Result != nil || value.FailureCode == "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type Repository interface {
	Create(context.Context, Operation, string, [32]byte) (Operation, error)
	Get(context.Context, string) (Operation, error)
	AcquireNext(context.Context, string, string, string, time.Time, time.Duration) (Operation, error)
	Complete(context.Context, string, string, int64, int64, string, [32]byte, *Result, string, time.Time) (Operation, error)
}

type Service struct {
	repository Repository
	now        func() time.Time
}

func NewService(repository Repository, now func() time.Time) (*Service, error) {
	if repository == nil || now == nil {
		return nil, ErrInvalid
	}
	return &Service{repository: repository, now: now}, nil
}

func (service *Service) Ensure(ctx context.Context, command Command, idempotencyKey string) (Operation, error) {
	hash, err := commandHash(command)
	if err != nil {
		return Operation{}, err
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	value := Operation{Command: command, State: StatePending, Revision: 1, CreatedAt: now, UpdatedAt: now}
	return service.repository.Create(ctx, value, idempotencyKey, hash)
}

func (service *Service) Get(ctx context.Context, operationID string) (Operation, error) {
	return service.repository.Get(ctx, operationID)
}

func (service *Service) AcquireNext(ctx context.Context, deploymentID, workerID, idempotencyKey string, lease time.Duration) (Operation, error) {
	if lease < 5*time.Second || lease > 30*time.Minute {
		return Operation{}, ErrInvalid
	}
	return service.repository.AcquireNext(ctx, deploymentID, workerID, idempotencyKey, service.now().UTC().Truncate(time.Microsecond), lease)
}

func (service *Service) Complete(ctx context.Context, operationID, workerID string, leaseEpoch, expectedRevision int64,
	idempotencyKey string, result *Result, failure string,
) (Operation, error) {
	if (failure == "" && result == nil) || (failure != "" && result != nil) {
		return Operation{}, ErrInvalid
	}
	if result != nil {
		current, err := service.repository.Get(ctx, operationID)
		if err != nil || !resultMatches(*result, current.Command) {
			return Operation{}, ErrInvalid
		}
	}
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s\n%s\n%d\n%d\n%s", operationID, workerID, leaseEpoch, expectedRevision, failure)))
	if result != nil {
		encoded, err := json.Marshal(result)
		if err != nil {
			return Operation{}, ErrInvalid
		}
		hash = sha256.Sum256(append(hash[:], encoded...))
		clear(encoded)
	}
	return service.repository.Complete(ctx, operationID, workerID, leaseEpoch, expectedRevision, idempotencyKey,
		hash, result, failure, service.now().UTC().Truncate(time.Microsecond))
}

type DurableDispatcher struct {
	Operations *Service
	Poll       time.Duration
}

func (dispatcher DurableDispatcher) Dispatch(ctx context.Context, command Command) (Result, error) {
	if dispatcher.Operations == nil {
		return Result{}, ErrInvalid
	}
	idempotencyKey := uuid.NewSHA1(uuid.MustParse(command.OperationID), []byte("create")).String()
	current, err := dispatcher.Operations.Ensure(ctx, command, idempotencyKey)
	if err != nil {
		return Result{}, err
	}
	poll := dispatcher.Poll
	if poll <= 0 {
		poll = 200 * time.Millisecond
	}
	for {
		switch current.State {
		case StateSucceeded:
			if current.Result == nil {
				return Result{}, ErrInvalid
			}
			return cloneResult(*current.Result), nil
		case StateFailed:
			return Result{}, fmt.Errorf("%w: %s", ErrLease, current.FailureCode)
		}
		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Result{}, ctx.Err()
		case <-timer.C:
		}
		current, err = dispatcher.Operations.Get(ctx, command.OperationID)
		if err != nil {
			return Result{}, err
		}
	}
}

func commandHash(command Command) ([32]byte, error) {
	if _, err := uuid.Parse(command.OperationID); err != nil || command.SessionID == "" || command.TaskID == "" ||
		command.StepID == "" || command.DeploymentID == "" || command.DeploymentRevision < 1 || command.OwnerID == "" || command.RecipeID == "" ||
		command.RecipeDigest == "" || command.RecipeRevision < 1 || command.PayloadScopeRevision < 1 ||
		command.CommandID == "" || command.ExecutionManifestDigest == "" || command.PairingExpiresAt.IsZero() ||
		command.ExecutionEpoch < 0 || command.ExecutionEpoch > 1 ||
		(command.Action == ActionBegin && (!validRecipient(command.RecipientPublicKey) ||
			command.RecipientPublicKeyDigest != recipientDigest(command.RecipientPublicKey))) ||
		(command.Action == ActionResume && (command.RecipientPublicKey != "" || command.RecipientPublicKeyDigest != "")) {
		return [32]byte{}, ErrInvalid
	}
	encoded, err := json.Marshal(command)
	if err != nil {
		return [32]byte{}, ErrInvalid
	}
	defer clear(encoded)
	return sha256.Sum256(encoded), nil
}

func recipientDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + fmt.Sprintf("%x", sum[:])
}

func resultMatches(result Result, command Command) bool {
	switch command.Action {
	case ActionBegin:
		return result.Begin != nil && result.Resume == nil && sameBegin(*result.Begin, command)
	case ActionResume:
		return result.Resume != nil && result.Begin == nil && sameResume(*result.Resume, command)
	default:
		return false
	}
}

func cloneResult(value Result) Result {
	encoded, _ := json.Marshal(value)
	var cloned Result
	_ = json.Unmarshal(encoded, &cloned)
	clear(encoded)
	return cloned
}

func sameHash(left, right [32]byte) bool { return bytes.Equal(left[:], right[:]) }
