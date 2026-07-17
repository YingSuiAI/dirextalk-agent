package workeroperation

import (
	"context"
	"sort"
	"sync"
)

type replayKey struct {
	operationID string
	operation   string
	key         string
}

type replayRecord struct {
	hash     [32]byte
	response Operation
}

// MemoryRepository is a deterministic fake used by the Worker runner boundary.
type MemoryRepository struct {
	mu         sync.Mutex
	operations map[string]Operation
	replays    map[replayKey]replayRecord
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{operations: map[string]Operation{}, replays: map[replayKey]replayRecord{}}
}

func (repository *MemoryRepository) CreateIdempotent(_ context.Context, value Operation, mutation Mutation) (Operation, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := replayKey{value.OperationID, "create", mutation.IdempotencyKey}
	if replay, ok := repository.replays[key]; ok {
		if replay.hash != mutation.RequestHash {
			return Operation{}, ErrIdempotencyConflict
		}
		return replay.response.Clone(), nil
	}
	if _, ok := repository.operations[value.OperationID]; ok {
		return Operation{}, ErrIdempotencyConflict
	}
	repository.operations[value.OperationID] = value.Clone()
	repository.replays[key] = replayRecord{mutation.RequestHash, value.Clone()}
	return value.Clone(), nil
}

func (repository *MemoryRepository) Get(_ context.Context, operationID string) (Operation, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	value, ok := repository.operations[operationID]
	if !ok {
		return Operation{}, ErrNotFound
	}
	return value.Clone(), nil
}

func (repository *MemoryRepository) MutateIdempotent(_ context.Context, operationID, operation string, mutation Mutation, update func(*Operation) error) (Operation, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := replayKey{operationID, operation, mutation.IdempotencyKey}
	if replay, ok := repository.replays[key]; ok {
		if replay.hash != mutation.RequestHash {
			return Operation{}, ErrIdempotencyConflict
		}
		return replay.response.Clone(), nil
	}
	current, ok := repository.operations[operationID]
	if !ok {
		return Operation{}, ErrNotFound
	}
	if current.Revision != mutation.ExpectedRevision {
		return Operation{}, ErrRevisionConflict
	}
	next := current.Clone()
	if err := update(&next); err != nil {
		return Operation{}, err
	}
	if err := next.Validate(); err != nil {
		return Operation{}, err
	}
	repository.operations[operationID] = next.Clone()
	repository.replays[key] = replayRecord{mutation.RequestHash, next.Clone()}
	return next.Clone(), nil
}

func (repository *MemoryRepository) AcquireNext(_ context.Context, selection AcquireSelection) (Operation, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if selection.Now.IsZero() || selection.LeaseDuration < minLease || selection.LeaseDuration > maxLease {
		return Operation{}, ErrInvalid
	}
	for key, replay := range repository.replays {
		if key.operation == "acquire" && key.key == selection.Mutation.IdempotencyKey {
			if replay.hash != selection.Mutation.RequestHash {
				return Operation{}, ErrIdempotencyConflict
			}
			if replay.response.DeploymentID != selection.DeploymentID || replay.response.WorkerID != selection.WorkerID {
				return Operation{}, ErrInvalid
			}
			return replay.response.Clone(), nil
		}
	}
	active := make([]Operation, 0, 1)
	for _, value := range repository.operations {
		if value.DeploymentID == selection.DeploymentID && value.State == StateLeased &&
			value.WorkerID == selection.WorkerID && selection.Now.Before(value.LeaseExpiresAt) {
			active = append(active, value)
		}
	}
	if len(active) > 1 {
		return Operation{}, ErrInvalid
	}
	if len(active) == 1 {
		value := active[0].Clone()
		repository.replays[replayKey{value.OperationID, "acquire", selection.Mutation.IdempotencyKey}] =
			replayRecord{selection.Mutation.RequestHash, value.Clone()}
		return value, nil
	}
	candidates := make([]Operation, 0)
	for _, value := range repository.operations {
		if value.DeploymentID == selection.DeploymentID &&
			(value.State == StatePending || (value.State == StateLeased && !selection.Now.Before(value.LeaseExpiresAt))) {
			candidates = append(candidates, value)
		}
	}
	if len(candidates) == 0 {
		return Operation{}, ErrNotFound
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].CreatedAt.Equal(candidates[j].CreatedAt) {
			return candidates[i].OperationID < candidates[j].OperationID
		}
		return candidates[i].CreatedAt.Before(candidates[j].CreatedAt)
	})
	next := candidates[0].Clone()
	next.State, next.WorkerID = StateLeased, selection.WorkerID
	next.LeaseEpoch++
	next.LeaseExpiresAt = selection.Now.Add(selection.LeaseDuration)
	next.Revision++
	next.UpdatedAt = selection.Now
	if next.Validate() != nil {
		return Operation{}, ErrInvalid
	}
	repository.operations[next.OperationID] = next.Clone()
	repository.replays[replayKey{next.OperationID, "acquire", selection.Mutation.IdempotencyKey}] =
		replayRecord{selection.Mutation.RequestHash, next.Clone()}
	return next.Clone(), nil
}
