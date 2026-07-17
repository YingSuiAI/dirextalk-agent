package pairingworker

import (
	"context"
	"sync"
	"time"
)

type memoryReplay struct {
	key  string
	hash [32]byte
}

type MemoryRepository struct {
	mu      sync.Mutex
	values  map[string]Operation
	creates map[string]memoryReplay
	done    map[string]memoryReplay
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{values: map[string]Operation{}, creates: map[string]memoryReplay{}, done: map[string]memoryReplay{}}
}

func (repo *MemoryRepository) Create(_ context.Context, value Operation, key string, hash [32]byte) (Operation, error) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if replay, ok := repo.creates[value.OperationID]; ok {
		if replay.key != key || !sameHash(replay.hash, hash) {
			return Operation{}, ErrRevisionConflict
		}
		return repo.values[value.OperationID], nil
	}
	if value.Validate() != nil {
		return Operation{}, ErrInvalid
	}
	repo.values[value.OperationID], repo.creates[value.OperationID] = value, memoryReplay{key, hash}
	return value, nil
}

func (repo *MemoryRepository) Get(_ context.Context, id string) (Operation, error) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	value, ok := repo.values[id]
	if !ok {
		return Operation{}, ErrNotFound
	}
	return value, nil
}

func (repo *MemoryRepository) AcquireNext(_ context.Context, deployment, worker, key string, now time.Time, lease time.Duration) (Operation, error) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	for _, value := range repo.values {
		if value.DeploymentID == deployment && value.State == StateLeased &&
			value.WorkerID == worker && now.Before(value.LeaseExpiresAt) {
			return value, nil
		}
	}
	for id, value := range repo.values {
		if value.DeploymentID != deployment || (value.State != StatePending && !(value.State == StateLeased && !now.Before(value.LeaseExpiresAt))) {
			continue
		}
		value.State, value.WorkerID, value.LeaseEpoch = StateLeased, worker, value.LeaseEpoch+1
		if value.ExecutionEpoch == 0 {
			// This is an operation identity, not a transport fencing token. It
			// survives every later lease so a response-lost root receipt remains
			// verifiable on replay.
			value.ExecutionEpoch = 1
		}
		value.LeaseExpiresAt, value.Revision, value.UpdatedAt = now.Add(lease), value.Revision+1, now
		repo.values[id] = value
		return value, nil
	}
	return Operation{}, ErrNotFound
}

func (repo *MemoryRepository) Complete(_ context.Context, id, worker string, epoch, expected int64, key string, hash [32]byte,
	result *Result, failure string, now time.Time,
) (Operation, error) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if replay, ok := repo.done[id]; ok {
		if replay.key != key || !sameHash(replay.hash, hash) {
			return Operation{}, ErrRevisionConflict
		}
		return repo.values[id], nil
	}
	value, ok := repo.values[id]
	if !ok {
		return Operation{}, ErrNotFound
	}
	if value.State != StateLeased || value.WorkerID != worker || value.LeaseEpoch != epoch || value.Revision != expected || !now.Before(value.LeaseExpiresAt) {
		return Operation{}, ErrLease
	}
	value.LeaseExpiresAt, value.Revision, value.UpdatedAt = time.Time{}, value.Revision+1, now
	if failure != "" {
		value.State, value.FailureCode = StateFailed, failure
	} else {
		cloned := cloneResult(*result)
		value.State, value.Result = StateSucceeded, &cloned
	}
	if value.Validate() != nil {
		return Operation{}, ErrInvalid
	}
	repo.values[id], repo.done[id] = value, memoryReplay{key, hash}
	return value, nil
}
