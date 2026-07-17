package helperkey

import (
	"context"
	"crypto/subtle"
	"sync"
)

type replay struct {
	hash  [32]byte
	value Record
}

type MemoryRepository struct {
	mu      sync.Mutex
	records map[string]Record
	replays map[string]replay
	workers map[string]memoryWorkerBinding
}

type memoryWorkerBinding struct {
	ownerID, instanceID, principalID string
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		records: map[string]Record{}, replays: map[string]replay{},
		workers: map[string]memoryWorkerBinding{},
	}
}

// BindWorkerSession supplies provider-verified identity facts to this
// deterministic fake. Production discovery reads the durable enrollment.
func (r *MemoryRepository) BindWorkerSession(deploymentID, workerID, ownerID, instanceID, principalID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.workers[deploymentID+"\x00"+workerID] = memoryWorkerBinding{ownerID, instanceID, principalID}
}

func (r *MemoryRepository) CreateIdempotent(_ context.Context, value Record, key string, hash [32]byte) (Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	replayKey := value.Binding.DeliveryID + "\x00create\x00" + key
	if existing, ok := r.replays[replayKey]; ok {
		if subtle.ConstantTimeCompare(existing.hash[:], hash[:]) != 1 {
			return Record{}, ErrConflict
		}
		return existing.value.Clone(), nil
	}
	if _, exists := r.records[value.Binding.DeliveryID]; exists {
		return Record{}, ErrConflict
	}
	r.records[value.Binding.DeliveryID] = value.Clone()
	r.replays[replayKey] = replay{hash: hash, value: value.Clone()}
	return value.Clone(), nil
}

func (r *MemoryRepository) Get(_ context.Context, id string) (Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.records[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	return value.Clone(), nil
}

func (r *MemoryRepository) DiscoverCurrent(_ context.Context, scope DiscoveryScope) (Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	identity, ok := r.workers[scope.DeploymentID+"\x00"+scope.WorkerID]
	if !ok || identity.ownerID != scope.OwnerID {
		return Record{}, ErrNotFound
	}
	found := make([]Record, 0, 2)
	for _, value := range r.records {
		if value.Binding.DeploymentID == scope.DeploymentID && value.Binding.OwnerID == scope.OwnerID &&
			value.Binding.InstanceID == identity.instanceID &&
			value.Binding.WorkerPrincipalID == identity.principalID && discoverableState(value.State) {
			found = append(found, value)
		}
	}
	if len(found) == 0 {
		return Record{}, ErrNotFound
	}
	if len(found) != 1 {
		return Record{}, ErrConflict
	}
	return found[0].Clone(), nil
}

func (r *MemoryRepository) UpdateIdempotent(_ context.Context, id string, expected State, key string, hash [32]byte, update func(*Record) error) (Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	replayKey := id + "\x00" + string(expected) + "\x00" + key
	if existing, ok := r.replays[replayKey]; ok {
		if subtle.ConstantTimeCompare(existing.hash[:], hash[:]) != 1 {
			return Record{}, ErrConflict
		}
		return existing.value.Clone(), nil
	}
	current, ok := r.records[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	if current.State != expected {
		return Record{}, ErrConflict
	}
	next := current.Clone()
	if err := update(&next); err != nil || next.Validate() != nil {
		return Record{}, ErrInvalid
	}
	r.records[id] = next.Clone()
	r.replays[replayKey] = replay{hash: hash, value: next.Clone()}
	return next, nil
}
