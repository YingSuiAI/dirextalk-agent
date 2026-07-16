package approval

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MemoryRegistry is the concurrency-safe fake for domain and provider contract
// tests. Production persistence is supplied by the Agent PostgreSQL adapter.
type MemoryRegistry struct {
	mu         sync.Mutex
	devices    map[string]DeviceKeyV1
	challenges map[string]ChallengeV1
}

func NewMemoryRegistry() *MemoryRegistry {
	return &MemoryRegistry{
		devices:    make(map[string]DeviceKeyV1),
		challenges: make(map[string]ChallengeV1),
	}
}

func (r *MemoryRegistry) PutDeviceKey(value DeviceKeyV1) error {
	if value.KeyID == "" || len(value.PublicKey) == 0 {
		return fmt.Errorf("device key is incomplete")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	value.PublicKey = append([]byte(nil), value.PublicKey...)
	r.devices[value.KeyID] = value
	return nil
}

func (r *MemoryRegistry) GetDeviceKey(ctx context.Context, keyID string) (DeviceKeyV1, error) {
	if ctx == nil {
		return DeviceKeyV1{}, fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return DeviceKeyV1{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	value, exists := r.devices[keyID]
	if !exists {
		return DeviceKeyV1{}, ErrDeviceNotFound
	}
	value.PublicKey = append([]byte(nil), value.PublicKey...)
	if value.RevokedAt != nil {
		copy := *value.RevokedAt
		value.RevokedAt = &copy
	}
	return value, nil
}

func (r *MemoryRegistry) CreateChallenge(ctx context.Context, value ChallengeV1) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.challenges[value.ChallengeID]; exists {
		return fmt.Errorf("challenge already exists: %w", ErrRevisionConflict)
	}
	r.challenges[value.ChallengeID] = cloneChallenge(value)
	return nil
}

func (r *MemoryRegistry) GetChallenge(ctx context.Context, challengeID string) (ChallengeV1, error) {
	if ctx == nil {
		return ChallengeV1{}, fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return ChallengeV1{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	value, exists := r.challenges[challengeID]
	if !exists {
		return ChallengeV1{}, ErrChallengeNotFound
	}
	return cloneChallenge(value), nil
}

func (r *MemoryRegistry) ConsumeChallenge(ctx context.Context, challengeID string, expectedRevision uint64, consumedAt time.Time) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	value, exists := r.challenges[challengeID]
	if !exists {
		return ErrChallengeNotFound
	}
	if value.ConsumedAt != nil {
		return ErrChallengeConsumed
	}
	if value.Revision != expectedRevision {
		return ErrRevisionConflict
	}
	value.Revision++
	copy := consumedAt.UTC()
	value.ConsumedAt = &copy
	r.challenges[challengeID] = value
	return nil
}

func cloneChallenge(value ChallengeV1) ChallengeV1 {
	if value.ConsumedAt != nil {
		copy := *value.ConsumedAt
		value.ConsumedAt = &copy
	}
	return value
}
