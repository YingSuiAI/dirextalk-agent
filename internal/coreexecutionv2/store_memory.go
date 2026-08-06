package coreexecutionv2

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type memoryReplay struct {
	digest           []byte
	response         []byte
	providerResponse []byte
	token            string
	leaseExpiresAt   time.Time
	completed        bool
	dispatched       bool
}

// MemoryStore is intentionally strict and mirrors the PostgreSQL CAS rules;
// it is suitable for focused contract tests and local composition probes.
type MemoryStore struct {
	mu        sync.RWMutex
	records   map[string]Record
	revisions map[string]map[uint64]Record
	replays   map[string]memoryReplay
	events    map[string][]Event
	secrets   map[string]Secret
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: map[string]Record{}, revisions: map[string]map[uint64]Record{}, replays: map[string]memoryReplay{}, events: map[string][]Event{}, secrets: map[string]Secret{}}
}

func scopeKey(owner string, generation int64) string { return owner + "\x00" + fmt.Sprint(generation) }
func recordKey(owner string, generation int64, kind, id string) string {
	return scopeKey(owner, generation) + "\x00" + kind + "\x00" + id
}
func replayKey(scope coretask.OwnerScope, action, id string) string {
	return scopeKey(scope.OwnerID, scope.AccountGeneration) + "\x00" + action + "\x00" + id
}
func eventKey(owner string, generation int64, kind, id string) string {
	return recordKey(owner, generation, kind, id)
}

func (m *MemoryStore) Read(_ context.Context, scope coretask.OwnerScope, kind, id string, revision uint64) (Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	record, ok := m.records[recordKey(scope.OwnerID, scope.AccountGeneration, kind, id)]
	if !ok {
		return Record{}, ErrNotFound
	}
	if revision > 0 && revision != record.Revision {
		if historical, exists := m.revisions[recordKey(scope.OwnerID, scope.AccountGeneration, kind, id)][revision]; exists {
			return cloneRecord(historical), nil
		}
		return Record{}, ErrNotFound
	}
	return cloneRecord(record), nil
}

func (m *MemoryStore) List(_ context.Context, scope coretask.OwnerScope, kind string, filter map[string]string, token string, limit int) ([]Record, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]Record, 0)
	for _, record := range m.records {
		if record.OwnerID != scope.OwnerID || record.AccountGeneration != scope.AccountGeneration || record.Kind != kind {
			continue
		}
		match := true
		for key, value := range filter {
			if value == "" {
				continue
			}
			if key == "state" {
				matched := false
				for _, state := range strings.Split(value, ",") {
					if strings.TrimSpace(state) == record.Status || strings.TrimSpace(state) == stringParam(record.Payload, "state") {
						matched = true
						break
					}
				}
				if !matched {
					match = false
					break
				}
				continue
			}
			if stringParam(record.Payload, key) != value {
				match = false
				break
			}
		}
		if match {
			items = append(items, cloneRecord(record))
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].ID < items[j].ID
		}
		return items[i].CreatedAt.Before(items[j].CreatedAt)
	})
	start := 0
	if token != "" {
		for i := range items {
			if items[i].ID == token {
				start = i + 1
				break
			}
		}
	}
	if start > len(items) {
		start = len(items)
	}
	end := start + limit
	if end > len(items) {
		end = len(items)
	}
	next := ""
	if end < len(items) {
		next = items[end-1].ID
	}
	return items[start:end], next, nil
}

func (m *MemoryStore) Create(_ context.Context, record Record) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := recordKey(record.OwnerID, record.AccountGeneration, record.Kind, record.ID)
	if _, exists := m.records[key]; exists {
		return Record{}, ErrConflict
	}
	m.records[key] = cloneRecord(record)
	m.revisions[key] = map[uint64]Record{record.Revision: cloneRecord(record)}
	return cloneRecord(record), nil
}

func (m *MemoryStore) Update(_ context.Context, record Record, expected uint64) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := recordKey(record.OwnerID, record.AccountGeneration, record.Kind, record.ID)
	current, ok := m.records[key]
	if !ok {
		return Record{}, ErrNotFound
	}
	if current.Revision != expected {
		return Record{}, ErrConflict
	}
	record.Revision = expected + 1
	m.records[key] = cloneRecord(record)
	if m.revisions[key] == nil {
		m.revisions[key] = map[uint64]Record{}
	}
	m.revisions[key][record.Revision] = cloneRecord(record)
	return cloneRecord(record), nil
}

func (m *MemoryStore) BeginReplay(_ context.Context, scope coretask.OwnerScope, action, id string, digest []byte, now time.Time, lease time.Duration) (ReplayClaim, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := replayKey(scope, action, id)
	if old, ok := m.replays[key]; ok {
		if !equalBytes(old.digest, digest) {
			return ReplayClaim{}, ErrConflict
		}
		if old.completed {
			return ReplayClaim{Response: append([]byte(nil), old.response...), Completed: true}, nil
		}
		if now.Before(old.leaseExpiresAt) {
			return ReplayClaim{}, ErrReplayInProgress
		}
		if old.dispatched && len(old.providerResponse) == 0 {
			return ReplayClaim{Dispatched: true}, nil
		}
	}
	token := uuid.NewString()
	old := m.replays[key]
	old.digest = append([]byte(nil), digest...)
	old.token = token
	old.leaseExpiresAt = now.Add(lease)
	m.replays[key] = old
	return ReplayClaim{Token: token, Dispatched: old.dispatched, ProviderResponse: append([]byte(nil), old.providerResponse...)}, nil
}

func (m *MemoryStore) MarkReplayDispatched(_ context.Context, scope coretask.OwnerScope, action, id string, digest []byte, token string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := replayKey(scope, action, id)
	current, ok := m.replays[key]
	if !ok || current.completed || current.dispatched || current.token != token || !equalBytes(current.digest, digest) {
		return ErrConflict
	}
	current.dispatched = true
	m.replays[key] = current
	return nil
}

func (m *MemoryStore) StoreReplayProviderResponse(_ context.Context, scope coretask.OwnerScope, action, id string, digest []byte, token string, response []byte, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := replayKey(scope, action, id)
	current, ok := m.replays[key]
	if !ok || current.completed || !current.dispatched || current.token != token || !equalBytes(current.digest, digest) {
		return ErrConflict
	}
	current.providerResponse = append([]byte(nil), response...)
	m.replays[key] = current
	return nil
}

func (m *MemoryStore) CompleteReplay(_ context.Context, scope coretask.OwnerScope, action, id string, digest []byte, token string, response []byte, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := replayKey(scope, action, id)
	current, ok := m.replays[key]
	if !ok || current.completed || current.token != token || !equalBytes(current.digest, digest) {
		return ErrConflict
	}
	current.response = append([]byte(nil), response...)
	current.completed = true
	current.token = ""
	current.leaseExpiresAt = time.Time{}
	m.replays[key] = current
	return nil
}

func (m *MemoryStore) AbortReplay(_ context.Context, scope coretask.OwnerScope, action, id string, digest []byte, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := replayKey(scope, action, id)
	current, ok := m.replays[key]
	if !ok {
		return nil
	}
	if current.completed || current.dispatched || current.token != token || !equalBytes(current.digest, digest) {
		return ErrConflict
	}
	delete(m.replays, key)
	return nil
}

func (m *MemoryStore) AppendEvent(_ context.Context, event Event) (Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := eventKey(event.OwnerID, event.AccountGeneration, event.Kind, event.ResourceID)
	for _, existing := range m.events[key] {
		if existing.EventID == event.EventID {
			if existing.Type != event.Type || digestPayload(existing.Payload) != digestPayload(event.Payload) {
				return Event{}, ErrConflict
			}
			return existing, nil
		}
	}
	event.Sequence = uint64(len(m.events[key]) + 1)
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	m.events[key] = append(m.events[key], event)
	return event, nil
}
func (m *MemoryStore) Events(_ context.Context, scope coretask.OwnerScope, kind, id string, after uint64, limit int) ([]Event, uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	source := m.events[eventKey(scope.OwnerID, scope.AccountGeneration, kind, id)]
	out := make([]Event, 0)
	for _, event := range source {
		if event.Sequence > after && len(out) < limit {
			out = append(out, event)
		}
	}
	latest := uint64(len(source))
	return out, latest, nil
}

func (m *MemoryStore) SaveSecret(_ context.Context, secret Secret) (Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := recordKey(secret.OwnerID, secret.AccountGeneration, "secret", secret.Ref)
	if _, ok := m.secrets[key]; ok {
		return Secret{}, ErrConflict
	}
	m.secrets[key] = secret
	return secret, nil
}
func (m *MemoryStore) ReadSecret(_ context.Context, scope coretask.OwnerScope, ref string, revision uint64) (Secret, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	secret, ok := m.secrets[recordKey(scope.OwnerID, scope.AccountGeneration, "secret", ref)]
	if !ok || revision > 0 && revision != secret.Revision {
		return Secret{}, ErrSecretNotFound
	}
	return secret, nil
}
func (m *MemoryStore) ListSecrets(_ context.Context, scope coretask.OwnerScope, token string, limit int) ([]Secret, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]Secret, 0)
	for _, secret := range m.secrets {
		if secret.OwnerID == scope.OwnerID && secret.AccountGeneration == scope.AccountGeneration {
			items = append(items, secret)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Ref < items[j].Ref })
	start := 0
	if token != "" {
		for i := range items {
			if items[i].Ref == token {
				start = i + 1
				break
			}
		}
	}
	end := start + limit
	if end > len(items) {
		end = len(items)
	}
	next := ""
	if end < len(items) {
		next = items[end-1].Ref
	}
	return items[start:end], next, nil
}
func (m *MemoryStore) RevokeSecret(_ context.Context, secret Secret, expected uint64) (Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := recordKey(secret.OwnerID, secret.AccountGeneration, "secret", secret.Ref)
	current, ok := m.secrets[key]
	if !ok {
		return Secret{}, ErrSecretNotFound
	}
	if current.Revision != expected {
		return Secret{}, ErrConflict
	}
	secret.Revision = expected + 1
	m.secrets[key] = secret
	return secret, nil
}

func cloneRecord(record Record) Record { record.Payload = cloneMap(record.Payload); return record }
