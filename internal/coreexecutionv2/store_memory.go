package coreexecutionv2

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

// MemoryStore is intentionally strict and mirrors the PostgreSQL CAS rules;
// it is suitable for focused contract tests and local composition probes.
type MemoryStore struct {
	mu        sync.RWMutex
	records   map[string]Record
	revisions map[string]map[uint64]Record
	replays   map[string]Replay
	events    map[string][]Event
	secrets   map[string]Secret
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: map[string]Record{}, revisions: map[string]map[uint64]Record{}, replays: map[string]Replay{}, events: map[string][]Event{}, secrets: map[string]Secret{}}
}

func recordKey(owner, kind, id string) string   { return owner + "\x00" + kind + "\x00" + id }
func replayKey(owner, action, id string) string { return owner + "\x00" + action + "\x00" + id }
func eventKey(owner, kind, id string) string    { return recordKey(owner, kind, id) }

func (m *MemoryStore) Read(_ context.Context, owner, kind, id string, revision uint64) (Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	record, ok := m.records[recordKey(owner, kind, id)]
	if !ok {
		return Record{}, ErrNotFound
	}
	if revision > 0 && revision != record.Revision {
		if historical, exists := m.revisions[recordKey(owner, kind, id)][revision]; exists {
			return cloneRecord(historical), nil
		}
		return Record{}, ErrNotFound
	}
	return cloneRecord(record), nil
}

func (m *MemoryStore) List(_ context.Context, owner, kind string, filter map[string]string, token string, limit int) ([]Record, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]Record, 0)
	for _, record := range m.records {
		if record.OwnerID != owner || record.Kind != kind {
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
	key := recordKey(record.OwnerID, record.Kind, record.ID)
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
	key := recordKey(record.OwnerID, record.Kind, record.ID)
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

func (m *MemoryStore) Replay(_ context.Context, owner, action, id string) (Replay, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	replay, ok := m.replays[replayKey(owner, action, id)]
	if !ok {
		return Replay{}, false, nil
	}
	replay.Response = append([]byte(nil), replay.Response...)
	replay.Digest = append([]byte(nil), replay.Digest...)
	return replay, true, nil
}
func (m *MemoryStore) SaveReplay(_ context.Context, owner, action, id string, digest, response []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := replayKey(owner, action, id)
	if old, ok := m.replays[key]; ok {
		if !equalBytes(old.Digest, digest) {
			return ErrConflict
		}
		return nil
	}
	m.replays[key] = Replay{Digest: append([]byte(nil), digest...), Response: append([]byte(nil), response...)}
	return nil
}

func (m *MemoryStore) AppendEvent(_ context.Context, event Event) (Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := eventKey(event.OwnerID, event.Kind, event.ResourceID)
	event.Sequence = uint64(len(m.events[key]) + 1)
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	m.events[key] = append(m.events[key], event)
	return event, nil
}
func (m *MemoryStore) Events(_ context.Context, owner, kind, id string, after uint64, limit int) ([]Event, uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	source := m.events[eventKey(owner, kind, id)]
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
	key := recordKey(secret.OwnerID, "secret", secret.Ref)
	if _, ok := m.secrets[key]; ok {
		return Secret{}, ErrConflict
	}
	m.secrets[key] = secret
	return secret, nil
}
func (m *MemoryStore) ReadSecret(_ context.Context, owner, ref string, revision uint64) (Secret, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	secret, ok := m.secrets[recordKey(owner, "secret", ref)]
	if !ok || revision > 0 && revision != secret.Revision {
		return Secret{}, ErrSecretNotFound
	}
	return secret, nil
}
func (m *MemoryStore) ListSecrets(_ context.Context, owner, token string, limit int) ([]Secret, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]Secret, 0)
	for _, secret := range m.secrets {
		if secret.OwnerID == owner {
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
	key := recordKey(secret.OwnerID, "secret", secret.Ref)
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
