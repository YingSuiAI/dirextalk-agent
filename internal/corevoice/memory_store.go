package corevoice

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"time"
)

// MemoryStore is a deterministic store for unit tests and local smoke runs.
// Its API is intentionally the same CAS/replay boundary as PostgresStore, so
// tests exercise owner/generation and restart semantics rather than a second
// fake protocol.
type MemoryStore struct {
	mu       sync.Mutex
	sessions map[string]Session
	turns    map[string]Turn
	events   map[string][]Event
	replay   map[string]memoryReplay
}

type memoryReplay struct {
	digest string
	value  []byte
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{sessions: map[string]Session{}, turns: map[string]Turn{}, events: map[string][]Event{}, replay: map[string]memoryReplay{}}
}

func (m *MemoryStore) CreateSession(_ context.Context, value Session) error {
	if m == nil || validateSession(value) != nil {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[value.ID]; ok {
		return ErrConflict
	}
	m.sessions[value.ID] = cloneSession(value)
	return nil
}

func (m *MemoryStore) CreateSessionWithReplay(_ context.Context, value Session, owner string, generation int64, operation, key, digest string, response []byte) error {
	if m == nil || validateSession(value) != nil || validateIdentity(owner, generation) != nil || value.OwnerID != owner || value.AccountGeneration != generation || operation == "" || key == "" || digest == "" || len(response) == 0 || !json.Valid(response) {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	mapKey := owner + "\x00" + strconv.FormatInt(generation, 10) + "\x00" + operation + "\x00" + key
	if _, exists := m.sessions[value.ID]; exists {
		return ErrConflict
	}
	if _, exists := m.replay[mapKey]; exists {
		return ErrConflict
	}
	m.sessions[value.ID] = cloneSession(value)
	m.replay[mapKey] = memoryReplay{digest: digest, value: append([]byte(nil), response...)}
	return nil
}

func (m *MemoryStore) GetSession(_ context.Context, owner, id string, generation int64) (Session, error) {
	if m == nil || validateIdentity(owner, generation) != nil {
		return Session{}, ErrForbidden
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.sessions[id]
	if !ok {
		return Session{}, ErrNotFound
	}
	if value.OwnerID != owner || value.AccountGeneration != generation {
		return Session{}, ErrForbidden
	}
	if value.State == SessionEnded && value.TombstoneExpiresAt != nil && !time.Now().UTC().Before(*value.TombstoneExpiresAt) {
		return Session{}, ErrNotFound
	}
	return cloneSession(value), nil
}

func (m *MemoryStore) FindSession(_ context.Context, id string) (Session, error) {
	if m == nil || id == "" {
		return Session{}, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.sessions[id]
	if !ok {
		return Session{}, ErrNotFound
	}
	return cloneSession(value), nil
}

func (m *MemoryStore) SaveSession(_ context.Context, value Session, expectedRevision int64) error {
	if m == nil || validateSession(value) != nil || expectedRevision <= 0 {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.sessions[value.ID]
	if !ok {
		return ErrNotFound
	}
	if current.OwnerID != value.OwnerID || current.AccountGeneration != value.AccountGeneration || current.Revision != expectedRevision {
		return ErrConflict
	}
	if stateTerminalValue(current.State) && value.State != current.State {
		return ErrTerminal
	}
	m.sessions[value.ID] = cloneSession(value)
	return nil
}

func (m *MemoryStore) CreateTurn(_ context.Context, value Turn) error {
	if m == nil || validateTurn(value) != nil {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.turns[value.ID]; ok {
		return ErrConflict
	}
	m.turns[value.ID] = value
	return nil
}

func (m *MemoryStore) GetTurn(_ context.Context, owner, sessionID, turnID string, generation int64) (Turn, error) {
	if m == nil || validateIdentity(owner, generation) != nil {
		return Turn{}, ErrForbidden
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.turns[turnID]
	if !ok {
		return Turn{}, ErrNotFound
	}
	if value.OwnerID != owner || value.AccountGeneration != generation || value.SessionID != sessionID {
		return Turn{}, ErrForbidden
	}
	return value, nil
}

func (m *MemoryStore) SaveTurn(_ context.Context, value Turn, expectedRevision int64) error {
	if m == nil || validateTurn(value) != nil || expectedRevision <= 0 {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.turns[value.ID]
	if !ok {
		return ErrNotFound
	}
	if current.OwnerID != value.OwnerID || current.AccountGeneration != value.AccountGeneration || current.Revision != expectedRevision {
		return ErrConflict
	}
	if stateTerminal(current.State) && value.State != current.State {
		return ErrTerminal
	}
	m.turns[value.ID] = value
	return nil
}

func (m *MemoryStore) AppendEvent(_ context.Context, event Event) (Event, error) {
	if m == nil || validateEvent(event) != nil {
		return Event{}, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	list := m.events[event.SessionID]
	if len(list) >= MaxEventsPerSession {
		return Event{}, ErrConflict
	}
	event.Sequence = int64(len(list) + 1)
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	event.Data = append([]byte(nil), event.Data...)
	m.events[event.SessionID] = append(list, event)
	return event, nil
}

func (m *MemoryStore) ListEvents(_ context.Context, owner, sessionID string, generation, after int64, limit int) ([]Event, error) {
	if m == nil || validateIdentity(owner, generation) != nil || after < 0 || limit <= 0 || limit > 256 {
		return nil, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.sessions[sessionID]
	if !ok {
		return nil, ErrNotFound
	}
	if value.OwnerID != owner || value.AccountGeneration != generation {
		return nil, ErrForbidden
	}
	list := m.events[sessionID]
	out := make([]Event, 0, limit)
	for _, event := range list {
		if event.Sequence <= after {
			continue
		}
		out = append(out, cloneEvent(event))
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *MemoryStore) Replay(_ context.Context, owner string, generation int64, operation, key, digest string) ([]byte, bool, error) {
	if m == nil || validateIdentity(owner, generation) != nil || operation == "" || key == "" || digest == "" {
		return nil, false, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.replay[owner+"\x00"+strconv.FormatInt(generation, 10)+"\x00"+operation+"\x00"+key]
	if !ok {
		return nil, false, nil
	}
	if value.digest != digest {
		return nil, false, ErrConflict
	}
	return append([]byte(nil), value.value...), true, nil
}

func (m *MemoryStore) SaveReplay(_ context.Context, owner string, generation int64, operation, key, digest string, value []byte) error {
	if m == nil || validateIdentity(owner, generation) != nil || operation == "" || key == "" || digest == "" || len(value) == 0 || !json.Valid(value) {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	mapKey := owner + "\x00" + strconv.FormatInt(generation, 10) + "\x00" + operation + "\x00" + key
	if current, ok := m.replay[mapKey]; ok {
		if current.digest != digest {
			return ErrConflict
		}
		return nil
	}
	m.replay[mapKey] = memoryReplay{digest: digest, value: append([]byte(nil), value...)}
	return nil
}

func (m *MemoryStore) Recover(_ context.Context, now time.Time) error {
	if m == nil {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, session := range m.sessions {
		if session.State != SessionEnded && !now.Before(session.ExpiresAt) {
			session.State = SessionEnded
			session.ProviderStopPending = true
			session.ActiveTurnID = ""
			session.Revision++
			session.EndedAt = ptrTime(now)
			session.TombstoneExpiresAt = ptrTime(now.Add(TombstoneTTL))
			session.UpdatedAt = now
			m.sessions[id] = session
			m.appendEventLocked(Event{SessionID: id, Event: "session.done", Data: []byte(`{"status":"done","session_ended":true}`), CreatedAt: now})
		}
	}
	for _, turn := range m.turns {
		if turn.State != TurnPending && turn.State != TurnRunning {
			continue
		}
		turn.State, turn.ErrorCode, turn.ErrorMessage, turn.Revision, turn.UpdatedAt = TurnUncertain, "UNCERTAIN", "turn interrupted by Agent restart", turn.Revision+1, now
		m.turns[turn.ID] = turn
		m.appendEventLocked(Event{SessionID: turn.SessionID, Event: "turn.uncertain", Data: []byte(`{"status":"uncertain"}`), CreatedAt: now})
	}
	return nil
}

func (m *MemoryStore) ListPendingStops(_ context.Context) ([]Session, error) {
	if m == nil {
		return nil, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]Session, 0)
	for _, value := range m.sessions {
		if value.ProviderStopPending {
			result = append(result, cloneSession(value))
		}
	}
	return result, nil
}

func (m *MemoryStore) ListProviderIntents(_ context.Context) ([]Session, error) {
	if m == nil {
		return nil, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]Session, 0)
	for _, value := range m.sessions {
		if value.ProviderIntent != ProviderIntentNone || value.ProviderUncertain {
			result = append(result, cloneSession(value))
		}
	}
	return result, nil
}

func (m *MemoryStore) appendEventLocked(event Event) {
	if len(m.events[event.SessionID]) >= MaxEventsPerSession {
		return
	}
	event.Sequence = int64(len(m.events[event.SessionID]) + 1)
	m.events[event.SessionID] = append(m.events[event.SessionID], event)
}

func cloneSession(value Session) Session {
	if value.StartedAt != nil {
		v := *value.StartedAt
		value.StartedAt = &v
	}
	if value.EndedAt != nil {
		v := *value.EndedAt
		value.EndedAt = &v
	}
	if value.TombstoneExpiresAt != nil {
		v := *value.TombstoneExpiresAt
		value.TombstoneExpiresAt = &v
	}
	return value
}

func cloneEvent(value Event) Event {
	value.Data = append([]byte(nil), value.Data...)
	return value
}

func stateTerminalValue(state SessionState) bool { return state == SessionEnded }

var _ Store = (*MemoryStore)(nil)
var _ AtomicCreateStore = (*MemoryStore)(nil)
