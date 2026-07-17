package secretbootstrap

import (
	"context"
	"crypto/subtle"
	"sort"
	"sync"
	"time"
)

type MemoryStore struct {
	mu      sync.Mutex
	records map[string]Record
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]Record)}
}

func (s *MemoryStore) Create(ctx context.Context, record Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateSession(record.Session); err != nil || ValidateClientID(record.CreatorClientID) != nil || record.Session.Status != StatusAwaitingUpload || record.Session.Revision != 1 || record.KeyHandle == "" || record.Envelope != nil || record.UploadTokenHash == ([32]byte{}) {
		return ErrInvalidContext
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[record.Session.SessionID]; exists {
		return ErrAlreadyExists
	}
	s.records[record.Session.SessionID] = cloneRecord(record)
	return nil
}

func (s *MemoryStore) Get(ctx context.Context, sessionID string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.records[sessionID]
	if !exists {
		return Record{}, ErrNotFound
	}
	return cloneRecord(record), nil
}

func (s *MemoryStore) FindUploaded(ctx context.Context, creatorClientID string, binding BindingV1, now time.Time) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var matched *Record
	for _, record := range s.records {
		if record.CreatorClientID != creatorClientID || record.Session.Binding() != binding ||
			record.Session.Status != StatusUploaded || !now.Before(record.Session.ExpiresAt) {
			continue
		}
		if matched != nil {
			return Record{}, ErrStateConflict
		}
		value := cloneRecord(record)
		matched = &value
	}
	if matched == nil {
		return Record{}, ErrNotFound
	}
	return *matched, nil
}

func (s *MemoryStore) CommitUpload(ctx context.Context, sessionID string, expectedRevision uint64, uploadTokenHash [32]byte, envelope EnvelopeV1, now time.Time) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.records[sessionID]
	if !exists {
		return Record{}, ErrNotFound
	}
	if record.Session.Revision != expectedRevision {
		return Record{}, ErrRevisionConflict
	}
	if record.Session.Status != StatusAwaitingUpload {
		return Record{}, ErrStateConflict
	}
	if !now.Before(record.Session.ExpiresAt) {
		return Record{}, ErrExpired
	}
	if subtle.ConstantTimeCompare(record.UploadTokenHash[:], uploadTokenHash[:]) != 1 {
		return Record{}, ErrInvalidUploadToken
	}
	record.Session.Status = StatusUploaded
	record.Session.Revision++
	record.UploadTokenHash = [32]byte{}
	record.Envelope = cloneEnvelope(&envelope)
	s.records[sessionID] = record
	return cloneRecord(record), nil
}

func (s *MemoryStore) ClaimConsume(ctx context.Context, sessionID string, expectedRevision uint64, now time.Time) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.records[sessionID]
	if !exists {
		return Record{}, ErrNotFound
	}
	if record.Session.Revision != expectedRevision {
		return Record{}, ErrRevisionConflict
	}
	if record.Session.Status != StatusUploaded || record.Envelope == nil || record.KeyHandle == "" {
		return Record{}, ErrStateConflict
	}
	if !now.Before(record.Session.ExpiresAt) {
		return Record{}, ErrExpired
	}
	claimed := cloneRecord(record)
	claimed.Session.Status = StatusConsumed
	claimed.Session.Revision++
	record.Session = claimed.Session
	record.UploadTokenHash = [32]byte{}
	record.Envelope = nil
	s.records[sessionID] = record
	return claimed, nil
}

func (s *MemoryStore) ExpireBefore(ctx context.Context, now time.Time) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.records))
	for id := range s.records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var expired []Record
	for _, id := range ids {
		record := s.records[id]
		if (record.Session.Status != StatusAwaitingUpload && record.Session.Status != StatusUploaded) || now.Before(record.Session.ExpiresAt) {
			continue
		}
		cleanup := cloneRecord(record)
		record.Session.Status = StatusExpired
		record.Session.Revision++
		record.UploadTokenHash = [32]byte{}
		record.Envelope = nil
		s.records[id] = record
		cleanup.Session = record.Session
		expired = append(expired, cleanup)
	}
	return expired, nil
}

func (s *MemoryStore) PendingKeyCleanup(ctx context.Context) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var pending []Record
	for _, record := range s.records {
		if record.KeyHandle != "" && (record.Session.Status == StatusConsumed || record.Session.Status == StatusExpired) {
			pending = append(pending, cloneRecord(record))
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].Session.SessionID < pending[j].Session.SessionID })
	return pending, nil
}

func (s *MemoryStore) ClearKeyHandle(ctx context.Context, sessionID string, revision uint64, keyHandle string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.records[sessionID]
	if !exists {
		return ErrNotFound
	}
	if record.Session.Revision != revision {
		return ErrRevisionConflict
	}
	if record.KeyHandle == "" {
		return nil
	}
	if record.KeyHandle != keyHandle || (record.Session.Status != StatusConsumed && record.Session.Status != StatusExpired) {
		return ErrStateConflict
	}
	record.KeyHandle = ""
	s.records[sessionID] = record
	return nil
}

func cloneRecord(value Record) Record {
	value.Envelope = cloneEnvelope(value.Envelope)
	return value
}

func cloneEnvelope(value *EnvelopeV1) *EnvelopeV1 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

type MemoryKeyStore struct {
	mu      sync.Mutex
	entries map[string][]byte
}

func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{entries: make(map[string][]byte)}
}

func (s *MemoryKeyStore) Put(ctx context.Context, sessionID string, privateKey []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(privateKey) != 32 || !uuidPattern.MatchString(sessionID) {
		return "", ErrInvalidContext
	}
	handle := "secret-bootstrap:" + sessionID
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.entries[handle]; exists {
		return "", ErrAlreadyExists
	}
	s.entries[handle] = append([]byte(nil), privateKey...)
	return handle, nil
}

func (s *MemoryKeyStore) Get(ctx context.Context, handle string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	value, exists := s.entries[handle]
	if !exists {
		return nil, ErrKeyUnavailable
	}
	return append([]byte(nil), value...), nil
}

func (s *MemoryKeyStore) Take(ctx context.Context, handle string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	value, exists := s.entries[handle]
	if !exists {
		return nil, ErrKeyUnavailable
	}
	result := append([]byte(nil), value...)
	Wipe(value)
	delete(s.entries, handle)
	return result, nil
}

func (s *MemoryKeyStore) Delete(ctx context.Context, handle string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if value, exists := s.entries[handle]; exists {
		Wipe(value)
		delete(s.entries, handle)
	}
	return nil
}

func (s *MemoryKeyStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}
