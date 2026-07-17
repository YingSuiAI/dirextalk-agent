package secretbootstrap

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

type Manager struct {
	store  Store
	keys   KeyStore
	random io.Reader
	now    func() time.Time
}

func NewManager(store Store, keys KeyStore, random io.Reader, now func() time.Time) (*Manager, error) {
	if store == nil || keys == nil || random == nil || now == nil {
		return nil, ErrInvalidContext
	}
	return &Manager{store: store, keys: keys, random: random, now: now}, nil
}

func (m *Manager) Create(ctx context.Context, creatorClientID string, binding BindingV1) (CreateResult, error) {
	if err := ctx.Err(); err != nil {
		return CreateResult{}, err
	}
	creatorClientID = strings.TrimSpace(creatorClientID)
	if err := ValidateClientID(creatorClientID); err != nil {
		return CreateResult{}, err
	}
	if err := validateBinding(binding); err != nil {
		return CreateResult{}, err
	}
	// Session timestamps are authenticated AAD and are persisted in PostgreSQL
	// timestamptz fields, whose wire precision is microseconds. Canonicalize
	// before returning the public descriptor so a client seals against exactly
	// the descriptor that a durable store later reads back.
	now := utc(m.now()).Truncate(time.Microsecond)
	if now.IsZero() {
		return CreateResult{}, ErrInvalidContext
	}
	sessionID, err := generateUUID(m.random)
	if err != nil {
		return CreateResult{}, ErrInvalidContext
	}
	privateKey, err := ecdh.X25519().GenerateKey(m.random)
	if err != nil {
		return CreateResult{}, ErrInvalidContext
	}
	privateKeyBytes := privateKey.Bytes()
	defer Wipe(privateKeyBytes)
	uploadTokenBytes := make([]byte, uploadTokenSize)
	if _, err := io.ReadFull(m.random, uploadTokenBytes); err != nil {
		return CreateResult{}, ErrInvalidContext
	}
	uploadTokenText := base64.RawURLEncoding.EncodeToString(uploadTokenBytes)
	uploadTokenHash := hashUploadToken(uploadTokenBytes)
	Wipe(uploadTokenBytes)

	session := SessionV1{
		SchemaVersion:   SessionSchemaV1,
		SessionID:       sessionID,
		AgentInstanceID: binding.AgentInstanceID,
		OwnerID:         binding.OwnerID,
		Purpose:         binding.Purpose,
		TargetID:        binding.TargetID,
		ServerPublicKey: base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
		CreatedAt:       now,
		ExpiresAt:       now.Add(SessionTTL),
		Status:          StatusAwaitingUpload,
		Revision:        1,
	}
	record := Record{Session: session, CreatorClientID: creatorClientID, UploadTokenHash: uploadTokenHash}
	if atomic, ok := m.store.(AtomicSessionStore); ok {
		record, err = atomic.CreateWithPrivateKey(ctx, record, privateKeyBytes)
		if err != nil {
			return CreateResult{}, err
		}
	} else {
		keyHandle, putErr := m.keys.Put(ctx, sessionID, privateKeyBytes)
		if putErr != nil {
			return CreateResult{}, putErr
		}
		record.KeyHandle = keyHandle
		if err := m.store.Create(ctx, record); err != nil {
			_ = m.keys.Delete(context.WithoutCancel(ctx), keyHandle)
			return CreateResult{}, err
		}
	}
	return CreateResult{Session: session, UploadToken: newUploadToken(uploadTokenText)}, nil
}

// CreateIdempotent is the public mutation path. It requires an adapter that
// atomically persists the scoped idempotency claim, session, sealed private
// key, and encrypted replay copy of the one-time upload token.
func (m *Manager) CreateIdempotent(ctx context.Context, scope MutationScope, idempotencyKey string, binding BindingV1) (CreateResult, error) {
	if err := ctx.Err(); err != nil {
		return CreateResult{}, err
	}
	if err := validateBinding(binding); err != nil {
		return CreateResult{}, err
	}
	mutation, err := createMutation(scope, idempotencyKey, binding)
	if err != nil {
		return CreateResult{}, err
	}
	atomic, ok := m.store.(AtomicIdempotentSessionStore)
	if !ok {
		return CreateResult{}, ErrInvalidContext
	}
	// Keep the idempotent public descriptor byte-for-byte compatible with its
	// PostgreSQL representation before it is used as envelope AAD.
	now := utc(m.now()).Truncate(time.Microsecond)
	if now.IsZero() {
		return CreateResult{}, ErrInvalidContext
	}
	sessionID, err := generateUUID(m.random)
	if err != nil {
		return CreateResult{}, ErrInvalidContext
	}
	privateKey, err := ecdh.X25519().GenerateKey(m.random)
	if err != nil {
		return CreateResult{}, ErrInvalidContext
	}
	privateKeyBytes := privateKey.Bytes()
	defer Wipe(privateKeyBytes)
	uploadTokenBytes := make([]byte, uploadTokenSize)
	if _, err := io.ReadFull(m.random, uploadTokenBytes); err != nil {
		return CreateResult{}, ErrInvalidContext
	}
	uploadTokenText := base64.RawURLEncoding.EncodeToString(uploadTokenBytes)
	uploadTokenHash := hashUploadToken(uploadTokenBytes)
	Wipe(uploadTokenBytes)
	session := SessionV1{
		SchemaVersion: SessionSchemaV1, SessionID: sessionID,
		AgentInstanceID: binding.AgentInstanceID, OwnerID: binding.OwnerID,
		Purpose: binding.Purpose, TargetID: binding.TargetID,
		ServerPublicKey: base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
		CreatedAt:       now, ExpiresAt: now.Add(SessionTTL), Status: StatusAwaitingUpload, Revision: 1,
	}
	record, replayToken, err := atomic.CreateIdempotent(ctx, mutation, Record{
		Session: session, CreatorClientID: strings.TrimSpace(scope.ClientID), UploadTokenHash: uploadTokenHash,
	}, privateKeyBytes, uploadTokenText)
	if err != nil {
		return CreateResult{}, err
	}
	if err := authorizeClient(record, scope.ClientID); err != nil {
		return CreateResult{}, err
	}
	if record.Session.Status == StatusAwaitingUpload {
		if replayToken == "" {
			return CreateResult{}, ErrKeyUnavailable
		}
	} else {
		// The upload token is a one-time capability. Idempotent create retries
		// return only the public descriptor after the upload transition.
		replayToken = ""
	}
	return CreateResult{Session: record.Session, UploadToken: newUploadToken(replayToken)}, nil
}

func (m *Manager) Get(ctx context.Context, callerClientID, sessionID string) (SessionV1, error) {
	if ValidateClientID(callerClientID) != nil || !uuidPattern.MatchString(sessionID) {
		return SessionV1{}, ErrInvalidContext
	}
	record, err := m.store.Get(ctx, sessionID)
	if err != nil {
		return SessionV1{}, err
	}
	if err := authorizeClient(record, callerClientID); err != nil {
		return SessionV1{}, err
	}
	if (record.Session.Status == StatusAwaitingUpload || record.Session.Status == StatusUploaded) && !utc(m.now()).Before(record.Session.ExpiresAt) {
		if _, err := m.Expire(ctx); err != nil {
			return SessionV1{}, err
		}
		record, err = m.store.Get(ctx, sessionID)
		if err != nil {
			return SessionV1{}, err
		}
		if err := authorizeClient(record, callerClientID); err != nil {
			return SessionV1{}, err
		}
	}
	return record.Session, nil
}

// FindUploaded returns only the public descriptor for the unique live session
// matching the authenticated caller and immutable binding. Plaintext remains
// sealed until the separately approved execution consumes the exact ref.
func (m *Manager) FindUploaded(ctx context.Context, callerClientID string, binding BindingV1) (SessionV1, error) {
	callerClientID = strings.TrimSpace(callerClientID)
	if ctx == nil || ValidateClientID(callerClientID) != nil || validateBinding(binding) != nil {
		return SessionV1{}, ErrInvalidContext
	}
	finder, ok := m.store.(UploadedSessionStore)
	if !ok {
		return SessionV1{}, ErrKeyUnavailable
	}
	now := utc(m.now())
	record, err := finder.FindUploaded(ctx, callerClientID, binding, now)
	if err != nil {
		return SessionV1{}, err
	}
	if authorizeClient(record, callerClientID) != nil || record.Session.Binding() != binding ||
		record.Session.Status != StatusUploaded || !now.Before(record.Session.ExpiresAt) {
		return SessionV1{}, ErrStateConflict
	}
	return record.Session, nil
}

func (m *Manager) Upload(ctx context.Context, callerClientID, sessionID string, expectedRevision uint64, token string, envelope EnvelopeV1) (SessionV1, error) {
	if ValidateClientID(callerClientID) != nil || !uuidPattern.MatchString(sessionID) || expectedRevision == 0 {
		return SessionV1{}, ErrInvalidContext
	}
	tokenBytes, err := parseUploadToken(token)
	if err != nil {
		return SessionV1{}, err
	}
	defer Wipe(tokenBytes)
	tokenHash := hashUploadToken(tokenBytes)
	record, err := m.store.Get(ctx, sessionID)
	if err != nil {
		return SessionV1{}, err
	}
	if err := authorizeClient(record, callerClientID); err != nil {
		return SessionV1{}, err
	}
	if record.Session.Revision != expectedRevision {
		return SessionV1{}, ErrRevisionConflict
	}
	if record.Session.Status != StatusAwaitingUpload {
		return SessionV1{}, ErrStateConflict
	}
	now := utc(m.now())
	if now.IsZero() {
		return SessionV1{}, ErrInvalidContext
	}
	if !now.Before(record.Session.ExpiresAt) {
		_, expireErr := m.Expire(ctx)
		return SessionV1{}, errors.Join(ErrExpired, expireErr)
	}
	if subtle.ConstantTimeCompare(record.UploadTokenHash[:], tokenHash[:]) != 1 {
		return SessionV1{}, ErrInvalidUploadToken
	}
	privateKey, err := m.keys.Get(ctx, record.KeyHandle)
	if err != nil {
		return SessionV1{}, ErrKeyUnavailable
	}
	defer Wipe(privateKey)
	plaintext, err := openEnvelope(record.Session, privateKey, envelope)
	if err != nil {
		return SessionV1{}, ErrInvalidEnvelope
	}
	Wipe(plaintext)
	updated, err := m.store.CommitUpload(ctx, sessionID, expectedRevision, tokenHash, envelope, now)
	if err != nil {
		if errors.Is(err, ErrExpired) {
			_, expireErr := m.Expire(ctx)
			return SessionV1{}, errors.Join(ErrExpired, expireErr)
		}
		return SessionV1{}, err
	}
	return updated.Session, nil
}

// UploadIdempotent is the public upload path. Authentication and envelope
// validation happen before the adapter atomically commits the state transition
// and idempotent response snapshot.
func (m *Manager) UploadIdempotent(ctx context.Context, scope MutationScope, idempotencyKey, sessionID string, expectedRevision uint64, token string, envelope EnvelopeV1) (SessionV1, error) {
	if !uuidPattern.MatchString(sessionID) || expectedRevision == 0 {
		return SessionV1{}, ErrInvalidContext
	}
	tokenBytes, err := parseUploadToken(token)
	if err != nil {
		return SessionV1{}, err
	}
	defer Wipe(tokenBytes)
	tokenHash := hashUploadToken(tokenBytes)
	mutation, err := uploadMutation(scope, idempotencyKey, sessionID, expectedRevision, tokenHash, envelope)
	if err != nil {
		return SessionV1{}, err
	}
	atomic, ok := m.store.(AtomicIdempotentSessionStore)
	if !ok {
		return SessionV1{}, ErrInvalidContext
	}
	waking, _ := m.store.(AtomicUploadWakeStore)
	record, err := m.store.Get(ctx, sessionID)
	if err != nil {
		return SessionV1{}, err
	}
	if err := authorizeClient(record, scope.ClientID); err != nil {
		return SessionV1{}, err
	}
	if record.Session.Status != StatusAwaitingUpload {
		// The adapter resolves a same-key replay before applying the CAS. Let it
		// return the original response even after the session revision has
		// advanced. A different key or request still reaches the adapter's
		// scoped idempotency/CAS checks and fails closed.
		var updated Record
		var replayErr error
		if waking != nil {
			updated, replayErr = waking.CommitUploadIdempotentAndWake(ctx, mutation, sessionID, expectedRevision, tokenHash, envelope, utc(m.now()))
		} else {
			updated, replayErr = atomic.CommitUploadIdempotent(ctx, mutation, sessionID, expectedRevision, tokenHash, envelope, utc(m.now()))
		}
		if replayErr != nil {
			return SessionV1{}, replayErr
		}
		return updated.Session, nil
	}
	if record.Session.Revision != expectedRevision {
		return SessionV1{}, ErrRevisionConflict
	}
	now := utc(m.now())
	if now.IsZero() {
		return SessionV1{}, ErrInvalidContext
	}
	if !now.Before(record.Session.ExpiresAt) {
		_, expireErr := m.Expire(ctx)
		return SessionV1{}, errors.Join(ErrExpired, expireErr)
	}
	if subtle.ConstantTimeCompare(record.UploadTokenHash[:], tokenHash[:]) != 1 {
		return SessionV1{}, ErrInvalidUploadToken
	}
	privateKey, err := m.keys.Get(ctx, record.KeyHandle)
	if err != nil {
		return SessionV1{}, ErrKeyUnavailable
	}
	defer Wipe(privateKey)
	plaintext, err := openEnvelope(record.Session, privateKey, envelope)
	if err != nil {
		return SessionV1{}, ErrInvalidEnvelope
	}
	Wipe(plaintext)
	var updated Record
	if waking != nil {
		updated, err = waking.CommitUploadIdempotentAndWake(ctx, mutation, sessionID, expectedRevision, tokenHash, envelope, now)
	} else {
		updated, err = atomic.CommitUploadIdempotent(ctx, mutation, sessionID, expectedRevision, tokenHash, envelope, now)
	}
	if err != nil {
		if errors.Is(err, ErrExpired) {
			_, expireErr := m.Expire(ctx)
			return SessionV1{}, errors.Join(ErrExpired, expireErr)
		}
		return SessionV1{}, err
	}
	return updated.Session, nil
}

func (m *Manager) Consume(ctx context.Context, callerClientID, sessionID string, expectedRevision uint64, consumer SecretConsumer) (SessionV1, error) {
	if ValidateClientID(callerClientID) != nil || !uuidPattern.MatchString(sessionID) || expectedRevision == 0 || consumer == nil {
		return SessionV1{}, ErrInvalidContext
	}
	record, err := m.store.Get(ctx, sessionID)
	if err != nil {
		return SessionV1{}, err
	}
	if err := authorizeClient(record, callerClientID); err != nil {
		return SessionV1{}, err
	}
	now := utc(m.now())
	if now.IsZero() {
		return SessionV1{}, ErrInvalidContext
	}
	claimed, err := m.store.ClaimConsume(ctx, sessionID, expectedRevision, now)
	if err != nil {
		if errors.Is(err, ErrExpired) {
			_, expireErr := m.Expire(ctx)
			return SessionV1{}, errors.Join(ErrExpired, expireErr)
		}
		return SessionV1{}, err
	}
	privateKey, err := m.keys.Take(ctx, claimed.KeyHandle)
	if err != nil {
		return claimed.Session, ErrKeyUnavailable
	}
	defer Wipe(privateKey)
	clearErr := m.store.ClearKeyHandle(context.WithoutCancel(ctx), claimed.Session.SessionID, claimed.Session.Revision, claimed.KeyHandle)
	plaintext, err := openEnvelope(claimed.Session, privateKey, *claimed.Envelope)
	if err != nil {
		return claimed.Session, ErrInvalidEnvelope
	}
	defer Wipe(plaintext)
	if err := consumer(plaintext); err != nil {
		return claimed.Session, ErrConsumerFailed
	}
	if clearErr != nil {
		return claimed.Session, clearErr
	}
	return claimed.Session, nil
}

// Inspect decrypts an uploaded envelope for a read-only, short-lived check
// such as STS GetCallerIdentity. It deliberately does not change the session
// revision or consume the private key; the caller must still use Consume for
// the approved one-time bootstrap operation. Plaintext is wiped immediately
// after the callback returns.
func (m *Manager) Inspect(ctx context.Context, callerClientID, sessionID string, expectedRevision uint64, consumer SecretConsumer) (SessionV1, error) {
	if ValidateClientID(callerClientID) != nil || !uuidPattern.MatchString(sessionID) || expectedRevision == 0 || consumer == nil {
		return SessionV1{}, ErrInvalidContext
	}
	record, err := m.store.Get(ctx, sessionID)
	if err != nil {
		return SessionV1{}, err
	}
	if err := authorizeClient(record, callerClientID); err != nil {
		return SessionV1{}, err
	}
	if record.Session.Revision != expectedRevision {
		return SessionV1{}, ErrRevisionConflict
	}
	if record.Session.Status != StatusUploaded || record.Envelope == nil || record.KeyHandle == "" {
		return SessionV1{}, ErrStateConflict
	}
	now := utc(m.now())
	if now.IsZero() {
		return SessionV1{}, ErrInvalidContext
	}
	if !now.Before(record.Session.ExpiresAt) {
		_, expireErr := m.Expire(ctx)
		return SessionV1{}, errors.Join(ErrExpired, expireErr)
	}
	privateKey, err := m.keys.Get(ctx, record.KeyHandle)
	if err != nil {
		return SessionV1{}, ErrKeyUnavailable
	}
	defer Wipe(privateKey)
	plaintext, err := openEnvelope(record.Session, privateKey, *record.Envelope)
	if err != nil {
		return SessionV1{}, ErrInvalidEnvelope
	}
	defer Wipe(plaintext)
	if err := consumer(plaintext); err != nil {
		return SessionV1{}, ErrConsumerFailed
	}
	return record.Session, nil
}

func authorizeClient(record Record, callerClientID string) error {
	callerClientID = strings.TrimSpace(callerClientID)
	if ValidateClientID(callerClientID) != nil || ValidateClientID(record.CreatorClientID) != nil {
		return ErrInvalidContext
	}
	if record.CreatorClientID != callerClientID {
		return ErrCallerMismatch
	}
	return nil
}

// Expire advances all due sessions to the terminal expired state and clears
// private-key handles. It is safe to call at startup and from a periodic job.
func (m *Manager) Expire(ctx context.Context) (int, error) {
	now := utc(m.now())
	if now.IsZero() {
		return 0, ErrInvalidContext
	}
	expired, err := m.store.ExpireBefore(ctx, now)
	if err != nil {
		return 0, err
	}
	if err := m.cleanupKeys(ctx); err != nil {
		return len(expired), err
	}
	return len(expired), nil
}

func (m *Manager) cleanupKeys(ctx context.Context) error {
	pending, err := m.store.PendingKeyCleanup(ctx)
	if err != nil {
		return err
	}
	for _, record := range pending {
		if err := m.keys.Delete(ctx, record.KeyHandle); err != nil {
			return err
		}
		if err := m.store.ClearKeyHandle(ctx, record.Session.SessionID, record.Session.Revision, record.KeyHandle); err != nil {
			return err
		}
	}
	return nil
}

func hashUploadToken(token []byte) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("dirextalk.agent.secret-bootstrap/upload-token/v1\x00"))
	_, _ = hash.Write(token)
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func generateUUID(random io.Reader) (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}
