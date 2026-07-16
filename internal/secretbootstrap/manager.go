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

func (m *Manager) Create(ctx context.Context, binding BindingV1) (CreateResult, error) {
	if err := ctx.Err(); err != nil {
		return CreateResult{}, err
	}
	if err := validateBinding(binding); err != nil {
		return CreateResult{}, err
	}
	now := utc(m.now())
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
	keyHandle, err := m.keys.Put(ctx, sessionID, privateKeyBytes)
	if err != nil {
		return CreateResult{}, err
	}
	record := Record{Session: session, UploadTokenHash: uploadTokenHash, KeyHandle: keyHandle}
	if err := m.store.Create(ctx, record); err != nil {
		_ = m.keys.Delete(context.WithoutCancel(ctx), keyHandle)
		return CreateResult{}, err
	}
	return CreateResult{Session: session, UploadToken: newUploadToken(uploadTokenText)}, nil
}

func (m *Manager) Get(ctx context.Context, sessionID string) (SessionV1, error) {
	if !uuidPattern.MatchString(sessionID) {
		return SessionV1{}, ErrInvalidContext
	}
	record, err := m.store.Get(ctx, sessionID)
	if err != nil {
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
	}
	return record.Session, nil
}

func (m *Manager) Upload(ctx context.Context, sessionID string, expectedRevision uint64, token string, envelope EnvelopeV1) (SessionV1, error) {
	if !uuidPattern.MatchString(sessionID) || expectedRevision == 0 {
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

func (m *Manager) Consume(ctx context.Context, sessionID string, expectedRevision uint64, consumer SecretConsumer) (SessionV1, error) {
	if !uuidPattern.MatchString(sessionID) || expectedRevision == 0 || consumer == nil {
		return SessionV1{}, ErrInvalidContext
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
