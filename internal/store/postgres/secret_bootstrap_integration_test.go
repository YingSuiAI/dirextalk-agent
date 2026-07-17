package postgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/google/uuid"
)

func TestSecretBootstrapPostgresAtomicRestartAndSingleConsumption(t *testing.T) {
	pool, _, instanceID := newPlanningTestStore(t)
	masterKey := bytes.Repeat([]byte{0x42}, 32)
	store, err := postgres.NewSecretBootstrapStore(pool, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	// PostgreSQL timestamptz persists microseconds. A non-representable input
	// verifies that the public descriptor used for envelope AAD is canonical.
	now := time.Date(2026, time.July, 16, 9, 0, 0, 123456789, time.UTC)
	manager, err := secretbootstrap.NewManager(store, store.KeyStore(), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	targetID := uuid.NewString()
	scope := secretbootstrap.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()}
	createKey := uuid.NewString()
	binding := secretbootstrap.BindingV1{
		AgentInstanceID: instanceID, OwnerID: "owner-bootstrap", Purpose: "aws_connection", TargetID: targetID,
	}
	created, err := manager.CreateIdempotent(context.Background(), scope, createKey, binding)
	if err != nil {
		t.Fatalf("CreateIdempotent: %v", err)
	}
	replayedCreate, err := manager.CreateIdempotent(context.Background(), scope, createKey, binding)
	if err != nil || replayedCreate.Session.SessionID != created.Session.SessionID || replayedCreate.UploadToken.Reveal() != created.UploadToken.Reveal() {
		t.Fatalf("CreateIdempotent replay=%#v err=%v", replayedCreate.Session, err)
	}
	conflictingBinding := binding
	conflictingBinding.TargetID = uuid.NewString()
	if _, err := manager.CreateIdempotent(context.Background(), scope, createKey, conflictingBinding); !errors.Is(err, idempotency.ErrConflict) {
		t.Fatalf("conflicting CreateIdempotent error=%v", err)
	}
	var sessions, sealedKeys int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM secret_bootstrap_sessions`).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("session rows=%d err=%v", sessions, err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM secret_bootstrap_keys`).Scan(&sealedKeys); err != nil || sealedKeys != 1 {
		t.Fatalf("sealed key rows=%d err=%v", sealedKeys, err)
	}
	var creatorClientID string
	if err := pool.QueryRow(context.Background(), `SELECT creator_client_id FROM secret_bootstrap_sessions WHERE session_id=$1`, created.Session.SessionID).Scan(&creatorClientID); err != nil || creatorClientID != scope.ClientID {
		t.Fatalf("creator client binding=%q err=%v", creatorClientID, err)
	}
	if _, err := manager.Get(context.Background(), "other-project", created.Session.SessionID); !errors.Is(err, secretbootstrap.ErrCallerMismatch) {
		t.Fatalf("other-client Get error=%v, want caller mismatch", err)
	}

	plaintext := []byte(`{"access_key_id":"synthetic","secret_access_key":"not-a-real-secret"}`)
	envelope, err := secretbootstrap.Seal(created.Session, plaintext, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uploadKey := uuid.NewString()
	rotatedScope := scope
	rotatedScope.CredentialID = uuid.NewString()
	otherScope := secretbootstrap.MutationScope{ClientID: "other-project", CredentialID: uuid.NewString()}
	if _, err := manager.UploadIdempotent(context.Background(), otherScope, uuid.NewString(), created.Session.SessionID, created.Session.Revision, created.UploadToken.Reveal(), envelope); !errors.Is(err, secretbootstrap.ErrCallerMismatch) {
		t.Fatalf("other-client UploadIdempotent error=%v, want caller mismatch", err)
	}
	uploaded, err := manager.UploadIdempotent(context.Background(), rotatedScope, uploadKey, created.Session.SessionID, created.Session.Revision, created.UploadToken.Reveal(), envelope)
	if err != nil {
		t.Fatalf("UploadIdempotent: %v", err)
	}
	var replayNonceAfterUpload, replayCiphertextAfterUpload []byte
	if err := pool.QueryRow(context.Background(), `SELECT idempotency_token_nonce, idempotency_token_ciphertext
		FROM secret_bootstrap_sessions WHERE session_id=$1`, uploaded.SessionID).Scan(&replayNonceAfterUpload, &replayCiphertextAfterUpload); err != nil {
		t.Fatal(err)
	}
	if replayNonceAfterUpload != nil || replayCiphertextAfterUpload != nil {
		t.Fatal("uploaded session retained encrypted upload-token replay material")
	}
	replayedCreateAfterUpload, err := manager.CreateIdempotent(context.Background(), scope, createKey, binding)
	if err != nil || replayedCreateAfterUpload.Session.Status != secretbootstrap.StatusUploaded || replayedCreateAfterUpload.UploadToken.Reveal() != "" {
		t.Fatalf("uploaded CreateIdempotent replay=%#v token_present=%t err=%v",
			replayedCreateAfterUpload.Session, replayedCreateAfterUpload.UploadToken.Reveal() != "", err)
	}
	replayedUpload, err := manager.UploadIdempotent(context.Background(), rotatedScope, uploadKey, created.Session.SessionID, created.Session.Revision, created.UploadToken.Reveal(), envelope)
	if err != nil || replayedUpload.SessionID != uploaded.SessionID || replayedUpload.Revision != uploaded.Revision {
		t.Fatalf("UploadIdempotent replay=%#v err=%v", replayedUpload, err)
	}
	conflictingEnvelope := envelope
	conflictingEnvelope.Ciphertext += "A"
	if _, err := manager.UploadIdempotent(context.Background(), rotatedScope, uploadKey, created.Session.SessionID, created.Session.Revision, created.UploadToken.Reveal(), conflictingEnvelope); !errors.Is(err, idempotency.ErrConflict) {
		t.Fatalf("conflicting UploadIdempotent error=%v", err)
	}
	if _, err := manager.UploadIdempotent(context.Background(), rotatedScope, uuid.NewString(), created.Session.SessionID, created.Session.Revision, created.UploadToken.Reveal(), envelope); !errors.Is(err, secretbootstrap.ErrRevisionConflict) {
		t.Fatalf("new-key UploadIdempotent after commit error=%v, want revision conflict", err)
	}
	var uploadClaims int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM idempotency_records WHERE operation=$1`, secretbootstrap.UploadOperation).Scan(&uploadClaims); err != nil || uploadClaims != 1 {
		t.Fatalf("durable upload idempotency claims=%d err=%v", uploadClaims, err)
	}

	// Reconstructing both adapters proves the sealed session survives an Agent
	// process restart without storing its X25519 private key in plaintext.
	restartedStore, err := postgres.NewSecretBootstrapStore(pool, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := secretbootstrap.NewManager(restartedStore, restartedStore.KeyStore(), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	var inspected []byte
	if _, err := restarted.Inspect(context.Background(), scope.ClientID, uploaded.SessionID, uploaded.Revision, func(value []byte) error {
		inspected = value
		if !bytes.Equal(value, plaintext) {
			t.Fatal("inspected plaintext changed after restart")
		}
		return nil
	}); err != nil {
		t.Fatalf("Inspect after restart: %v", err)
	}
	if !allZeroBytes(inspected) {
		t.Fatal("Inspect did not wipe its callback buffer")
	}

	wrongKeyStore, err := postgres.NewSecretBootstrapStore(pool, bytes.Repeat([]byte{0x24}, 32))
	if err != nil {
		t.Fatal(err)
	}
	wrongManager, _ := secretbootstrap.NewManager(wrongKeyStore, wrongKeyStore.KeyStore(), rand.Reader, func() time.Time { return now })
	if _, err := wrongManager.Inspect(context.Background(), scope.ClientID, uploaded.SessionID, uploaded.Revision, func([]byte) error { return nil }); !errors.Is(err, secretbootstrap.ErrKeyUnavailable) {
		t.Fatalf("wrong master key error=%v, want ErrKeyUnavailable", err)
	}

	var consumed []byte
	terminal, err := restarted.Consume(context.Background(), scope.ClientID, uploaded.SessionID, uploaded.Revision, func(value []byte) error {
		consumed = value
		return nil
	})
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if terminal.Status != secretbootstrap.StatusConsumed || terminal.Revision != 3 || !allZeroBytes(consumed) {
		t.Fatalf("terminal session=%#v wiped=%t", terminal, allZeroBytes(consumed))
	}
	if _, err := restarted.Consume(context.Background(), scope.ClientID, uploaded.SessionID, uploaded.Revision, func([]byte) error { return nil }); !errors.Is(err, secretbootstrap.ErrRevisionConflict) {
		t.Fatalf("second Consume error=%v, want revision conflict", err)
	}
	var keyHandle, envelopeSchema *string
	var replayNonce, replayCiphertext []byte
	if err := pool.QueryRow(context.Background(), `SELECT key_handle::text, envelope_schema, idempotency_token_nonce, idempotency_token_ciphertext FROM secret_bootstrap_sessions WHERE session_id=$1`, uploaded.SessionID).Scan(&keyHandle, &envelopeSchema, &replayNonce, &replayCiphertext); err != nil {
		t.Fatal(err)
	}
	if keyHandle != nil || envelopeSchema != nil || replayNonce != nil || replayCiphertext != nil {
		t.Fatalf("terminal session retained encrypted bootstrap material: key=%v envelope=%v replay=%t", keyHandle, envelopeSchema, replayNonce != nil || replayCiphertext != nil)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM secret_bootstrap_keys`).Scan(&sealedKeys); err != nil || sealedKeys != 0 {
		t.Fatalf("terminal sealed key rows=%d err=%v", sealedKeys, err)
	}
}

func allZeroBytes(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
