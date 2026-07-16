package secretbootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSessionUploadAndConsumeExactlyOnce(t *testing.T) {
	manager, store, keys, clock := newTestManager(t)
	created, err := manager.Create(context.Background(), testBinding())
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("bootstrap material for a disposable account")
	envelope, err := Seal(created.Session, plaintext, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uploaded, err := manager.Upload(context.Background(), created.Session.SessionID, created.Session.Revision, created.UploadToken.Reveal(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	if uploaded.Status != StatusUploaded || uploaded.Revision != 2 {
		t.Fatalf("uploaded session = %#v", uploaded)
	}
	if _, err := manager.Upload(context.Background(), created.Session.SessionID, created.Session.Revision, created.UploadToken.Reveal(), envelope); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("second upload error = %v, want ErrRevisionConflict", err)
	}

	var callbackBuffer []byte
	consumed, err := manager.Consume(context.Background(), uploaded.SessionID, uploaded.Revision, func(secret []byte) error {
		callbackBuffer = secret
		if !bytes.Equal(secret, plaintext) {
			t.Fatalf("consumer secret = %q, want original", secret)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if consumed.Status != StatusConsumed || consumed.Revision != 3 {
		t.Fatalf("consumed session = %#v", consumed)
	}
	if !allZero(callbackBuffer) {
		t.Fatal("consumer plaintext was not zeroized after callback")
	}
	if _, err := manager.Consume(context.Background(), uploaded.SessionID, uploaded.Revision, func([]byte) error { return nil }); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("second consume error = %v, want ErrRevisionConflict", err)
	}

	record, err := store.Get(context.Background(), created.Session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Envelope != nil || record.KeyHandle != "" || record.UploadTokenHash != ([32]byte{}) {
		t.Fatalf("terminal record retained bootstrap material: %#v", record)
	}
	if keys.Len() != 0 {
		t.Fatal("terminal session retained its X25519 private key")
	}
	_ = clock
}

func TestUploadRejectsTokenAADAndConcurrentReplay(t *testing.T) {
	manager, _, _, _ := newTestManager(t)
	created, err := manager.Create(context.Background(), testBinding())
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Seal(created.Session, []byte("synthetic payload"), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Upload(context.Background(), created.Session.SessionID, 1, strings.Repeat("A", 43), envelope); !errors.Is(err, ErrInvalidUploadToken) {
		t.Fatalf("invalid token error = %v", err)
	}
	drifted := created.Session
	drifted.OwnerID = "owner-2"
	driftedEnvelope, err := Seal(drifted, []byte("synthetic payload"), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Upload(context.Background(), created.Session.SessionID, 1, created.UploadToken.Reveal(), driftedEnvelope); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("AAD drift error = %v", err)
	}

	var successes atomic.Int32
	var revisionConflicts atomic.Int32
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, uploadErr := manager.Upload(context.Background(), created.Session.SessionID, 1, created.UploadToken.Reveal(), envelope)
			switch {
			case uploadErr == nil:
				successes.Add(1)
			case errors.Is(uploadErr, ErrRevisionConflict):
				revisionConflicts.Add(1)
			default:
				t.Errorf("concurrent upload error = %v", uploadErr)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 || revisionConflicts.Load() != 1 {
		t.Fatalf("concurrent results successes=%d revision_conflicts=%d", successes.Load(), revisionConflicts.Load())
	}
}

func TestConcurrentConsumeInvokesConsumerOnce(t *testing.T) {
	manager, _, _, _ := newTestManager(t)
	created, err := manager.Create(context.Background(), testBinding())
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Seal(created.Session, []byte("synthetic payload"), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uploaded, err := manager.Upload(context.Background(), created.Session.SessionID, 1, created.UploadToken.Reveal(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	var callbacks atomic.Int32
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, consumeErr := manager.Consume(context.Background(), uploaded.SessionID, uploaded.Revision, func([]byte) error {
				callbacks.Add(1)
				return nil
			})
			results <- consumeErr
		}()
	}
	wait.Wait()
	close(results)
	var successes, conflicts int
	for result := range results {
		switch {
		case result == nil:
			successes++
		case errors.Is(result, ErrRevisionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent consume error = %v", result)
		}
	}
	if successes != 1 || conflicts != 1 || callbacks.Load() != 1 {
		t.Fatalf("concurrent consume successes=%d conflicts=%d callbacks=%d", successes, conflicts, callbacks.Load())
	}
}

func TestSessionExpiryDeletesKeyAndRejectsUpload(t *testing.T) {
	manager, store, keys, clock := newTestManager(t)
	created, err := manager.Create(context.Background(), testBinding())
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Seal(created.Session, []byte("synthetic payload"), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(SessionTTL)
	if _, err := manager.Upload(context.Background(), created.Session.SessionID, 1, created.UploadToken.Reveal(), envelope); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired upload error = %v, want ErrExpired", err)
	}
	record, err := store.Get(context.Background(), created.Session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Session.Status != StatusExpired || record.Session.Revision != 2 {
		t.Fatalf("expired record = %#v", record.Session)
	}
	if keys.Len() != 0 {
		t.Fatal("expired session retained its private key")
	}
}

func TestCleanupRecoversTerminalKeyAfterInterruptedConsume(t *testing.T) {
	manager, store, keys, clock := newTestManager(t)
	created, err := manager.Create(context.Background(), testBinding())
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Seal(created.Session, []byte("synthetic payload"), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uploaded, err := manager.Upload(context.Background(), created.Session.SessionID, 1, created.UploadToken.Reveal(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimConsume(context.Background(), uploaded.SessionID, uploaded.Revision, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	keys.mu.Lock()
	keyBuffer := keys.entries[claimed.KeyHandle]
	keys.mu.Unlock()
	if _, err := manager.Expire(context.Background()); err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(context.Background(), uploaded.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if record.KeyHandle != "" || keys.Len() != 0 || !allZero(keyBuffer) {
		t.Fatal("startup cleanup did not remove interrupted terminal key")
	}
}

func TestSecretCanaryNeverAppearsAndBuffersAreWiped(t *testing.T) {
	manager, store, keys, _ := newTestManager(t)
	canary := "sk_" + strings.Repeat("z", 40)
	badBinding := testBinding()
	badBinding.OwnerID = canary
	if _, err := manager.Create(context.Background(), badBinding); !errors.Is(err, ErrInvalidContext) || strings.Contains(err.Error(), canary) {
		t.Fatalf("credential-bearing context error = %v", err)
	}
	created, err := manager.Create(context.Background(), testBinding())
	if err != nil {
		t.Fatal(err)
	}
	rawToken := created.UploadToken.Reveal()
	formatted := fmt.Sprintf("%+v", created)
	encoded, err := json.Marshal(created)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(formatted, rawToken) || strings.Contains(string(encoded), rawToken) {
		t.Fatal("create result formatting exposed the upload token")
	}

	envelope, err := Seal(created.Session, []byte(canary), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uploaded, err := manager.Upload(context.Background(), created.Session.SessionID, 1, rawToken, envelope)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(context.Background(), created.Session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	storedJSON, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(storedJSON), canary) || strings.Contains(string(storedJSON), rawToken) {
		t.Fatal("stored session exposed plaintext or upload token")
	}

	keys.mu.Lock()
	keyBuffer := keys.entries[record.KeyHandle]
	keys.mu.Unlock()
	var consumerBuffer []byte
	_, consumeErr := manager.Consume(context.Background(), uploaded.SessionID, uploaded.Revision, func(secret []byte) error {
		consumerBuffer = secret
		return fmt.Errorf("downstream rejected %s", canary)
	})
	if !errors.Is(consumeErr, ErrConsumerFailed) || strings.Contains(consumeErr.Error(), canary) {
		t.Fatalf("consumer error leaked canary: %v", consumeErr)
	}
	if !allZero(consumerBuffer) || !allZero(keyBuffer) {
		t.Fatal("plaintext or private-key buffer was not zeroized")
	}
}

func newTestManager(t *testing.T) (*Manager, *MemoryStore, *MemoryKeyStore, *fakeClock) {
	t.Helper()
	store := NewMemoryStore()
	keys := NewMemoryKeyStore()
	clock := &fakeClock{now: time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)}
	manager, err := NewManager(store, keys, rand.Reader, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	return manager, store, keys, clock
}

func testBinding() BindingV1 {
	return BindingV1{AgentInstanceID: "agent-instance-1", OwnerID: "owner-1", Purpose: "aws_connection", TargetID: "connection-1"}
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
