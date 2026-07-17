package secretresolver

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/google/uuid"
)

func TestResolverBindsSessionAndConsumesOnlyAfterReadBack(t *testing.T) {
	sessionID, recipeDigest := uuid.NewString(), "sha256:"+strings.Repeat("a", 64)
	manager := &fakeManager{session: secretbootstrap.SessionV1{
		SessionID: sessionID, OwnerID: "owner-1", Purpose: "model token", TargetID: recipeDigest,
		Status: secretbootstrap.StatusUploaded, Revision: 2,
	}, callerClientID: "message-server", plaintext: []byte("secret-canary")}
	resolver, _ := New(manager)
	content, err := resolver.Resolve(context.Background(), secretRequest(sessionID, recipeDigest))
	if err != nil {
		t.Fatal(err)
	}
	var staged []byte
	if err := content.Materialize(context.Background(), func(value []byte) error {
		staged = bytes.Clone(value)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if manager.consumeCalls != 0 || !bytes.Equal(staged, manager.plaintext) {
		t.Fatal("secret was consumed before the destination was independently verified")
	}
	if err := content.Commit(context.Background(), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if manager.consumeCalls != 1 || manager.session.Status != secretbootstrap.StatusConsumed {
		t.Fatal("verified destination did not consume the one-use session")
	}
	if err := content.Materialize(context.Background(), func([]byte) error {
		t.Fatal("consumed session exposed plaintext on retry")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := content.Commit(context.Background(), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if manager.consumeCalls != 1 {
		t.Fatalf("consume calls = %d, want exactly one", manager.consumeCalls)
	}
	clear(staged)
}

func TestResolverRejectsBindingDriftAndDoesNotExposePlaintextOnVerifyRetry(t *testing.T) {
	sessionID, recipeDigest := uuid.NewString(), "sha256:"+strings.Repeat("a", 64)
	base := secretbootstrap.SessionV1{SessionID: sessionID, OwnerID: "owner-1", Purpose: "model token", TargetID: recipeDigest, Status: secretbootstrap.StatusUploaded, Revision: 2}
	for name, mutate := range map[string]func(*fakeManager){
		"caller":  func(value *fakeManager) { value.callerClientID = "different-client" },
		"owner":   func(value *fakeManager) { value.session.OwnerID = "other" },
		"purpose": func(value *fakeManager) { value.session.Purpose = "other" },
		"recipe":  func(value *fakeManager) { value.session.TargetID = "sha256:" + strings.Repeat("b", 64) },
		"state":   func(value *fakeManager) { value.session.Status = secretbootstrap.StatusAwaitingUpload },
	} {
		t.Run(name, func(t *testing.T) {
			manager := &fakeManager{session: base, callerClientID: "message-server", plaintext: []byte("secret-canary")}
			mutate(manager)
			resolver, _ := New(manager)
			if _, err := resolver.Resolve(context.Background(), secretRequest(sessionID, recipeDigest)); err == nil {
				t.Fatal("session binding drift was accepted")
			}
		})
	}

	manager := &fakeManager{session: base, callerClientID: "message-server", plaintext: []byte("secret-canary")}
	resolver, _ := New(manager)
	content, _ := resolver.Resolve(context.Background(), secretRequest(sessionID, recipeDigest))
	if err := content.Materialize(context.Background(), func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := content.Commit(context.Background(), func() error { return errors.New("read-back failed") }); err == nil {
		t.Fatal("failed read-back was accepted")
	}
}

func secretRequest(sessionID, recipeDigest string) cloudexecution.InstallerSecretResolveRequest {
	return cloudexecution.InstallerSecretResolveRequest{
		CallerClientID: "message-server", OwnerID: "owner-1", PlanID: uuid.NewString(), Purpose: "model token",
		SecretRef: referencePrefix + sessionID, RecipeDigest: recipeDigest,
	}
}

type fakeManager struct {
	session        secretbootstrap.SessionV1
	callerClientID string
	plaintext      []byte
	consumeCalls   int
}

func (manager *fakeManager) Get(_ context.Context, callerClientID, sessionID string) (secretbootstrap.SessionV1, error) {
	if callerClientID != manager.callerClientID || sessionID != manager.session.SessionID {
		return secretbootstrap.SessionV1{}, errors.New("scope")
	}
	return manager.session, nil
}

func (manager *fakeManager) Inspect(_ context.Context, _ string, _ string, revision uint64, consumer secretbootstrap.SecretConsumer) (secretbootstrap.SessionV1, error) {
	if revision != manager.session.Revision || manager.session.Status != secretbootstrap.StatusUploaded {
		return secretbootstrap.SessionV1{}, errors.New("state")
	}
	return manager.session, consumer(manager.plaintext)
}

func (manager *fakeManager) Consume(_ context.Context, _ string, _ string, revision uint64, consumer secretbootstrap.SecretConsumer) (secretbootstrap.SessionV1, error) {
	manager.consumeCalls++
	if revision != manager.session.Revision || manager.session.Status != secretbootstrap.StatusUploaded {
		return secretbootstrap.SessionV1{}, errors.New("state")
	}
	if err := consumer(manager.plaintext); err != nil {
		return secretbootstrap.SessionV1{}, err
	}
	manager.session.Status = secretbootstrap.StatusConsumed
	manager.session.Revision++
	return manager.session, nil
}
