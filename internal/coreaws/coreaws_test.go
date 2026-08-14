package coreaws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestCredentialViewRedactsSecrets(t *testing.T) {
	c := Credentials{ID: "11111111-1111-4111-8111-111111111111", Name: "prod", Region: "us-east-1", private: &credentialPayload{accessKeyID: "AKIA", secretAccessKey: "secret", sessionToken: "token"}, Revision: 1}
	v := c.View()
	if !v.HasAccessKey || !v.HasSecretKey || !v.HasSessionToken {
		t.Fatal("configured flags missing")
	}
	b, _ := json.Marshal(c)
	out := string(b) + fmt.Sprintf("%v %#+v %v", c, c, c)
	if bytes.Contains([]byte(out), []byte("secret")) || bytes.Contains([]byte(out), []byte("token")) {
		t.Fatalf("secret leaked: %s", out)
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("credential", "value", c)
	if bytes.Contains(buf.Bytes(), []byte("secret")) {
		t.Fatal("slog leaked secret")
	}
	if d := canonicalDigest(c); strings.Contains(d, "secret") {
		t.Fatal("digest leaked secret")
	}
}

type credentialDeleteGuardStub struct {
	retained bool
	err      error
}

func (guard credentialDeleteGuardStub) DeleteCredentialIfUnused(_ context.Context, _ string, deleteCredential func() error) (bool, error) {
	if guard.err != nil || guard.retained {
		return guard.retained, guard.err
	}
	return false, deleteCredential()
}

func TestDeleteCredentialRejectsRetainedWorkerReference(t *testing.T) {
	repository := NewMemoryRepository()
	service := NewService(repository, nil, nil)
	credential, err := service.SaveCredential(context.Background(), CredentialInput{IdempotencyKey: newUUID(), Name: "worker", Region: "us-east-1", AccessKeyID: "access", SecretAccessKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	service.SetCredentialDeleteGuard(credentialDeleteGuardStub{retained: true})
	if err = service.DeleteCredential(context.Background(), credential.ID, credential.Revision, newUUID()); !errors.Is(err, ErrCredentialInUse) {
		t.Fatalf("delete error=%v", err)
	}
	if _, err = service.GetCredential(context.Background(), credential.ID); err != nil {
		t.Fatalf("guard deleted credential: %v", err)
	}
	readErr := errors.New("worker state unavailable")
	service.SetCredentialDeleteGuard(credentialDeleteGuardStub{err: readErr})
	if err = service.DeleteCredential(context.Background(), credential.ID, credential.Revision, newUUID()); !errors.Is(err, readErr) {
		t.Fatalf("guard read error=%v", err)
	}
	if _, err = service.GetCredential(context.Background(), credential.ID); err != nil {
		t.Fatalf("read error deleted credential: %v", err)
	}
}
