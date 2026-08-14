package coreaws

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"log/slog"
	"strings"
	"testing"
)

func TestCredentialInputRedactionAndDigest(t *testing.T) {
	in := CredentialInput{ID: uuid.NewString(), Name: "prod", Region: "us-east-1", AccessKeyID: "AKIA", SecretAccessKey: "super-secret", SessionToken: "token", IdempotencyKey: uuid.NewString()}
	b, _ := json.Marshal(in)
	out := string(b) + fmt.Sprintf("%v %#+v", in, in)
	var log strings.Builder
	slog.New(slog.NewTextHandler(&log, nil)).Info("credential", "input", in)
	out += log.String()
	if strings.Contains(out, "super-secret") || strings.Contains(out, `"token"`) || strings.Contains(credentialInputDigest(in), "super-secret") {
		t.Fatalf("credential leaked: %s", out)
	}
}

func TestCredentialIdentityBindsRevisionAndReplacementInvalidates(t *testing.T) {
	r := NewMemoryRepository()
	sts := &FakeSTSProvider{AccountID: "123456789012", UserARN: "arn:aws:iam::123456789012:user/test"}
	s := NewService(r, sts, nil)
	view, err := s.SaveCredential(context.Background(), CredentialInput{Name: "prod", Region: "us-east-1", AccessKeyID: "a", SecretAccessKey: "b", IdempotencyKey: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	checked, err := s.TestCredential(context.Background(), view.ID)
	if err != nil || checked.CredentialRevision != 1 {
		t.Fatalf("test=%#v err=%v", checked, err)
	}
	updated, err := s.ReplaceCredential(context.Background(), CredentialInput{ID: view.ID, Name: "prod2", Region: "us-east-1", AccessKeyID: "a", SecretAccessKey: "b"}, 1, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if updated.AccountID != "" || updated.UserARN != "" {
		t.Fatal("identity survived replacement")
	}
}
