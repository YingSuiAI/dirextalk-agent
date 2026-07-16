package postgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/google/uuid"
)

func TestAWSIdentityEvidencePostgresPreservesBootstrapBinding(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	secretStore, err := postgres.NewSecretBootstrapStore(pool, bytes.Repeat([]byte{0x64}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 16, 9, 0, 0, 123456000, time.UTC)
	manager, err := secretbootstrap.NewManager(secretStore, secretStore.KeyStore(), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	scope := secretbootstrap.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()}
	targetID := uuid.NewString()
	created, err := manager.CreateIdempotent(context.Background(), scope, uuid.NewString(), secretbootstrap.BindingV1{
		AgentInstanceID: instanceID, OwnerID: "owner-evidence", Purpose: "aws_connection", TargetID: targetID,
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := secretbootstrap.Seal(created.Session, []byte("synthetic bootstrap payload"), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uploaded, err := manager.UploadIdempotent(context.Background(), scope, uuid.NewString(), created.Session.SessionID, created.Session.Revision, created.UploadToken.Reveal(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	evidence := cloudapp.AWSIdentityEvidence{
		BootstrapSessionID: uploaded.SessionID, SessionRevision: uploaded.Revision, AgentInstanceID: instanceID,
		OwnerID: "owner-evidence", TargetID: targetID,
		Identity: cloudapp.AWSIdentity{
			AccountID: "123456789012", PrincipalARN: "arn:aws:iam::123456789012:root",
			PrincipalID: "123456789012", Region: "us-east-1", RootIdentity: true,
		},
		ObservedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	if err := store.PutAWSIdentityEvidence(context.Background(), evidence); err != nil {
		t.Fatal(err)
	}
	persisted, err := store.GetAWSIdentityEvidence(context.Background(), uploaded.SessionID, uploaded.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if persisted != evidence {
		t.Fatalf("persisted evidence=%#v, want %#v", persisted, evidence)
	}
	if _, err := store.GetAWSIdentityEvidence(context.Background(), uploaded.SessionID, uploaded.Revision-1); !errors.Is(err, cloudapp.ErrNotFound) {
		t.Fatalf("old-revision lookup error=%v, want ErrNotFound", err)
	}
	conflict := evidence
	conflict.Identity.Region = "eu-west-1"
	if err := store.PutAWSIdentityEvidence(context.Background(), conflict); !errors.Is(err, cloudapp.ErrRevisionConflict) {
		t.Fatalf("different-region write error=%v, want ErrRevisionConflict", err)
	}
	unchanged, err := store.GetAWSIdentityEvidence(context.Background(), uploaded.SessionID, uploaded.Revision)
	if err != nil || unchanged != evidence {
		t.Fatalf("conflicting write changed evidence=%#v err=%v", unchanged, err)
	}
}
