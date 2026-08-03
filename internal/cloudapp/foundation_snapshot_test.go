package cloudapp

import (
	"context"
	"strings"
	"testing"
	"time"

	cloudfoundation "github.com/YingSuiAI/dirextalk-agent/internal/cloud/foundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/google/uuid"
)

type foundationTemplateDigestStub string

func (digest foundationTemplateDigestStub) TemplateDigest() string {
	return string(digest)
}

type foundationSnapshotConnections struct {
	cloudstatus.Reader
	connection cloudstatus.Connection
}

func (connections *foundationSnapshotConnections) GetConnection(context.Context, string, string) (cloudstatus.Connection, error) {
	return connections.connection, nil
}

type foundationSnapshotTeardownGuard struct{}

func (foundationSnapshotTeardownGuard) CheckFoundationTeardown(context.Context, string, string, string, string) error {
	return nil
}

func TestFoundationSnapshotUsesExecutorCanonicalTemplateDigest(t *testing.T) {
	now := time.Date(2026, time.July, 31, 3, 30, 0, 0, time.UTC)
	agentInstanceID := uuid.NewString()
	connectionID := uuid.NewString()
	sessionID := uuid.NewString()
	ownerID := "dirextalk-project:demo2.dirextalk.ai"
	templateDigest := "sha256:" + strings.Repeat("a", 64)
	secrets := &connectionSecrets{session: secretbootstrap.SessionV1{
		SessionID: sessionID, AgentInstanceID: agentInstanceID, OwnerID: ownerID,
		Purpose: "aws_foundation_upgrade", TargetID: connectionID,
		Status: secretbootstrap.StatusUploaded, Revision: 2,
		CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(4 * time.Minute),
	}}
	identities := &connectionIdentities{evidence: AWSIdentityEvidence{
		BootstrapSessionID: sessionID, SessionRevision: 2,
		AgentInstanceID: agentInstanceID, OwnerID: ownerID, TargetID: connectionID,
		Identity: AWSIdentity{
			AccountID: "123456789012", PrincipalARN: "arn:aws:iam::123456789012:root",
			PrincipalID: "123456789012", Region: "ap-northeast-3", RootIdentity: true,
		},
		ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(4 * time.Minute),
	}}
	connections := &foundationSnapshotConnections{connection: cloudstatus.Connection{
		ConnectionID: connectionID, OwnerID: ownerID, AccountID: "123456789012",
		Region: "ap-northeast-3", CredentialGeneration: 3, Status: "active", Revision: 7,
	}}
	reader, err := NewFoundationSnapshotReader(
		agentInstanceID, foundationTemplateDigestStub(templateDigest),
		"123456789012.dkr.ecr.ap-northeast-3.amazonaws.com/reaper:v0.1.0-alpha.1@sha256:"+strings.Repeat("b", 64),
		secrets, identities, connections, foundationSnapshotTeardownGuard{}, func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("NewFoundationSnapshotReader() error = %v", err)
	}

	snapshot, err := reader.SnapshotFoundation(
		context.Background(),
		cloudfoundation.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()},
		ownerID, cloudfoundation.ActionUpgrade, connectionID, sessionID, 2,
	)
	if err != nil {
		t.Fatalf("SnapshotFoundation() error = %v", err)
	}
	if snapshot.Scope.FoundationTemplateDigest != templateDigest {
		t.Fatalf("signed template digest = %q, executor digest = %q", snapshot.Scope.FoundationTemplateDigest, templateDigest)
	}
}

func TestFoundationSnapshotRejectsInvalidExecutorTemplateDigest(t *testing.T) {
	_, err := NewFoundationSnapshotReader(
		uuid.NewString(), foundationTemplateDigestStub("sha256:not-a-digest"), "reaper@sha256:"+strings.Repeat("b", 64),
		&connectionSecrets{}, &connectionIdentities{}, &foundationSnapshotConnections{},
		foundationSnapshotTeardownGuard{}, time.Now,
	)
	if err == nil {
		t.Fatal("invalid executor template digest was accepted")
	}
}
