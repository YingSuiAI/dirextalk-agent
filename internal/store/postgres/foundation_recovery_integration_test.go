package postgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/google/uuid"
)

func TestFoundationRecoveryEnumeratesDurableCallerSessionAndMutationBindingAfterRestart(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Second)
	masterKey := bytes.Repeat([]byte{0x53}, 32)
	secretStore, err := postgres.NewSecretBootstrapStore(pool, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := secretbootstrap.NewManager(secretStore, secretStore.KeyStore(), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	facts, err := postgres.NewCloudAdapter(store)
	if err != nil {
		t.Fatal(err)
	}
	caller := cloudapp.MutationScope{ClientID: "foundation-recovery-test", CredentialID: uuid.NewString()}
	statuses := []cloudapp.FoundationOperationStatus{
		cloudapp.FoundationOperationIntentStatus,
		cloudapp.FoundationOperationRunning,
		cloudapp.FoundationOperationFailedRetriable,
	}
	for index, status := range statuses {
		connectionID := uuid.NewString()
		plan := cloudApprovalPlanFixture(instanceID)
		plan.ConnectionID = connectionID
		quote := cloudApprovalQuoteFixture(t, plan, uuid.NewString(), now.Add(-time.Minute))
		quoteDigest, digestErr := quote.Digest()
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		plan.Quote.QuoteID, plan.Quote.Digest, plan.Quote.ValidUntil = quote.QuoteID, quoteDigest, quote.ValidUntil
		plan.Quote.ScopeDigest = quote.Candidates[1].ScopeDigest
		if _, err = facts.PersistQuote(ctx, caller, uuid.NewString(), [32]byte{byte(index + 1)}, quote); err != nil {
			t.Fatal(err)
		}
		if _, err = facts.PersistPlan(ctx, caller, uuid.NewString(), plan); err != nil {
			t.Fatal(err)
		}
		created, createErr := manager.CreateIdempotent(ctx, secretbootstrap.MutationScope(caller), uuid.NewString(), secretbootstrap.BindingV1{
			AgentInstanceID: instanceID, OwnerID: plan.OwnerID, Purpose: "aws_connection", TargetID: connectionID,
		})
		if createErr != nil {
			t.Fatal(createErr)
		}
		envelope, sealErr := secretbootstrap.Seal(created.Session, []byte("synthetic bootstrap payload"), rand.Reader)
		if sealErr != nil {
			t.Fatal(sealErr)
		}
		uploaded, uploadErr := manager.UploadIdempotent(ctx, secretbootstrap.MutationScope(caller), uuid.NewString(), created.Session.SessionID, created.Session.Revision, created.UploadToken.Reveal(), envelope)
		if uploadErr != nil {
			t.Fatal(uploadErr)
		}
		if err = store.PutAWSIdentityEvidence(ctx, cloudapp.AWSIdentityEvidence{
			BootstrapSessionID: uploaded.SessionID, SessionRevision: uploaded.Revision,
			AgentInstanceID: instanceID, OwnerID: plan.OwnerID, TargetID: connectionID,
			Identity:   cloudapp.AWSIdentity{AccountID: "123456789012", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012", Region: "us-east-1", RootIdentity: true},
			ObservedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		operation, _, beginErr := store.BeginFoundationOperation(ctx, caller, cloudapp.FoundationOperationIntent{
			Caller: caller, OperationID: uuid.NewString(), IdempotencyKey: uuid.NewString(), RequestHash: [32]byte{byte(index + 1)},
			OwnerID: plan.OwnerID, BootstrapSessionID: uploaded.SessionID, PlanID: plan.PlanID, ConnectionID: connectionID,
			AccountID: "123456789012", Region: "us-east-1", ExpectedSessionRevision: uploaded.Revision,
			ReaperImageURI: "registry.example/reaper:v0.1.0-alpha.1@sha256:" + strings.Repeat("a", 64),
		})
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		if status != cloudapp.FoundationOperationIntentStatus {
			operation, err = store.MarkFoundationOperationRunning(ctx, operation.OperationID, operation.Revision)
			if err != nil {
				t.Fatal(err)
			}
		}
		if status == cloudapp.FoundationOperationFailedRetriable {
			if _, err = store.FailFoundationOperation(ctx, operation.OperationID, operation.Revision, false, "transient provider failure"); err != nil {
				t.Fatal(err)
			}
		}
	}

	restarted, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	recoverable, err := restarted.ListRecoverableFoundationOperations(ctx, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(recoverable) != len(statuses) {
		t.Fatalf("recoverable operations=%d, want %d", len(recoverable), len(statuses))
	}
	seen := make(map[cloudapp.FoundationOperationStatus]bool, len(statuses))
	for _, operation := range recoverable {
		seen[operation.Status] = true
		if operation.Caller != caller || operation.ExpectedSessionRevision != 2 || operation.AccountID != "123456789012" ||
			operation.Region != "us-east-1" || operation.BootstrapSessionID == "" || operation.OperationID == "" {
			t.Fatalf("recovery binding changed after restart: %#v", operation)
		}
	}
	for _, status := range statuses {
		if !seen[status] {
			t.Fatalf("missing recoverable status %q", status)
		}
	}
}
