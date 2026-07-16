package postgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestSucceededFoundationRemainsPendingUntilExactLaunchIntentExists(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Second)
	caller := cloudapp.MutationScope{ClientID: "foundation-launch-handoff-test", CredentialID: uuid.NewString()}
	taskCaller := task.MutationScope{ClientID: caller.ClientID, CredentialID: caller.CredentialID}
	facts, err := postgres.NewCloudAdapter(store)
	if err != nil {
		t.Fatal(err)
	}
	connectionID := uuid.NewString()
	plan := cloudApprovalPlanFixture(instanceID)
	plan.ConnectionID = connectionID
	quote := cloudApprovalQuoteFixture(t, plan, uuid.NewString(), now.Add(-time.Minute))
	quoteDigest, err := quote.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan.Quote.QuoteID, plan.Quote.Digest, plan.Quote.ValidUntil = quote.QuoteID, quoteDigest, quote.ValidUntil
	plan.Quote.ScopeDigest = quote.Candidates[1].ScopeDigest
	if _, err = facts.PersistQuote(ctx, caller, uuid.NewString(), [32]byte{1}, quote); err != nil {
		t.Fatal(err)
	}
	if _, err = facts.PersistPlan(ctx, caller, uuid.NewString(), plan); err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	device := cloudapproval.DeviceKeyV1{
		KeyID: "foundation-handoff-device", AgentInstanceID: instanceID, OwnerID: plan.OwnerID,
		Revision: 1, Status: cloudapproval.DeviceKeyActive, PublicKey: privateKey.Public().(ed25519.PublicKey),
		NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	}
	if _, err = store.RegisterApprovalDevice(ctx, taskCaller, postgres.RegisterApprovalDeviceCommand{
		IdempotencyKey: uuid.NewString(), Device: device,
	}); err != nil {
		t.Fatal(err)
	}
	approvalAdapter, err := postgres.NewApprovalRepositoryAdapter(store, taskCaller, uuid.NewString(), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	approvalService, err := cloudapproval.NewService(approvalAdapter, approvalAdapter, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := approvalService.DraftChallenge(ctx, plan, quote, device.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err = facts.PersistChallenge(ctx, caller, uuid.NewString(), challenge)
	if err != nil {
		t.Fatal(err)
	}
	approval := signedCloudApproval(t, plan, challenge, privateKey)
	approvedPlan, err := facts.PersistApproval(ctx, caller, uuid.NewString(), challenge.Revision, plan.Revision, approval)
	if err != nil {
		t.Fatal(err)
	}
	if approvedPlan.Status != cloudapproval.PlanApproved {
		t.Fatalf("approved Plan status=%q", approvedPlan.Status)
	}

	masterKey := bytes.Repeat([]byte{0x54}, 32)
	secretStore, err := postgres.NewSecretBootstrapStore(pool, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := secretbootstrap.NewManager(secretStore, secretStore.KeyStore(), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	created, err := manager.CreateIdempotent(ctx, secretbootstrap.MutationScope(caller), uuid.NewString(), secretbootstrap.BindingV1{
		AgentInstanceID: instanceID, OwnerID: plan.OwnerID, Purpose: "aws_connection", TargetID: connectionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := secretbootstrap.Seal(created.Session, []byte("synthetic bootstrap payload"), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uploaded, err := manager.UploadIdempotent(ctx, secretbootstrap.MutationScope(caller), uuid.NewString(), created.Session.SessionID, created.Session.Revision, created.UploadToken.Reveal(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	operation, _, err := store.BeginFoundationOperation(ctx, caller, cloudapp.FoundationOperationIntent{
		Caller: caller, OperationID: uuid.NewString(), IdempotencyKey: uuid.NewString(), RequestHash: [32]byte{2},
		OwnerID: plan.OwnerID, BootstrapSessionID: uploaded.SessionID, PlanID: plan.PlanID, ConnectionID: connectionID,
		AccountID: "123456789012", Region: "us-east-1", ExpectedSessionRevision: uploaded.Revision,
		ReaperImageURI: "registry.example/reaper:v0.1.0-alpha.1@sha256:" + strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	operation, err = store.MarkFoundationOperationRunning(ctx, operation.OperationID, operation.Revision)
	if err != nil {
		t.Fatal(err)
	}
	connection := cloudapp.Connection{
		ConnectionID: connectionID, OwnerID: plan.OwnerID, AccountID: "123456789012", Region: "us-east-1",
		ControlRoleARN: "arn:aws:iam::123456789012:role/dtx-control", FoundationStack: "foundation-stack", Status: "active", Revision: 1,
	}
	if _, err = store.FinalizeFoundationOperation(ctx, operation.OperationID, operation.Revision, uploaded.SessionID, uploaded.Revision, connection); err != nil {
		t.Fatal(err)
	}

	restarted, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := restarted.ListPendingFoundationLaunchHandoffs(ctx, 16)
	if err != nil {
		t.Fatal(err)
	}
	want := cloudapp.FoundationLaunchHandoff{Caller: caller, OwnerID: plan.OwnerID, PlanID: plan.PlanID, ApprovalID: approval.ApprovalID}
	if len(pending) != 1 || pending[0] != want {
		t.Fatalf("pending Foundation handoffs=%#v, want %#v", pending, want)
	}
	storedApproval, err := facts.LoadApproval(ctx, plan.OwnerID, approval.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	launchRequest := cloudexecution.LaunchRequest{
		IdempotencyKey: uuid.NewString(), OwnerID: plan.OwnerID, PlanID: plan.PlanID, ApprovalID: approval.ApprovalID,
		ControlPlaneTarget: "grpcs://agent.example:8443",
	}
	if _, _, err = restarted.Begin(ctx, cloudexecution.Intent{
		OperationID: uuid.NewString(), RequestHash: [32]byte{3},
		Caller: cloudapp.MutationScope{ClientID: "internal.cloud-launcher", CredentialID: uuid.NewString()}, Launch: launchRequest,
		ConnectionID: connectionID, ApprovedPlanHash: storedApproval.PlanHash, TaskStepID: uuid.NewString(), DeploymentID: uuid.NewString(), RecordedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	pending, err = restarted.ListPendingFoundationLaunchHandoffs(ctx, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("Foundation handoff remained pending after exact launch intent: %#v", pending)
	}
}

func TestFoundationIntentIdempotencyRejectsChangedSpecification(t *testing.T) {
	_, store, _ := newPlanningTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	scope := cloudapp.MutationScope{ClientID: "foundation-idempotency-test", CredentialID: uuid.NewString()}
	intent := cloudapp.FoundationOperationIntent{
		Caller: scope, OperationID: uuid.NewString(), IdempotencyKey: uuid.NewString(), RequestHash: [32]byte{1},
		OwnerID: "owner-idempotency", BootstrapSessionID: uuid.NewString(), PlanID: uuid.NewString(), ConnectionID: uuid.NewString(),
		AccountID: "123456789012", Region: "us-east-1", ExpectedSessionRevision: 2,
		ReaperImageURI: "registry.example/reaper:v0.1.0-alpha.1@sha256:" + strings.Repeat("a", 64),
	}
	created, wasCreated, err := store.BeginFoundationOperation(ctx, scope, intent)
	if err != nil || !wasCreated {
		t.Fatalf("first intent=%#v created=%t err=%v", created, wasCreated, err)
	}
	replayed, wasCreated, err := store.BeginFoundationOperation(ctx, scope, intent)
	if err != nil || wasCreated || replayed.OperationID != created.OperationID {
		t.Fatalf("intent replay=%#v created=%t err=%v", replayed, wasCreated, err)
	}
	changed := intent
	changed.RequestHash = [32]byte{2}
	if _, _, err := store.BeginFoundationOperation(ctx, scope, changed); !errors.Is(err, idempotency.ErrConflict) {
		t.Fatalf("changed specification error=%v, want idempotency conflict", err)
	}
}

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
