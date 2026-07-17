package foundation

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/google/uuid"
)

func TestIndependentDeviceApprovedFoundationLifecycle(t *testing.T) {
	now := time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC)
	agentID, ownerID, connectionID, sessionID := uuid.NewString(), "owner-foundation", uuid.NewString(), uuid.NewString()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	device := cloudapproval.DeviceKeyV1{KeyID: "device-foundation", AgentInstanceID: agentID, OwnerID: ownerID, Revision: 1,
		Status: cloudapproval.DeviceKeyActive, PublicKey: publicKey, NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}
	devices := &deviceRepository{device: device}
	repository := &memoryRepository{}
	snapshots := &snapshotReader{snapshot: foundationSnapshot(t, agentID, ownerID, connectionID, sessionID, ActionEstablish, now)}
	notifier := &foundationNotifier{}
	service, err := NewService(agentID, repository, devices, snapshots, notifier, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	caller := MutationScope{ClientID: "foundation-client", CredentialID: uuid.NewString()}
	prepared, err := service.Prepare(context.Background(), PrepareCommand{Caller: caller, IdempotencyKey: uuid.NewString(), OwnerID: ownerID,
		Action: ActionEstablish, ConnectionID: connectionID, BootstrapSessionID: sessionID, ExpectedBootstrapRevision: 2, SignerKeyID: device.KeyID})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if prepared.Scope.Action != ActionEstablish || prepared.Scope.ExpectedConnectionRevision != 0 || prepared.Scope.ExpectedCredentialGeneration != 0 ||
		!prepared.Scope.ReleaseEnvironment.ZeroIngress || !prepared.Scope.ReleaseEnvironment.BucketVersioned || !prepared.Scope.ReleaseEnvironment.BucketSSEKMS {
		t.Fatalf("prepared scope does not bind independent Foundation establishment: %#v", prepared.Scope)
	}
	// The signed document intentionally has no Worker plan, quote, Recipe,
	// instance type, or operator credential surface.
	signature := SignatureV1{ApprovalID: prepared.ApprovalID, ChallengeID: prepared.ChallengeID, SignerKeyID: prepared.SignerKeyID, ExpiresAt: prepared.ExpiresAt,
		Signature: ed25519.Sign(privateKey, prepared.SigningCBOR)}
	approved, err := service.Approve(context.Background(), ApproveCommand{Caller: caller, IdempotencyKey: uuid.NewString(), OwnerID: ownerID,
		OperationID: prepared.OperationID, ExpectedRevision: prepared.Revision, ConnectionID: prepared.Scope.ConnectionID, Action: prepared.Scope.Action, ScopeDigest: prepared.ScopeDigest, Signature: signature})
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if approved.Status != StatusApproved || notifier.calls != 1 {
		t.Fatalf("approved=%#v notifier.calls=%d", approved, notifier.calls)
	}
}

func TestFoundationUpgradeAndTeardownRequireFreshBootstrapAndExactRevision(t *testing.T) {
	now := time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC)
	agentID, ownerID, connectionID, sessionID := uuid.NewString(), "owner-foundation", uuid.NewString(), uuid.NewString()
	publicKey, _, _ := ed25519.GenerateKey(nil)
	device := cloudapproval.DeviceKeyV1{KeyID: "device-foundation", AgentInstanceID: agentID, OwnerID: ownerID, Revision: 1,
		Status: cloudapproval.DeviceKeyActive, PublicKey: publicKey, NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}
	for _, action := range []Action{ActionUpgrade, ActionTeardown, ActionRemediate} {
		t.Run(string(action), func(t *testing.T) {
			snapshot := foundationSnapshot(t, agentID, ownerID, connectionID, sessionID, action, now)
			snapshot.Scope.ExpectedConnectionRevision, snapshot.Scope.ExpectedCredentialGeneration = 7, 3
			snapshot.SessionExpiresAt = now
			service, _ := NewService(agentID, &memoryRepository{}, &deviceRepository{device: device}, &snapshotReader{snapshot: snapshot}, &foundationNotifier{}, func() time.Time { return now })
			_, err := service.Prepare(context.Background(), PrepareCommand{Caller: MutationScope{ClientID: "foundation-client", CredentialID: uuid.NewString()},
				IdempotencyKey: uuid.NewString(), OwnerID: ownerID, Action: action, ConnectionID: connectionID, BootstrapSessionID: sessionID,
				ExpectedBootstrapRevision: 2, SignerKeyID: device.KeyID})
			if !errors.Is(err, ErrRevisionConflict) {
				t.Fatalf("Prepare() error = %v, want ErrRevisionConflict", err)
			}
		})
	}
}

func foundationSnapshot(t *testing.T, agentID, ownerID, connectionID, sessionID string, action Action, now time.Time) Snapshot {
	t.Helper()
	alias, err := awsfoundation.KMSAliasForAgent(agentID)
	if err != nil {
		t.Fatal(err)
	}
	return Snapshot{Scope: ScopeV1{SchemaVersion: ScopeSchemaV1, AgentInstanceID: agentID, OwnerID: ownerID, Action: action,
		ConnectionID: connectionID, AccountID: "123456789012", Region: "ap-south-1", BootstrapSessionID: sessionID, ExpectedBootstrapRevision: 2,
		IdentityObservedAt: now.Add(-time.Minute), IdentityExpiresAt: now.Add(time.Minute),
		FoundationTemplateDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ReaperImageURI:           "repo/reaper:v1.2.3@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ReleaseEnvironment:       ReleaseEnvironmentV1{PrivateSubnetCIDR: "10.255.0.0/26", ZeroIngress: true, ArtifactBucket: "dtx-agent-123456789012-ap-south-1-test", KMSAlias: alias, BucketVersioned: true, BucketSSEKMS: true}},
		SessionUploadedAt: now.Add(-time.Minute), SessionExpiresAt: now.Add(time.Minute)}
}

type deviceRepository struct{ device cloudapproval.DeviceKeyV1 }

func (repository *deviceRepository) GetDeviceKey(_ context.Context, keyID string) (cloudapproval.DeviceKeyV1, error) {
	if keyID != repository.device.KeyID {
		return cloudapproval.DeviceKeyV1{}, cloudapproval.ErrDeviceNotFound
	}
	return repository.device, nil
}

type snapshotReader struct{ snapshot Snapshot }

func (reader *snapshotReader) SnapshotFoundation(_ context.Context, _ MutationScope, _ string, _ Action, _ string, _ string, _ uint64) (Snapshot, error) {
	return reader.snapshot, nil
}

type foundationNotifier struct{ calls int }

func (notifier *foundationNotifier) NotifyFoundationOperation() { notifier.calls++ }

type memoryRepository struct {
	challenge ChallengeV1
	operation OperationV1
}

func (repository *memoryRepository) CreateChallenge(_ context.Context, _ Mutation, challenge ChallengeV1) (ChallengeV1, error) {
	repository.challenge = challenge
	repository.operation = OperationV1{Challenge: challenge, Status: StatusAwaitingApproval, Revision: 1, CreatedAt: challenge.IssuedAt, UpdatedAt: challenge.IssuedAt}
	return challenge, nil
}
func (repository *memoryRepository) GetChallenge(_ context.Context, ownerID, challengeID string) (ChallengeV1, error) {
	if repository.challenge.Scope.OwnerID != ownerID || repository.challenge.ChallengeID != challengeID {
		return ChallengeV1{}, ErrNotFound
	}
	return repository.challenge, nil
}
func (repository *memoryRepository) Approve(_ context.Context, _ Mutation, signature SignatureV1, approvedAt time.Time) (OperationV1, error) {
	repository.operation.Status, repository.operation.Signature, repository.operation.ApprovedAt = StatusApproved, append([]byte(nil), signature.Signature...), &approvedAt
	repository.operation.Revision++
	repository.operation.UpdatedAt = approvedAt
	return repository.operation, nil
}
func (repository *memoryRepository) GetOperation(_ context.Context, ownerID, operationID string) (OperationV1, error) {
	if repository.operation.Challenge.Scope.OwnerID != ownerID || repository.operation.Challenge.OperationID != operationID {
		return OperationV1{}, ErrNotFound
	}
	return repository.operation, nil
}
