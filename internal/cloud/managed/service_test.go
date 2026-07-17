package managed

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/google/uuid"
)

func TestManagedAcceptanceRequiresExactCurrentScopeAndDeviceSignature(t *testing.T) {
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	public, private, _ := ed25519.GenerateKey(nil)
	owner, deployment, connection, plan := "owner-a", uuid.NewString(), uuid.NewString(), uuid.NewString()
	builder := &scopeFake{scope: testScope(deployment, connection, plan, now)}
	repository := &repositoryFake{}
	agentID := uuid.NewString()
	service, err := NewService(agentID, repository, deviceFake{cloudapproval.DeviceKeyV1{KeyID: "device-1", AgentInstanceID: agentID, OwnerID: owner, Revision: 1, Status: cloudapproval.DeviceKeyActive, PublicKey: public, NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}}, builder, notifierFake{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := service.Prepare(context.Background(), PrepareCommand{ClientID: "message-server", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString(), OwnerID: owner, DeploymentID: deployment, SignerKeyID: "device-1", ExpectedDeploymentRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := challenge.SigningPayload()
	signature := SignatureV1{ChallengeID: challenge.ChallengeID, ApprovalID: challenge.ApprovalID, SignerKeyID: "device-1", Signature: ed25519.Sign(private, payload)}
	builder.scope.HealthRevision++
	if _, err := service.Approve(context.Background(), ApproveCommand{ClientID: "message-server", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString(), OwnerID: owner, OperationID: challenge.ApprovalID, DeploymentID: deployment, ScopeDigest: challenge.ScopeDigest, ExpectedRevision: 1, Signature: signature}); err != ErrRevisionConflict {
		t.Fatalf("drift error=%v", err)
	}
	builder.scope.HealthRevision--
	if _, err := service.Approve(context.Background(), ApproveCommand{ClientID: "message-server", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString(), OwnerID: owner, OperationID: challenge.ApprovalID, DeploymentID: deployment, ScopeDigest: challenge.ScopeDigest, ExpectedRevision: 1, Signature: signature}); err != nil {
		t.Fatalf("approve: %v", err)
	}
}

func TestManagedAcceptanceExactReplaysPrecedeMutableDeviceAndHealthChecks(t *testing.T) {
	now := time.Date(2026, 7, 17, 10, 10, 0, 0, time.UTC)
	owner, deployment := "owner-a", uuid.NewString()
	prepare := PrepareCommand{ClientID: "message-server", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString(),
		OwnerID: owner, DeploymentID: deployment, SignerKeyID: "expired-device", ExpectedDeploymentRevision: 1}
	challenge := ChallengeV1{ApprovalID: uuid.NewString(), ChallengeID: uuid.NewString()}
	approvedAt := now.Add(-time.Hour)
	operation := OperationV1{OperationID: challenge.ApprovalID, Challenge: challenge, Status: StatusSucceeded, Revision: 4, ApprovedAt: &approvedAt}
	repository := &repositoryFake{replayChallenge: &challenge, replayOperation: &operation}
	service, err := NewService(uuid.NewString(), repository, deviceFake{}, &scopeFake{}, notifierFake{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if replay, replayErr := service.Prepare(context.Background(), prepare); replayErr != nil || replay.ChallengeID != challenge.ChallengeID {
		t.Fatalf("prepare replay=%+v error=%v", replay, replayErr)
	}
	approve := ApproveCommand{ClientID: prepare.ClientID, CredentialID: prepare.CredentialID, IdempotencyKey: uuid.NewString(),
		OwnerID: owner, OperationID: challenge.ApprovalID, DeploymentID: deployment, ScopeDigest: "stale", ExpectedRevision: 1,
		Signature: SignatureV1{ChallengeID: challenge.ChallengeID, ApprovalID: challenge.ApprovalID, SignerKeyID: "expired-device"}}
	if replay, replayErr := service.Approve(context.Background(), approve); replayErr != nil || replay.Status != StatusSucceeded {
		t.Fatalf("approve replay=%+v error=%v", replay, replayErr)
	}
}

func TestManagedAcceptanceConflictingReplayKeyFailsClosedBeforeMutableChecks(t *testing.T) {
	now := time.Date(2026, 7, 17, 10, 10, 0, 0, time.UTC)
	repository := &repositoryFake{replayErr: ErrRevisionConflict}
	service, err := NewService(uuid.NewString(), repository, deviceFake{}, &scopeFake{}, notifierFake{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Prepare(context.Background(), PrepareCommand{ClientID: "message-server", CredentialID: uuid.NewString(),
		IdempotencyKey: uuid.NewString(), OwnerID: "owner-a", DeploymentID: uuid.NewString(), SignerKeyID: "device-1",
		ExpectedDeploymentRevision: 1})
	if err != ErrRevisionConflict {
		t.Fatalf("conflicting prepare replay error=%v", err)
	}
}

func testScope(deployment, connection, plan string, now time.Time) ScopeV1 {
	d := "sha256:" + strings.Repeat("a", 64)
	return ScopeV1{SchemaVersion: ScopeSchemaV1, ServiceID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(deployment)).String(), ServiceRevision: 1, OwnerID: "owner-a", DeploymentID: deployment, DeploymentRevision: 1,
		ConnectionID: connection, ConnectionRevision: 1, PlanID: plan, PlanRevision: 1, PlanHash: d, RecipeID: "recipe", RecipeDigest: d, RecipeRevision: 1, RecipeMaturity: "awaiting_management_acceptance",
		InstalledManifestDigest: d, ArtifactDigest: d, ReadinessSemanticEvidenceDigest: d, ReadinessStackObservationDigest: d,
		RestartOperationID: uuid.NewString(), RestartOperationRevision: 1, BackupID: uuid.NewString(), BackupRevision: 1, RestoreID: uuid.NewString(), RestoreRevision: 1,
		SourceArtifactDigests: []string{d}, HealthRevision: 1, HealthMonitorKind: "service", HealthStatus: "healthy", HealthEvidenceType: "independent_external", HealthEvidenceDigest: d, HealthObservedAt: now, Currency: "USD", CostAlertAmountMinor: 5000,
		Health:      HealthContractV1{Liveness: ProbeV1{"http", "/live"}, Readiness: ProbeV1{"http", "/ready"}, Semantic: ProbeV1{"command", "semantic-check"}},
		Lifecycle:   LifecycleV1{"start", "stop", "maintenance", "restart", "backup", "restore", "upgrade", "rollback", "destroy"},
		VolumeSlots: []VolumeSlotV1{{"data", "volume://data", false}}, DataSlots: []DataSlotV1{{"knowledge", "data://knowledge", true}}, SecretSlots: []SecretSlotV1{{"model", "secret://model"}},
		Resources: []ResourceV1{
			{"11111111-1111-4111-8111-111111111111", "ec2", 1, "i-0123456789abcdef0", d},
			{"22222222-2222-4222-8222-222222222222", "ebs", 1, "vol-0123456789abcdef0", d},
			{"33333333-3333-4333-8333-333333333333", "eni", 1, "eni-0123456789abcdef0", d},
			{"44444444-4444-4444-8444-444444444444", "snapshot", 1, "snap-0123456789abcdef0", d},
		}, DestroyInstanceID: "i-0123456789abcdef0",
		DestroyVolumeIDs: []string{"vol-0123456789abcdef0"}, DestroyNetworkInterfaceIDs: []string{"eni-0123456789abcdef0"}, AcceptancePolicy: AcceptancePolicyV1}
}

type scopeFake struct{ scope ScopeV1 }

func (f *scopeFake) BuildManagedAcceptanceSnapshot(context.Context, string, string, string) (SnapshotV1, error) {
	return SnapshotV1{
		Scope:   f.scope,
		Service: compatibilityServiceFixture(f.scope, 1, 1),
		Recipe: CompatibilityRecipeV1{RecipeID: f.scope.RecipeID, Name: "Managed recipe", Version: "v1", Digest: f.scope.RecipeDigest,
			Maturity: f.scope.RecipeMaturity, Revision: int64(f.scope.RecipeRevision), CreatedAt: 1, UpdatedAt: 1},
	}, nil
}

func compatibilityServiceFixture(scope ScopeV1, createdAt, updatedAt int64) CompatibilityServiceV1 {
	return CompatibilityServiceV1{
		ServiceID: scope.ServiceID, DeploymentID: scope.DeploymentID, RecipeID: scope.RecipeID,
		Name: "Managed service", Status: "awaiting_management_acceptance", Integration: "not_requested",
		Revision: int64(scope.ServiceRevision), CreatedAt: createdAt, UpdatedAt: updatedAt,
		Backups: []CompatibilityBackupV1{{
			BackupID: scope.BackupID, ServiceID: scope.ServiceID, DeploymentID: scope.DeploymentID,
			Status: "available", RetentionPolicy: "manual", SnapshotIDs: []string{"snap-0123456789abcdef0"},
			Revision: int64(scope.BackupRevision), CreatedAt: createdAt, UpdatedAt: updatedAt,
		}},
		Restores: []CompatibilityRestoreV1{{
			RestoreID: scope.RestoreID, RestorePlanID: "44444444-4444-4444-8444-444444444444",
			ServiceID: scope.ServiceID, DeploymentID: scope.DeploymentID, BackupID: scope.BackupID, Status: "succeeded",
			OriginalVolumeIDs: []string{"vol-1123456789abcdef0"}, ReplacementVolumeIDs: []string{"vol-0123456789abcdef0"},
			Revision: int64(scope.RestoreRevision), CreatedAt: createdAt, UpdatedAt: updatedAt,
		}},
	}
}

type deviceFake struct{ key cloudapproval.DeviceKeyV1 }

func (f deviceFake) GetDeviceKey(context.Context, string) (cloudapproval.DeviceKeyV1, error) {
	return f.key, nil
}

type notifierFake struct{}

func (notifierFake) NotifyManagedAcceptance() {}
func (notifierFake) ExecuteManagedAcceptance(_ context.Context, operation OperationV1) (OperationV1, error) {
	operation.Status = StatusSucceeded
	operation.Revision = 4
	return operation, nil
}

type repositoryFake struct {
	challenge       ChallengeV1
	replayChallenge *ChallengeV1
	replayOperation *OperationV1
	replayErr       error
}

func (f *repositoryFake) FindManagedAcceptanceChallengeReplay(context.Context, Mutation) (ChallengeV1, error) {
	if f.replayErr != nil {
		return ChallengeV1{}, f.replayErr
	}
	if f.replayChallenge != nil {
		return *f.replayChallenge, nil
	}
	return ChallengeV1{}, ErrNotFound
}
func (f *repositoryFake) CreateManagedAcceptanceChallenge(_ context.Context, _ Mutation, c ChallengeV1) (ChallengeV1, error) {
	f.challenge = c
	return c, nil
}
func (f *repositoryFake) GetManagedAcceptanceChallenge(context.Context, string, string) (ChallengeV1, error) {
	return f.challenge, nil
}
func (f *repositoryFake) FindManagedAcceptanceApprovalReplay(context.Context, Mutation) (OperationV1, error) {
	if f.replayErr != nil {
		return OperationV1{}, f.replayErr
	}
	if f.replayOperation != nil {
		return *f.replayOperation, nil
	}
	return OperationV1{}, ErrNotFound
}
func (f *repositoryFake) ApproveManagedAcceptance(_ context.Context, _ Mutation, s SignatureV1, at time.Time) (OperationV1, error) {
	return OperationV1{OperationID: f.challenge.ApprovalID, Challenge: f.challenge, Status: StatusApproved, Signature: s.Signature, Revision: 2, CreatedAt: f.challenge.IssuedAt, UpdatedAt: at, ApprovedAt: &at}, nil
}
func (f *repositoryFake) GetManagedAcceptanceOperation(context.Context, string, string) (OperationV1, error) {
	return OperationV1{}, ErrNotFound
}
