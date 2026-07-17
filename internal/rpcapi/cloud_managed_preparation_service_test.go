package rpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/serviceoperation"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCloudManagedPreparationRPCRoundTripPreservesSignedScopeStepsAndResult(t *testing.T) {
	now := time.Date(2026, 7, 17, 9, 0, 0, 0, time.UTC)
	challenge := rpcManagedPreparationChallenge(t, now)
	operation := rpcManagedPreparationOperation(challenge, now)
	fake := &managedPreparationCoordinatorFake{challenge: challenge, operation: operation}
	service := NewCloudControlService(nil, challenge.Scope.AgentInstanceID).WithManagedPreparation(fake)
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "rpc-client", CredentialID: uuid.NewString()})

	created, err := service.CreateCloudManagedPreparation(ctx, &agentv1.CreateCloudManagedPreparationRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: challenge.Scope.OwnerID, DeploymentId: challenge.Scope.DeploymentID,
		SignerKeyId: challenge.SignerKeyID, ExpectedDeploymentRevision: challenge.Scope.DeploymentRevision,
		CostAlertAmountMinor: challenge.Scope.CostAlertAmountMinor,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := challenge.SigningPayload()
	volume := created.GetChallenge().GetScope().GetVolumes()[0]
	if volume.GetReplacementVolumeResourceId() != challenge.Scope.Volumes[0].ReplacementVolumeResourceID ||
		volume.GetVolumeType() != "gp3" || volume.GetIops() != 3000 || volume.GetThroughputMibps() != 125 ||
		volume.GetMountPath() != "/srv/knowledge" || !volume.GetPersistent() ||
		volume.GetDisposition() != string(cloudapproval.VolumeRetainWithManagedService) ||
		string(created.GetChallenge().GetSigningPayloadCbor()) != string(payload) || fake.prepare.CostAlertAmountMinor != 25_000 {
		t.Fatal("Create ManagedPreparation lost signed scope, raw CBOR, or threshold")
	}
	approval := &agentv1.DeviceApprovalSignature{ApprovalId: challenge.OperationID, ChallengeId: challenge.ChallengeID,
		SignerKeyId: challenge.SignerKeyID, ExpiresAt: timestamppb.New(challenge.ExpiresAt), Signature: make([]byte, 64)}
	approved, err := service.ApproveCloudManagedPreparation(ctx, &agentv1.ApproveCloudManagedPreparationRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: challenge.Scope.OwnerID, OperationId: challenge.OperationID,
		DeploymentId: challenge.Scope.DeploymentID, ScopeDigest: challenge.ScopeDigest, ExpectedRevision: 1, Approval: approval,
	})
	if err != nil || approved.GetOperation().GetSteps()[0].GetPhase() != string(serviceoperation.PhaseRestart) ||
		fake.approve.Signature.OperationID != challenge.OperationID {
		t.Fatalf("Approve ManagedPreparation mapping error=%v", err)
	}
	got, err := service.GetCloudManagedPreparation(ctx, &agentv1.GetCloudManagedPreparationRequest{OwnerId: challenge.Scope.OwnerID, OperationId: challenge.OperationID})
	if err != nil || got.GetOperation().GetStatus() != agentv1.CloudManagedPreparationStatus_CLOUD_MANAGED_PREPARATION_STATUS_SUCCEEDED ||
		got.GetOperation().GetResult().GetPreparationDigest() != operation.Result.PreparationDigest ||
		len(got.GetOperation().GetSteps()) != len(serviceoperation.Phases()) {
		t.Fatalf("Get ManagedPreparation lost succeeded-only result or steps: error=%v", err)
	}
}

func TestCloudManagedPreparationRPCMapsV2BoundedSnapshotTerms(t *testing.T) {
	challenge := rpcManagedPreparationChallenge(t, time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC))
	challenge.SchemaVersion = serviceoperation.ChallengeSchemaV2
	challenge.Scope.SchemaVersion = serviceoperation.ScopeSchemaV2
	challenge.Scope.Volumes[0].SnapshotOperationKey = "managed-snapshot-knowledge"
	challenge.Scope.Volumes[0].SnapshotSourceVolumeScopeDigest = rpcManagedDigest('f')
	challenge.Scope.Volumes[0].SnapshotMaxRetentionSeconds = 3_600
	var err error
	challenge.ScopeDigest, err = serviceoperation.SigningPayloadDigest(challenge)
	if err != nil {
		t.Fatal(err)
	}
	value, err := managedPreparationChallengeToProto(challenge)
	if err != nil {
		t.Fatal(err)
	}
	volume := value.GetScope().GetVolumes()[0]
	if volume.GetSnapshotOperationKey() != challenge.Scope.Volumes[0].SnapshotOperationKey ||
		volume.GetSnapshotSourceVolumeScopeDigest() != challenge.Scope.Volumes[0].SnapshotSourceVolumeScopeDigest ||
		volume.GetSnapshotMaxRetentionSeconds() != challenge.Scope.Volumes[0].SnapshotMaxRetentionSeconds {
		t.Fatalf("V2 snapshot terms lost in protobuf mapping: %+v", volume)
	}
}

type managedPreparationCoordinatorFake struct {
	challenge serviceoperation.ChallengeV1
	operation serviceoperation.OperationV1
	prepare   serviceoperation.PrepareCommand
	approve   serviceoperation.ApproveCommand
}

func (fake *managedPreparationCoordinatorFake) Prepare(_ context.Context, command serviceoperation.PrepareCommand) (serviceoperation.ChallengeV1, error) {
	fake.prepare = command
	return fake.challenge, nil
}
func (fake *managedPreparationCoordinatorFake) Approve(_ context.Context, command serviceoperation.ApproveCommand) (serviceoperation.OperationV1, error) {
	fake.approve = command
	value := fake.operation
	value.Status, value.Result = serviceoperation.StatusApproved, nil
	return value, nil
}
func (fake *managedPreparationCoordinatorFake) Get(context.Context, string, string) (serviceoperation.OperationV1, error) {
	return fake.operation, nil
}

func rpcManagedPreparationChallenge(t *testing.T, now time.Time) serviceoperation.ChallengeV1 {
	t.Helper()
	operationID := "11111111-1111-4111-8111-111111111111"
	sourceID := "88888888-8888-4888-8888-888888888888"
	snapshotID, replacementID, _ := serviceoperation.DeriveVolumeResourceIDs(operationID, sourceID, "knowledge")
	source := serviceoperation.ResourceFactV1{ResourceID: sourceID, ProviderID: "vol-0123456789abcdef0", Revision: 8,
		SpecDigest: rpcManagedDigest('5'), TagDigest: rpcManagedDigest('6')}
	scope := serviceoperation.ScopeV1{
		SchemaVersion: serviceoperation.ScopeSchemaV1, Intent: serviceoperation.IntentManagedPreparation,
		PreparationOperationID: operationID, OwnerID: "owner-golden", AgentInstanceID: "22222222-2222-4222-8222-222222222222",
		DeploymentID: "33333333-3333-4333-8333-333333333333", DeploymentRevision: 7,
		ConnectionID: "55555555-5555-4555-8555-555555555555", ConnectionRevision: 3,
		PlanID: "66666666-6666-4666-8666-666666666666", PlanRevision: 4, PlanHash: rpcManagedDigest('1'),
		RecipeID: "postgresql", RecipeDigest: rpcManagedDigest('2'), RecipeRevision: 5,
		EC2: serviceoperation.ResourceFactV1{ResourceID: "77777777-7777-4777-8777-777777777777", ProviderID: "i-0123456789abcdef0",
			Revision: 6, SpecDigest: rpcManagedDigest('3'), TagDigest: rpcManagedDigest('4')},
		SourceVolumes: []serviceoperation.ResourceFactV1{source},
		Restart: serviceoperation.RestartReferenceV1{OperationID: uuid.NewSHA1(uuid.MustParse(operationID), []byte("restart")).String(),
			ExpectedInitialRevision: 1, Action: "restart", LifecycleRestartRef: "restart-service", ExecutionBundleDigest: rpcManagedDigest('7')},
		Volumes: []serviceoperation.VolumePreparationV1{{SlotID: "knowledge", SourceVolume: source,
			SnapshotResourceID: snapshotID, ReplacementVolumeResourceID: replacementID, AvailabilityZone: "us-east-1a",
			SizeGiB: 80, VolumeType: "gp3", IOPS: 3000, ThroughputMiBPS: 125,
			KMSKeyID: "alias/dtx-agent-golden", DeviceName: "/dev/sdf", MountPath: "/srv/knowledge",
			Persistent: true, Disposition: string(cloudapproval.VolumeRetainWithManagedService)}},
		ServiceMonitorRevision: 9, ServiceMonitorSuiteDigest: rpcManagedDigest('8'), Currency: "USD",
		CostAlertAmountMinor: 25_000, ExpectedInstalledManifestDigest: rpcManagedDigest('9'),
	}
	sourceSpecDigest, err := scope.Volumes[0].SourceSpecDigest()
	if err != nil {
		t.Fatal(err)
	}
	scope.Volumes[0].SourceVolume.SpecDigest = sourceSpecDigest
	scope.SourceVolumes[0].SpecDigest = sourceSpecDigest
	value := serviceoperation.ChallengeV1{SchemaVersion: serviceoperation.ChallengeSchemaV1,
		ChallengeID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", OperationID: operationID, SignerKeyID: "device-golden",
		Scope: scope, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	value.ScopeDigest, err = serviceoperation.SigningPayloadDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func rpcManagedPreparationOperation(challenge serviceoperation.ChallengeV1, now time.Time) serviceoperation.OperationV1 {
	approved := now.Add(time.Minute)
	value := serviceoperation.OperationV1{OperationID: challenge.OperationID, Challenge: challenge,
		Status: serviceoperation.StatusSucceeded, CurrentPhase: serviceoperation.PhaseFinalize, Revision: 15,
		CreatedAt: now, UpdatedAt: now.Add(10 * time.Minute), ApprovedAt: &approved}
	for index, phase := range serviceoperation.Phases() {
		started, completed := now.Add(time.Duration(index+2)*time.Minute), now.Add(time.Duration(index+3)*time.Minute)
		value.Steps = append(value.Steps, serviceoperation.StepV1{Phase: phase, Ordinal: index + 1,
			Status: serviceoperation.StepSucceeded, Revision: 3, IntentDigest: rpcManagedDigest(byte('a' + index)),
			StartedAt: &started, CompletedAt: &completed})
	}
	value.Result = &serviceoperation.ManagedPreparationResultV1{
		PreparationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", PreparationDigest: rpcManagedDigest('b'),
		FreshHealthDigest: rpcManagedDigest('c'), FreshHealthRevision: 10, FreshHealthObservedAt: now.Add(7 * time.Minute),
		CostDigest: rpcManagedDigest('d'), CostPolicyRevision: 2, CostObservedAt: now.Add(8 * time.Minute),
		StackDigest: rpcManagedDigest('e'), StackRevision: 3, StackObservedAt: now.Add(9 * time.Minute),
	}
	return value
}

func rpcManagedDigest(fill byte) string { return "sha256:" + strings.Repeat(string(fill), 64) }
