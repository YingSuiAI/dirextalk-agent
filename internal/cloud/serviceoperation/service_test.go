package serviceoperation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/google/uuid"
)

func TestManagedPreparationSigningPayloadGolden(t *testing.T) {
	operationID := "11111111-1111-4111-8111-111111111111"
	sourceID := "88888888-8888-4888-8888-888888888888"
	snapshotID, replacementID, err := DeriveVolumeResourceIDs(operationID, sourceID, "knowledge")
	if err != nil {
		t.Fatal(err)
	}
	scope := ScopeV1{
		SchemaVersion: ScopeSchemaV1, Intent: IntentManagedPreparation, PreparationOperationID: operationID,
		OwnerID: "owner-golden", AgentInstanceID: "22222222-2222-4222-8222-222222222222",
		DeploymentID: "33333333-3333-4333-8333-333333333333", DeploymentRevision: 7,
		ConnectionID: "55555555-5555-4555-8555-555555555555", ConnectionRevision: 3,
		PlanID: "66666666-6666-4666-8666-666666666666", PlanRevision: 4, PlanHash: digest("1"),
		RecipeID: "postgresql", RecipeDigest: digest("2"), RecipeRevision: 5,
		EC2:           ResourceFactV1{ResourceID: "77777777-7777-4777-8777-777777777777", ProviderID: "i-0123456789abcdef0", Revision: 6, SpecDigest: digest("3"), TagDigest: digest("4")},
		SourceVolumes: []ResourceFactV1{{ResourceID: sourceID, ProviderID: "vol-0123456789abcdef0", Revision: 8, SpecDigest: digest("5"), TagDigest: digest("6")}},
		Restart: RestartReferenceV1{OperationID: uuid.NewSHA1(uuid.MustParse(operationID), []byte("restart")).String(),
			ExpectedInitialRevision: 1, Action: "restart", LifecycleRestartRef: "restart-service", ExecutionBundleDigest: digest("7")},
		Volumes: []VolumePreparationV1{{SlotID: "knowledge",
			SourceVolume:       ResourceFactV1{ResourceID: sourceID, ProviderID: "vol-0123456789abcdef0", Revision: 8, SpecDigest: digest("5"), TagDigest: digest("6")},
			SnapshotResourceID: snapshotID, ReplacementVolumeResourceID: replacementID, AvailabilityZone: "us-east-1a",
			SizeGiB: 80, VolumeType: "gp3", IOPS: 3000, ThroughputMiBPS: 125,
			KMSKeyID: "alias/dtx-agent-golden", DeviceName: "/dev/sdf", MountPath: "/srv/knowledge",
			Persistent: true, Disposition: string(cloudapproval.VolumeRetainWithManagedService)}},
		ServiceMonitorRevision: 9, ServiceMonitorSuiteDigest: digest("8"), Currency: "USD",
		CostAlertAmountMinor: 25_000, ExpectedInstalledManifestDigest: digest("9"),
	}
	refreshTestVolumeDigest(t, &scope, 0)
	challenge := ChallengeV1{SchemaVersion: ChallengeSchemaV1, ChallengeID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		OperationID: operationID, SignerKeyID: "device-golden", Scope: scope,
		IssuedAt: time.Date(2026, 7, 17, 8, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 7, 17, 8, 5, 0, 0, time.UTC)}
	challenge.ScopeDigest, err = SigningPayloadDigest(challenge)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := challenge.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	got := hex.EncodeToString(sum[:])
	const expected = "1c12fffde17b8bc5b7e975a9270e0e791d55071dc33323519b96f9616eec2f51"
	if got != expected {
		t.Fatalf("payload sha256=%s scope_digest=%s", got, challenge.ScopeDigest)
	}
}

func TestManagedPreparationV2SignsBoundedSnapshotRetention(t *testing.T) {
	scope := testScope(t)
	scope.SchemaVersion = ScopeSchemaV2
	scope.Volumes[0].SnapshotOperationKey = "managed-snapshot-data"
	scope.Volumes[0].SnapshotSourceVolumeScopeDigest = digest("a")
	scope.Volumes[0].SnapshotMaxRetentionSeconds = uint64((30 * 24 * time.Hour) / time.Second)
	challenge := ChallengeV1{
		SchemaVersion: ChallengeSchemaV2, ChallengeID: uuid.NewString(), OperationID: scope.PreparationOperationID,
		SignerKeyID: "device-v2", Scope: scope,
		IssuedAt:  time.Date(2026, 7, 18, 9, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 7, 18, 9, 5, 0, 0, time.UTC),
	}
	var err error
	challenge.ScopeDigest, err = SigningPayloadDigest(challenge)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := challenge.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) == 0 {
		t.Fatal("V2 signing payload is empty")
	}
	deadline, err := challenge.SnapshotDestroyDeadline(scope.Volumes[0])
	if err != nil || !deadline.Equal(challenge.IssuedAt.Add(30*24*time.Hour)) {
		t.Fatalf("bounded snapshot deadline=%v err=%v", deadline, err)
	}
	precision := challenge
	precision.IssuedAt = time.Date(2026, 7, 18, 9, 0, 0, 123_456_789, time.UTC)
	precision.ExpiresAt = precision.IssuedAt.Add(5 * time.Minute)
	precision.ScopeDigest, err = SigningPayloadDigest(precision)
	if err != nil {
		t.Fatal(err)
	}
	deadline, err = precision.SnapshotDestroyDeadline(precision.Scope.Volumes[0])
	if err != nil || !deadline.Equal(precision.IssuedAt.Add(30*24*time.Hour).Truncate(time.Microsecond)) {
		t.Fatalf("PostgreSQL-normalized snapshot deadline=%v err=%v", deadline, err)
	}
	for name, mutate := range map[string]func(*VolumePreparationV1){
		"operation key":       func(volume *VolumePreparationV1) { volume.SnapshotOperationKey = "other-snapshot" },
		"source scope digest": func(volume *VolumePreparationV1) { volume.SnapshotSourceVolumeScopeDigest = digest("b") },
		"retention":           func(volume *VolumePreparationV1) { volume.SnapshotMaxRetentionSeconds++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := challenge
			changed.Scope = cloneScope(challenge.Scope)
			mutate(&changed.Scope.Volumes[0])
			digest, err := SigningPayloadDigest(changed)
			if err != nil {
				t.Fatal(err)
			}
			if digest == challenge.ScopeDigest {
				t.Fatal("bounded snapshot term did not change signed digest")
			}
		})
	}
	invalid := challenge
	invalid.Scope = cloneScope(challenge.Scope)
	invalid.Scope.Volumes[0].SnapshotMaxRetentionSeconds = 0
	if _, err := invalid.SigningPayload(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbounded V2 snapshot signed: %v", err)
	}
	mismatched := challenge
	mismatched.SchemaVersion = ChallengeSchemaV1
	if _, err := SigningPayloadDigest(mismatched); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched V2 challenge schema received a signing digest: %v", err)
	}
	legacy := testScope(t)
	legacy.Volumes[0].SnapshotMaxRetentionSeconds = 1
	if err := legacy.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("V1 scope accepted V2 retention field: %v", err)
	}
}

func TestManagedPreparationSigningPayloadBindsEveryAuthorityBoundary(t *testing.T) {
	challenge := testChallenge(t)
	base, err := SigningPayloadDigest(challenge)
	if err != nil {
		t.Fatal(err)
	}
	changeVolume := func(change func(*VolumePreparationV1)) func(*ChallengeV1) {
		return func(value *ChallengeV1) {
			change(&value.Scope.Volumes[0])
			refreshTestVolumeDigest(t, &value.Scope, 0)
		}
	}
	tests := map[string]func(*ChallengeV1){
		"challenge": func(value *ChallengeV1) { value.ChallengeID = uuid.NewString() },
		"operation": func(value *ChallengeV1) { value.OperationID = uuid.NewString() },
		"signer":    func(value *ChallengeV1) { value.SignerKeyID = "device-2" },
		"validity window": func(value *ChallengeV1) {
			value.IssuedAt = value.IssuedAt.Add(time.Second)
			value.ExpiresAt = value.ExpiresAt.Add(time.Second)
		},
		"owner":               func(value *ChallengeV1) { value.Scope.OwnerID = "owner-2" },
		"agent":               func(value *ChallengeV1) { value.Scope.AgentInstanceID = uuid.NewString() },
		"deployment revision": func(value *ChallengeV1) { value.Scope.DeploymentRevision++ },
		"connection revision": func(value *ChallengeV1) { value.Scope.ConnectionRevision++ },
		"plan hash":           func(value *ChallengeV1) { value.Scope.PlanHash = digest("b") },
		"recipe revision":     func(value *ChallengeV1) { value.Scope.RecipeRevision++ },
		"ec2 fact":            func(value *ChallengeV1) { value.Scope.EC2.Revision++ },
		"source EBS fact": func(value *ChallengeV1) {
			value.Scope.SourceVolumes[0].Revision++
			value.Scope.Volumes[0].SourceVolume.Revision++
		},
		"restart": func(value *ChallengeV1) { value.Scope.Restart.ExecutionBundleDigest = digest("a") },
		"derived volume resources": func(value *ChallengeV1) {
			source := value.Scope.SourceVolumes[0]
			source.ResourceID = uuid.NewString()
			value.Scope.SourceVolumes[0] = source
			value.Scope.Volumes[0].SourceVolume = source
			value.Scope.Volumes[0].SnapshotResourceID, value.Scope.Volumes[0].ReplacementVolumeResourceID, _ =
				DeriveVolumeResourceIDs(value.Scope.PreparationOperationID, source.ResourceID, value.Scope.Volumes[0].SlotID)
		},
		"volume AZ":         changeVolume(func(value *VolumePreparationV1) { value.AvailabilityZone = "us-east-1b" }),
		"volume IOPS":       changeVolume(func(value *VolumePreparationV1) { value.IOPS++ }),
		"volume throughput": changeVolume(func(value *VolumePreparationV1) { value.ThroughputMiBPS++ }),
		"volume mount":      changeVolume(func(value *VolumePreparationV1) { value.MountPath = "/srv/other" }),
		"volume read only":  changeVolume(func(value *VolumePreparationV1) { value.ReadOnly = true }),
		"monitor suite":     func(value *ChallengeV1) { value.Scope.ServiceMonitorSuiteDigest = digest("c") },
		"cost":              func(value *ChallengeV1) { value.Scope.CostAlertAmountMinor++ },
		"manifest":          func(value *ChallengeV1) { value.Scope.ExpectedInstalledManifestDigest = digest("d") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := challenge
			changed.Scope = cloneScope(challenge.Scope)
			mutate(&changed)
			got, err := SigningPayloadDigest(changed)
			if err != nil {
				t.Fatal(err)
			}
			if got == base {
				t.Fatal("authority-bearing field did not change deterministic CBOR digest")
			}
		})
	}
}

func TestServiceExactReplayPrecedesMutableChecks(t *testing.T) {
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	challenge := testChallenge(t)
	operation := OperationV1{OperationID: challenge.OperationID, Challenge: challenge, Status: StatusApproved, Revision: 2}
	repository := &serviceRepositoryFake{challengeReplay: &challenge, approvalReplay: &operation}
	service, err := NewService(challenge.Scope.AgentInstanceID, repository, failingDeviceRepository{}, failingScopeBuilder{}, func() time.Time {
		return now.Add(time.Hour)
	})
	if err != nil {
		t.Fatal(err)
	}
	prepare := PrepareCommand{ClientID: "message-server", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString(),
		OwnerID: challenge.Scope.OwnerID, DeploymentID: challenge.Scope.DeploymentID, SignerKeyID: challenge.SignerKeyID,
		ExpectedDeploymentRevision: challenge.Scope.DeploymentRevision}
	prepare.CostAlertAmountMinor = challenge.Scope.CostAlertAmountMinor
	if replay, err := service.Prepare(context.Background(), prepare); err != nil || replay.ChallengeID != challenge.ChallengeID {
		t.Fatalf("prepare replay consulted mutable state: replay=%+v err=%v", replay, err)
	}
	approve := ApproveCommand{ClientID: "message-server", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString(),
		OwnerID: challenge.Scope.OwnerID, OperationID: challenge.OperationID, DeploymentID: challenge.Scope.DeploymentID,
		ScopeDigest: challenge.ScopeDigest, ExpectedRevision: 1}
	if replay, err := service.Approve(context.Background(), approve); err != nil || replay.OperationID != operation.OperationID {
		t.Fatalf("approve replay consulted expired/live state: replay=%+v err=%v", replay, err)
	}
}

func TestServiceRejectsConflictingIdempotencyBeforeMutableChecks(t *testing.T) {
	challenge := testChallenge(t)
	repository := &serviceRepositoryFake{challengeReplayErr: ErrRevisionConflict, approvalReplayErr: ErrRevisionConflict}
	service, err := NewService(challenge.Scope.AgentInstanceID, repository, failingDeviceRepository{}, failingScopeBuilder{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	prepare := PrepareCommand{ClientID: "message-server", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString(),
		OwnerID: challenge.Scope.OwnerID, DeploymentID: challenge.Scope.DeploymentID, SignerKeyID: challenge.SignerKeyID,
		ExpectedDeploymentRevision: challenge.Scope.DeploymentRevision}
	prepare.CostAlertAmountMinor = challenge.Scope.CostAlertAmountMinor
	if _, err := service.Prepare(context.Background(), prepare); err != ErrRevisionConflict {
		t.Fatalf("conflicting prepare idempotency error=%v", err)
	}
	approve := ApproveCommand{ClientID: "message-server", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString(),
		OwnerID: challenge.Scope.OwnerID, OperationID: challenge.OperationID, DeploymentID: challenge.Scope.DeploymentID,
		ScopeDigest: challenge.ScopeDigest, ExpectedRevision: 1}
	if _, err := service.Approve(context.Background(), approve); err != ErrRevisionConflict {
		t.Fatalf("conflicting approve idempotency error=%v", err)
	}
}

func TestServicePrepareApproveV2ScopeUsesV2Challenge(t *testing.T) {
	now := time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC)
	scope := testScope(t)
	scope.SchemaVersion = ScopeSchemaV2
	scope.Volumes[0].SnapshotOperationKey = "managed-snapshot-data"
	scope.Volumes[0].SnapshotSourceVolumeScopeDigest = digest("a")
	scope.Volumes[0].SnapshotMaxRetentionSeconds = 3_600
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	device := cloudapproval.DeviceKeyV1{
		KeyID: "device-v2", AgentInstanceID: scope.AgentInstanceID, OwnerID: scope.OwnerID, Revision: 1,
		Status: cloudapproval.DeviceKeyActive, PublicKey: public, NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	}
	repository := &serviceRepositoryFake{}
	service, err := NewService(scope.AgentInstanceID, repository, serviceDeviceFake{device}, serviceScopeBuilderFake{scope}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	prepare := PrepareCommand{
		ClientID: "message-server", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString(), OwnerID: scope.OwnerID,
		DeploymentID: scope.DeploymentID, SignerKeyID: device.KeyID, ExpectedDeploymentRevision: scope.DeploymentRevision,
		CostAlertAmountMinor: scope.CostAlertAmountMinor,
	}
	challenge, err := service.Prepare(context.Background(), prepare)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.SchemaVersion != ChallengeSchemaV2 || challenge.Scope.SchemaVersion != ScopeSchemaV2 {
		t.Fatalf("V2 preparation returned incompatible challenge: %+v", challenge)
	}
	payload, err := challenge.SigningPayload()
	if err != nil {
		t.Fatalf("V2 challenge is not signable: %v", err)
	}
	approve := ApproveCommand{
		ClientID: "message-server", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString(), OwnerID: scope.OwnerID,
		OperationID: challenge.OperationID, DeploymentID: scope.DeploymentID, ScopeDigest: challenge.ScopeDigest, ExpectedRevision: 1,
		Signature: SignatureV1{ChallengeID: challenge.ChallengeID, OperationID: challenge.OperationID, SignerKeyID: device.KeyID,
			Signature: ed25519.Sign(private, payload)},
	}
	operation, err := service.Approve(context.Background(), approve)
	if err != nil {
		t.Fatalf("V2 challenge approval failed: %v", err)
	}
	if operation.Challenge.SchemaVersion != ChallengeSchemaV2 || operation.OperationID != challenge.OperationID {
		t.Fatalf("V2 approval did not persist the prepared operation: %+v", operation)
	}
}

func TestManagedPreparationPhaseOrderIsClosedAndCASFriendly(t *testing.T) {
	phases := Phases()
	for index := 0; index < len(phases)-1; index++ {
		if err := ValidatePhaseAdvance(phases[index], phases[index+1]); err != nil {
			t.Fatalf("phase %s -> %s rejected: %v", phases[index], phases[index+1], err)
		}
	}
	for _, pair := range [][2]Phase{
		{PhaseRestart, PhaseRestoreCreate}, {PhaseBackup, PhaseRestart}, {PhaseFinalize, PhaseRestart},
		{PhaseSemanticHealth, PhaseRestoreSwap}, {PhaseFinalize, PhaseFinalize},
	} {
		if err := ValidatePhaseAdvance(pair[0], pair[1]); err != ErrRevisionConflict {
			t.Fatalf("illegal phase %s -> %s error=%v", pair[0], pair[1], err)
		}
	}
	if err := ValidatePhaseAdvance(PhaseFinalize, ""); err != nil {
		t.Fatalf("finalize completion rejected: %v", err)
	}
}

func testChallenge(t *testing.T) ChallengeV1 {
	t.Helper()
	scope := testScope(t)
	challenge := ChallengeV1{
		SchemaVersion: ChallengeSchemaV1, ChallengeID: uuid.NewString(), OperationID: scope.PreparationOperationID,
		SignerKeyID: "device-1", Scope: scope,
		IssuedAt:  time.Date(2026, 7, 17, 9, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 7, 17, 9, 5, 0, 0, time.UTC),
	}
	var err error
	challenge.ScopeDigest, err = SigningPayloadDigest(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := challenge.SigningPayload(); err != nil {
		t.Fatal(err)
	}
	return challenge
}

func testScope(t *testing.T) ScopeV1 {
	t.Helper()
	source := ResourceFactV1{ResourceID: uuid.NewString(), ProviderID: "vol-0123456789abcdef0", Revision: 3, SpecDigest: digest("1"), TagDigest: digest("2")}
	operationID := uuid.NewString()
	snapshotID, replacementID, err := DeriveVolumeResourceIDs(operationID, source.ResourceID, "data")
	if err != nil {
		t.Fatal(err)
	}
	scope := ScopeV1{
		SchemaVersion: ScopeSchemaV1, Intent: IntentManagedPreparation, PreparationOperationID: operationID, OwnerID: "owner-1",
		AgentInstanceID: uuid.NewString(), DeploymentID: uuid.NewString(), DeploymentRevision: 7,
		ConnectionID: uuid.NewString(), ConnectionRevision: 4,
		PlanID: uuid.NewString(), PlanRevision: 8, PlanHash: digest("3"),
		RecipeID: "postgresql", RecipeDigest: digest("4"), RecipeRevision: 2,
		EC2:           ResourceFactV1{ResourceID: uuid.NewString(), ProviderID: "i-0123456789abcdef0", Revision: 5, SpecDigest: digest("5"), TagDigest: digest("6")},
		SourceVolumes: []ResourceFactV1{source},
		Restart: RestartReferenceV1{OperationID: uuid.NewSHA1(uuid.MustParse(operationID), []byte("restart")).String(), ExpectedInitialRevision: 1, Action: "restart",
			LifecycleRestartRef: "restart", ExecutionBundleDigest: digest("9")},
		Volumes: []VolumePreparationV1{{SlotID: "data", SourceVolume: source, SnapshotResourceID: snapshotID,
			ReplacementVolumeResourceID: replacementID, AvailabilityZone: "us-east-1a", SizeGiB: 80,
			VolumeType: "gp3", IOPS: 3000, ThroughputMiBPS: 125, KMSKeyID: "alias/dtx-agent-test",
			DeviceName: "/dev/sdf", MountPath: "/srv/data", Persistent: true,
			Disposition: string(cloudapproval.VolumeRetainWithManagedService)}},
		ServiceMonitorRevision: 9, ServiceMonitorSuiteDigest: digest("7"), Currency: "USD",
		CostAlertAmountMinor: 1500, ExpectedInstalledManifestDigest: digest("8"),
	}
	refreshTestVolumeDigest(t, &scope, 0)
	return scope
}

func refreshTestVolumeDigest(t *testing.T, scope *ScopeV1, index int) {
	t.Helper()
	digest, err := scope.Volumes[index].SourceSpecDigest()
	if err != nil {
		t.Fatal(err)
	}
	scope.Volumes[index].SourceVolume.SpecDigest = digest
	for sourceIndex := range scope.SourceVolumes {
		if scope.SourceVolumes[sourceIndex].ResourceID == scope.Volumes[index].SourceVolume.ResourceID {
			scope.SourceVolumes[sourceIndex].SpecDigest = digest
		}
	}
}

func digest(value string) string { return "sha256:" + strings.Repeat(value, 64) }

type failingDeviceRepository struct{}

func (failingDeviceRepository) GetDeviceKey(context.Context, string) (cloudapproval.DeviceKeyV1, error) {
	return cloudapproval.DeviceKeyV1{}, ErrNotFound
}

type failingScopeBuilder struct{}

func (failingScopeBuilder) BuildManagedPreparationScope(context.Context, string, string, string, int64) (ScopeV1, error) {
	return ScopeV1{}, ErrRevisionConflict
}

type serviceDeviceFake struct{ device cloudapproval.DeviceKeyV1 }

func (fake serviceDeviceFake) GetDeviceKey(_ context.Context, keyID string) (cloudapproval.DeviceKeyV1, error) {
	if keyID != fake.device.KeyID {
		return cloudapproval.DeviceKeyV1{}, ErrNotFound
	}
	return fake.device, nil
}

type serviceScopeBuilderFake struct{ scope ScopeV1 }

func (fake serviceScopeBuilderFake) BuildManagedPreparationScope(_ context.Context, ownerID, deploymentID, operationID string, amountMinor int64) (ScopeV1, error) {
	scope := cloneScope(fake.scope)
	if scope.OwnerID != ownerID || scope.DeploymentID != deploymentID || scope.CostAlertAmountMinor != amountMinor {
		return ScopeV1{}, ErrRevisionConflict
	}
	scope.PreparationOperationID = operationID
	scope.Restart.OperationID = uuid.NewSHA1(uuid.MustParse(operationID), []byte("restart")).String()
	for index := range scope.Volumes {
		snapshotID, replacementID, err := DeriveVolumeResourceIDs(operationID, scope.Volumes[index].SourceVolume.ResourceID, scope.Volumes[index].SlotID)
		if err != nil {
			return ScopeV1{}, err
		}
		scope.Volumes[index].SnapshotResourceID = snapshotID
		scope.Volumes[index].ReplacementVolumeResourceID = replacementID
	}
	return scope, nil
}

type serviceRepositoryFake struct {
	challengeReplay    *ChallengeV1
	approvalReplay     *OperationV1
	challengeReplayErr error
	approvalReplayErr  error
	createdChallenge   *ChallengeV1
}

func (repository *serviceRepositoryFake) FindServiceOperationChallengeReplay(context.Context, Mutation) (ChallengeV1, error) {
	if repository.challengeReplayErr != nil {
		return ChallengeV1{}, repository.challengeReplayErr
	}
	if repository.challengeReplay == nil {
		return ChallengeV1{}, ErrNotFound
	}
	return *repository.challengeReplay, nil
}
func (repository *serviceRepositoryFake) CreateServiceOperationChallenge(_ context.Context, _ Mutation, challenge ChallengeV1) (ChallengeV1, error) {
	copy := challenge
	repository.createdChallenge = &copy
	return copy, nil
}
func (repository *serviceRepositoryFake) GetServiceOperationChallenge(_ context.Context, _ string, challengeID string) (ChallengeV1, error) {
	if repository.createdChallenge != nil && repository.createdChallenge.ChallengeID == challengeID {
		return *repository.createdChallenge, nil
	}
	return ChallengeV1{}, ErrNotFound
}
func (repository *serviceRepositoryFake) FindServiceOperationApprovalReplay(context.Context, Mutation) (OperationV1, error) {
	if repository.approvalReplayErr != nil {
		return OperationV1{}, repository.approvalReplayErr
	}
	if repository.approvalReplay == nil {
		return OperationV1{}, ErrNotFound
	}
	return *repository.approvalReplay, nil
}
func (repository *serviceRepositoryFake) ApproveServiceOperation(_ context.Context, _ Mutation, _ SignatureV1, _ time.Time) (OperationV1, error) {
	if repository.createdChallenge == nil {
		return OperationV1{}, ErrNotFound
	}
	return OperationV1{OperationID: repository.createdChallenge.OperationID, Challenge: *repository.createdChallenge, Status: StatusApproved, Revision: 2}, nil
}
func (*serviceRepositoryFake) GetServiceOperation(context.Context, string, string) (OperationV1, error) {
	return OperationV1{}, ErrNotFound
}
func (*serviceRepositoryFake) BeginServiceOperationPhase(context.Context, string, int64, Phase, string, time.Time) (OperationV1, error) {
	return OperationV1{}, ErrInvalid
}
func (*serviceRepositoryFake) AdvanceServiceOperationPhase(context.Context, string, int64, Phase, Phase, time.Time) (OperationV1, error) {
	return OperationV1{}, ErrInvalid
}
func (*serviceRepositoryFake) CompleteServiceOperation(context.Context, string, int64, ManagedPreparationResultV1, time.Time) (OperationV1, error) {
	return OperationV1{}, ErrInvalid
}
func (*serviceRepositoryFake) ListRecoverableServiceOperations(context.Context, int) ([]OperationV1, error) {
	return nil, nil
}

var _ = ed25519.PublicKeySize
