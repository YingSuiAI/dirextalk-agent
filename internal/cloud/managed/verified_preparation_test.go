package managed

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestVerifiedPreparationBindsCompleteSnapshotAndIndependentAttestations(t *testing.T) {
	value := verifiedPreparationFixture(t)
	if err := value.Validate(); err != nil {
		t.Fatalf("valid preparation rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*VerifiedPreparationV1)
	}{
		{"snapshot tamper", func(v *VerifiedPreparationV1) { v.Snapshot.Scope.CostAlertAmountMinor++ }},
		{"deployment revision drift", func(v *VerifiedPreparationV1) { v.ExpectedDeploymentRevision++ }},
		{"missing restore evidence", func(v *VerifiedPreparationV1) { v.Attestations = v.Attestations[:len(v.Attestations)-1] }},
		{"worker-style unbound evidence", func(v *VerifiedPreparationV1) {
			for index := range v.Attestations {
				if v.Attestations[index].Kind == AttestationInstall {
					v.Attestations[index].Digest = digestForPreparation('f')
				}
			}
		}},
		{"restart revision is not digest-bound", func(v *VerifiedPreparationV1) {
			v.Snapshot.Scope.RestartOperationRevision++
			v.SnapshotDigest, _ = SnapshotDigest(v.Snapshot)
		}},
		{"cost amount is not digest-bound", func(v *VerifiedPreparationV1) {
			v.Snapshot.Scope.CostAlertAmountMinor++
			v.SnapshotDigest, _ = SnapshotDigest(v.Snapshot)
		}},
		{"unknown attestation kind", func(v *VerifiedPreparationV1) {
			v.Attestations[0].Kind = AttestationKind("worker_success")
			v.Attestations = SortVerifiedAttestations(v.Attestations)
		}},
		{"restart observed before install", func(v *VerifiedPreparationV1) {
			setPreparationObservation(v.Attestations, AttestationRestart, v.CreatedAt.Add(-9*time.Minute))
		}},
		{"service readiness observed before restore", func(v *VerifiedPreparationV1) {
			setPreparationObservation(v.Attestations, AttestationServiceReadiness, v.CreatedAt.Add(-6*time.Minute))
			v.Snapshot.Scope.HealthObservedAt = v.CreatedAt.Add(-6 * time.Minute)
			v.SnapshotDigest, _ = SnapshotDigest(v.Snapshot)
		}},
		{"stack observation before restore", func(v *VerifiedPreparationV1) {
			setPreparationObservation(v.Attestations, AttestationStackObservation, v.CreatedAt.Add(-6*time.Minute))
		}},
		{"future observation", func(v *VerifiedPreparationV1) { v.Attestations[0].ObservedAt = v.CreatedAt.Add(time.Second) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := value
			changed.Attestations = append([]VerifiedAttestationV1(nil), value.Attestations...)
			test.mutate(&changed)
			if err := changed.Validate(); err != ErrInvalid {
				t.Fatalf("error=%v, want ErrInvalid", err)
			}
		})
	}
}

func TestVerifiedPreparationSnapshotForAcceptanceReturnsIndependentCopy(t *testing.T) {
	value := verifiedPreparationFixture(t)
	originalAcceptanceID := value.Snapshot.Scope.AcceptanceID
	originalResourceID := value.Snapshot.Scope.Resources[0].ResourceID
	originalSnapshotID := value.Snapshot.Service.Backups[0].SnapshotIDs[0]
	originalReplacementVolumeID := value.Snapshot.Service.Restores[0].ReplacementVolumeIDs[0]
	rebound, err := value.SnapshotForAcceptance(uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if rebound.Scope.AcceptanceID == originalAcceptanceID || value.Snapshot.Scope.AcceptanceID != originalAcceptanceID {
		t.Fatal("acceptance ID was not rebound without mutating the ledger snapshot")
	}
	rebound.Scope.Resources[0].ResourceID = uuid.NewString()
	rebound.Service.Backups[0].SnapshotIDs[0] = "snap-1123456789abcdef0"
	rebound.Service.Restores[0].ReplacementVolumeIDs[0] = "vol-2123456789abcdef0"
	if value.Snapshot.Scope.Resources[0].ResourceID != originalResourceID {
		t.Fatal("returned snapshot aliases persisted resource slices")
	}
	if value.Snapshot.Service.Backups[0].SnapshotIDs[0] != originalSnapshotID ||
		value.Snapshot.Service.Restores[0].ReplacementVolumeIDs[0] != originalReplacementVolumeID {
		t.Fatal("returned snapshot aliases persisted compatibility operation slices")
	}
	if _, err := value.SnapshotForAcceptance("not-a-uuid"); err != ErrInvalid {
		t.Fatalf("invalid acceptance ID error=%v", err)
	}
}

func verifiedPreparationFixture(t *testing.T) VerifiedPreparationV1 {
	t.Helper()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	digest := digestForPreparation('a')
	scope := ScopeV1{
		SchemaVersion: ScopeSchemaV1, AgentInstanceID: uuid.NewString(), AcceptanceID: uuid.NewString(),
		ServiceID: uuid.NewString(), ServiceRevision: 1, OwnerID: "owner-preparation", DeploymentID: uuid.NewString(),
		DeploymentRevision: 7, ConnectionID: uuid.NewString(), ConnectionRevision: 2, PlanID: uuid.NewString(),
		PlanRevision: 3, PlanHash: digest, RecipeID: "recipe", RecipeDigest: digest, RecipeRevision: 4,
		RecipeMaturity: "awaiting_management_acceptance", InstalledManifestDigest: digest, ArtifactDigest: digest,
		ReadinessSemanticEvidenceDigest: digest, ReadinessStackObservationDigest: digest,
		RestartOperationID: uuid.NewString(), RestartOperationRevision: 2, BackupID: uuid.NewString(), BackupRevision: 2,
		RestoreID: uuid.NewString(), RestoreRevision: 2, SourceArtifactDigests: []string{digest},
		HealthRevision: 5, HealthMonitorKind: "service", HealthStatus: "healthy",
		HealthEvidenceType: "independent_external", HealthEvidenceDigest: digest, HealthObservedAt: now.Add(-time.Minute),
		Currency: "USD", CostAlertAmountMinor: 5000,
		Health: HealthContractV1{Liveness: ProbeV1{"http", "/live"}, Readiness: ProbeV1{"http", "/ready"}, Semantic: ProbeV1{"command", "semantic"}},
		Lifecycle: LifecycleV1{Start: "start", Stop: "stop", Maintenance: "maintenance", Restart: "restart", Backup: "backup",
			Restore: "restore", Upgrade: "upgrade", Rollback: "rollback", Destroy: "destroy"},
		VolumeSlots: []VolumeSlotV1{{SlotID: "data", VolumeRef: "volume://data"}}, DataSlots: []DataSlotV1{},
		SecretSlots: []SecretSlotV1{}, Resources: []ResourceV1{
			{ResourceID: "11111111-1111-4111-8111-111111111111", Type: "ec2", Revision: 2, ProviderID: "i-0123456789abcdef0", TagDigest: digest},
			{ResourceID: "22222222-2222-4222-8222-222222222222", Type: "ebs", Revision: 2, ProviderID: "vol-0123456789abcdef0", TagDigest: digest},
			{ResourceID: "33333333-3333-4333-8333-333333333333", Type: "eni", Revision: 2, ProviderID: "eni-0123456789abcdef0", TagDigest: digest},
			{ResourceID: "44444444-4444-4444-8444-444444444444", Type: "snapshot", Revision: 2, ProviderID: "snap-0123456789abcdef0", TagDigest: digest},
		},
		DestroyInstanceID: "i-0123456789abcdef0", DestroyVolumeIDs: []string{"vol-0123456789abcdef0"}, DestroyNetworkInterfaceIDs: []string{"eni-0123456789abcdef0"},
		AcceptancePolicy: AcceptancePolicyV1,
	}
	snapshot := SnapshotV1{
		Scope:   scope,
		Service: compatibilityServiceFixture(scope, now.Add(-time.Hour).UnixMilli(), now.UnixMilli()),
		Recipe: CompatibilityRecipeV1{RecipeID: scope.RecipeID, Name: "recipe", Version: "v1", Digest: scope.RecipeDigest,
			Maturity: scope.RecipeMaturity, Revision: int64(scope.RecipeRevision), CreatedAt: now.Add(-time.Hour).UnixMilli(), UpdatedAt: now.UnixMilli()},
	}
	snapshotDigest, err := SnapshotDigest(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	restartDigest, err := OperationAttestationDigest(scope.RestartOperationID, scope.RestartOperationRevision)
	if err != nil {
		t.Fatal(err)
	}
	backupDigest, err := OperationAttestationDigest(scope.BackupID, scope.BackupRevision)
	if err != nil {
		t.Fatal(err)
	}
	restoreDigest, err := OperationAttestationDigest(scope.RestoreID, scope.RestoreRevision)
	if err != nil {
		t.Fatal(err)
	}
	costDigest, err := CostAlertAttestationDigest(scope.Currency, scope.CostAlertAmountMinor)
	if err != nil {
		t.Fatal(err)
	}
	attestations := SortVerifiedAttestations([]VerifiedAttestationV1{
		{uuid.NewString(), AttestationInstall, scope.InstalledManifestDigest, now.Add(-8 * time.Minute)},
		{uuid.NewString(), AttestationServiceReadiness, scope.HealthEvidenceDigest, scope.HealthObservedAt},
		{scope.RestartOperationID, AttestationRestart, restartDigest, now.Add(-7 * time.Minute)},
		{scope.BackupID, AttestationBackup, backupDigest, now.Add(-6 * time.Minute)},
		{scope.RestoreID, AttestationRestore, restoreDigest, now.Add(-5 * time.Minute)},
		{uuid.NewString(), AttestationStackObservation, scope.ReadinessStackObservationDigest, now.Add(-4 * time.Minute)},
		{uuid.NewString(), AttestationCostAlert, costDigest, now.Add(-3 * time.Minute)},
	})
	return VerifiedPreparationV1{SchemaVersion: VerifiedPreparationSchemaV1, PreparationID: uuid.NewString(),
		AgentInstanceID: scope.AgentInstanceID, OwnerID: scope.OwnerID, DeploymentID: scope.DeploymentID,
		ExpectedDeploymentRevision: scope.DeploymentRevision, Snapshot: snapshot, SnapshotDigest: snapshotDigest,
		Attestations: attestations, CreatedAt: now}
}

func setPreparationObservation(values []VerifiedAttestationV1, kind AttestationKind, observedAt time.Time) {
	for index := range values {
		if values[index].Kind == kind {
			values[index].ObservedAt = observedAt
		}
	}
}

func digestForPreparation(value byte) string { return "sha256:" + strings.Repeat(string(value), 64) }
