package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/managed"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/google/uuid"
)

func TestVerifiedPreparationPostgresExactReplayRevisionGuardAndOwnerScope(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	taskID, stepID := createWorkerTask(t, store)
	value := postgresVerifiedPreparationFixture(t, instanceID, now)
	if _, err := pool.Exec(ctx, `INSERT INTO worker_deployments
		(deployment_id,agent_instance_id,owner_id,task_id,step_id,control_plane_endpoint,recipe_bundle_ref,recipe_bundle_sha256,
		 execution_bundle_ref,execution_bundle_sha256,execution_timeout_seconds,worker_id,state,outcome,artifact_prefix,checkpoint_prefix,
		 evidence_prefix,log_prefix,enrollment_digest,enrollment_expires_at,session_digest,enrollment_consumed_at,revision,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,'grpcs://agent.example:8443','s3://bucket/recipe',$6,'s3://bucket/execution',$7,300,$8,
		 'finished','succeeded','s3://bucket/artifacts/','s3://bucket/checkpoints/','s3://bucket/evidence/',
		 'cloudwatch://managed/logs',$9,$10,$11,$12,$13,$14,$14)`,
		value.DeploymentID, instanceID, value.OwnerID, taskID, stepID, bytes.Repeat([]byte{1}, 32),
		bytes.Repeat([]byte{2}, 32), uuid.NewString(), bytes.Repeat([]byte{3}, 32), now.Add(time.Hour),
		bytes.Repeat([]byte{4}, 32), now, value.ExpectedDeploymentRevision, now); err != nil {
		t.Fatal(err)
	}
	mutation := managed.Mutation{
		ClientID: "message-server", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString(),
		RequestHash: postgresPreparationDigest('f'),
	}
	created, err := store.CreateVerifiedPreparation(ctx, mutation, value)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := store.CreateVerifiedPreparation(ctx, mutation, value); err != nil || replay.PreparationID != created.PreparationID {
		t.Fatalf("exact replay=%+v error=%v", replay, err)
	}
	changed := value
	changed.Attestations = append([]managed.VerifiedAttestationV1(nil), value.Attestations...)
	changed.Snapshot.Scope.CostAlertAmountMinor++
	changed.SnapshotDigest, err = managed.SnapshotDigest(changed.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	changedCostDigest, err := managed.CostAlertAttestationDigest(
		changed.Snapshot.Scope.Currency, changed.Snapshot.Scope.CostAlertAmountMinor,
	)
	if err != nil {
		t.Fatal(err)
	}
	setPostgresPreparationDigest(changed.Attestations, managed.AttestationCostAlert, changedCostDigest)
	if _, err := store.CreateVerifiedPreparation(ctx, mutation, changed); !errors.Is(err, managed.ErrRevisionConflict) {
		t.Fatalf("same idempotency key accepted a changed snapshot: %v", err)
	}
	otherMutation := mutation
	otherMutation.IdempotencyKey = uuid.NewString()
	otherMutation.RequestHash = postgresPreparationDigest('9')
	if _, err := store.CreateVerifiedPreparation(ctx, otherMutation, changed); !errors.Is(err, managed.ErrRevisionConflict) {
		t.Fatalf("deployment revision was overwritten: %v", err)
	}
	next := value
	next.PreparationID = uuid.NewString()
	next.ExpectedDeploymentRevision++
	next.Snapshot.Scope.DeploymentRevision++
	next.SnapshotDigest, err = managed.SnapshotDigest(next.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE worker_deployments SET revision=$1,updated_at=$2 WHERE deployment_id=$3`,
		next.ExpectedDeploymentRevision, now.Add(time.Second), next.DeploymentID); err != nil {
		t.Fatal(err)
	}
	nextMutation := mutation
	nextMutation.IdempotencyKey = uuid.NewString()
	nextMutation.RequestHash = postgresPreparationDigest('8')
	if _, err := store.CreateVerifiedPreparation(ctx, nextMutation, next); err != nil {
		t.Fatal(err)
	}
	latest, err := store.GetLatestVerifiedPreparation(ctx, value.OwnerID, value.DeploymentID)
	if err != nil || latest.PreparationID != next.PreparationID {
		t.Fatalf("latest preparation=%+v error=%v", latest, err)
	}
	if _, err := store.GetLatestVerifiedPreparation(ctx, "other-owner", value.DeploymentID); !errors.Is(err, managed.ErrNotFound) {
		t.Fatalf("cross-owner latest read error=%v", err)
	}
	restarted, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	read, err := restarted.GetVerifiedPreparation(ctx, value.OwnerID, value.PreparationID)
	if err != nil || read.SnapshotDigest != value.SnapshotDigest {
		t.Fatalf("restart read=%+v error=%v", read, err)
	}
	if _, err := restarted.GetVerifiedPreparation(ctx, "other-owner", value.PreparationID); !errors.Is(err, managed.ErrNotFound) {
		t.Fatalf("cross-owner read error=%v", err)
	}
}

func postgresVerifiedPreparationFixture(t *testing.T, instanceID string, now time.Time) managed.VerifiedPreparationV1 {
	t.Helper()
	digest := postgresPreparationDigest('a')
	scope := managed.ScopeV1{
		SchemaVersion: managed.ScopeSchemaV1, AgentInstanceID: instanceID, AcceptanceID: uuid.NewString(),
		ServiceID: uuid.NewString(), ServiceRevision: 1, OwnerID: "owner-worker-store", DeploymentID: uuid.NewString(),
		DeploymentRevision: 7, ConnectionID: uuid.NewString(), ConnectionRevision: 2, PlanID: uuid.NewString(),
		PlanRevision: 3, PlanHash: digest, RecipeID: "recipe", RecipeDigest: digest, RecipeRevision: 4,
		RecipeMaturity: "awaiting_management_acceptance", InstalledManifestDigest: digest, ArtifactDigest: digest,
		ReadinessSemanticEvidenceDigest: digest, ReadinessStackObservationDigest: digest,
		RestartOperationID: uuid.NewString(), RestartOperationRevision: 2, BackupID: uuid.NewString(), BackupRevision: 2,
		RestoreID: uuid.NewString(), RestoreRevision: 2, SourceArtifactDigests: []string{digest},
		HealthRevision: 5, HealthMonitorKind: "service", HealthStatus: "healthy",
		HealthEvidenceType: "independent_external", HealthEvidenceDigest: digest, HealthObservedAt: now.Add(-time.Minute),
		Currency: "USD", CostAlertAmountMinor: 5000,
		Health: managed.HealthContractV1{
			Liveness:  managed.ProbeV1{Kind: "http", Target: "/live"},
			Readiness: managed.ProbeV1{Kind: "http", Target: "/ready"},
			Semantic:  managed.ProbeV1{Kind: "command", Target: "semantic"},
		},
		Lifecycle: managed.LifecycleV1{
			Start: "start", Stop: "stop", Maintenance: "maintenance", Restart: "restart", Backup: "backup",
			Restore: "restore", Upgrade: "upgrade", Rollback: "rollback", Destroy: "destroy",
		},
		VolumeSlots: []managed.VolumeSlotV1{{SlotID: "data", VolumeRef: "volume://data"}},
		DataSlots:   []managed.DataSlotV1{}, SecretSlots: []managed.SecretSlotV1{},
		Resources: []managed.ResourceV1{
			{ResourceID: "11111111-1111-4111-8111-111111111111", Type: "ec2", Revision: 2, ProviderID: "i-0123456789abcdef0", TagDigest: digest},
			{ResourceID: "22222222-2222-4222-8222-222222222222", Type: "ebs", Revision: 2, ProviderID: "vol-0123456789abcdef0", TagDigest: digest},
			{ResourceID: "33333333-3333-4333-8333-333333333333", Type: "eni", Revision: 2, ProviderID: "eni-0123456789abcdef0", TagDigest: digest},
			{ResourceID: "44444444-4444-4444-8444-444444444444", Type: "snapshot", Revision: 2, ProviderID: "snap-0123456789abcdef0", TagDigest: digest},
		},
		DestroyInstanceID: "i-0123456789abcdef0", DestroyVolumeIDs: []string{"vol-0123456789abcdef0"},
		DestroyNetworkInterfaceIDs: []string{"eni-0123456789abcdef0"}, AcceptancePolicy: managed.AcceptancePolicyV1,
	}
	snapshot := managed.SnapshotV1{
		Scope:   scope,
		Service: managedCompatibilityServiceFixture(scope, now.Add(-time.Hour).UnixMilli(), now.UnixMilli()),
		Recipe: managed.CompatibilityRecipeV1{
			RecipeID: scope.RecipeID, Name: "recipe", Version: "v1", Digest: scope.RecipeDigest,
			Maturity: scope.RecipeMaturity, Revision: 4, CreatedAt: now.Add(-time.Hour).UnixMilli(), UpdatedAt: now.UnixMilli(),
		},
	}
	snapshotDigest, err := managed.SnapshotDigest(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	attestations := managed.SortVerifiedAttestations([]managed.VerifiedAttestationV1{
		{AttestationID: uuid.NewString(), Kind: managed.AttestationInstall, Digest: scope.InstalledManifestDigest, ObservedAt: now.Add(-8 * time.Minute)},
		{AttestationID: uuid.NewString(), Kind: managed.AttestationServiceReadiness, Digest: scope.HealthEvidenceDigest, ObservedAt: scope.HealthObservedAt},
		{AttestationID: scope.RestartOperationID, Kind: managed.AttestationRestart, Digest: mustPostgresOperationDigest(t, scope.RestartOperationID, scope.RestartOperationRevision), ObservedAt: now.Add(-7 * time.Minute)},
		{AttestationID: scope.BackupID, Kind: managed.AttestationBackup, Digest: mustPostgresOperationDigest(t, scope.BackupID, scope.BackupRevision), ObservedAt: now.Add(-6 * time.Minute)},
		{AttestationID: scope.RestoreID, Kind: managed.AttestationRestore, Digest: mustPostgresOperationDigest(t, scope.RestoreID, scope.RestoreRevision), ObservedAt: now.Add(-5 * time.Minute)},
		{AttestationID: uuid.NewString(), Kind: managed.AttestationStackObservation, Digest: scope.ReadinessStackObservationDigest, ObservedAt: now.Add(-4 * time.Minute)},
		{AttestationID: uuid.NewString(), Kind: managed.AttestationCostAlert, Digest: mustPostgresCostDigest(t, scope.Currency, scope.CostAlertAmountMinor), ObservedAt: now.Add(-3 * time.Minute)},
	})
	return managed.VerifiedPreparationV1{
		SchemaVersion: managed.VerifiedPreparationSchemaV1, PreparationID: uuid.NewString(),
		AgentInstanceID: instanceID, OwnerID: scope.OwnerID, DeploymentID: scope.DeploymentID,
		ExpectedDeploymentRevision: scope.DeploymentRevision, Snapshot: snapshot, SnapshotDigest: snapshotDigest,
		Attestations: attestations, CreatedAt: now,
	}
}

func postgresPreparationDigest(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}

func mustPostgresOperationDigest(t *testing.T, operationID string, revision uint64) string {
	t.Helper()
	digest, err := managed.OperationAttestationDigest(operationID, revision)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func mustPostgresCostDigest(t *testing.T, currency string, amountMinor int64) string {
	t.Helper()
	digest, err := managed.CostAlertAttestationDigest(currency, amountMinor)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func setPostgresPreparationDigest(values []managed.VerifiedAttestationV1, kind managed.AttestationKind, digest string) {
	for index := range values {
		if values[index].Kind == kind {
			values[index].Digest = digest
		}
	}
}
