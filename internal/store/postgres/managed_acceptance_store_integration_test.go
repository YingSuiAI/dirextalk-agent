package postgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/managed"
	"github.com/google/uuid"
)

func TestManagedAcceptancePostgresIdempotencyTransitionsAndRestart(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	owner := "owner-managed-store"
	taskID, stepID := createWorkerTask(t, store)
	deploymentID, connectionID, quoteID, planID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	digest := "sha256:" + strings.Repeat("a", 64)
	keyID := "managed-device-" + uuid.NewString()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO cloud_connections
		(connection_id,agent_instance_id,owner_id,account_id,region,control_role_arn,foundation_stack_id,credential_generation,status,revision)
		VALUES($1,$2,$3,'123456789012','us-east-1','arn:aws:iam::123456789012:role/control','arn:aws:cloudformation:us-east-1:123456789012:stack/foundation/00000000-0000-4000-8000-000000000000',1,'active',1)`,
		connectionID, instanceID, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO cloud_quotes
		(quote_id,agent_instance_id,owner_id,connection_id,quote_digest,quote_json,quote_cbor,revision,quoted_at,valid_until)
		VALUES($1,$2,$3,$4,$5,'{}',$6,1,$7,$8)`,
		quoteID, instanceID, owner, connectionID, digest, []byte{1}, now, now.Add(15*time.Minute)); err != nil {
		t.Fatal(err)
	}
	planJSON, _ := json.Marshal(map[string]any{"plan_id": planID})
	if _, err := pool.Exec(ctx, `INSERT INTO cloud_plans
		(plan_id,agent_instance_id,owner_id,connection_id,quote_id,quote_digest,quote_scope_digest,plan_hash,status,plan_json,plan_cbor,revision)
		VALUES($1,$2,$3,$4,$5,$6,$6,$6,'approved',$7,$8,1)`,
		planID, instanceID, owner, connectionID, quoteID, digest, planJSON, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO cloud_approval_devices
		(device_id,key_id,agent_instance_id,owner_id,public_key,status,revision,not_before,expires_at)
		VALUES($1,$2,$3,$4,$5,'active',1,$6,$7)`,
		uuid.NewString(), keyID, instanceID, owner, publicKey, now.Add(-time.Hour), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO worker_deployments
		(deployment_id,agent_instance_id,owner_id,task_id,step_id,control_plane_endpoint,recipe_bundle_ref,recipe_bundle_sha256,
		 execution_bundle_ref,execution_bundle_sha256,execution_timeout_seconds,worker_id,state,outcome,artifact_prefix,checkpoint_prefix,
		 evidence_prefix,log_prefix,enrollment_digest,enrollment_expires_at,session_digest,enrollment_consumed_at,revision,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,'grpcs://agent.example:8443','s3://bucket/recipe',$6,'s3://bucket/execution',$7,300,$8,
		 'finished','succeeded','s3://bucket/artifacts/','s3://bucket/checkpoints/','s3://bucket/evidence/',
		 'cloudwatch://managed/logs',$9,$10,$11,$12,1,$13,$13)`,
		deploymentID, instanceID, owner, taskID, stepID, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32),
		uuid.NewString(), bytes.Repeat([]byte{3}, 32), now.Add(time.Hour), bytes.Repeat([]byte{4}, 32), now, now); err != nil {
		t.Fatal(err)
	}
	approvalID := uuid.NewString()
	scope := managed.ScopeV1{
		SchemaVersion: managed.ScopeSchemaV1, AgentInstanceID: instanceID, AcceptanceID: approvalID,
		ServiceID: uuid.NewString(), ServiceRevision: 1, OwnerID: owner, DeploymentID: deploymentID, DeploymentRevision: 1,
		ConnectionID: connectionID, ConnectionRevision: 1, PlanID: planID, PlanRevision: 1, PlanHash: digest,
		RecipeID: "recipe", RecipeDigest: digest, RecipeRevision: 1, RecipeMaturity: "awaiting_management_acceptance",
		InstalledManifestDigest: digest, ArtifactDigest: digest, ReadinessSemanticEvidenceDigest: digest,
		ReadinessStackObservationDigest: digest, RestartOperationID: uuid.NewString(), RestartOperationRevision: 1,
		BackupID: uuid.NewString(), BackupRevision: 1, RestoreID: uuid.NewString(), RestoreRevision: 1,
		SourceArtifactDigests: []string{digest}, HealthRevision: 1, HealthMonitorKind: "service", HealthStatus: "healthy", HealthEvidenceType: "independent_external",
		HealthEvidenceDigest: digest, HealthObservedAt: now, Currency: "USD", CostAlertAmountMinor: 5000,
		Lifecycle: managed.LifecycleV1{Start: "start", Stop: "stop", Maintenance: "maintenance", Restart: "restart",
			Backup: "backup", Restore: "restore", Upgrade: "upgrade", Rollback: "rollback", Destroy: "destroy"},
		Health:      managed.HealthContractV1{Liveness: managed.ProbeV1{Kind: "http", Target: "/live"}, Readiness: managed.ProbeV1{Kind: "http", Target: "/ready"}, Semantic: managed.ProbeV1{Kind: "command", Target: "semantic"}},
		VolumeSlots: []managed.VolumeSlotV1{{SlotID: "data", VolumeRef: "volume://data"}},
		DataSlots:   []managed.DataSlotV1{{SlotID: "knowledge", DataRef: "data://knowledge", ReadOnly: true}},
		SecretSlots: []managed.SecretSlotV1{{SlotID: "model", SecretRef: "secret://model"}},
		Resources: []managed.ResourceV1{
			{ResourceID: "11111111-1111-4111-8111-111111111111", Type: "ec2", Revision: 1, ProviderID: "i-0123456789abcdef0", TagDigest: digest},
			{ResourceID: "22222222-2222-4222-8222-222222222222", Type: "ebs", Revision: 1, ProviderID: "vol-0123456789abcdef0", TagDigest: digest},
			{ResourceID: "33333333-3333-4333-8333-333333333333", Type: "eni", Revision: 1, ProviderID: "eni-0123456789abcdef0", TagDigest: digest},
			{ResourceID: "44444444-4444-4444-8444-444444444444", Type: "snapshot", Revision: 1, ProviderID: "snap-0123456789abcdef0", TagDigest: digest},
		},
		DestroyInstanceID: "i-0123456789abcdef0", DestroyVolumeIDs: []string{"vol-0123456789abcdef0"},
		DestroyNetworkInterfaceIDs: []string{"eni-0123456789abcdef0"}, AcceptancePolicy: managed.AcceptancePolicyV1,
	}
	challenge := managed.ChallengeV1{SchemaVersion: managed.ChallengeSchemaV1, ChallengeID: uuid.NewString(),
		ApprovalID: approvalID, SignerKeyID: keyID, Scope: scope,
		Service: managedCompatibilityServiceFixture(scope, now.UnixMilli(), now.UnixMilli()),
		Recipe: managed.CompatibilityRecipeV1{RecipeID: scope.RecipeID, Name: "Managed recipe", Version: "v1", Digest: digest,
			Maturity: scope.RecipeMaturity, Revision: 1, CreatedAt: now.UnixMilli(), UpdatedAt: now.UnixMilli()},
		IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	challenge.ScopeDigest, err = managed.SigningPayloadDigest(challenge)
	if err != nil {
		t.Fatal(err)
	}
	prepare := managed.Mutation{ClientID: "message-server", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString(), RequestHash: digest}
	first, err := store.CreateManagedAcceptanceChallenge(ctx, prepare, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := store.CreateManagedAcceptanceChallenge(ctx, prepare, challenge); err != nil || replay.ChallengeID != first.ChallengeID {
		t.Fatalf("prepare replay=%+v err=%v", replay, err)
	}
	if replay, err := store.FindManagedAcceptanceChallengeReplay(ctx, prepare); err != nil || replay.ChallengeID != first.ChallengeID {
		t.Fatalf("prepare read-only replay=%+v err=%v", replay, err)
	}
	changed := challenge
	changed.Scope.CostAlertAmountMinor++
	changed.ScopeDigest, _ = managed.SigningPayloadDigest(changed)
	if replay, err := store.CreateManagedAcceptanceChallenge(ctx, prepare, changed); err != nil || replay.Scope.CostAlertAmountMinor != challenge.Scope.CostAlertAmountMinor {
		t.Fatalf("prepare replay did not return the exact original challenge: replay=%+v error=%v", replay, err)
	}
	conflictingPrepare := prepare
	conflictingPrepare.RequestHash = "sha256:" + strings.Repeat("f", 64)
	if _, err := store.CreateManagedAcceptanceChallenge(ctx, conflictingPrepare, challenge); !errors.Is(err, managed.ErrRevisionConflict) {
		t.Fatalf("conflicting prepare request error=%v", err)
	}
	if _, err := store.FindManagedAcceptanceChallengeReplay(ctx, conflictingPrepare); !errors.Is(err, managed.ErrRevisionConflict) {
		t.Fatalf("conflicting prepare read-only replay error=%v", err)
	}
	payload, _ := challenge.SigningPayload()
	signature := managed.SignatureV1{ChallengeID: challenge.ChallengeID, ApprovalID: approvalID, SignerKeyID: keyID, Signature: ed25519.Sign(privateKey, payload)}
	approve := managed.Mutation{ClientID: "message-server", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString(), RequestHash: "sha256:" + strings.Repeat("b", 64)}
	approved, err := store.ApproveManagedAcceptance(ctx, approve, signature, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := store.ApproveManagedAcceptance(ctx, approve, signature, now.Add(2*time.Second)); err != nil || replay.OperationID != approved.OperationID {
		t.Fatalf("approve replay=%+v err=%v", replay, err)
	}
	if replay, err := store.FindManagedAcceptanceApprovalReplay(ctx, approve); err != nil || replay.OperationID != approved.OperationID {
		t.Fatalf("approve read-only replay=%+v err=%v", replay, err)
	}
	conflictingApprove := approve
	conflictingApprove.RequestHash = "sha256:" + strings.Repeat("c", 64)
	if _, err := store.FindManagedAcceptanceApprovalReplay(ctx, conflictingApprove); !errors.Is(err, managed.ErrRevisionConflict) {
		t.Fatalf("conflicting approve read-only replay error=%v", err)
	}
	running, err := store.TransitionManagedAcceptance(ctx, approvalID, approved.Revision, managed.StatusRunning, "", "")
	if err != nil {
		t.Fatal(err)
	}
	failed, err := store.TransitionManagedAcceptance(ctx, approvalID, running.Revision, managed.StatusFailedTerminal,
		"accept_failed", "credential AKIAIOSFODNN7EXAMPLE was rejected")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(failed.ErrorSummary, "AKIA") || failed.Status != managed.StatusFailedTerminal {
		t.Fatalf("terminal failure was not redacted: %+v", failed)
	}
	restarted, err := store.GetManagedAcceptanceOperation(ctx, owner, approvalID)
	if err != nil || restarted.Revision != failed.Revision {
		t.Fatalf("restart read=%+v err=%v", restarted, err)
	}
	if _, err := store.GetManagedAcceptanceOperation(ctx, "other-owner", approvalID); !errors.Is(err, managed.ErrNotFound) {
		t.Fatalf("cross-owner read error=%v", err)
	}
	if _, err := store.ListExecutableManagedAcceptances(ctx, 0); !errors.Is(err, managed.ErrInvalid) {
		t.Fatalf("invalid list limit error=%v", err)
	}
}

func managedCompatibilityServiceFixture(scope managed.ScopeV1, createdAt, updatedAt int64) managed.CompatibilityServiceV1 {
	return managed.CompatibilityServiceV1{
		ServiceID: scope.ServiceID, DeploymentID: scope.DeploymentID, RecipeID: scope.RecipeID, Name: "Managed service",
		Status: "awaiting_management_acceptance", Integration: "not_requested", Revision: int64(scope.ServiceRevision),
		CreatedAt: createdAt, UpdatedAt: updatedAt,
		Backups: []managed.CompatibilityBackupV1{{
			BackupID: scope.BackupID, ServiceID: scope.ServiceID, DeploymentID: scope.DeploymentID,
			Status: "available", RetentionPolicy: "manual", SnapshotIDs: []string{"snap-0123456789abcdef0"},
			Revision: int64(scope.BackupRevision), CreatedAt: createdAt, UpdatedAt: updatedAt,
		}},
		Restores: []managed.CompatibilityRestoreV1{{
			RestoreID: scope.RestoreID, RestorePlanID: "44444444-4444-4444-8444-444444444444",
			ServiceID: scope.ServiceID, DeploymentID: scope.DeploymentID, BackupID: scope.BackupID, Status: "succeeded",
			OriginalVolumeIDs: []string{"vol-1123456789abcdef0"}, ReplacementVolumeIDs: []string{"vol-0123456789abcdef0"},
			Revision: int64(scope.RestoreRevision), CreatedAt: createdAt, UpdatedAt: updatedAt,
		}},
	}
}
