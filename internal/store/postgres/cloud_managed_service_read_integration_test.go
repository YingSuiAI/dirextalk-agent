package postgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/managed"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCloudManagedServiceReadPostgresOwnerIsolationPaginationAndRedaction(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	taskID, stepID := createWorkerTask(t, store)

	first := seedManagedServiceReadFact(t, ctx, pool, instanceID, taskID, stepID, "owner-managed-a", now, "active", "succeeded")
	second := seedManagedServiceReadFact(t, ctx, pool, instanceID, taskID, stepID, "owner-managed-a", now.Add(time.Second), "degraded", "succeeded")
	foreign := seedManagedServiceReadFact(t, ctx, pool, instanceID, taskID, stepID, "owner-managed-b", now.Add(2*time.Second), "active", "succeeded")
	pending := seedManagedServiceReadFact(t, ctx, pool, instanceID, taskID, stepID, "owner-managed-a", now.Add(3*time.Second), "active", "running")
	destroyed := seedManagedServiceReadFact(t, ctx, pool, instanceID, taskID, stepID, "owner-managed-a", now.Add(4*time.Second), "destroyed", "succeeded")
	misbound := seedManagedServiceReadFact(t, ctx, pool, instanceID, taskID, stepID, "owner-managed-a", now.Add(5*time.Second), "active", "succeeded")
	if _, err := pool.Exec(ctx, `UPDATE managed_services
		SET contract_json=jsonb_set(contract_json, '{AcceptanceApprovalID}', to_jsonb($2::text))
		WHERE service_id=$1`, misbound.serviceID, foreign.operationID); err != nil {
		t.Fatal(err)
	}

	statuses, err := postgres.NewCloudStatusStore(store)
	if err != nil {
		t.Fatal(err)
	}
	got, err := statuses.GetManagedService(ctx, "owner-managed-a", first.serviceID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ServiceID != first.serviceID || got.DeploymentID != first.deploymentID || got.ServiceStatus != "active" ||
		got.Revision != first.revision || !got.CreatedAt.Equal(first.createdAt) || !got.UpdatedAt.Equal(first.updatedAt) {
		t.Fatalf("managed service facts=%+v", got)
	}
	if len(got.Backups) != 1 || len(got.Restores) != 1 || got.Name != "Managed service" || got.IntegrationStatus != "not_requested" {
		t.Fatalf("managed compatibility snapshot=%+v", got)
	}
	serialized := fmt.Sprintf("%+v", got)
	for _, forbidden := range []string{"i-0123456789abcdef0", "vol-0123456789abcdef0", "snap-0123456789abcdef0", "eni-0123456789abcdef0", "secret://model", "runbook://"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("managed compatibility projection leaked %q: %s", forbidden, serialized)
		}
	}
	if _, err := statuses.GetManagedService(ctx, "owner-managed-b", first.serviceID); !errors.Is(err, cloudstatus.ErrNotFound) {
		t.Fatalf("cross-owner managed read error=%v", err)
	}
	if _, err := statuses.GetManagedService(ctx, "owner-managed-a", strings.ToUpper(first.serviceID)); !errors.Is(err, cloudstatus.ErrInvalid) {
		t.Fatalf("non-canonical service ID error=%v", err)
	}
	if _, err := statuses.GetManagedService(ctx, "owner-managed-a", pending.serviceID); !errors.Is(err, cloudstatus.ErrNotFound) {
		t.Fatalf("non-succeeded acceptance became visible: %v", err)
	}
	if _, err := statuses.GetManagedService(ctx, "owner-managed-a", destroyed.serviceID); !errors.Is(err, cloudstatus.ErrNotFound) {
		t.Fatalf("destroyed service became visible: %v", err)
	}
	if _, err := statuses.GetManagedService(ctx, "owner-managed-a", misbound.serviceID); !errors.Is(err, cloudstatus.ErrNotFound) {
		t.Fatalf("misbound acceptance operation became visible: %v", err)
	}

	firstPage, err := statuses.ListManagedServices(ctx, cloudstatus.ListQuery{OwnerID: "owner-managed-a", PageSize: 1})
	if err != nil || len(firstPage.Services) != 1 || firstPage.NextPageToken == "" {
		t.Fatalf("first managed service page=%+v err=%v", firstPage, err)
	}
	secondPage, err := statuses.ListManagedServices(ctx, cloudstatus.ListQuery{OwnerID: "owner-managed-a", PageSize: 1, PageToken: firstPage.NextPageToken})
	if err != nil || len(secondPage.Services) != 1 || secondPage.NextPageToken != "" || secondPage.Services[0].ServiceID == firstPage.Services[0].ServiceID {
		t.Fatalf("second managed service page=%+v err=%v", secondPage, err)
	}
	seen := map[string]bool{firstPage.Services[0].ServiceID: true, secondPage.Services[0].ServiceID: true}
	if !seen[first.serviceID] || !seen[second.serviceID] || seen[foreign.serviceID] || seen[pending.serviceID] || seen[destroyed.serviceID] || seen[misbound.serviceID] {
		t.Fatalf("managed pagination visibility=%v", seen)
	}
	if _, err := statuses.ListManagedServices(ctx, cloudstatus.ListQuery{
		OwnerID: "owner-managed-b", PageSize: 1, PageToken: firstPage.NextPageToken,
	}); !errors.Is(err, cloudstatus.ErrInvalid) {
		t.Fatalf("foreign owner accepted managed cursor: %v", err)
	}
}

type managedServiceReadFixture struct {
	serviceID    string
	deploymentID string
	operationID  string
	revision     int64
	createdAt    time.Time
	updatedAt    time.Time
}

func seedManagedServiceReadFact(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	instanceID, taskID, stepID, ownerID string,
	createdAt time.Time,
	serviceState, operationStatus string,
) managedServiceReadFixture {
	t.Helper()
	connectionID, quoteID, planID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	deploymentID, operationID := uuid.NewString(), uuid.NewString()
	serviceID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(deploymentID)).String()
	keyID := "managed-read-device-" + uuid.NewString()
	accountID := fmt.Sprintf("%012d", createdAt.UnixNano()%1_000_000_000_000)
	digest := "sha256:" + strings.Repeat("a", 64)
	if _, err := pool.Exec(ctx, `INSERT INTO cloud_connections
		(connection_id,agent_instance_id,owner_id,account_id,region,control_role_arn,foundation_stack_id,credential_generation,status,revision)
		VALUES($1,$2,$3,$4,'us-east-1','arn:aws:iam::123456789012:role/control',
		'arn:aws:cloudformation:us-east-1:123456789012:stack/foundation/00000000-0000-4000-8000-000000000000',1,'active',1)`,
		connectionID, instanceID, ownerID, accountID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO cloud_quotes
		(quote_id,agent_instance_id,owner_id,connection_id,quote_digest,quote_json,quote_cbor,revision,quoted_at,valid_until)
		VALUES($1,$2,$3,$4,$5,'{}',$6,1,$7,$7+interval '15 minutes')`,
		quoteID, instanceID, ownerID, connectionID, digest, []byte{1}, createdAt); err != nil {
		t.Fatal(err)
	}
	planJSON, err := json.Marshal(map[string]any{"plan_id": planID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO cloud_plans
		(plan_id,agent_instance_id,owner_id,connection_id,quote_id,quote_digest,quote_scope_digest,plan_hash,status,plan_json,plan_cbor,revision)
		VALUES($1,$2,$3,$4,$5,$6,$6,$6,'approved',$7,$8,1)`,
		planID, instanceID, ownerID, connectionID, quoteID, digest, planJSON, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO cloud_approval_devices
		(device_id,key_id,agent_instance_id,owner_id,public_key,status,revision,not_before,expires_at)
		VALUES($1,$2,$3,$4,$5,'active',1,$6,$7)`,
		uuid.NewString(), keyID, instanceID, ownerID, bytes.Repeat([]byte{0x4a}, 32), createdAt.Add(-time.Hour), createdAt.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO worker_deployments
		(deployment_id,agent_instance_id,owner_id,task_id,step_id,control_plane_endpoint,recipe_bundle_ref,recipe_bundle_sha256,
		 execution_bundle_ref,execution_bundle_sha256,execution_timeout_seconds,worker_id,state,outcome,artifact_prefix,checkpoint_prefix,
		 evidence_prefix,log_prefix,enrollment_digest,enrollment_expires_at,session_digest,enrollment_consumed_at,revision,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,'grpcs://agent.example:8443','s3://bucket/recipe',$6,'s3://bucket/execution',$7,300,$8,
		 'finished','succeeded','s3://bucket/artifacts/','s3://bucket/checkpoints/','s3://bucket/evidence/',
		 'cloudwatch://managed/read',$9,$10,$11,$12,1,$13,$13)`,
		deploymentID, instanceID, ownerID, taskID, stepID, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32),
		uuid.NewString(), bytes.Repeat([]byte{3}, 32), createdAt.Add(time.Hour), bytes.Repeat([]byte{4}, 32), createdAt, createdAt); err != nil {
		t.Fatal(err)
	}
	scope := managed.ScopeV1{
		SchemaVersion: managed.ScopeSchemaV1, AgentInstanceID: instanceID, AcceptanceID: operationID,
		ServiceID: serviceID, ServiceRevision: 1, OwnerID: ownerID, DeploymentID: deploymentID, DeploymentRevision: 1,
		ConnectionID: connectionID, ConnectionRevision: 1, PlanID: planID, PlanRevision: 1, PlanHash: digest,
		RecipeID: "managed-recipe-v1", RecipeDigest: digest, RecipeRevision: 1, RecipeMaturity: "awaiting_management_acceptance",
		InstalledManifestDigest: digest, ArtifactDigest: digest, ReadinessSemanticEvidenceDigest: digest,
		ReadinessStackObservationDigest: digest, RestartOperationID: uuid.NewString(), RestartOperationRevision: 1,
		BackupID: uuid.NewString(), BackupRevision: 1, RestoreID: uuid.NewString(), RestoreRevision: 1,
		SourceArtifactDigests: []string{digest}, HealthRevision: 1, HealthMonitorKind: "service", HealthStatus: "healthy",
		HealthEvidenceType: "independent_external", HealthEvidenceDigest: digest, HealthObservedAt: createdAt.UTC(), Currency: "USD", CostAlertAmountMinor: 5000,
		Lifecycle:   managed.LifecycleV1{Start: "start", Stop: "stop", Maintenance: "maintenance", Restart: "restart", Backup: "backup", Restore: "restore", Upgrade: "upgrade", Rollback: "rollback", Destroy: "destroy"},
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
		DestroyInstanceID: "i-0123456789abcdef0", DestroyVolumeIDs: []string{"vol-0123456789abcdef0"}, DestroyNetworkInterfaceIDs: []string{"eni-0123456789abcdef0"},
		AcceptancePolicy: managed.AcceptancePolicyV1,
	}
	challenge := managed.ChallengeV1{
		SchemaVersion: managed.ChallengeSchemaV1, ChallengeID: uuid.NewString(), ApprovalID: operationID, SignerKeyID: keyID,
		Scope: scope, Service: managedCompatibilityServiceFixture(scope, createdAt.UnixMilli(), createdAt.UnixMilli()),
		Recipe:   managed.CompatibilityRecipeV1{RecipeID: scope.RecipeID, Name: "Managed recipe", Version: "v1", Digest: digest, Maturity: scope.RecipeMaturity, Revision: 1, CreatedAt: createdAt.UnixMilli(), UpdatedAt: createdAt.UnixMilli()},
		IssuedAt: createdAt.Add(time.Second).UTC(), ExpiresAt: createdAt.Add(2 * time.Minute).UTC(),
	}
	challenge.ScopeDigest, err = managed.SigningPayloadDigest(challenge)
	if err != nil {
		t.Fatal(err)
	}
	challengeJSON, err := json.Marshal(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO cloud_managed_acceptance_operations
		(operation_id,agent_instance_id,owner_id,deployment_id,plan_id,plan_revision,connection_id,signer_key_id,
		 challenge_id,approval_id,challenge_json,signature,status,revision,prepare_client_id,prepare_credential_id,
		 prepare_idempotency_key,prepare_request_hash,approve_client_id,approve_credential_id,approve_idempotency_key,
		 approve_request_hash,approved_at,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,$1,$9,$10,$11,3,'managed-read', $12, $13, $14,
		 'managed-read', $15, $16, $17, $18, $18, $19)`,
		operationID, instanceID, ownerID, deploymentID, planID, connectionID, keyID, challenge.ChallengeID, challengeJSON,
		bytes.Repeat([]byte{0x31}, 64), operationStatus, uuid.NewString(), uuid.NewString(), digest, uuid.NewString(), uuid.NewString(), digest,
		createdAt, createdAt.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	contractJSON, err := json.Marshal(resource.ManagedContractV1{
		DeploymentID: deploymentID, OwnerID: ownerID, AcceptanceApprovalID: operationID, Currency: "USD", CostAlertAmountMinor: 5000,
		MonitorRef: "health://service/managed", MaintenanceRef: "maintenance", RestartRef: "restart", BackupRef: "backup", RestoreRef: "restore",
		UpgradeRef: "upgrade", RollbackRef: "rollback", DestroyRef: "destroy", AcceptedAt: createdAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	managedCreatedAt, managedUpdatedAt := createdAt.Add(3*time.Second), createdAt.Add(4*time.Second)
	const revision int64 = 7
	if _, err := pool.Exec(ctx, `INSERT INTO managed_services
		(service_id,deployment_id,agent_instance_id,owner_id,contract_json,state,revision,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		serviceID, deploymentID, instanceID, ownerID, contractJSON, serviceState, revision, managedCreatedAt, managedUpdatedAt); err != nil {
		t.Fatal(err)
	}
	return managedServiceReadFixture{serviceID: serviceID, deploymentID: deploymentID, operationID: operationID, revision: revision, createdAt: managedCreatedAt, updatedAt: managedUpdatedAt}
}
