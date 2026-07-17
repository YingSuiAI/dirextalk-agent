package postgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/serviceoperation"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestManagedPreparationResourceLedgerOriginSwapAndRetire(t *testing.T) {
	fixture := seedManagedPreparationResourceLedger(t)
	ctx := context.Background()
	resourceStore, err := fixture.store.NewResourceStore()
	if err != nil {
		t.Fatal(err)
	}

	snapshot := fixture.preparationIntent(resource.TypeSnapshot, fixture.snapshotID, fixture.sourceID)
	if _, err := resourceStore.CreateIntent(ctx, snapshot); err != nil {
		t.Fatalf("create signed snapshot intent: %v", err)
	}
	fixture.activate(t, snapshot, "snap-1123456789abcdef0")
	fixture.setPhase(t, serviceoperation.PhaseRestoreCreate)
	replacement := fixture.preparationIntent(resource.TypeEBS, fixture.replacementID, fixture.snapshotID)
	if _, err := resourceStore.CreateIntent(ctx, replacement); err != nil {
		t.Fatalf("create signed replacement intent: %v", err)
	}
	fixture.activate(t, replacement, "vol-1123456789abcdef0")
	fixture.setPhase(t, serviceoperation.PhaseRestoreSwap)

	request := resource.ManagedPreparationSwapRequest{
		OperationID: fixture.operationID, OwnerID: fixture.ownerID, DeploymentID: fixture.deploymentID,
		EC2ResourceID: fixture.ec2ID, SourceResourceID: fixture.sourceID,
		SnapshotResourceID: fixture.snapshotID, ReplacementResourceID: fixture.replacementID,
		InstanceID: fixture.instanceProviderID, ReplacementVolumeID: "vol-1123456789abcdef0",
		DeviceName: "/dev/sdf", AttachmentEvidenceDigest: managedPreparationDigest("d"),
		AttachmentObservedAt: fixture.now.Add(4 * time.Minute),
	}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			record, ec2, swapErr := resourceStore.CommitManagedPreparationSwap(ctx, request, fixture.now.Add(5*time.Minute))
			if swapErr == nil && (record.Status != "swapped" || !containsResourceID(ec2.DependsOn, fixture.replacementID) || containsResourceID(ec2.DependsOn, fixture.sourceID)) {
				swapErr = errors.New("swap read-back did not contain the exact replacement dependency")
			}
			results <- swapErr
		}()
	}
	wait.Wait()
	close(results)
	for result := range results {
		if result != nil {
			t.Fatalf("concurrent exact swap replay: %v", result)
		}
	}

	if _, err := resourceStore.BeginManagedPreparationRetire(ctx, resource.ManagedPreparationRetireRequest{
		OperationID: fixture.operationID, OwnerID: fixture.ownerID, DeploymentID: fixture.deploymentID, ResourceID: fixture.sourceID,
	}, fixture.now.Add(6*time.Minute)); !errors.Is(err, resource.ErrRevisionConflict) {
		t.Fatalf("retirement before fresh semantic-health success error=%v", err)
	}
	fixture.setFinalizeAfterSemanticHealth(t)
	retire := resource.ManagedPreparationRetireRequest{
		OperationID: fixture.operationID, OwnerID: fixture.ownerID, DeploymentID: fixture.deploymentID, ResourceID: fixture.sourceID,
	}
	destroying, err := resourceStore.BeginManagedPreparationRetire(ctx, retire, fixture.now.Add(7*time.Minute))
	if err != nil || destroying.State != resource.StateDestroying || destroying.Intent.Operation != resource.MutationDestroy {
		t.Fatalf("persist retirement intent=%+v error=%v", destroying, err)
	}
	absent := resource.ReadBackEvidence{
		ProviderID: fixture.sourceProviderID, ObservedAt: fixture.now.Add(8 * time.Minute),
		TagDigest: managedPreparationDigest("e"),
	}
	retired, err := resourceStore.CompleteManagedPreparationRetire(ctx, retire, absent, fixture.now.Add(8*time.Minute))
	if err != nil || retired.State != resource.StateVerifiedDestroyed || retired.ReadBack.Exists {
		t.Fatalf("complete retirement=%+v error=%v", retired, err)
	}
	if replay, replayErr := resourceStore.BeginManagedPreparationRetire(ctx, retire, fixture.now.Add(9*time.Minute)); replayErr != nil || replay.State != resource.StateVerifiedDestroyed {
		t.Fatalf("retirement response-loss replay=%+v error=%v", replay, replayErr)
	}
	snapshotAfter, err := resourceStore.Get(ctx, fixture.snapshotID)
	if err != nil || snapshotAfter.State != resource.StateActive {
		t.Fatalf("signed snapshot was not retained: %+v error=%v", snapshotAfter, err)
	}
}

func TestManagedPreparationResourceIntentFailsClosedForTerminalOrTamperedScope(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, managedPreparationResourceFixture, *resource.ResourceV1)
	}{
		{name: "terminal operation", mutate: func(t *testing.T, fixture managedPreparationResourceFixture, _ *resource.ResourceV1) {
			if _, err := fixture.pool.Exec(context.Background(), `
				UPDATE cloud_service_operations SET status='failed_terminal',updated_at=clock_timestamp()
				WHERE operation_id=$1`, fixture.operationID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "stale deployment revision", mutate: func(t *testing.T, fixture managedPreparationResourceFixture, _ *resource.ResourceV1) {
			if _, err := fixture.pool.Exec(context.Background(), `
				UPDATE worker_deployments SET revision=2,updated_at=clock_timestamp() WHERE deployment_id=$1`,
				fixture.deploymentID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unsigned dependency", mutate: func(_ *testing.T, _ managedPreparationResourceFixture, item *resource.ResourceV1) {
			item.DependsOn = []string{uuid.NewString()}
		}},
		{name: "unknown origin", mutate: func(_ *testing.T, _ managedPreparationResourceFixture, item *resource.ResourceV1) {
			item.IntentOrigin = resource.IntentOrigin("unknown")
			item.Tags[resource.TagIntentOrigin] = "unknown"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := seedManagedPreparationResourceLedger(t)
			resourceStore, _ := fixture.store.NewResourceStore()
			item := fixture.preparationIntent(resource.TypeSnapshot, fixture.snapshotID, fixture.sourceID)
			test.mutate(t, fixture, &item)
			if _, err := resourceStore.CreateIntent(context.Background(), item); !errors.Is(err, resource.ErrInvalid) {
				t.Fatalf("%s authorized a resource intent: %v", test.name, err)
			}
		})
	}
}

type managedPreparationResourceFixture struct {
	pool               *pgxpool.Pool
	store              *postgres.Store
	instanceID         string
	ownerID            string
	taskID             string
	deploymentID       string
	connectionID       string
	planID             string
	planHash           string
	originalApprovalID string
	operationID        string
	scopeDigest        string
	ec2ID              string
	sourceID           string
	snapshotID         string
	replacementID      string
	instanceProviderID string
	sourceProviderID   string
	deadline           time.Time
	now                time.Time
}

func seedManagedPreparationResourceLedger(t *testing.T) managedPreparationResourceFixture {
	t.Helper()
	pool, store, instanceID := newPlanningTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	taskID, stepID := createWorkerTask(t, store)
	fixture := managedPreparationResourceFixture{
		pool: pool, store: store, instanceID: instanceID, ownerID: "owner-managed-preparation-ledger",
		taskID: taskID, deploymentID: uuid.NewString(), operationID: uuid.NewString(),
		instanceProviderID: "i-0123456789abcdef0", sourceProviderID: "vol-0123456789abcdef0",
		deadline: now.Add(time.Hour).Truncate(time.Second), now: now,
	}
	seedWorkerIdentityBinding(t, pool, instanceID, fixture.ownerID, taskID, fixture.deploymentID, fixture.instanceProviderID, "123456789012")
	if err := pool.QueryRow(ctx, `
		SELECT launch.connection_id::text,launch.plan_id::text,approval.plan_hash,approval.approval_id::text,
		       resources.resource_id::text
		FROM cloud_launch_operations AS launch
		JOIN cloud_approvals AS approval ON approval.approval_id=launch.approval_id
		JOIN cloud_resources AS resources ON resources.deployment_id=launch.deployment_id AND resources.resource_type='ec2'
		WHERE launch.deployment_id=$1`,
		fixture.deploymentID,
	).Scan(&fixture.connectionID, &fixture.planID, &fixture.planHash, &fixture.originalApprovalID, &fixture.ec2ID); err != nil {
		t.Fatal(err)
	}
	fixture.sourceID = uuid.NewString()
	fixture.snapshotID, fixture.replacementID, _ = serviceoperation.DeriveVolumeResourceIDs(fixture.operationID, fixture.sourceID, "data")
	if _, err := pool.Exec(ctx, `INSERT INTO worker_deployments
		(deployment_id,agent_instance_id,owner_id,task_id,step_id,control_plane_endpoint,recipe_bundle_ref,recipe_bundle_sha256,
		 execution_bundle_ref,execution_bundle_sha256,execution_timeout_seconds,state,outcome,artifact_prefix,checkpoint_prefix,
		 evidence_prefix,log_prefix,enrollment_digest,enrollment_expires_at,revision,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,'grpcs://agent.example:8443','s3://bucket/recipe',$6,'s3://bucket/execution',$7,300,
		 'finished','succeeded','s3://bucket/artifacts/','s3://bucket/checkpoints/','s3://bucket/evidence/',
		 'cloudwatch://managed-preparation/logs',$8,$9,1,$10,$10)`,
		fixture.deploymentID, instanceID, fixture.ownerID, taskID, stepID, bytes.Repeat([]byte{1}, 32),
		bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32), now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	ec2TagDigest, sourceTagDigest := managedPreparationDigest("1"), managedPreparationDigest("2")
	if _, err := pool.Exec(ctx, `
		UPDATE cloud_resources SET depends_on=ARRAY[$2::uuid],readback_exists=true,readback_provider_id=provider_id,
		       readback_observed_at=$3,readback_tag_digest=$4,destroy_deadline=$5,
		       tags=jsonb_set(tags,'{destroy_deadline}',to_jsonb($6::text)),updated_at=$3
		WHERE resource_id=$1`,
		fixture.ec2ID, fixture.sourceID, now, ec2TagDigest, fixture.deadline, fixture.deadline.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	sourceSpecDigest := managedPreparationVolumeSpecDigest(t)
	sourceTags := fixture.tags(fixture.sourceID, fixture.originalApprovalID, fixture.planHash, "", "")
	sourceTagsJSON, _ := json.Marshal(sourceTags)
	if _, err := pool.Exec(ctx, `
		INSERT INTO cloud_resources (
			resource_id,agent_instance_id,owner_id,task_id,deployment_id,resource_type,logical_name,region,spec_digest,
			approved_plan_hash,approval_id,provider_id,retention,destroy_deadline,auto_destroy_approved,tags,state,
			readback_exists,readback_provider_id,readback_observed_at,readback_tag_digest,revision,created_at,updated_at
		) VALUES ($1,$2,$3,$4,$5,'ebs','data','us-west-2',$6,$7,$8,$9,'ephemeral_auto_destroy',$10,true,$11,
		          'active',true,$9,$12,$13,1,$12,$12)`,
		fixture.sourceID, instanceID, fixture.ownerID, taskID, fixture.deploymentID, sourceSpecDigest,
		fixture.planHash, fixture.originalApprovalID, fixture.sourceProviderID, fixture.deadline, sourceTagsJSON, now, sourceTagDigest); err != nil {
		t.Fatal(err)
	}
	scope := serviceoperation.ScopeV1{
		SchemaVersion: serviceoperation.ScopeSchemaV1, Intent: serviceoperation.IntentManagedPreparation,
		PreparationOperationID: fixture.operationID, OwnerID: fixture.ownerID, AgentInstanceID: instanceID,
		DeploymentID: fixture.deploymentID, DeploymentRevision: 1,
		ConnectionID: fixture.connectionID, ConnectionRevision: 1,
		PlanID: fixture.planID, PlanRevision: 2, PlanHash: fixture.planHash,
		RecipeID: "managed-preparation-fixture", RecipeRevision: 1, RecipeDigest: managedPreparationDigest("4"),
		EC2: serviceoperation.ResourceFactV1{
			ResourceID: fixture.ec2ID, ProviderID: fixture.instanceProviderID, Revision: 1,
			SpecDigest: managedPreparationDigest("e"), TagDigest: ec2TagDigest,
		},
		SourceVolumes: []serviceoperation.ResourceFactV1{{
			ResourceID: fixture.sourceID, ProviderID: fixture.sourceProviderID, Revision: 1,
			SpecDigest: managedPreparationDigest("3"), TagDigest: sourceTagDigest,
		}},
		Restart: serviceoperation.RestartReferenceV1{
			OperationID:             uuid.NewSHA1(uuid.MustParse(fixture.operationID), []byte("restart")).String(),
			ExpectedInitialRevision: 1, Action: "restart", LifecycleRestartRef: "restart-service",
			ExecutionBundleDigest: managedPreparationDigest("5"),
		},
		Volumes: []serviceoperation.VolumePreparationV1{{
			SlotID: "data", SourceVolume: serviceoperation.ResourceFactV1{
				ResourceID: fixture.sourceID, ProviderID: fixture.sourceProviderID, Revision: 1,
				SpecDigest: sourceSpecDigest, TagDigest: sourceTagDigest,
			},
			SnapshotResourceID: fixture.snapshotID, ReplacementVolumeResourceID: fixture.replacementID,
			AvailabilityZone: "us-west-2a", SizeGiB: 80, VolumeType: "gp3", IOPS: 3000, ThroughputMiBPS: 125,
			KMSKeyID: "alias/dtx-agent-test", DeviceName: "/dev/sdf", MountPath: "/srv/data",
			Persistent: true, Disposition: string(cloudapproval.VolumeRetainWithManagedService),
		}},
		ServiceMonitorRevision: 1, ServiceMonitorSuiteDigest: managedPreparationDigest("6"),
		Currency: "USD", CostAlertAmountMinor: 1000, ExpectedInstalledManifestDigest: managedPreparationDigest("7"),
	}
	calculatedSourceSpecDigest, err := scope.Volumes[0].SourceSpecDigest()
	if err != nil || calculatedSourceSpecDigest != sourceSpecDigest {
		t.Fatal(err)
	}
	challenge := serviceoperation.ChallengeV1{
		SchemaVersion: serviceoperation.ChallengeSchemaV1, ChallengeID: uuid.NewString(),
		OperationID: fixture.operationID, SignerKeyID: "worker-identity-device-123456789012",
		Scope: scope, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(4 * time.Minute),
	}
	challenge.ScopeDigest, _ = serviceoperation.SigningPayloadDigest(challenge)
	fixture.scopeDigest = challenge.ScopeDigest
	challengeJSON, _ := json.Marshal(challenge)
	if _, err := pool.Exec(ctx, `
		INSERT INTO cloud_service_operations (
			operation_id,agent_instance_id,owner_id,deployment_id,deployment_revision,connection_id,connection_revision,
			plan_id,plan_revision,plan_hash,recipe_id,recipe_revision,recipe_digest,scope_digest,challenge_id,signer_key_id,
			challenge_json,signature,status,current_phase,revision,prepare_client_id,prepare_credential_id,
			prepare_idempotency_key,prepare_request_hash,approve_client_id,approve_credential_id,approve_idempotency_key,
			approve_request_hash,approved_at,created_at,updated_at
		) VALUES ($1,$2,$3,$4,1,$5,1,$6,2,$7,'managed-preparation-fixture',1,$8,$9,$10,$11,$12,
		          $13,'running','backup',3,'message-server',$14,$15,$16,'message-server',$17,$18,$19,$20,$20,$20)`,
		fixture.operationID, instanceID, fixture.ownerID, fixture.deploymentID, fixture.connectionID, fixture.planID,
		fixture.planHash, scope.RecipeDigest, challenge.ScopeDigest, challenge.ChallengeID, challenge.SignerKeyID,
		challengeJSON, bytes.Repeat([]byte{9}, 64), uuid.New(), uuid.New(), managedPreparationDigest("8"),
		uuid.New(), uuid.New(), managedPreparationDigest("9"), now); err != nil {
		t.Fatal(err)
	}
	for index, phase := range serviceoperation.Phases() {
		status := "pending"
		var intent any
		var started, completed any
		if phase == serviceoperation.PhaseRestart {
			status, intent, started, completed = "succeeded", managedPreparationDigest("a"), now.Add(-time.Minute), now
		} else if phase == serviceoperation.PhaseBackup {
			status, intent, started = "running", managedPreparationDigest("b"), now
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO cloud_service_operation_steps(operation_id,ordinal,phase,status,revision,intent_digest,started_at,completed_at)
			VALUES($1,$2,$3,$4,1,$5,$6,$7)`,
			fixture.operationID, index+1, phase, status, intent, started, completed); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func (fixture managedPreparationResourceFixture) preparationIntent(kind resource.Type, resourceID, dependencyID string) resource.ResourceV1 {
	logicalName := "managed-preparation-snapshot"
	if kind == resource.TypeEBS {
		logicalName = "managed-preparation-replacement"
	}
	return resource.ResourceV1{
		ResourceID: resourceID, AgentInstanceID: fixture.instanceID, OwnerID: fixture.ownerID,
		TaskID: fixture.taskID, DeploymentID: fixture.deploymentID, Type: kind, LogicalName: logicalName,
		Region: "us-west-2", SpecDigest: managedPreparationDigest("c"), ApprovedPlanHash: fixture.planHash,
		ApprovalID: fixture.operationID, IntentOrigin: resource.IntentOriginManagedPreparation,
		OriginScopeDigest: fixture.scopeDigest, DependsOn: []string{dependencyID},
		Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: fixture.deadline, AutoDestroyApproved: true,
		Tags:  fixture.tags(resourceID, fixture.operationID, fixture.planHash, string(resource.IntentOriginManagedPreparation), fixture.scopeDigest),
		State: resource.StateProvisioning, Intent: resource.MutationIntent{
			Operation: resource.MutationCreate, ClientToken: strings.Repeat("c", 64), RecordedAt: fixture.now,
		},
		Revision: 1, CreatedAt: fixture.now, UpdatedAt: fixture.now,
	}
}

func (fixture managedPreparationResourceFixture) tags(resourceID, approvalID, planHash, origin, scopeDigest string) map[string]string {
	result := map[string]string{
		resource.TagAgentInstanceID: fixture.instanceID, resource.TagOwnerID: fixture.ownerID,
		resource.TagTaskID: fixture.taskID, resource.TagDeploymentID: fixture.deploymentID,
		resource.TagResourceID: resourceID, resource.TagRetention: string(task.RetentionEphemeralAutoDestroy),
		resource.TagDestroyDeadline:  fixture.deadline.Format(time.RFC3339),
		resource.TagApprovedPlanHash: planHash, resource.TagApprovalID: approvalID,
	}
	if origin != "" {
		result[resource.TagIntentOrigin], result[resource.TagOriginScopeDigest] = origin, scopeDigest
	}
	return result
}

func (fixture managedPreparationResourceFixture) activate(t *testing.T, item resource.ResourceV1, providerID string) {
	t.Helper()
	if _, err := fixture.pool.Exec(context.Background(), `
		UPDATE cloud_resources SET provider_id=$2,state='active',readback_exists=true,readback_provider_id=$2,
		       readback_observed_at=$3,readback_tag_digest=$4,revision=2,updated_at=$3
		WHERE resource_id=$1`,
		item.ResourceID, providerID, fixture.now.Add(2*time.Minute), managedPreparationDigest("f")); err != nil {
		t.Fatal(err)
	}
}

func (fixture managedPreparationResourceFixture) setPhase(t *testing.T, phase serviceoperation.Phase) {
	t.Helper()
	ctx := context.Background()
	if _, err := fixture.pool.Exec(ctx, `
		UPDATE cloud_service_operation_steps SET status='succeeded',completed_at=$2,revision=revision+1
		WHERE operation_id=$1 AND status='running'`,
		fixture.operationID, fixture.now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `
		UPDATE cloud_service_operation_steps SET status='running',intent_digest=$3,started_at=$2,revision=revision+1
		WHERE operation_id=$1 AND phase=$4`,
		fixture.operationID, fixture.now.Add(3*time.Minute), managedPreparationDigest("a"), phase); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `
		UPDATE cloud_service_operations SET current_phase=$3,revision=revision+1,updated_at=$2 WHERE operation_id=$1`,
		fixture.operationID, fixture.now.Add(3*time.Minute), phase); err != nil {
		t.Fatal(err)
	}
}

func (fixture managedPreparationResourceFixture) setFinalizeAfterSemanticHealth(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if _, err := fixture.pool.Exec(ctx, `
		UPDATE cloud_service_operation_steps
		SET status='succeeded',intent_digest=COALESCE(intent_digest,$2),started_at=COALESCE(started_at,$3),
		    completed_at=$3,revision=revision+1
		WHERE operation_id=$1 AND phase IN ('restore_swap','semantic_health')`,
		fixture.operationID, managedPreparationDigest("b"), fixture.now.Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `
		UPDATE cloud_service_operation_steps
		SET status='running',intent_digest=$2,started_at=$3,revision=revision+1
		WHERE operation_id=$1 AND phase='finalize'`,
		fixture.operationID, managedPreparationDigest("b"), fixture.now.Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `
		UPDATE cloud_service_operations SET current_phase='finalize',revision=revision+1,updated_at=$2
		WHERE operation_id=$1`,
		fixture.operationID, fixture.now.Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func managedPreparationDigest(value string) string { return "sha256:" + strings.Repeat(value, 64) }

func managedPreparationVolumeSpecDigest(t *testing.T) string {
	t.Helper()
	value := serviceoperation.VolumePreparationV1{
		SlotID: "data", AvailabilityZone: "us-west-2a", SizeGiB: 80, VolumeType: "gp3",
		IOPS: 3000, ThroughputMiBPS: 125, KMSKeyID: "alias/dtx-agent-test",
		DeviceName: "/dev/sdf", MountPath: "/srv/data", Persistent: true,
		Disposition: string(cloudapproval.VolumeRetainWithManagedService),
	}
	digest, err := value.SourceSpecDigest()
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func containsResourceID(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
