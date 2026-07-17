package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entrypoint"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The entry approval is intentionally not a cloud_approvals row. This
// protects the migration-19 contract: a resource intent must use its exact
// durable approval source, not fall back to the historical Worker approval.
func TestResourceStoreCreateIntentAcceptsExactEntryApprovalOrigin(t *testing.T) {
	fixture := seedEntryOperationPlanLookup(t)
	operation := transitionEntryOperationToProvisioning(t, fixture)
	store, err := fixture.store.NewResourceStore()
	if err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := fixture.pool.QueryRow(fixture.ctx, `SELECT EXISTS(SELECT 1 FROM cloud_approvals WHERE approval_id=$1)`, operation.Challenge.ApprovalID).Scan(&exists); err != nil {
		t.Fatalf("read historical approval source: %v", err)
	}
	if exists {
		t.Fatal("entry approval unexpectedly exists in cloud_approvals")
	}
	item := entryResourceIntentFixture(t, fixture, operation)
	advanceApprovedWorkerPlanSnapshot(t, fixture.ctx, fixture.pool, fixture.plan.Scope.Worker.DeploymentID)
	created, err := store.CreateIntent(fixture.ctx, item)
	if err != nil {
		t.Fatalf("create exact entry resource intent: %v", err)
	}
	if created.ResourceID != item.ResourceID || created.ApprovalID != operation.Challenge.ApprovalID || created.ApprovedPlanHash != operation.Challenge.PlanHash {
		t.Fatalf("stored entry resource intent=%+v", created)
	}
}

// An approval records the exact signed pre-transition Plan snapshot. The
// cloud_plans row becomes approved at a later revision and has a different
// hash, so the mutable row is only a current plan-ID/status guard; it is not
// the authorization fact for a Worker resource intent.
func TestResourceStoreCreateIntentAcceptsWorkerApprovalSnapshotAfterPlanTransition(t *testing.T) {
	pool, baseStore, instanceID := newPlanningTestStore(t)
	ctx := context.Background()
	taskID, _ := createWorkerTask(t, baseStore)
	deploymentID := uuid.NewString()
	const ownerID = "owner-worker-snapshot"
	seedWorkerIdentityBinding(t, pool, instanceID, ownerID, taskID, deploymentID, "i-0123456789abcdef0", "123456789012")
	approvalID, approvalHash := workerApprovalSnapshot(t, ctx, pool, deploymentID)
	advanceApprovedWorkerPlanSnapshot(t, ctx, pool, deploymentID)

	store, err := baseStore.NewResourceStore()
	if err != nil {
		t.Fatal(err)
	}
	item := workerResourceIntentFixture(instanceID, ownerID, taskID, deploymentID, approvalHash, approvalID)
	created, err := store.CreateIntent(ctx, item)
	if err != nil {
		t.Fatalf("create Worker resource from immutable approval snapshot: %v", err)
	}
	if created.ResourceID != item.ResourceID || created.ApprovedPlanHash != approvalHash || created.ApprovalID != approvalID {
		t.Fatalf("stored Worker resource intent=%+v", created)
	}
}

func TestResourceStoreCreateIntentRejectsActiveDestroyOperation(t *testing.T) {
	tests := []struct {
		name       string
		status     string
		wantReject bool
	}{
		{name: "awaiting approval does not fence create", status: "awaiting_approval"},
		{name: "approved", status: "approved", wantReject: true},
		{name: "destroying", status: "destroying", wantReject: true},
		{name: "destroy blocked", status: "destroy_blocked", wantReject: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool, baseStore, instanceID := newPlanningTestStore(t)
			ctx := context.Background()
			taskID, _ := createWorkerTask(t, baseStore)
			deploymentID := uuid.NewString()
			const ownerID = "owner-resource-destroy-fence"
			seedWorkerIdentityBinding(t, pool, instanceID, ownerID, taskID, deploymentID, "i-0123456789abcdef0", "123456789012")
			approvalID, approvalHash := workerApprovalSnapshot(t, ctx, pool, deploymentID)
			insertDeploymentDestroyOperation(t, ctx, pool, instanceID, ownerID, deploymentID, test.status)

			store, err := baseStore.NewResourceStore()
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.CreateIntent(ctx, workerResourceIntentFixture(instanceID, ownerID, taskID, deploymentID, approvalHash, approvalID))
			if test.wantReject {
				if !errors.Is(err, resource.ErrInvalid) {
					t.Fatalf("CreateIntent during %s error=%v, want resource.ErrInvalid", test.status, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateIntent during %s error=%v, want success", test.status, err)
			}
		})
	}
}

func TestResourceStoreWithDeploymentFenceSerializesCallbacksAndReleases(t *testing.T) {
	_, baseStore, _ := newPlanningTestStore(t)
	store, err := baseStore.NewResourceStore()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	deploymentID := uuid.NewString()
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- store.WithDeploymentFence(ctx, deploymentID, func(runCtx context.Context) error {
			close(firstEntered)
			select {
			case <-releaseFirst:
				return nil
			case <-runCtx.Done():
				return runCtx.Err()
			}
		})
	}()
	select {
	case <-firstEntered:
	case <-ctx.Done():
		t.Fatalf("first deployment fence did not enter: %v", ctx.Err())
	}

	secondEntered := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- store.WithDeploymentFence(ctx, deploymentID, func(context.Context) error {
			close(secondEntered)
			return nil
		})
	}()
	select {
	case <-secondEntered:
		t.Fatal("same deployment entered a second fence before the first released")
	case <-time.After(150 * time.Millisecond):
	}
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatalf("first deployment fence result: %v", err)
	}
	select {
	case <-secondEntered:
	case <-ctx.Done():
		t.Fatalf("second deployment fence did not enter after release: %v", ctx.Err())
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second deployment fence result: %v", err)
	}

	callbackErr := errors.New("stop after fenced callback")
	if err := store.WithDeploymentFence(ctx, deploymentID, func(context.Context) error { return callbackErr }); !errors.Is(err, callbackErr) {
		t.Fatalf("callback error=%v, want %v", err, callbackErr)
	}
	runAfterError := false
	if err := store.WithDeploymentFence(ctx, deploymentID, func(context.Context) error {
		runAfterError = true
		return nil
	}); err != nil || !runAfterError {
		t.Fatalf("deployment fence was not released after callback error: ran=%v err=%v", runAfterError, err)
	}
}

func TestResourceStoreCreateIntentRejectsTamperedEntryOrigin(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, fixture entryOperationPlanLookupFixture, item *resource.ResourceV1)
	}{
		{
			name: "owner",
			mutate: func(_ *testing.T, _ entryOperationPlanLookupFixture, item *resource.ResourceV1) {
				item.OwnerID = "other-owner"
				item.Tags[resource.TagOwnerID] = item.OwnerID
			},
		},
		{
			name: "task",
			mutate: func(_ *testing.T, _ entryOperationPlanLookupFixture, item *resource.ResourceV1) {
				item.TaskID = uuid.NewString()
				item.Tags[resource.TagTaskID] = item.TaskID
			},
		},
		{
			name: "deployment",
			mutate: func(_ *testing.T, _ entryOperationPlanLookupFixture, item *resource.ResourceV1) {
				item.DeploymentID = uuid.NewString()
				item.Tags[resource.TagDeploymentID] = item.DeploymentID
			},
		},
		{
			name: "approved plan hash",
			mutate: func(_ *testing.T, _ entryOperationPlanLookupFixture, item *resource.ResourceV1) {
				item.ApprovedPlanHash = entryDigest("9")
				item.Tags[resource.TagApprovedPlanHash] = item.ApprovedPlanHash
			},
		},
		{
			name: "entry approval",
			mutate: func(_ *testing.T, _ entryOperationPlanLookupFixture, item *resource.ResourceV1) {
				item.ApprovalID = uuid.NewString()
				item.Tags[resource.TagApprovalID] = item.ApprovalID
			},
		},
		{
			name: "connection",
			mutate: func(t *testing.T, fixture entryOperationPlanLookupFixture, _ *resource.ResourceV1) {
				t.Helper()
				connectionID := uuid.New()
				now := time.Now().UTC().Truncate(time.Microsecond)
				if _, err := fixture.pool.Exec(fixture.ctx, `
					INSERT INTO cloud_connections (
						connection_id, agent_instance_id, owner_id, account_id, region, control_role_arn,
						foundation_stack_id, credential_generation, status, revision, created_at, updated_at
					) VALUES ($1,$2,$3,'210987654321','us-west-2',
						'arn:aws:iam::210987654321:role/control','fixture-entry-connection',1,'active',1,$4,$4)`,
					connectionID, fixture.plan.Scope.AgentInstanceID, fixture.ownerID, now); err != nil {
					t.Fatalf("create mismatched connection: %v", err)
				}
				if _, err := fixture.pool.Exec(fixture.ctx, `UPDATE cloud_entry_operations SET connection_id=$2 WHERE operation_id=$1`, fixture.operation.Challenge.OperationID, connectionID); err != nil {
					t.Fatalf("tamper entry operation connection: %v", err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := seedEntryOperationPlanLookup(t)
			operation := transitionEntryOperationToProvisioning(t, fixture)
			store, err := fixture.store.NewResourceStore()
			if err != nil {
				t.Fatal(err)
			}
			item := entryResourceIntentFixture(t, fixture, operation)
			test.mutate(t, fixture, &item)
			if _, err := store.CreateIntent(fixture.ctx, item); !errors.Is(err, resource.ErrInvalid) {
				t.Fatalf("tampered %s origin error=%v, want resource.ErrInvalid", test.name, err)
			}
		})
	}
}

func TestResourceStoreImportOrphanRequiresTaggedWorkerOrEntryOrigin(t *testing.T) {
	t.Run("Worker launch history", func(t *testing.T) {
		pool, baseStore, instanceID := newPlanningTestStore(t)
		ctx := context.Background()
		taskID, _ := createWorkerTask(t, baseStore)
		deploymentID := uuid.NewString()
		seedWorkerIdentityBinding(t, pool, instanceID, "owner-worker-store", taskID, deploymentID, "i-0123456789abcdef0", "123456789012")
		approvalID, planHash := workerApprovalSnapshot(t, ctx, pool, deploymentID)
		advanceApprovedWorkerPlanSnapshot(t, ctx, pool, deploymentID)
		if _, err := pool.Exec(ctx, `DELETE FROM cloud_resources WHERE deployment_id=$1`, deploymentID); err != nil {
			t.Fatalf("remove fixture Worker resource: %v", err)
		}
		store, err := baseStore.NewResourceStore()
		if err != nil {
			t.Fatal(err)
		}
		item := orphanResourceFixture(instanceID, "owner-worker-store", taskID, deploymentID, planHash, approvalID, "i-orphan-worker")
		if _, err := store.ImportOrphan(ctx, item); err != nil {
			t.Fatalf("import Worker orphan with exact historical origin: %v", err)
		}
	})

	t.Run("signed entry history without active connection", func(t *testing.T) {
		fixture := seedEntryOperationPlanLookup(t)
		operation := transitionEntryOperationToProvisioning(t, fixture)
		advanceApprovedWorkerPlanSnapshot(t, fixture.ctx, fixture.pool, fixture.plan.Scope.Worker.DeploymentID)
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE cloud_connections
			SET status='destroyed', revision=revision+1, updated_at=clock_timestamp()
			WHERE connection_id=(SELECT connection_id FROM cloud_entry_operations WHERE operation_id=$1)`, operation.Challenge.OperationID,
		); err != nil {
			t.Fatalf("retire entry connection after provisioning: %v", err)
		}
		store, err := fixture.store.NewResourceStore()
		if err != nil {
			t.Fatal(err)
		}
		item := orphanResourceFixture(
			fixture.plan.Scope.AgentInstanceID, fixture.ownerID, fixture.plan.Scope.Worker.TaskID, fixture.plan.Scope.Worker.DeploymentID,
			operation.Challenge.PlanHash, operation.Challenge.ApprovalID, "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/orphan/0123456789abcdef",
		)
		item.Type, item.LogicalName = resource.TypeALB, "entry-orphan"
		if _, err := store.ImportOrphan(fixture.ctx, item); err != nil {
			t.Fatalf("import entry orphan after connection retirement: %v", err)
		}

		legacy := orphanResourceFixture(
			fixture.plan.Scope.AgentInstanceID, fixture.ownerID, fixture.plan.Scope.Worker.TaskID, fixture.plan.Scope.Worker.DeploymentID,
			operation.Challenge.PlanHash, operation.Challenge.ApprovalID, "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/legacy/0123456789abcdef",
		)
		legacy.Type, legacy.LogicalName = resource.TypeALB, "legacy-entry-orphan"
		delete(legacy.Tags, resource.TagApprovedPlanHash)
		if _, err := store.ImportOrphan(fixture.ctx, legacy); !errors.Is(err, resource.ErrInvalid) {
			t.Fatalf("old orphan without origin tag error=%v, want resource.ErrInvalid", err)
		}
	})
}

func workerApprovalSnapshot(t *testing.T, ctx context.Context, pool *pgxpool.Pool, deploymentID string) (string, string) {
	t.Helper()
	var approvalID uuid.UUID
	var approvalHash string
	if err := pool.QueryRow(ctx, `
		SELECT launch.approval_id, approval.plan_hash
		FROM cloud_launch_operations AS launch
		JOIN cloud_approvals AS approval ON approval.approval_id=launch.approval_id
		WHERE launch.deployment_id=$1`, deploymentID,
	).Scan(&approvalID, &approvalHash); err != nil {
		t.Fatalf("load immutable Worker approval snapshot: %v", err)
	}
	return approvalID.String(), approvalHash
}

func insertDeploymentDestroyOperation(t *testing.T, ctx context.Context, pool *pgxpool.Pool, instanceID, ownerID, deploymentID, status string) {
	t.Helper()
	var planID, connectionID uuid.UUID
	var signerKeyID string
	if err := pool.QueryRow(ctx, `
		SELECT launch.plan_id, launch.connection_id, device.key_id
		FROM cloud_launch_operations AS launch
		JOIN cloud_approval_devices AS device
		  ON device.agent_instance_id=launch.agent_instance_id AND device.owner_id=launch.owner_id
		WHERE launch.deployment_id=$1
		ORDER BY device.created_at, device.device_id
		LIMIT 1`, deploymentID,
	).Scan(&planID, &connectionID, &signerKeyID); err != nil {
		t.Fatalf("load destroy fence prerequisites: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	var signature []byte
	var approveClient, approveCredential, approveIdempotency, approveRequestHash, approvedAt any
	var errorCode, blockedReason any
	if status != "awaiting_approval" {
		signature = make([]byte, 64)
		approveClient = "resource-store-destroy-approve"
		approveCredential = uuid.New()
		approveIdempotency = uuid.New()
		approveRequestHash = make([]byte, 32)
		approvedAt = now
	}
	if status == "destroy_blocked" {
		errorCode, blockedReason = "AWS_READ_BACK_PENDING", "provider absence is not yet verified"
	}
	_, err := pool.Exec(ctx, `
		INSERT INTO cloud_destroy_operations (
			operation_id, agent_instance_id, owner_id, deployment_id, plan_id, connection_id,
			challenge_id, approval_id, signer_key_id, expected_deployment_revision, scope_digest, scope_json,
			signing_payload, challenge_expires_at, signature, status, error_code, blocked_reason, revision,
			prepare_client_id, prepare_credential_id, prepare_idempotency_key, prepare_request_hash,
			approve_client_id, approve_credential_id, approve_idempotency_key, approve_request_hash,
			created_at, updated_at, approved_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,1,$10,'{}'::jsonb,$11,$12,$13,$14,$15,$16,2,
			'resource-store-destroy-prepare',$17,$18,$19,$20,$21,$22,$23,$24,$24,$25
		)`,
		uuid.New(), instanceID, ownerID, deploymentID, planID, connectionID, uuid.New(), uuid.New(), signerKeyID,
		"sha256:"+strings.Repeat("d", 64), []byte{1}, now.Add(time.Minute), signature, status, errorCode, blockedReason,
		uuid.New(), uuid.New(), make([]byte, 32),
		approveClient, approveCredential, approveIdempotency, approveRequestHash, now, approvedAt,
	)
	if err != nil {
		t.Fatalf("insert %s destroy operation: %v", status, err)
	}
}

func advanceApprovedWorkerPlanSnapshot(t *testing.T, ctx context.Context, pool *pgxpool.Pool, deploymentID string) {
	t.Helper()
	var planID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT plan_id FROM cloud_launch_operations WHERE deployment_id=$1`, deploymentID).Scan(&planID); err != nil {
		t.Fatalf("load Worker plan for snapshot transition: %v", err)
	}
	const nextPlanHash = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	result, err := pool.Exec(ctx, `
		UPDATE cloud_plans
		SET plan_hash=$2, revision=revision+1, updated_at=clock_timestamp()
		WHERE plan_id=$1 AND status='approved'`, planID, nextPlanHash)
	if err != nil || result.RowsAffected() != 1 {
		t.Fatalf("advance mutable approved Plan after approval: rows=%d err=%v", result.RowsAffected(), err)
	}
	var approvalHash, planHash string
	var approvalRevision, planRevision int64
	if err := pool.QueryRow(ctx, `
		SELECT approval.plan_hash, plan.plan_hash, approval.plan_revision, plan.revision
		FROM cloud_launch_operations AS launch
		JOIN cloud_approvals AS approval ON approval.approval_id=launch.approval_id
		JOIN cloud_plans AS plan ON plan.plan_id=launch.plan_id
		WHERE launch.deployment_id=$1`, deploymentID,
	).Scan(&approvalHash, &planHash, &approvalRevision, &planRevision); err != nil {
		t.Fatalf("read advanced mutable Plan snapshot: %v", err)
	}
	if approvalHash == planHash || approvalRevision == planRevision {
		t.Fatalf("fixture did not separate immutable approval snapshot: approval=(%s,%d) plan=(%s,%d)", approvalHash, approvalRevision, planHash, planRevision)
	}
}

func workerResourceIntentFixture(agentID, ownerID, taskID, deploymentID, approvalHash, approvalID string) resource.ResourceV1 {
	now := time.Now().UTC().Truncate(time.Microsecond)
	deadline := now.Add(time.Hour).Truncate(time.Second)
	resourceID := uuid.NewString()
	return resource.ResourceV1{
		ResourceID: resourceID, AgentInstanceID: agentID, OwnerID: ownerID, TaskID: taskID, DeploymentID: deploymentID,
		Type: resource.TypeEBS, LogicalName: "snapshot-authorized-volume", Region: "us-west-2",
		SpecDigest: entryDigest("e"), ApprovedPlanHash: approvalHash, ApprovalID: approvalID,
		Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: deadline, AutoDestroyApproved: true,
		Tags: map[string]string{
			resource.TagAgentInstanceID: agentID, resource.TagOwnerID: ownerID, resource.TagTaskID: taskID,
			resource.TagDeploymentID: deploymentID, resource.TagResourceID: resourceID,
			resource.TagRetention: string(task.RetentionEphemeralAutoDestroy), resource.TagDestroyDeadline: deadline.Format(time.RFC3339),
			resource.TagApprovedPlanHash: approvalHash, resource.TagApprovalID: approvalID,
		},
		State:    resource.StateProvisioning,
		Intent:   resource.MutationIntent{Operation: resource.MutationCreate, ClientToken: strings.Repeat("a", 64), RecordedAt: now},
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
}

func orphanResourceFixture(agentID, ownerID, taskID, deploymentID, planHash, approvalID, providerID string) resource.ResourceV1 {
	now := time.Now().UTC().Truncate(time.Microsecond)
	resourceID := uuid.NewString()
	deadline := now.Add(time.Hour).Truncate(time.Second)
	return resource.ResourceV1{
		ResourceID: resourceID, AgentInstanceID: agentID, OwnerID: ownerID, TaskID: taskID, DeploymentID: deploymentID,
		Type: resource.TypeEC2, LogicalName: "recovered-resource", ApprovedPlanHash: planHash, ApprovalID: approvalID,
		ProviderID: providerID, Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: deadline, State: resource.StateOrphaned,
		Tags: map[string]string{
			resource.TagAgentInstanceID: agentID, resource.TagOwnerID: ownerID, resource.TagTaskID: taskID,
			resource.TagDeploymentID: deploymentID, resource.TagResourceID: resourceID,
			resource.TagRetention: string(task.RetentionEphemeralAutoDestroy), resource.TagDestroyDeadline: deadline.Format(time.RFC3339),
			resource.TagApprovedPlanHash: planHash, resource.TagApprovalID: approvalID,
		},
		ReadBack: resource.ReadBackEvidence{Exists: true, ProviderID: providerID, ObservedAt: now, TagDigest: entryDigest("7")},
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
}

func transitionEntryOperationToProvisioning(t *testing.T, fixture entryOperationPlanLookupFixture) entrypoint.OperationV1 {
	t.Helper()
	next := fixture.operation
	next.Status = entrypoint.StatusProvisioning
	next.UpdatedAt = next.UpdatedAt.Add(time.Second)
	operation, err := fixture.store.SaveEntryOperation(fixture.ctx, next, fixture.operation.Revision)
	if err != nil {
		t.Fatalf("transition entry operation to provisioning: %v", err)
	}
	return operation
}

func entryResourceIntentFixture(t *testing.T, fixture entryOperationPlanLookupFixture, operation entrypoint.OperationV1) resource.ResourceV1 {
	t.Helper()
	scope := fixture.plan.Scope
	planHash, err := fixture.plan.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if planHash != operation.Challenge.PlanHash {
		t.Fatalf("entry plan hash=%s operation hash=%s", planHash, operation.Challenge.PlanHash)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	resourceID := uuid.NewString()
	deadline := scope.Retention.DestroyDeadline.UTC()
	return resource.ResourceV1{
		ResourceID: resourceID, AgentInstanceID: scope.AgentInstanceID, OwnerID: scope.OwnerID,
		TaskID: scope.Worker.TaskID, DeploymentID: scope.Worker.DeploymentID,
		Type: resource.TypeALB, LogicalName: "entry-origin-guard", Region: scope.Region,
		SpecDigest: entryDigest("8"), ApprovedPlanHash: planHash, ApprovalID: operation.Challenge.ApprovalID,
		Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: deadline, AutoDestroyApproved: true,
		Tags: map[string]string{
			resource.TagAgentInstanceID:  scope.AgentInstanceID,
			resource.TagOwnerID:          scope.OwnerID,
			resource.TagTaskID:           scope.Worker.TaskID,
			resource.TagDeploymentID:     scope.Worker.DeploymentID,
			resource.TagResourceID:       resourceID,
			resource.TagRetention:        string(task.RetentionEphemeralAutoDestroy),
			resource.TagDestroyDeadline:  deadline.Format(time.RFC3339),
			resource.TagApprovedPlanHash: planHash,
			resource.TagApprovalID:       operation.Challenge.ApprovalID,
		},
		State: resource.StateProvisioning,
		Intent: resource.MutationIntent{
			Operation: resource.MutationCreate, ClientToken: strings.Repeat("a", 64), RecordedAt: now,
		},
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
}
