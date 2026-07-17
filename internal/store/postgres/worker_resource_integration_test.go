package postgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestWorkerPostgresEncryptedEnrollmentReplayLeaseFencingAndRestart(t *testing.T) {
	pool, baseStore, instanceID := newPlanningTestStore(t)
	ctx := context.Background()
	taskID, stepID := createWorkerTask(t, baseStore)
	replayKey := bytes.Repeat([]byte{0x31}, 32)
	pepper := bytes.Repeat([]byte{0x42}, 32)
	workerStore, err := baseStore.NewWorkerStore(replayKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{0x54}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	service, err := worker.NewService(workerStore, pepper, worker.WithInstallerTrustIssuer(issuer))
	if err != nil {
		t.Fatal(err)
	}
	deploymentID := uuid.NewString()
	createMutation := worker.ControlMutation{ClientID: "worker-store-test", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString()}
	createRequest := worker.CreateDeploymentRequest{
		DeploymentID: deploymentID, OwnerID: "owner-worker-store", TaskID: taskID, StepID: stepID,
		ControlPlaneEndpoint: "grpcs://agent.example.internal:8443", EnrollmentTTL: 10 * time.Minute,
		RecipeBundle:     worker.BundleRef{S3Ref: "s3://agent-fixture/deployments/worker/recipe.json", SHA256: [32]byte{1}},
		ExecutionBundle:  worker.BundleRef{S3Ref: "s3://agent-fixture/deployments/worker/execution.json", SHA256: [32]byte{2}},
		ExecutionTimeout: 30 * time.Minute,
		Access: worker.AccessScope{
			ArtifactPrefix: "s3://agent-fixture/deployments/worker/artifacts/", CheckpointPrefix: "s3://agent-fixture/deployments/worker/checkpoints/",
			EvidencePrefix: "s3://agent-fixture/deployments/worker/evidence/", LogPrefix: "cloudwatch://agent-fixture/worker",
			SecretRefs: []string{"secret://agent-fixture/deployments/worker/model"},
		},
	}
	createRequest.InstallerDelivery = integrationInstallerDelivery(t, issuer, instanceID, deploymentID, taskID, createRequest.RecipeBundle.SHA256)
	createRequest.InstallerCommandIDs = []string{"install-service"}
	created, enrollment, err := service.CreateDeployment(ctx, createMutation, createRequest)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentRaw := enrollment.Reveal()
	defer wipeIntegrationBytes(enrollmentRaw)

	// Simulate loss of the create response. The durable replay must return the
	// original one-time enrollment credential instead of creating a second VM
	// bootstrap secret or stranding the already-created deployment.
	restartedCreateStore, err := baseStore.NewWorkerStore(replayKey)
	if err != nil {
		t.Fatal(err)
	}
	restartedCreateService, err := worker.NewService(restartedCreateStore, pepper, worker.WithInstallerTrustIssuer(issuer))
	if err != nil {
		t.Fatal(err)
	}
	replayedCreate, replayedEnrollment, err := restartedCreateService.CreateDeployment(ctx, createMutation, createRequest)
	if err != nil {
		t.Fatal(err)
	}
	replayedEnrollmentRaw := replayedEnrollment.Reveal()
	if replayedCreate.Revision != created.Revision || !bytes.Equal(replayedEnrollmentRaw, enrollmentRaw) {
		t.Fatal("Worker create response loss did not replay the original enrollment response")
	}
	wipeIntegrationBytes(replayedEnrollmentRaw)
	replayedEnrollment.Destroy()
	changedCreate := createRequest
	changedCreate.ExecutionTimeout += time.Minute
	if _, credential, err := restartedCreateService.CreateDeployment(ctx, createMutation, changedCreate); !errors.Is(err, worker.ErrIdempotencyConflict) {
		credential.Destroy()
		t.Fatalf("changed Worker create replay error=%v", err)
	}

	concurrentRequest := createRequest
	concurrentRequest.DeploymentID = uuid.NewString()
	concurrentRequest.RecipeBundle.S3Ref = "s3://agent-fixture/deployments/concurrent/recipe.json"
	concurrentRequest.ExecutionBundle.S3Ref = "s3://agent-fixture/deployments/concurrent/execution.json"
	concurrentRequest.Access.ArtifactPrefix = "s3://agent-fixture/deployments/concurrent/artifacts/"
	concurrentRequest.Access.CheckpointPrefix = "s3://agent-fixture/deployments/concurrent/checkpoints/"
	concurrentRequest.Access.EvidencePrefix = "s3://agent-fixture/deployments/concurrent/evidence/"
	concurrentRequest.Access.LogPrefix = "cloudwatch://agent-fixture/concurrent"
	concurrentRequest.InstallerDelivery = integrationInstallerDelivery(t, issuer, instanceID, concurrentRequest.DeploymentID, taskID, concurrentRequest.RecipeBundle.SHA256)
	concurrentMutation := worker.ControlMutation{ClientID: "worker-store-test", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString()}
	type createResult struct {
		credential []byte
		err        error
	}
	results := make(chan createResult, 2)
	for range 2 {
		go func() {
			_, credential, createErr := restartedCreateService.CreateDeployment(ctx, concurrentMutation, concurrentRequest)
			raw := credential.Reveal()
			credential.Destroy()
			results <- createResult{credential: raw, err: createErr}
		}()
	}
	left, right := <-results, <-results
	defer wipeIntegrationBytes(left.credential)
	defer wipeIntegrationBytes(right.credential)
	if left.err != nil || right.err != nil || !bytes.Equal(left.credential, right.credential) {
		t.Fatalf("concurrent Worker create replay left=%v right=%v credential_equal=%v", left.err, right.err, bytes.Equal(left.credential, right.credential))
	}

	workerID := uuid.NewString()
	enrollRequest := worker.EnrollRequest{
		DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: created.Revision, Credential: enrollmentRaw,
	}
	enrolledAssignment, firstSession, err := service.Enroll(ctx, enrollRequest)
	if err != nil {
		t.Fatal(err)
	}
	firstSessionRaw := firstSession.Reveal()
	defer wipeIntegrationBytes(firstSessionRaw)
	firstSession.Destroy()

	// Simulate loss of the first response and reconstruct both store and service.
	restartedStore, err := baseStore.NewWorkerStore(replayKey)
	if err != nil {
		t.Fatal(err)
	}
	restartedService, err := worker.NewService(restartedStore, pepper, worker.WithInstallerTrustIssuer(issuer))
	if err != nil {
		t.Fatal(err)
	}
	_, replayedSession, err := restartedService.Enroll(ctx, enrollRequest)
	if err != nil {
		t.Fatalf("replay enrollment after response loss: %v", err)
	}
	replayedRaw := replayedSession.Reveal()
	if !bytes.Equal(replayedRaw, firstSessionRaw) {
		t.Fatal("enrollment replay did not return the original session credential")
	}
	wipeIntegrationBytes(replayedRaw)
	replayedSession.Destroy()

	changedEnrollment := append([]byte(nil), enrollmentRaw...)
	changedEnrollment[len(changedEnrollment)-1] ^= 1
	conflict := enrollRequest
	conflict.Credential = changedEnrollment
	if _, credential, err := restartedService.Enroll(ctx, conflict); !errors.Is(err, worker.ErrIdempotencyConflict) {
		credential.Destroy()
		t.Fatalf("changed enrollment replay error=%v", err)
	}
	wipeIntegrationBytes(changedEnrollment)
	wrongStore, err := baseStore.NewWorkerStore(bytes.Repeat([]byte{0x24}, 32))
	if err != nil {
		t.Fatal(err)
	}
	wrongService, _ := worker.NewService(wrongStore, pepper, worker.WithInstallerTrustIssuer(issuer))
	if _, credential, err := wrongService.Enroll(ctx, enrollRequest); !errors.Is(err, worker.ErrInvalidCredential) {
		credential.Destroy()
		t.Fatalf("wrong replay key error=%v", err)
	}

	claimRequest := worker.AuthenticatedRequest{
		DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: enrolledAssignment.Revision, Credential: firstSessionRaw,
	}
	firstLease, err := restartedService.Claim(ctx, claimRequest, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	checkpointRequest := worker.LeasedRequest{AuthenticatedRequest: worker.AuthenticatedRequest{
		DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: firstLease.Revision, Credential: firstSessionRaw,
	}, LeaseEpoch: firstLease.LeaseEpoch}
	checkpointRef := "s3://agent-fixture/deployments/worker/checkpoints/install.json"
	checkpointed, err := restartedService.Checkpoint(ctx, checkpointRequest, checkpointRef)
	if err != nil {
		t.Fatal(err)
	}
	replayedLease, err := restartedService.Claim(ctx, claimRequest, 30*time.Second)
	if err != nil {
		t.Fatalf("claim exact replay: %v", err)
	}
	if replayedLease.CheckpointRef != "" || replayedLease.LeaseEpoch != firstLease.LeaseEpoch {
		t.Fatalf("claim replay did not return the original snapshot: %+v", replayedLease)
	}
	if _, err := restartedService.Claim(ctx, claimRequest, time.Minute); !errors.Is(err, worker.ErrIdempotencyConflict) {
		t.Fatalf("changed claim replay error=%v", err)
	}

	expired, err := pool.Exec(ctx, `UPDATE worker_deployments SET lease_expires_at=clock_timestamp()-interval '1 minute' WHERE deployment_id=$1`, deploymentID)
	if err != nil {
		t.Fatal(err)
	}
	if expired.RowsAffected() != 1 {
		t.Fatalf("expire Worker lease rows=%d", expired.RowsAffected())
	}
	var expiredAt time.Time
	if err := pool.QueryRow(ctx, `SELECT lease_expires_at FROM worker_deployments WHERE deployment_id=$1`, deploymentID).Scan(&expiredAt); err != nil || !expiredAt.Before(time.Now().UTC()) {
		t.Fatalf("Worker lease was not expired: at=%s err=%v", expiredAt, err)
	}
	current, err := restartedService.GetCurrentAssignment(ctx, worker.SessionRequest{DeploymentID: deploymentID, WorkerID: workerID, Credential: firstSessionRaw})
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != checkpointed.Revision || current.CheckpointAttempt != firstLease.Attempt || current.CheckpointLeaseEpoch != firstLease.LeaseEpoch {
		t.Fatalf("session resume did not recover current checkpoint fence: current=%+v checkpointed=%+v", current, checkpointed)
	}
	secondLease, err := restartedService.Claim(ctx, worker.AuthenticatedRequest{
		DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: current.Revision, Credential: firstSessionRaw,
	}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if secondLease.LeaseEpoch != firstLease.LeaseEpoch+1 || secondLease.CheckpointRef != checkpointRef {
		t.Fatalf("restart recovery lost checkpoint or lease fencing: first=%+v second=%+v", firstLease, secondLease)
	}
	if _, err := restartedService.Complete(ctx, worker.CompleteRequest{
		LeasedRequest: worker.LeasedRequest{AuthenticatedRequest: worker.AuthenticatedRequest{
			DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: secondLease.Revision, Credential: firstSessionRaw,
		}, LeaseEpoch: firstLease.LeaseEpoch}, Outcome: worker.OutcomeSucceeded,
		ResultRef: "s3://agent-fixture/deployments/worker/artifacts/late.tar",
	}); !errors.Is(err, worker.ErrStaleLease) {
		t.Fatalf("late result error=%v", err)
	}

	reloaded, err := restartedStore.Get(ctx, created.DeploymentID)
	if err != nil || reloaded.Lease.Epoch != secondLease.LeaseEpoch || reloaded.Lease.CheckpointRef != checkpointRef ||
		reloaded.RecipeBundle != created.RecipeBundle || reloaded.ExecutionBundle != created.ExecutionBundle || reloaded.ExecutionTimeout != created.ExecutionTimeout ||
		reloaded.InstallerDelivery == nil || reloaded.InstallerDelivery.TrustID != createRequest.InstallerDelivery.TrustID ||
		!slices.Equal(reloaded.InstallerCommandIDs, createRequest.InstallerCommandIDs) {
		t.Fatalf("worker restart reload=%+v err=%v", reloaded, err)
	}
	assertWorkerCredentialCanaryAbsent(t, pool, enrollmentRaw, firstSessionRaw)
	enrollment.Destroy()
}

func integrationInstallerDelivery(t *testing.T, issuer *installer.TrustIssuer, instanceID, deploymentID, taskID string, recipeDigest [32]byte) *installer.DeliveryV1 {
	t.Helper()
	now := time.Now().UTC()
	root := installer.PreinstalledArtifactRoot
	binding := installer.BindingV1{
		AgentInstanceID: instanceID, DeploymentID: deploymentID, TaskID: taskID,
		PlanHash: "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{0x61}, 32)), ApprovalID: uuid.NewString(),
		RecipeDigest: "sha256:" + hex.EncodeToString(recipeDigest[:]),
	}
	delivery, err := issuer.Issue(installer.InstallerPlanV1{
		SchemaVersion: installer.PlanSchemaV1, Binding: binding,
		Artifacts: []installer.ArtifactV1{{
			Name: "installer", SHA256: "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{0x62}, 32)),
			SizeBytes: 32, TargetPath: root + "/installer",
		}},
		Commands: []installer.CommandV1{{
			CommandID: "install-service", Argv: []string{root + "/installer"}, WorkingDirectory: root,
			TimeoutSeconds: 30, ArtifactRefs: []string{"installer"},
		}},
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}, installer.DaemonConfigV1{SchemaVersion: installer.DaemonConfigSchema, Binding: binding, TargetRoot: root}, now)
	if err != nil {
		t.Fatal(err)
	}
	return &delivery
}

func TestResourcePostgresCASManagedAndManifestRecovery(t *testing.T) {
	pool, baseStore, instanceID := newPlanningTestStore(t)
	ctx := context.Background()
	store, err := baseStore.NewResourceStore()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	taskID, _ := createWorkerTask(t, baseStore)
	deploymentID := uuid.NewString()
	seedWorkerIdentityBinding(t, pool, instanceID, "owner-worker-store", taskID, deploymentID, "i-0123456789abcdef0", "123456789012")
	var approvalID uuid.UUID
	var approvedPlanHash string
	if err := pool.QueryRow(ctx, `
		SELECT launch.approval_id, plan.plan_hash
		FROM cloud_launch_operations AS launch
		JOIN cloud_plans AS plan ON plan.plan_id=launch.plan_id
		WHERE launch.deployment_id=$1`, deploymentID).Scan(&approvalID, &approvedPlanHash); err != nil {
		t.Fatalf("load Worker resource origin: %v", err)
	}
	// The worker-identity fixture includes a deliberately minimal EC2 ledger
	// row for its own identity tests. This resource-store test starts before
	// real Worker resources exist, so remove that fixture-only row while
	// retaining the exact approved launch origin.
	if _, err := pool.Exec(ctx, `DELETE FROM cloud_resources WHERE deployment_id=$1`, deploymentID); err != nil {
		t.Fatalf("remove Worker identity fixture resource: %v", err)
	}
	deadline := now.Add(30 * time.Minute).Truncate(time.Second)
	newItem := func(kind resource.Type, logicalName string, dependencies ...string) resource.ResourceV1 {
		resourceID := uuid.NewString()
		tags := map[string]string{
			resource.TagAgentInstanceID: instanceID, resource.TagOwnerID: "owner-worker-store",
			resource.TagTaskID: taskID, resource.TagDeploymentID: deploymentID, resource.TagResourceID: resourceID,
			resource.TagRetention: string(task.RetentionEphemeralAutoDestroy), resource.TagDestroyDeadline: deadline.Format(time.RFC3339),
			resource.TagApprovedPlanHash: approvedPlanHash, resource.TagApprovalID: approvalID.String(),
		}
		return resource.ResourceV1{
			ResourceID: resourceID, AgentInstanceID: instanceID, OwnerID: "owner-worker-store", TaskID: taskID,
			DeploymentID: deploymentID, Type: kind, LogicalName: logicalName, Region: "us-west-2",
			SpecDigest: "sha256:" + strings.Repeat("a", 64), ApprovedPlanHash: approvedPlanHash,
			ApprovalID: approvalID.String(), DependsOn: dependencies, Retention: task.RetentionEphemeralAutoDestroy,
			DestroyDeadline: deadline, AutoDestroyApproved: true, Tags: tags, State: resource.StateProvisioning,
			Intent:   resource.MutationIntent{Operation: resource.MutationCreate, ClientToken: strings.Repeat("c", 64), RecordedAt: now},
			Revision: 1, CreatedAt: now, UpdatedAt: now,
		}
	}
	volume, err := store.CreateIntent(ctx, newItem(resource.TypeEBS, "data-volume"))
	if err != nil {
		t.Fatal(err)
	}
	if replayed, err := store.CreateIntent(ctx, volume); err != nil || replayed.ResourceID != volume.ResourceID {
		t.Fatalf("resource intent replay=%+v err=%v", replayed, err)
	}
	secondStore, err := baseStore.NewResourceStore()
	if err != nil {
		t.Fatal(err)
	}
	staleClaim := volume
	staleClaim.Intent.ProviderCreateStartedAt = now.Add(100 * time.Millisecond)
	staleClaim.ProviderCandidateIDs = []string{"vol-candidate-a", "vol-candidate-b"}
	staleClaim.Revision, staleClaim.UpdatedAt = 2, now.Add(100*time.Millisecond)
	claimed, err := store.Save(ctx, staleClaim, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secondStore.Save(ctx, staleClaim, 1); !errors.Is(err, resource.ErrRevisionConflict) {
		t.Fatalf("cross-store provider-create fence CAS error=%v", err)
	}
	reloadedClaim, err := secondStore.Get(ctx, volume.ResourceID)
	if err != nil || !reloadedClaim.Intent.ProviderCreateStartedAt.Equal(staleClaim.Intent.ProviderCreateStartedAt) ||
		reloadedClaim.Revision != 2 || !slices.Equal(reloadedClaim.ProviderCandidateIDs, staleClaim.ProviderCandidateIDs) {
		t.Fatalf("provider-create fence did not survive reload: resource=%+v error=%v", reloadedClaim, err)
	}
	volume = claimed
	volume.ProviderCandidateIDs = nil
	volume.ProviderID = "vol-fixture"
	volume.ReadBack = resource.ReadBackEvidence{
		Exists: true, ProviderID: volume.ProviderID, ObservedAt: now.Add(time.Second), TagDigest: "sha256:" + strings.Repeat("d", 64),
	}
	volume.State, volume.Revision, volume.UpdatedAt = resource.StateActive, 3, now.Add(time.Second)
	volume, err = store.Save(ctx, volume, 2)
	if err != nil {
		t.Fatal(err)
	}
	stale := volume
	stale.Revision = 3
	if _, err := store.Save(ctx, stale, 2); !errors.Is(err, resource.ErrRevisionConflict) {
		t.Fatalf("stale resource CAS error=%v", err)
	}

	instance := newItem(resource.TypeEC2, "worker-instance", volume.ResourceID)
	instance, err = store.CreateIntent(ctx, instance)
	if err != nil {
		t.Fatal(err)
	}
	instance.ProviderID = "i-fixture"
	instance.ReadBack = resource.ReadBackEvidence{
		Exists: true, ProviderID: instance.ProviderID, ObservedAt: now.Add(2 * time.Second), TagDigest: "sha256:" + strings.Repeat("e", 64),
	}
	instance.State, instance.Revision, instance.UpdatedAt = resource.StateActive, 2, now.Add(2*time.Second)
	instance, err = store.Save(ctx, instance, 1)
	if err != nil {
		t.Fatal(err)
	}

	manifest := resource.Manifest{
		ManifestID: deploymentID, AgentInstanceID: instanceID, OwnerID: volume.OwnerID, TaskID: taskID,
		DeploymentID: deploymentID, Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: deadline,
		AutoDestroyApproved: true, AutoDestroyApprovalID: approvalID.String(), ApprovedPlanHash: volume.ApprovedPlanHash,
		ApprovalBindings: []resource.ApprovalBinding{{ApprovedPlanHash: volume.ApprovedPlanHash, ApprovalID: approvalID.String()}},
		Resources:        []resource.ResourceV1{volume, instance}, Revision: 2, UpdatedAt: now.Add(2 * time.Second),
	}
	record, err := store.PutResourceManifestPending(ctx, manifest, 0)
	if err != nil {
		t.Fatal(err)
	}
	replayedRecord, err := store.PutResourceManifestPending(ctx, manifest, 0)
	if err != nil || replayedRecord.Generation != record.Generation {
		t.Fatalf("manifest intent replay=%+v err=%v", replayedRecord, err)
	}
	canary := "sk-abcdefghijklmnopqrstuvwxyz012345"
	failed, err := store.MarkResourceManifestFailed(ctx, deploymentID, record.Generation, errors.New("Dynamo failure "+canary))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(failed.LastError, canary) || !strings.Contains(failed.LastError, "[redacted]") {
		t.Fatalf("manifest failure was not redacted: %q", failed.LastError)
	}
	pending, err := store.ListResourceManifestsNeedingRecovery(ctx, 10)
	if err != nil || len(pending) != 1 || pending[0].Status != postgres.ResourceManifestFailed {
		t.Fatalf("manifest recovery list=%+v err=%v", pending, err)
	}
	manifest.Revision++
	manifest.UpdatedAt = manifest.UpdatedAt.Add(time.Second)
	record, err = store.PutResourceManifestPending(ctx, manifest, failed.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkResourceManifestMirrored(ctx, deploymentID, record.Generation); err != nil {
		t.Fatal(err)
	}
	remoteMirror := &recordingManifestMirror{}
	trackedMirror, err := postgres.NewTrackedResourceManifestMirror(store, remoteMirror)
	if err != nil {
		t.Fatal(err)
	}
	// Two different resource updates can have the same maximum per-resource
	// revision. The tracked mirror must still assign a deployment-monotonic
	// revision instead of reusing that maximum and conflicting in DynamoDB.
	manifest.Revision = 2
	manifest.Resources[0].ReadBack.TagDigest = "sha256:" + strings.Repeat("b", 64)
	manifest.UpdatedAt = manifest.UpdatedAt.Add(time.Second)
	if err := trackedMirror.Put(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Resources[1].ReadBack.TagDigest = "sha256:" + strings.Repeat("c", 64)
	manifest.UpdatedAt = manifest.UpdatedAt.Add(time.Second)
	if err := trackedMirror.Put(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	if len(remoteMirror.revisions) != 2 || remoteMirror.revisions[1] != remoteMirror.revisions[0]+1 {
		t.Fatalf("remote manifest revisions = %v", remoteMirror.revisions)
	}
	latestRecord, err := store.GetResourceManifestRecord(ctx, deploymentID)
	if err != nil || latestRecord.Status != postgres.ResourceManifestMirrored ||
		latestRecord.Generation != record.Generation+2 || latestRecord.Manifest.Revision != remoteMirror.revisions[1] {
		t.Fatalf("latest manifest record=%+v remote revisions=%v err=%v", latestRecord, remoteMirror.revisions, err)
	}

	contract := resource.ManagedContractV1{
		DeploymentID: deploymentID, OwnerID: volume.OwnerID, AcceptanceApprovalID: uuid.NewString(),
		Currency: "USD", CostAlertAmountMinor: 5000, MonitorRef: "monitor://service/health",
		MaintenanceRef: "runbook://service/maintenance", RestartRef: "runbook://service/restart",
		BackupRef: "runbook://service/backup", RestoreRef: "runbook://service/restore",
		UpgradeRef: "runbook://service/upgrade", RollbackRef: "runbook://service/rollback",
		DestroyRef: "runbook://service/destroy", AcceptedAt: now.Add(4 * time.Second),
	}
	managed := resource.ManagedServiceV1{
		ServiceID: uuid.NewString(), Contract: contract, State: "active", Revision: 1,
		CreatedAt: now.Add(4 * time.Second), UpdatedAt: now.Add(4 * time.Second),
	}
	expected := map[string]int64{volume.ResourceID: volume.Revision, instance.ResourceID: instance.Revision}
	accepted, err := store.AcceptManaged(ctx, deploymentID, managed, expected)
	if err != nil {
		t.Fatal(err)
	}
	if len(accepted) != 2 || accepted[0].State != resource.StateRetainedManaged || accepted[1].State != resource.StateRetainedManaged {
		t.Fatalf("managed resources=%+v", accepted)
	}
	if replayed, err := store.AcceptManaged(ctx, deploymentID, managed, expected); err != nil || len(replayed) != 2 {
		t.Fatalf("managed acceptance replay=%+v err=%v", replayed, err)
	}
	changed := managed
	changed.Contract.CostAlertAmountMinor++
	if _, err := store.AcceptManaged(ctx, deploymentID, changed, expected); !errors.Is(err, resource.ErrRevisionConflict) {
		t.Fatalf("changed managed replay error=%v", err)
	}

	restarted, err := baseStore.NewResourceStore()
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := restarted.ListDeployment(ctx, deploymentID)
	if err != nil || len(reloaded) != 2 || reloaded[0].Retention != task.RetentionManaged || reloaded[1].Retention != task.RetentionManaged {
		t.Fatalf("resource restart reload=%+v err=%v", reloaded, err)
	}
	mirrored, err := restarted.GetResourceManifestRecord(ctx, deploymentID)
	if err != nil || mirrored.Status != postgres.ResourceManifestMirrored ||
		mirrored.Generation != latestRecord.Generation || mirrored.Manifest.Revision != latestRecord.Manifest.Revision {
		t.Fatalf("manifest restart reload=%+v err=%v", mirrored, err)
	}
}

func TestApprovePlanAcceptsChallengeIssuedWithinAllowedClockSkew(t *testing.T) {
	_, store, instanceID := newPlanningTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Challenge creation explicitly accepts a client clock up to 30 seconds
	// ahead of PostgreSQL. Approval must use a timestamp inside that accepted
	// challenge window instead of violating consumed_at >= issued_at.
	clientNow := time.Now().UTC().Add(2 * time.Second).Truncate(time.Microsecond)
	createApprovedResourcePlan(t, ctx, store, instanceID, "owner-clock-skew", clientNow)
}

type recordingManifestMirror struct {
	revisions []int64
}

func (mirror *recordingManifestMirror) Put(_ context.Context, manifest resource.Manifest) error {
	mirror.revisions = append(mirror.revisions, manifest.Revision)
	return nil
}

func (*recordingManifestMirror) ListExpired(context.Context, time.Time) ([]resource.Manifest, error) {
	return nil, nil
}

func createApprovedResourcePlan(
	t *testing.T,
	ctx context.Context,
	store *postgres.Store,
	agentInstanceID string,
	ownerID string,
	now time.Time,
) (string, string) {
	t.Helper()
	scope := task.MutationScope{ClientID: "resource-store-test", CredentialID: uuid.NewString()}
	plan := cloudApprovalPlanFixture(agentInstanceID)
	plan.OwnerID = ownerID
	plan.PlanID = uuid.NewString()
	plan.ConnectionID = "connection-resource-store"
	plan.ResourceScope.Region = "us-west-2"
	plan.ResourceScope.AvailabilityZones = []string{"us-west-2a", "us-west-2b"}
	var err error
	plan.Quote.ScopeDigest, err = plan.PricingScopeDigest()
	if err != nil {
		t.Fatal(err)
	}

	quoted := cloudApprovalQuoteFixture(t, plan, uuid.NewString(), now.Add(-time.Minute))
	quoteDigest, err := quoted.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan.Quote.QuoteID = quoted.QuoteID
	plan.Quote.Digest = quoteDigest
	plan.Quote.ValidUntil = quoted.ValidUntil
	createdQuote, err := store.CreateQuote(ctx, scope, postgres.CreateQuoteCommand{
		IdempotencyKey: uuid.NewString(), Quote: quoted,
	})
	if err != nil {
		t.Fatal(err)
	}
	createdPlan, err := store.CreatePlan(ctx, scope, postgres.CreatePlanCommand{
		IdempotencyKey: uuid.NewString(), Plan: plan,
	})
	if err != nil {
		t.Fatal(err)
	}

	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x63}, ed25519.SeedSize))
	device := cloudapproval.DeviceKeyV1{
		KeyID: "resource-store-device", AgentInstanceID: agentInstanceID, OwnerID: ownerID,
		Revision: 1, Status: cloudapproval.DeviceKeyActive,
		PublicKey: append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...),
		NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	}
	if _, err := store.RegisterApprovalDevice(ctx, scope, postgres.RegisterApprovalDeviceCommand{
		IdempotencyKey: uuid.NewString(), Device: device,
	}); err != nil {
		t.Fatal(err)
	}
	adapter, err := postgres.NewApprovalRepositoryAdapter(store, scope, uuid.NewString(), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	approvalService, err := cloudapproval.NewService(adapter, adapter, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	draft, err := approvalService.DraftChallenge(ctx, createdPlan, createdQuote, device.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := store.CreateApprovalChallenge(ctx, scope, postgres.CreateApprovalChallengeCommand{
		IdempotencyKey: uuid.NewString(), Challenge: draft,
	})
	if err != nil {
		t.Fatal(err)
	}
	approval := signedCloudApproval(t, createdPlan, challenge, privateKey)
	if err := approval.VerifyForPlan(device.PublicKey, createdPlan, now); err != nil {
		t.Fatalf("resource approval signature or Plan binding is invalid: %v", err)
	}
	approvedPlan, err := store.ApprovePlan(ctx, scope, postgres.ApprovePlanCommand{
		IdempotencyKey: uuid.NewString(), ExpectedChallengeRevision: 1, ExpectedPlanRevision: 1, Approval: approval,
	})
	if err != nil {
		t.Fatal(err)
	}
	if approvedPlan.Status != cloudapproval.PlanApproved {
		t.Fatalf("approved resource Plan status=%s", approvedPlan.Status)
	}
	return approval.ApprovalID, approval.PlanHash
}

func createWorkerTask(t *testing.T, store *postgres.Store) (string, string) {
	t.Helper()
	stepID := uuid.NewString()
	created, err := store.Create(context.Background(), task.MutationScope{ClientID: "worker-store-test", CredentialID: uuid.NewString()}, task.CreateCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: "owner-worker-store", Goal: "Run a durable exclusive cloud worker integration test.",
		Retention: task.RetentionEphemeralAutoDestroy,
		Steps:     []task.StepDefinition{{StepID: stepID, Name: "execute_on_exclusive_worker", ExecutorKind: task.ExecutorCloudWorker}},
	})
	if err != nil {
		t.Fatal(err)
	}
	taskUUID := uuid.MustParse(created.TaskID)
	return created.TaskID, uuid.NewSHA1(taskUUID, []byte(stepID)).String()
}

func assertWorkerCredentialCanaryAbsent(t *testing.T, pool *pgxpool.Pool, enrollment, session []byte) {
	t.Helper()
	var enrollmentDigest, sessionDigest, createNonce, createCiphertext, nonce, ciphertext []byte
	var createResponse, enrollmentResponse, mutationResponses string
	if err := pool.QueryRow(context.Background(), `
		SELECT d.enrollment_digest, d.session_digest, c.nonce, c.enrollment_ciphertext, c.response_json::text,
		       r.nonce, r.session_ciphertext,
		       r.response_json::text,
		       COALESCE((SELECT string_agg(response_json::text, '') FROM worker_mutation_replays WHERE deployment_id=d.deployment_id), '')
		FROM worker_deployments d
		JOIN worker_deployment_create_replays c USING (deployment_id)
		JOIN worker_enrollment_replays r USING (deployment_id)
		LIMIT 1`).Scan(
		&enrollmentDigest, &sessionDigest, &createNonce, &createCiphertext, &createResponse,
		&nonce, &ciphertext, &enrollmentResponse, &mutationResponses,
	); err != nil {
		t.Fatal(err)
	}
	for name, persisted := range map[string][]byte{
		"enrollment_digest": enrollmentDigest, "session_digest": sessionDigest,
		"create_nonce": createNonce, "create_ciphertext": createCiphertext, "create_response": []byte(createResponse), "nonce": nonce,
		"session_ciphertext": ciphertext, "enrollment_response": []byte(enrollmentResponse), "mutation_responses": []byte(mutationResponses),
	} {
		if bytes.Equal(persisted, enrollment) || bytes.Equal(persisted, session) || bytes.Contains(persisted, enrollment) || bytes.Contains(persisted, session) {
			t.Fatalf("worker plaintext credential reached %s", name)
		}
	}
}

func wipeIntegrationBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
