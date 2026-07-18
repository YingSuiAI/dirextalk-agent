package postgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"github.com/google/uuid"
)

func TestWorkerServiceOperationPostgresPersistsLeaseAndExactReplay(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	taskID, stepID := createWorkerTask(t, store)
	deploymentID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO worker_deployments
		(deployment_id,agent_instance_id,owner_id,task_id,step_id,control_plane_endpoint,recipe_bundle_ref,recipe_bundle_sha256,
		 execution_bundle_ref,execution_bundle_sha256,execution_timeout_seconds,worker_id,state,outcome,artifact_prefix,checkpoint_prefix,
		 evidence_prefix,log_prefix,enrollment_digest,enrollment_expires_at,session_digest,enrollment_consumed_at,revision,created_at,updated_at)
		VALUES($1,$2,'owner-worker-operation',$3,$4,'grpcs://agent.example:8443','s3://bucket/recipe',$5,
		 's3://bucket/execution',$6,300,$7,'finished','succeeded','s3://bucket/artifacts/','s3://bucket/checkpoints/',
		 's3://bucket/evidence/','cloudwatch://worker-operation/logs',$8,$9,$10,$11,1,$12,$12)`,
		deploymentID, instanceID, taskID, stepID, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32),
		uuid.NewString(), bytes.Repeat([]byte{3}, 32), now.Add(time.Hour), bytes.Repeat([]byte{4}, 32), now, now); err != nil {
		t.Fatal(err)
	}
	repository, err := postgres.NewWorkerServiceOperationStore(store)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, _ := ed25519.GenerateKey(nil)
	service, err := workeroperation.NewService(repository,
		workeroperation.Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{"root-1": publicKey}},
		func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	createRequest := workeroperation.CreateRestartRequest{
		OperationID: uuid.NewString(), DeploymentID: deploymentID, OwnerID: "owner-worker-operation",
		LifecycleRestartRef: "restart-service", ExecutionBundleDigest: postgresWorkerOperationDigest('a'),
		ExpectedInstalledManifestDigest: postgresWorkerOperationDigest('b'),
		IdempotencyKey:                  uuid.NewString(),
	}
	created, err := service.CreateRestart(ctx, createRequest)
	if err != nil {
		t.Fatal(err)
	}
	claimRequest := workeroperation.ClaimRequest{
		OperationID: created.OperationID, DeploymentID: deploymentID, WorkerID: uuid.NewString(),
		IdempotencyKey: uuid.NewString(), ExpectedRevision: created.Revision, LeaseDuration: time.Minute,
	}
	claimed, err := service.Claim(ctx, claimRequest)
	if err != nil {
		t.Fatal(err)
	}
	acquireRequest := workeroperation.AcquireRequest{
		DeploymentID: deploymentID, WorkerID: claimRequest.WorkerID,
		IdempotencyKey: uuid.NewString(), LeaseDuration: time.Minute,
	}
	recovered, err := service.AcquireNext(ctx, acquireRequest)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.OperationID != claimed.OperationID || recovered.DeploymentID != deploymentID ||
		recovered.Revision != claimed.Revision || recovered.LeaseEpoch != claimed.LeaseEpoch {
		t.Fatalf("active recovery=%#v claimed=%#v", recovered, claimed)
	}

	restartedRepository, err := postgres.NewWorkerServiceOperationStore(store)
	if err != nil {
		t.Fatal(err)
	}
	restarted, _ := workeroperation.NewService(restartedRepository,
		workeroperation.Ed25519ReceiptVerifier{Keys: map[string]ed25519.PublicKey{"root-1": publicKey}},
		func() time.Time { return now })
	replayed, err := restarted.Claim(ctx, claimRequest)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Revision != claimed.Revision || replayed.LeaseEpoch != claimed.LeaseEpoch ||
		!replayed.LeaseExpiresAt.Equal(claimed.LeaseExpiresAt) {
		t.Fatalf("restart replay = %#v, want %#v", replayed, claimed)
	}
	acquireReplay, err := restarted.AcquireNext(ctx, acquireRequest)
	if err != nil {
		t.Fatal(err)
	}
	if acquireReplay.OperationID != recovered.OperationID || acquireReplay.DeploymentID != deploymentID ||
		acquireReplay.Revision != recovered.Revision || acquireReplay.LeaseEpoch != recovered.LeaseEpoch ||
		!acquireReplay.LeaseExpiresAt.Equal(recovered.LeaseExpiresAt) {
		t.Fatalf("acquire replay=%#v recovered=%#v", acquireReplay, recovered)
	}
}

func postgresWorkerOperationDigest(value byte) string {
	result := make([]byte, 64)
	for index := range result {
		result[index] = value
	}
	return "sha256:" + string(result)
}
