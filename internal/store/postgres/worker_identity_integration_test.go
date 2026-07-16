package postgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestWorkerIdentityPostgresChallengeAtomicEnrollmentAndEncryptedReplay(t *testing.T) {
	pool, baseStore, instanceID := newPlanningTestStore(t)
	ctx := context.Background()
	taskID, stepID := createWorkerTask(t, baseStore)
	workerStore, err := baseStore.NewWorkerStore(bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	service, err := worker.NewService(workerStore, bytes.Repeat([]byte{0x72}, 32))
	if err != nil {
		t.Fatal(err)
	}
	deploymentID := uuid.NewString()
	created, enrollment, err := service.CreateDeployment(ctx, worker.ControlMutation{
		ClientID: "worker-identity-store-test", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString(),
	}, worker.CreateDeploymentRequest{
		DeploymentID: deploymentID, OwnerID: "owner-worker-store", TaskID: taskID, StepID: stepID,
		ControlPlaneEndpoint: "grpcs://agent.example.internal:8443", EnrollmentTTL: 10 * time.Minute,
		RecipeBundle:     worker.BundleRef{S3Ref: "s3://agent-fixture/deployments/identity/recipe.cbor", SHA256: [32]byte{1}},
		ExecutionBundle:  worker.BundleRef{S3Ref: "s3://agent-fixture/deployments/identity/execution.json", SHA256: [32]byte{2}},
		ExecutionTimeout: 30 * time.Minute,
		Access: worker.AccessScope{
			ArtifactPrefix: "s3://agent-fixture/deployments/identity/artifacts/", CheckpointPrefix: "s3://agent-fixture/deployments/identity/checkpoints/",
			EvidencePrefix: "s3://agent-fixture/deployments/identity/evidence/", LogPrefix: "cloudwatch://agent-fixture/identity",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	enrollment.Destroy()
	providerInstanceID := "i-0123456789abcdef0"
	seedWorkerIdentityBinding(t, pool, instanceID, created.OwnerID, taskID, deploymentID, providerInstanceID, "123456789012")
	workerID := uuid.NewString()

	firstChallenge, err := service.CreateIdentityChallenge(ctx, worker.CreateIdentityChallengeRequest{
		DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: created.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE worker_identity_challenges
		SET created_at=clock_timestamp()-interval '2 minutes', expires_at=clock_timestamp()-interval '1 minute'
		WHERE challenge_id=$1`, firstChallenge.ChallengeID); err != nil {
		t.Fatal(err)
	}
	expiredIdentity, expiredMaterial := testVerifiedWorkerIdentity(firstChallenge, providerInstanceID)
	if _, credential, err := service.EnrollVerifiedIdentity(ctx, worker.VerifiedIdentityEnrollmentRequest{
		ChallengeID: firstChallenge.ChallengeID, DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(),
		ExpectedRevision: created.Revision, Identity: expiredIdentity, Materialization: expiredMaterial,
	}); !errors.Is(err, worker.ErrIdentityChallengeExpired) {
		credential.Destroy()
		t.Fatalf("expired identity challenge error=%v", err)
	}

	challengeRequest := worker.CreateIdentityChallengeRequest{
		DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(), ExpectedRevision: created.Revision,
	}
	challenge, err := service.CreateIdentityChallenge(ctx, challengeRequest)
	if err != nil {
		t.Fatal(err)
	}
	replayedChallenge, err := service.CreateIdentityChallenge(ctx, challengeRequest)
	if err != nil || replayedChallenge.ChallengeID != challenge.ChallengeID {
		t.Fatalf("challenge replay=%+v err=%v", replayedChallenge, err)
	}
	identity, materialization := testVerifiedWorkerIdentity(challenge, providerInstanceID)
	wrongIdentity := identity
	wrongIdentity.InstanceID = "i-0abcdef0123456789"
	wrongIdentity.PrincipalID = "AROAABCDEFGHIJKLMNOP:" + wrongIdentity.InstanceID
	_, wrongMaterial := testVerifiedWorkerIdentity(challenge, wrongIdentity.InstanceID)
	if _, credential, err := service.EnrollVerifiedIdentity(ctx, worker.VerifiedIdentityEnrollmentRequest{
		ChallengeID: challenge.ChallengeID, DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(),
		ExpectedRevision: created.Revision, Identity: wrongIdentity, Materialization: wrongMaterial,
	}); !errors.Is(err, worker.ErrIdentityRejected) {
		credential.Destroy()
		t.Fatalf("wrong provider instance identity error=%v", err)
	}

	enrollRequest := worker.VerifiedIdentityEnrollmentRequest{
		ChallengeID: challenge.ChallengeID, DeploymentID: deploymentID, WorkerID: workerID, IdempotencyKey: uuid.NewString(),
		ExpectedRevision: created.Revision, Identity: identity, Materialization: materialization,
	}
	type enrollmentResult struct {
		assignment worker.Assignment
		session    []byte
		err        error
	}
	results := make(chan enrollmentResult, 2)
	for range 2 {
		go func() {
			assignment, credential, enrollErr := service.EnrollVerifiedIdentity(ctx, enrollRequest)
			raw := credential.Reveal()
			credential.Destroy()
			results <- enrollmentResult{assignment: assignment, session: raw, err: enrollErr}
		}()
	}
	left, right := <-results, <-results
	defer wipeIntegrationBytes(left.session)
	defer wipeIntegrationBytes(right.session)
	if left.err != nil || right.err != nil || !bytes.Equal(left.session, right.session) || left.assignment.Revision != right.assignment.Revision {
		t.Fatalf("concurrent identity replay left=%v right=%v equal=%v", left.err, right.err, bytes.Equal(left.session, right.session))
	}
	if _, err := pool.Exec(ctx, `
		UPDATE worker_identity_challenges
		SET created_at=clock_timestamp()-interval '2 minutes', expires_at=clock_timestamp()-interval '1 minute'
		WHERE challenge_id=$1`, challenge.ChallengeID); err != nil {
		t.Fatal(err)
	}
	if resumedChallenge, err := service.CreateIdentityChallenge(ctx, challengeRequest); err != nil || resumedChallenge.ChallengeID != challenge.ChallengeID {
		t.Fatalf("consumed challenge restart replay=%+v err=%v", resumedChallenge, err)
	}
	_, resumedSession, err := service.EnrollVerifiedIdentity(ctx, enrollRequest)
	if err != nil {
		t.Fatalf("expired consumed enrollment replay: %v", err)
	}
	resumedRaw := resumedSession.Reveal()
	resumedSession.Destroy()
	if !bytes.Equal(resumedRaw, left.session) {
		wipeIntegrationBytes(resumedRaw)
		t.Fatal("response-loss restart did not replay the original identity session")
	}
	wipeIntegrationBytes(resumedRaw)
	stored, err := workerStore.Get(ctx, deploymentID)
	if err != nil || stored.ProviderInstanceID != providerInstanceID || stored.WorkerID != workerID ||
		stored.RecipeBundle != materialization.RecipeBundle || stored.ExecutionBundle != materialization.ExecutionBundle ||
		stored.Access.ArtifactPrefix != materialization.Access.ArtifactPrefix {
		t.Fatalf("stored identity Worker=%+v err=%v", stored, err)
	}
	differentKey := enrollRequest
	differentKey.IdempotencyKey = uuid.NewString()
	if _, credential, err := service.EnrollVerifiedIdentity(ctx, differentKey); !errors.Is(err, worker.ErrIdentityChallengeConsumed) {
		credential.Destroy()
		t.Fatalf("consumed challenge error=%v", err)
	}
	assertWorkerIdentitySessionAbsent(t, pool, left.session)
}

func testVerifiedWorkerIdentity(challenge worker.IdentityChallenge, instanceID string) (workeridentity.VerifiedIdentity, worker.IdentityMaterialization) {
	principalID := "AROAABCDEFGHIJKLMNOP:" + instanceID
	identity := workeridentity.VerifiedIdentity{
		Partition: "aws", AccountID: challenge.AccountID, Region: challenge.Region, WorkerRoleName: "dirextalk-worker-role",
		InstanceID: instanceID, PrincipalID: principalID, DeploymentID: challenge.DeploymentID, OwnerID: challenge.OwnerID,
		Trust: workeridentity.TrustSTSAndEC2ReadBack, VerifiedAt: time.Now().UTC(),
	}
	base := "s3://agent-fixture/workers/" + principalID + "/" + challenge.DeploymentID + "/"
	return identity, worker.IdentityMaterialization{
		RecipeBundle:    worker.BundleRef{S3Ref: base + "bundles/recipe.cbor", SHA256: [32]byte{1}},
		ExecutionBundle: worker.BundleRef{S3Ref: base + "bundles/execution.json", SHA256: [32]byte{2}},
		Access: worker.AccessScope{
			ArtifactPrefix: base + "artifacts/", CheckpointPrefix: base + "checkpoints/", EvidencePrefix: base + "evidence/",
			LogPrefix: "cloudwatch://agent-fixture/" + principalID,
		},
	}
}

func seedWorkerIdentityBinding(t *testing.T, pool *pgxpool.Pool, instanceID, ownerID, taskID, deploymentID, providerInstanceID, accountID string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := time.Now().UTC().Truncate(time.Microsecond)
	connectionID, quoteID, planID, deviceID, challengeRowID, approvalID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	keyID := "worker-identity-device-" + accountID
	challengeID := strings.Repeat("q", 36) + accountID
	controlRoleARN := "arn:aws:iam::" + accountID + ":role/control"
	digest := func(value string) string { return "sha256:" + strings.Repeat(value, 64) }
	if _, err = tx.Exec(ctx, `
		INSERT INTO cloud_connections (connection_id,agent_instance_id,owner_id,account_id,region,control_role_arn,foundation_stack_id,credential_generation,status,revision,created_at,updated_at)
		VALUES ($1,$2,$3,$4,'us-west-2',$5,'foundation-stack',1,'active',1,$6,$6)`,
		connectionID, instanceID, ownerID, accountID, controlRoleARN, now); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO cloud_quotes (quote_id,agent_instance_id,owner_id,connection_id,quote_digest,quote_json,quote_cbor,revision,quoted_at,valid_until)
		VALUES ($1,$2,$3,$4,$5,'{}',decode('01','hex'),1,$6,$7)`, quoteID, instanceID, ownerID, connectionID.String(), digest("a"), now, now.Add(15*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO cloud_plans (plan_id,agent_instance_id,owner_id,connection_id,quote_id,quote_digest,quote_scope_digest,plan_hash,status,plan_json,plan_cbor,revision,created_at,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'approved','{}',decode('01','hex'),2,$9,$9)`,
		planID, instanceID, ownerID, connectionID.String(), quoteID, digest("a"), digest("b"), digest("c"), now); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO cloud_approval_devices (device_id,key_id,agent_instance_id,owner_id,public_key,status,revision,not_before,expires_at,created_at,updated_at)
		VALUES ($1,$2,$3,$4,decode(repeat('01',32),'hex'),'active',1,$5,$6,$5,$5)`,
		deviceID, keyID, instanceID, ownerID, now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO cloud_approval_challenges (challenge_row_id,challenge_id,agent_instance_id,owner_id,plan_id,plan_revision,plan_hash,connection_id,recipe_digest,quote_id,quote_digest,quote_scope_digest,quote_candidate_id,device_id,signer_key_id,issued_at,expires_at,consumed_at,revision,created_at,updated_at)
		VALUES ($1,$2,$3,$4,$5,2,$6,$7,$8,$9,$10,$11,'recommended',$12,$13,$14,$15,$16,2,$16,$16)`,
		challengeRowID, challengeID, instanceID, ownerID, planID, digest("c"), connectionID.String(), digest("d"), quoteID,
		digest("a"), digest("b"), deviceID, keyID, now.Add(-time.Minute), now.Add(4*time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO cloud_approvals (approval_id,agent_instance_id,owner_id,plan_id,plan_revision,plan_hash,quote_id,quote_digest,challenge_row_id,signer_key_id,approval_json,signing_payload,signature,revision,approved_at)
		VALUES ($1,$2,$3,$4,2,$5,$6,$7,$8,$9,'{}',decode('01','hex'),decode(repeat('01',64),'hex'),1,$10)`,
		approvalID, instanceID, ownerID, planID, digest("c"), quoteID, digest("a"), challengeRowID, keyID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO cloud_launch_operations (operation_id,agent_instance_id,caller_client_id,caller_credential_id,idempotency_key,request_hash,owner_id,plan_id,approval_id,connection_id,task_step_id,deployment_id,task_id,state,operation_json,revision,created_at,updated_at)
		VALUES ($1,$2,'worker-identity-test',$3,$4,decode(repeat('01',32),'hex'),$5,$6,$7,$8,$9,$10,$11,'provisioning','{}',1,$12,$12)`,
		uuid.New(), instanceID, uuid.New(), uuid.New(), ownerID, planID, approvalID, connectionID, uuid.New(), deploymentID, taskID, now); err != nil {
		t.Fatal(err)
	}
	tags, _ := json.Marshal(map[string]string{
		"agent_instance_id": instanceID, "owner_id": ownerID, "task_id": taskID, "deployment_id": deploymentID,
		"resource_id": "placeholder", "retention": "ephemeral_auto_destroy", "destroy_deadline": now.Add(time.Hour).Format(time.RFC3339),
	})
	resourceID := uuid.New()
	var tagValues map[string]string
	_ = json.Unmarshal(tags, &tagValues)
	tagValues["resource_id"] = resourceID.String()
	tags, _ = json.Marshal(tagValues)
	if _, err = tx.Exec(ctx, `
		INSERT INTO cloud_resources (resource_id,agent_instance_id,owner_id,task_id,deployment_id,resource_type,logical_name,region,spec_digest,approved_plan_hash,approval_id,provider_id,retention,destroy_deadline,auto_destroy_approved,tags,state,revision,created_at,updated_at)
		VALUES ($1,$2,$3,$4,$5,'ec2','worker','us-west-2',$6,$7,$8,$9,'ephemeral_auto_destroy',$10,true,$11,'active',1,$12,$12)`,
		resourceID, instanceID, ownerID, taskID, deploymentID, digest("e"), digest("c"), approvalID, providerInstanceID, now.Add(time.Hour), string(tags), now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func assertWorkerIdentitySessionAbsent(t *testing.T, pool *pgxpool.Pool, session []byte) {
	t.Helper()
	var nonce, ciphertext []byte
	var response string
	if err := pool.QueryRow(context.Background(), `
		SELECT nonce, session_ciphertext, response_json::text
		FROM worker_identity_enrollment_replays LIMIT 1`).Scan(&nonce, &ciphertext, &response); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string][]byte{"nonce": nonce, "ciphertext": ciphertext, "response": []byte(response)} {
		if bytes.Equal(value, session) || bytes.Contains(value, session) {
			t.Fatalf("Worker identity session plaintext reached %s", name)
		}
	}
}
