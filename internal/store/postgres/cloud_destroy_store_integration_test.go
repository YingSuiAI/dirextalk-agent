package postgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	clouddestroy "github.com/YingSuiAI/dirextalk-agent/internal/cloud/destroy"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCloudDestroyStorePersistsApprovalAndFencesLifecycle(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ownerID := "owner-worker-store"
	taskID, _ := createWorkerTask(t, store)
	deploymentID := uuid.NewString()
	seedWorkerIdentityBinding(t, pool, instanceID, ownerID, taskID, deploymentID, "i-0123456789abcdef0", "123456789012")

	var planID, connectionID, planHash, originalApprovalID string
	if err := pool.QueryRow(ctx, `
		SELECT launch.plan_id::text, launch.connection_id::text, plan.plan_hash, launch.approval_id::text
		FROM cloud_launch_operations launch
		JOIN cloud_plans plan ON plan.plan_id=launch.plan_id
		WHERE launch.deployment_id=$1`, deploymentID).
		Scan(&planID, &connectionID, &planHash, &originalApprovalID); err != nil {
		t.Fatalf("read destroy prerequisite facts failed (%T)", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	seed := bytes.Repeat([]byte{0x6d}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	device := cloudapproval.DeviceKeyV1{
		KeyID: "destroy-integration-device", AgentInstanceID: instanceID, OwnerID: ownerID,
		Revision: 1, Status: cloudapproval.DeviceKeyActive,
		PublicKey: append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...),
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
	if _, err := store.RegisterApprovalDevice(ctx,
		task.MutationScope{ClientID: "destroy-integration", CredentialID: uuid.NewString()},
		postgres.RegisterApprovalDeviceCommand{IdempotencyKey: uuid.NewString(), Device: device},
	); err != nil {
		t.Fatalf("register destroy approval device failed: %v", err)
	}
	concurrentChallenge := destroyChallengeFixture(t, instanceID, ownerID, taskID, deploymentID, planID, planHash, connectionID, originalApprovalID, device.KeyID, now)
	exerciseConcurrentDestroyReplay(t, ctx, pool, store, concurrentChallenge, privateKey, now)

	challenge := destroyChallengeFixture(t, instanceID, ownerID, taskID, deploymentID, planID, planHash, connectionID, originalApprovalID, device.KeyID, now)
	prepare := destroyMutation(ownerID, "destroy-prepare", uuid.NewString())
	created, err := store.CreateDestroyChallenge(ctx, prepare, challenge)
	if err != nil {
		t.Fatalf("create destroy challenge failed: %v", err)
	}
	replayed, err := store.CreateDestroyChallenge(ctx, prepare, challenge)
	if err != nil {
		t.Fatalf("replay destroy challenge failed: %v", err)
	}
	if replayed.OperationID != created.OperationID || replayed.ChallengeID != created.ChallengeID ||
		replayed.ScopeDigest != created.ScopeDigest || !bytes.Equal(replayed.SigningCBOR, created.SigningCBOR) {
		t.Fatalf("exact challenge replay changed persisted response: %#v", replayed)
	}

	conflict := challenge
	conflict.Scope.Resources = append([]clouddestroy.ResourceScopeV1(nil), challenge.Scope.Resources...)
	conflict.Scope.Resources[0].SpecDigest = destroyDigest("f")
	conflict.ScopeDigest, err = clouddestroy.ScopeDigest(conflict.Scope)
	if err != nil {
		t.Fatal(err)
	}
	conflict.SigningCBOR, err = conflict.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	conflictingPrepare := prepare
	conflictingPrepare.RequestHash = sha256.Sum256([]byte("destroy-prepare-different-spec"))
	if _, err := store.CreateDestroyChallenge(ctx, conflictingPrepare, conflict); !errors.Is(err, clouddestroy.ErrIdempotencyConflict) {
		t.Fatalf("changed destroy challenge replay error=%v", err)
	}

	signed := ed25519.Sign(privateKey, challenge.SigningCBOR)
	tampered := append([]byte(nil), signed...)
	tampered[0] ^= 0xff
	badSignature := destroySignature(challenge, tampered)
	if _, err := store.ApproveDestroy(ctx, destroyMutation(ownerID, "destroy-approve-tampered", uuid.NewString()),
		challenge.ChallengeID, challenge.Scope.DeploymentRevision, badSignature, now.Add(time.Second)); !errors.Is(err, clouddestroy.ErrApprovalRequired) {
		t.Fatalf("tampered destroy approval error=%v", err)
	}

	approve := destroyMutation(ownerID, "destroy-approve", uuid.NewString())
	operation, err := store.ApproveDestroy(ctx, approve, challenge.ChallengeID, challenge.Scope.DeploymentRevision,
		destroySignature(challenge, signed), now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("approve destroy operation failed: %v", err)
	}
	if operation.Status != clouddestroy.StatusApproved || operation.Revision != 2 || operation.ApprovedAt == nil {
		t.Fatalf("approved destroy operation=%#v", operation)
	}

	restarted, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := restarted.GetDestroyOperation(ctx, ownerID, operation.Challenge.OperationID)
	if err != nil {
		t.Fatalf("read destroy operation after Store reconstruction failed: %v", err)
	}
	if persisted.Status != clouddestroy.StatusApproved || persisted.Revision != 2 || !bytes.Equal(persisted.Signature, signed) {
		t.Fatalf("restarted destroy operation=%#v", persisted)
	}
	if _, err := restarted.GetDestroyOperation(ctx, "different-owner", operation.Challenge.OperationID); !errors.Is(err, clouddestroy.ErrNotFound) {
		t.Fatalf("cross-owner destroy operation read error=%v", err)
	}
	pending, err := restarted.ListPendingDestroy(ctx, 16)
	if err != nil || len(pending) != 1 || pending[0].Challenge.OperationID != operation.Challenge.OperationID {
		t.Fatalf("pending destroy operations=%#v err=%v", pending, err)
	}

	destroying := persisted
	destroying.Status = clouddestroy.StatusDestroying
	destroying.UpdatedAt = persisted.UpdatedAt.Add(time.Second)
	destroying, err = restarted.SaveDestroyOperation(ctx, destroying, persisted.Revision)
	if err != nil || destroying.Revision != 3 {
		t.Fatalf("approved -> destroying=%#v err=%v", destroying, err)
	}

	stale := destroying
	stale.Status = clouddestroy.StatusDestroyBlocked
	stale.ErrorCode = "AWS_READ_BACK_PENDING"
	stale.BlockedReason = "provider read-back did not confirm absence"
	stale.UpdatedAt = destroying.UpdatedAt.Add(time.Second)
	if _, err := restarted.SaveDestroyOperation(ctx, stale, persisted.Revision); !errors.Is(err, clouddestroy.ErrRevisionConflict) {
		t.Fatalf("stale destroy transition error=%v", err)
	}

	blocked, err := restarted.SaveDestroyOperation(ctx, stale, destroying.Revision)
	if err != nil || blocked.Status != clouddestroy.StatusDestroyBlocked || blocked.Revision != 4 {
		t.Fatalf("destroying -> blocked=%#v err=%v", blocked, err)
	}
	retrying := blocked
	retrying.Status = clouddestroy.StatusDestroying
	retrying.ErrorCode = ""
	retrying.BlockedReason = ""
	retrying.UpdatedAt = blocked.UpdatedAt.Add(time.Second)
	retrying, err = restarted.SaveDestroyOperation(ctx, retrying, blocked.Revision)
	if err != nil || retrying.Revision != 5 {
		t.Fatalf("blocked -> destroying=%#v err=%v", retrying, err)
	}
	verified := retrying
	verified.Status = clouddestroy.StatusVerifiedDestroyed
	verified.UpdatedAt = retrying.UpdatedAt.Add(time.Second)
	verified, err = restarted.SaveDestroyOperation(ctx, verified, retrying.Revision)
	if err != nil || verified.Revision != 6 {
		t.Fatalf("destroying -> verified=%#v err=%v", verified, err)
	}
	pending, err = restarted.ListPendingDestroy(ctx, 16)
	if err != nil || len(pending) != 0 {
		t.Fatalf("verified operation remained pending: %#v err=%v", pending, err)
	}
}

func exerciseConcurrentDestroyReplay(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	store *postgres.Store,
	challenge clouddestroy.ChallengeV1,
	privateKey ed25519.PrivateKey,
	now time.Time,
) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION cloud_destroy_insert_delay() RETURNS trigger LANGUAGE plpgsql AS $function$
		BEGIN
			PERFORM pg_sleep(0.2);
			RETURN NEW;
		END
		$function$;
		CREATE TRIGGER cloud_destroy_insert_delay
		BEFORE INSERT ON cloud_destroy_operations
		FOR EACH ROW EXECUTE FUNCTION cloud_destroy_insert_delay()`); err != nil {
		t.Fatalf("install concurrent destroy insert barrier failed (%T)", err)
	}
	prepare := destroyMutation(challenge.Scope.OwnerID, "destroy-concurrent-prepare", uuid.NewString())
	created := make([]clouddestroy.ChallengeV1, 2)
	errorsByAttempt := make([]error, len(created))
	start := make(chan struct{})
	var group sync.WaitGroup
	for index := range created {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			<-start
			created[index], errorsByAttempt[index] = store.CreateDestroyChallenge(ctx, prepare, challenge)
		}(index)
	}
	close(start)
	group.Wait()
	if _, err := pool.Exec(ctx, `
		DROP TRIGGER cloud_destroy_insert_delay ON cloud_destroy_operations;
		DROP FUNCTION cloud_destroy_insert_delay()`); err != nil {
		t.Fatalf("remove concurrent destroy insert barrier failed (%T)", err)
	}
	for index, attemptErr := range errorsByAttempt {
		if attemptErr != nil {
			t.Fatalf("concurrent exact destroy challenge replay %d failed: %v", index, attemptErr)
		}
		if created[index].OperationID != challenge.OperationID || created[index].ScopeDigest != challenge.ScopeDigest ||
			!bytes.Equal(created[index].SigningCBOR, challenge.SigningCBOR) {
			t.Fatalf("concurrent exact destroy challenge replay %d changed response: %#v", index, created[index])
		}
	}

	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION cloud_destroy_update_delay() RETURNS trigger LANGUAGE plpgsql AS $function$
		BEGIN
			PERFORM pg_sleep(0.2);
			RETURN NEW;
		END
		$function$;
		CREATE TRIGGER cloud_destroy_update_delay
		BEFORE UPDATE OF status ON cloud_destroy_operations
		FOR EACH ROW WHEN (OLD.status = 'awaiting_approval')
		EXECUTE FUNCTION cloud_destroy_update_delay()`); err != nil {
		t.Fatalf("install concurrent destroy approval barrier failed (%T)", err)
	}
	signature := destroySignature(challenge, ed25519.Sign(privateKey, challenge.SigningCBOR))
	approve := destroyMutation(challenge.Scope.OwnerID, "destroy-concurrent-approve", uuid.NewString())
	operations := make([]clouddestroy.OperationV1, 2)
	errorsByAttempt = make([]error, len(operations))
	start = make(chan struct{})
	for index := range operations {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			<-start
			operations[index], errorsByAttempt[index] = store.ApproveDestroy(ctx, approve, challenge.ChallengeID,
				challenge.Scope.DeploymentRevision, signature, now.Add(time.Second))
		}(index)
	}
	close(start)
	group.Wait()
	if _, err := pool.Exec(ctx, `
		DROP TRIGGER cloud_destroy_update_delay ON cloud_destroy_operations;
		DROP FUNCTION cloud_destroy_update_delay()`); err != nil {
		t.Fatalf("remove concurrent destroy approval barrier failed (%T)", err)
	}
	for index, attemptErr := range errorsByAttempt {
		if attemptErr != nil {
			t.Fatalf("concurrent exact destroy approval replay %d failed: %v", index, attemptErr)
		}
		if operations[index].Status != clouddestroy.StatusApproved || operations[index].Revision != 2 ||
			!bytes.Equal(operations[index].Signature, signature.Signature) {
			t.Fatalf("concurrent exact destroy approval replay %d changed response: %#v", index, operations[index])
		}
	}

	destroying := operations[0]
	destroying.Status = clouddestroy.StatusDestroying
	destroying.UpdatedAt = destroying.UpdatedAt.Add(time.Second)
	destroying, err := store.SaveDestroyOperation(ctx, destroying, operations[0].Revision)
	if err != nil {
		t.Fatalf("clean up concurrent destroy replay operation failed: %v", err)
	}
	verified := destroying
	verified.Status = clouddestroy.StatusVerifiedDestroyed
	verified.UpdatedAt = verified.UpdatedAt.Add(time.Second)
	if _, err := store.SaveDestroyOperation(ctx, verified, destroying.Revision); err != nil {
		t.Fatalf("verify concurrent destroy replay operation failed: %v", err)
	}
}

func destroyChallengeFixture(
	t *testing.T,
	instanceID, ownerID, taskID, deploymentID, planID, planHash, connectionID, originalApprovalID, signerKeyID string,
	now time.Time,
) clouddestroy.ChallengeV1 {
	t.Helper()
	resourceID := uuid.NewString()
	value := clouddestroy.ChallengeV1{
		OperationID: uuid.NewString(), ChallengeID: uuid.NewString(), ApprovalID: uuid.NewString(), SignerKeyID: signerKeyID,
		Scope: clouddestroy.ScopeV1{
			SchemaVersion: clouddestroy.ScopeSchemaV1, AgentInstanceID: instanceID, OwnerID: ownerID,
			DeploymentID: deploymentID, DeploymentRevision: 2, TaskID: taskID, PlanID: planID, PlanHash: planHash, ConnectionID: connectionID,
			Resources: []clouddestroy.ResourceScopeV1{{
				ResourceID: resourceID, Type: resource.TypeEC2, ProviderID: "i-0123456789abcdef0", Revision: 1,
				Retention: task.RetentionEphemeralAutoDestroy, State: resource.StateActive, Region: "us-west-2",
				SpecDigest: destroyDigest("e"), ApprovedPlanHash: planHash, OriginalApprovalID: originalApprovalID,
				ReadBack:        clouddestroy.ReadBackScopeV1{Observed: true, Exists: true, ProviderID: "i-0123456789abcdef0", ObservedAt: now, TagDigest: destroyDigest("d")},
				DestroyDeadline: now.Add(30 * time.Minute), AutoDestroyApproved: true,
			}},
		},
		IssuedAt: now, ExpiresAt: now.Add(clouddestroy.ChallengeValidity), Revision: 1,
	}
	var err error
	value.ScopeDigest, err = clouddestroy.ScopeDigest(value.Scope)
	if err != nil {
		t.Fatal(err)
	}
	value.SigningCBOR, err = value.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func destroyMutation(ownerID, label, idempotencyKey string) clouddestroy.Mutation {
	return clouddestroy.Mutation{
		Caller:  clouddestroy.MutationScope{ClientID: "destroy-integration", CredentialID: uuid.NewString()},
		OwnerID: ownerID, IdempotencyKey: idempotencyKey, RequestHash: sha256.Sum256([]byte(label)),
	}
}

func destroySignature(challenge clouddestroy.ChallengeV1, signature []byte) clouddestroy.SignatureV1 {
	return clouddestroy.SignatureV1{
		ApprovalID: challenge.ApprovalID, ChallengeID: challenge.ChallengeID, SignerKeyID: challenge.SignerKeyID,
		ExpiresAt: challenge.ExpiresAt, Signature: signature,
	}
}

func destroyDigest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }
