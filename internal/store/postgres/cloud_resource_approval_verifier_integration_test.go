package postgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	clouddestroy "github.com/YingSuiAI/dirextalk-agent/internal/cloud/destroy"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entrypoint"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestResourceApprovalVerifierAcceptsOnlyApprovedEntrySource(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if legacyResourceApprovalForeignKey(t, ctx, pool) {
		t.Skip("entry resource approval FK migration is required before entry resources can persist")
	}

	const ownerID = "owner-entry-resource-verifier"
	taskID, stepID := createWorkerTask(t, store)
	deploymentID := uuid.NewString()
	seedWorkerIdentityBinding(t, pool, instanceID, ownerID, taskID, deploymentID, "i-0123456789abcdef0", "123456789012")
	scope := seedEntryScope(t, ctx, pool, instanceID, ownerID, taskID, stepID, deploymentID, "i-0123456789abcdef0")
	plan, err := entrypoint.NewPlanV1(uuid.NewString(), 1, entrypoint.PlanReadyForApproval, scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateEntryPlan(ctx, entryMutation(ownerID, "entry-resource-plan", uuid.NewString()), plan); err != nil {
		t.Fatalf("create entry plan: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x73}, ed25519.SeedSize))
	device := cloudapproval.DeviceKeyV1{
		KeyID: "entry-resource-verifier-device", AgentInstanceID: instanceID, OwnerID: ownerID, Revision: 1,
		Status: cloudapproval.DeviceKeyActive, PublicKey: append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...),
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
	if _, err := store.RegisterApprovalDevice(ctx, task.MutationScope{ClientID: "entry-resource-verifier", CredentialID: uuid.NewString()},
		postgres.RegisterApprovalDeviceCommand{IdempotencyKey: uuid.NewString(), Device: device}); err != nil {
		t.Fatalf("register device: %v", err)
	}
	challenge, err := entrypoint.NewChallengeV1(plan, uuid.NewString(), uuid.NewString(), uuid.NewString(), device.KeyID, now, now.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateEntryChallenge(ctx, entryMutation(ownerID, "entry-resource-prepare", uuid.NewString()), challenge); err != nil {
		t.Fatalf("prepare entry: %v", err)
	}
	approved, err := store.ApproveEntry(ctx, entryMutation(ownerID, "entry-resource-approve", uuid.NewString()), challenge.ChallengeID,
		plan.Revision, entrySignature(challenge, ed25519.Sign(privateKey, challenge.SigningCBOR)), now.Add(time.Second))
	if err != nil {
		t.Fatalf("approve entry: %v", err)
	}
	for _, status := range []entrypoint.Status{entrypoint.StatusProvisioning, entrypoint.StatusVerifying, entrypoint.StatusActive} {
		next := approved
		next.Status, next.UpdatedAt = status, approved.UpdatedAt.Add(time.Second)
		approved, err = store.SaveEntryOperation(ctx, next, approved.Revision)
		if err != nil {
			t.Fatalf("transition entry to %s: %v", status, err)
		}
	}

	entryResourceID := uuid.NewString()
	tagsJSON, err := json.Marshal(map[string]string{
		"agent_instance_id": instanceID, "owner_id": ownerID, "task_id": taskID, "deployment_id": deploymentID,
		"resource_id": entryResourceID, "retention": string(task.RetentionEphemeralAutoDestroy),
		"destroy_deadline": scope.Retention.DestroyDeadline.UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO cloud_resources (
			resource_id,agent_instance_id,owner_id,task_id,deployment_id,resource_type,logical_name,region,
			spec_digest,approved_plan_hash,approval_id,provider_id,retention,destroy_deadline,auto_destroy_approved,
			tags,state,revision,created_at,updated_at
		) VALUES ($1,$2,$3,$4,$5,'alb','approved-entry','us-west-2',$6,$7,$8,$9,'ephemeral_auto_destroy',$10,true,$11,'active',1,$12,$12)`,
		entryResourceID, instanceID, ownerID, taskID, deploymentID, entryDigest("a"), approved.Challenge.PlanHash,
		approved.Challenge.ApprovalID, "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/dtx/0123456789abcdef", scope.Retention.DestroyDeadline, string(tagsJSON), now); err != nil {
		t.Fatalf("insert separately approved entry resource: %v", err)
	}
	var oldApprovalExists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM cloud_approvals WHERE approval_id=$1)`, approved.Challenge.ApprovalID).Scan(&oldApprovalExists); err != nil {
		t.Fatal(err)
	}
	if oldApprovalExists {
		t.Fatal("entry approval unexpectedly appeared in the original Worker approval table")
	}

	proof := clouddestroy.ResourceApprovalProofV1{
		AgentInstanceID: instanceID, OwnerID: ownerID, TaskID: taskID, DeploymentID: deploymentID, ConnectionID: scope.ConnectionID,
		OriginalPlanID: scope.Worker.OriginalPlanID, OriginalPlanHash: scope.Worker.OriginalPlanHash,
		ResourceID: entryResourceID, ApprovedPlanHash: approved.Challenge.PlanHash, ApprovalID: approved.Challenge.ApprovalID,
		Retention: task.RetentionEphemeralAutoDestroy, DestroyDeadline: scope.Retention.DestroyDeadline, AutoDestroy: true, State: "active",
	}
	if err := store.VerifyResourceApproval(ctx, proof); err != nil {
		t.Fatalf("valid separate entry approval rejected: %v", err)
	}
	for _, mutate := range []struct {
		name string
		fn   func(*clouddestroy.ResourceApprovalProofV1)
	}{
		{"entry hash", func(value *clouddestroy.ResourceApprovalProofV1) { value.ApprovedPlanHash = entryDigest("b") }},
		{"entry approval", func(value *clouddestroy.ResourceApprovalProofV1) { value.ApprovalID = uuid.NewString() }},
		{"owner", func(value *clouddestroy.ResourceApprovalProofV1) { value.OwnerID = "different-owner" }},
		{"connection", func(value *clouddestroy.ResourceApprovalProofV1) { value.ConnectionID = uuid.NewString() }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			forged := proof
			mutate.fn(&forged)
			if err := store.VerifyResourceApproval(ctx, forged); !errors.Is(err, clouddestroy.ErrInvalid) {
				t.Fatalf("forged %s verification error=%v, want ErrInvalid", mutate.name, err)
			}
		})
	}
}

func legacyResourceApprovalForeignKey(t *testing.T, ctx context.Context, pool *pgxpool.Pool) bool {
	t.Helper()
	var legacy bool
	err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid='cloud_resources'::regclass AND contype='f'
			  AND pg_get_constraintdef(oid) LIKE '%approval_id%cloud_approvals%'
		)`).Scan(&legacy)
	if err != nil {
		t.Fatalf("inspect resource approval FK: %v", err)
	}
	return legacy
}
