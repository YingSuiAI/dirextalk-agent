package postgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entrypoint"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCloudEntryStorePersistsSeparateApprovalAndFencesTransitions(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const ownerID = "owner-worker-store"
	taskID, stepID := createWorkerTask(t, store)
	deploymentID := uuid.NewString()
	const instanceIDProvider = "i-0123456789abcdef0"
	seedWorkerIdentityBinding(t, pool, instanceID, ownerID, taskID, deploymentID, instanceIDProvider, "123456789012")
	scope := seedEntryScope(t, ctx, pool, instanceID, ownerID, taskID, stepID, deploymentID, instanceIDProvider)
	plan, err := entrypoint.NewPlanV1(uuid.NewString(), 1, entrypoint.PlanReadyForApproval, scope)
	if err != nil {
		t.Fatal(err)
	}
	create := entryMutation(ownerID, "entry-plan", uuid.NewString())
	created, err := store.CreateEntryPlan(ctx, create, plan)
	if err != nil {
		t.Fatalf("create entry plan failed: %v", err)
	}
	replayed, err := store.CreateEntryPlan(ctx, create, plan)
	if err != nil || replayed.EntryPlanID != created.EntryPlanID || replayed.ScopeDigest != created.ScopeDigest {
		t.Fatalf("exact entry plan replay=%#v err=%v", replayed, err)
	}
	conflict := create
	conflict.RequestHash = sha256.Sum256([]byte("entry-plan-different"))
	if _, err := store.CreateEntryPlan(ctx, conflict, plan); !errors.Is(err, entrypoint.ErrIdempotencyConflict) {
		t.Fatalf("changed entry plan replay error=%v", err)
	}
	if _, err := store.GetEntryPlan(ctx, "different-owner", plan.EntryPlanID); !errors.Is(err, entrypoint.ErrNotFound) {
		t.Fatalf("cross-owner entry plan read error=%v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	if !now.Before(scope.Cost.ValidUntil) {
		t.Fatal("entry quote unexpectedly expired before approval test")
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x53}, ed25519.SeedSize))
	device := cloudapproval.DeviceKeyV1{
		KeyID: "entry-store-integration-device", AgentInstanceID: instanceID, OwnerID: ownerID,
		Revision: 1, Status: cloudapproval.DeviceKeyActive,
		PublicKey: append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...),
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
	if _, err := store.RegisterApprovalDevice(ctx, task.MutationScope{ClientID: "entry-store-integration", CredentialID: uuid.NewString()},
		postgres.RegisterApprovalDeviceCommand{IdempotencyKey: uuid.NewString(), Device: device}); err != nil {
		t.Fatalf("register entry approval device failed: %v", err)
	}
	challenge, err := entrypoint.NewChallengeV1(plan, uuid.NewString(), uuid.NewString(), uuid.NewString(), device.KeyID, now, now.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	prepare := entryMutation(ownerID, "entry-prepare", uuid.NewString())
	if _, err := pool.Exec(ctx, `UPDATE cloud_resources SET readback_exists=false WHERE resource_id=$1`, scope.Worker.WorkerResourceID); err != nil {
		t.Fatalf("remove worker read-back fixture failed: %v", err)
	}
	if _, err := store.CreateEntryChallenge(ctx, prepare, challenge); !errors.Is(err, entrypoint.ErrRevisionConflict) {
		t.Fatalf("stale worker read-back prepare error=%v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE cloud_resources SET readback_exists=true WHERE resource_id=$1`, scope.Worker.WorkerResourceID); err != nil {
		t.Fatalf("restore worker read-back fixture failed: %v", err)
	}
	prepared, err := store.CreateEntryChallenge(ctx, prepare, challenge)
	if err != nil {
		t.Fatalf("create entry challenge failed: %v", err)
	}
	preparedReplay, err := store.CreateEntryChallenge(ctx, prepare, challenge)
	if err != nil || preparedReplay.ChallengeID != prepared.ChallengeID || !bytes.Equal(preparedReplay.SigningCBOR, prepared.SigningCBOR) {
		t.Fatalf("exact entry challenge replay=%#v err=%v", preparedReplay, err)
	}
	conflictingPrepare := prepare
	conflictingPrepare.RequestHash = sha256.Sum256([]byte("entry-prepare-different"))
	if _, err := store.CreateEntryChallenge(ctx, conflictingPrepare, challenge); !errors.Is(err, entrypoint.ErrIdempotencyConflict) {
		t.Fatalf("changed entry challenge replay error=%v", err)
	}

	signed := ed25519.Sign(privateKey, challenge.SigningCBOR)
	tampered := append([]byte(nil), signed...)
	tampered[0] ^= 0xff
	bad := entrySignature(challenge, tampered)
	if _, err := store.ApproveEntry(ctx, entryMutation(ownerID, "entry-approve-tampered", uuid.NewString()), challenge.ChallengeID, plan.Revision, bad, now.Add(time.Second)); !errors.Is(err, entrypoint.ErrApprovalRequired) {
		t.Fatalf("tampered entry approval error=%v", err)
	}
	approve := entryMutation(ownerID, "entry-approve", uuid.NewString())
	operation, err := store.ApproveEntry(ctx, approve, challenge.ChallengeID, plan.Revision, entrySignature(challenge, signed), now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("approve entry operation failed: %v", err)
	}
	if operation.Status != entrypoint.StatusApproved || operation.Revision != 2 || operation.ApprovedAt == nil {
		t.Fatalf("approved entry operation=%#v", operation)
	}
	approvedReplay, err := store.ApproveEntry(ctx, approve, challenge.ChallengeID, plan.Revision, entrySignature(challenge, signed), now.Add(2*time.Second))
	if err != nil || approvedReplay.Revision != operation.Revision || approvedReplay.Status != entrypoint.StatusApproved {
		t.Fatalf("exact entry approval replay=%#v err=%v", approvedReplay, err)
	}
	conflictingApprove := approve
	conflictingApprove.RequestHash = sha256.Sum256([]byte("entry-approve-different"))
	if _, err := store.ApproveEntry(ctx, conflictingApprove, challenge.ChallengeID, plan.Revision, entrySignature(challenge, signed), now.Add(2*time.Second)); !errors.Is(err, entrypoint.ErrIdempotencyConflict) {
		t.Fatalf("changed entry approval replay error=%v", err)
	}
	approvedPlan, err := store.GetEntryPlan(ctx, ownerID, plan.EntryPlanID)
	if err != nil || approvedPlan.Status != entrypoint.PlanApproved || approvedPlan.Revision != plan.Revision {
		t.Fatalf("persisted approved entry plan=%#v err=%v", approvedPlan, err)
	}

	restarted, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := restarted.GetEntryOperation(ctx, ownerID, operation.Challenge.OperationID)
	if err != nil || persisted.Status != entrypoint.StatusApproved || persisted.Signature == nil || !bytes.Equal(persisted.Signature.Signature, signed) {
		t.Fatalf("restarted entry operation=%#v err=%v", persisted, err)
	}
	if _, err := restarted.GetEntryOperation(ctx, "different-owner", operation.Challenge.OperationID); !errors.Is(err, entrypoint.ErrNotFound) {
		t.Fatalf("cross-owner entry operation read error=%v", err)
	}
	pending, err := restarted.ListPendingEntry(ctx, 16)
	if err != nil || len(pending) != 1 || pending[0].Challenge.OperationID != operation.Challenge.OperationID {
		t.Fatalf("pending entry operations=%#v err=%v", pending, err)
	}

	provisioning := persisted
	provisioning.Status = entrypoint.StatusProvisioning
	provisioning.UpdatedAt = persisted.UpdatedAt.Add(time.Second)
	provisioning, err = restarted.SaveEntryOperation(ctx, provisioning, persisted.Revision)
	if err != nil || provisioning.Revision != 3 {
		t.Fatalf("approved -> provisioning=%#v err=%v", provisioning, err)
	}
	stale := provisioning
	stale.Status = entrypoint.StatusVerifying
	stale.UpdatedAt = provisioning.UpdatedAt.Add(time.Second)
	if _, err := restarted.SaveEntryOperation(ctx, stale, persisted.Revision); !errors.Is(err, entrypoint.ErrRevisionConflict) {
		t.Fatalf("stale entry transition error=%v", err)
	}
	verifying, err := restarted.SaveEntryOperation(ctx, stale, provisioning.Revision)
	if err != nil || verifying.Revision != 4 {
		t.Fatalf("provisioning -> verifying=%#v err=%v", verifying, err)
	}
	active := verifying
	active.Status = entrypoint.StatusActive
	active.UpdatedAt = verifying.UpdatedAt.Add(time.Second)
	active, err = restarted.SaveEntryOperation(ctx, active, verifying.Revision)
	if err != nil || active.Revision != 5 {
		t.Fatalf("verifying -> active=%#v err=%v", active, err)
	}
	destroying := active
	destroying.Status = entrypoint.StatusDestroying
	destroying.UpdatedAt = active.UpdatedAt.Add(time.Second)
	destroying, err = restarted.SaveEntryOperation(ctx, destroying, active.Revision)
	if err != nil || destroying.Revision != 6 {
		t.Fatalf("active -> destroying=%#v err=%v", destroying, err)
	}
	blocked := destroying
	blocked.Status = entrypoint.StatusDestroyBlocked
	blocked.ErrorCode = entrypoint.ErrorCodeDestroyBlocked
	blocked.ErrorSummary = "provider read-back did not confirm entry resource absence"
	blocked.UpdatedAt = destroying.UpdatedAt.Add(time.Second)
	blocked, err = restarted.SaveEntryOperation(ctx, blocked, destroying.Revision)
	if err != nil || blocked.Revision != 7 {
		t.Fatalf("destroying -> blocked=%#v err=%v", blocked, err)
	}
	destroying = blocked
	destroying.Status = entrypoint.StatusDestroying
	destroying.ErrorCode = entrypoint.ErrorCodeNone
	destroying.ErrorSummary = ""
	destroying.UpdatedAt = blocked.UpdatedAt.Add(time.Second)
	destroying, err = restarted.SaveEntryOperation(ctx, destroying, blocked.Revision)
	if err != nil || destroying.Revision != 8 {
		t.Fatalf("blocked -> destroying=%#v err=%v", destroying, err)
	}
	destroyed := destroying
	destroyed.Status = entrypoint.StatusDestroyed
	destroyed.UpdatedAt = destroying.UpdatedAt.Add(time.Second)
	destroyed, err = restarted.SaveEntryOperation(ctx, destroyed, destroying.Revision)
	if err != nil || destroyed.Revision != 9 {
		t.Fatalf("destroying -> destroyed=%#v err=%v", destroyed, err)
	}
	pending, err = restarted.ListPendingEntry(ctx, 16)
	if err != nil || len(pending) != 0 {
		t.Fatalf("destroyed entry operation remained pending=%#v err=%v", pending, err)
	}
}

func seedEntryScope(t *testing.T, ctx context.Context, pool *pgxpool.Pool, instanceID, ownerID, taskID, stepID, deploymentID, providerInstanceID string) entrypoint.ScopeV1 {
	t.Helper()
	var planID, approvalID, connectionID, resourceID, quoteID uuid.UUID
	var planHash, resourceSpecDigest, quoteDigest string
	var quotedAt, validUntil, destroyDeadline time.Time
	if err := pool.QueryRow(ctx, `SELECT launch.plan_id, plan.plan_hash, launch.approval_id, launch.connection_id,
		resource.resource_id, resource.spec_digest, resource.destroy_deadline,
		quote.quote_id, quote.quote_digest, quote.quoted_at, quote.valid_until
		FROM cloud_launch_operations launch
		JOIN cloud_resources resource ON resource.deployment_id=launch.deployment_id AND resource.resource_type='ec2'
		JOIN cloud_plans plan ON plan.plan_id=launch.plan_id
		JOIN cloud_quotes quote ON quote.quote_id=plan.quote_id
		WHERE launch.deployment_id=$1`, deploymentID).Scan(
		&planID, &planHash, &approvalID, &connectionID, &resourceID, &resourceSpecDigest, &destroyDeadline,
		&quoteID, &quoteDigest, &quotedAt, &validUntil); err != nil {
		t.Fatalf("read entrypoint fixture prerequisites failed: %v", err)
	}
	observedAt := quotedAt.Add(10 * time.Second).UTC().Truncate(time.Microsecond)
	readBackDigest := entryDigest("c")
	var resourceRevision int64
	if err := pool.QueryRow(ctx, `UPDATE cloud_resources SET
		readback_exists=true, readback_provider_id=$2, readback_observed_at=$3,
		readback_tag_digest=$4, revision=revision+1, updated_at=$3
		WHERE resource_id=$1 RETURNING revision`, resourceID, providerInstanceID, observedAt, readBackDigest).Scan(&resourceRevision); err != nil {
		t.Fatalf("record independent worker read-back failed: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO worker_deployments (
		deployment_id, agent_instance_id, owner_id, task_id, step_id, control_plane_endpoint,
		recipe_bundle_ref, recipe_bundle_sha256, execution_bundle_ref, execution_bundle_sha256,
		execution_timeout_seconds, worker_id, state, outcome, artifact_prefix, checkpoint_prefix,
		evidence_prefix, log_prefix, enrollment_digest, enrollment_expires_at, enrollment_consumed_at,
		session_digest, revision, created_at, updated_at, provider_instance_id
	) VALUES ($1,$2,$3,$4,$5,'grpcs://agent.fixture.test:9443',
		's3://fixture/recipe.tgz',$6,'s3://fixture/execution.tgz',$7,
		600,$8,'finished','succeeded','s3://fixture/artifacts/','s3://fixture/checkpoints/',
		's3://fixture/evidence/','cloudwatch://fixture/logs',$9,$10,$11,$12,3,$11,$11,$13)`,
		deploymentID, instanceID, ownerID, taskID, stepID,
		bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x12}, 32), uuid.New(), bytes.Repeat([]byte{0x13}, 32),
		observedAt.Add(time.Hour), observedAt.Add(-time.Second), bytes.Repeat([]byte{0x14}, 32), providerInstanceID); err != nil {
		t.Fatalf("seed successful worker deployment failed: %v", err)
	}
	return entrypoint.ScopeV1{
		SchemaVersion: entrypoint.ScopeSchemaV1, Kind: entrypoint.EntryKindALB,
		AgentInstanceID: instanceID, OwnerID: ownerID, ConnectionID: connectionID.String(), Region: "us-west-2",
		Worker: entrypoint.WorkerReadBackScopeV1{
			DeploymentID: deploymentID, DeploymentRevision: 3, TaskID: taskID,
			OriginalPlanID: planID.String(), OriginalPlanHash: planHash, OriginalApprovalID: approvalID.String(),
			WorkerResourceID: resourceID.String(), WorkerResourceRevision: resourceRevision, WorkerSpecDigest: resourceSpecDigest,
			InstanceID: providerInstanceID, VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0", SecurityGroupID: "sg-0123456789abcdef0",
			ExecutionOutcome: entrypoint.WorkerOutcomeSucceeded, SucceededAt: observedAt.Add(-time.Second),
			ReadBack:  entrypoint.AWSReadBackV1{Observed: true, Exists: true, State: entrypoint.EC2InstanceRunning, ObservedAt: observedAt, TagDigest: readBackDigest},
			Retention: entrypoint.RetentionScopeV1{Class: entrypoint.RetentionEphemeral, AutoDestroy: true, DestroyDeadline: destroyDeadline},
		},
		Recipe: entrypoint.RecipeHealthBindingV1{RecipeDigest: entryDigest("d"), HealthContractDigest: entryDigest("e"), AuthenticationContractDigest: entryDigest("f")},
		Certificate: entrypoint.CertificateScopeV1{CertificateARN: "arn:aws:acm:us-west-2:123456789012:certificate/12345678-1234-4234-8234-1234567890ab",
			Region: "us-west-2", Hostname: "service.example.com", SubjectAlternativeNames: []string{"service.example.com", "*.example.com"},
			Status: entrypoint.CertificateStatusIssued, ReadBackDigest: entryDigest("1"), ObservedAt: observedAt},
		ALB: entrypoint.ALBScopeV1{Scheme: entrypoint.ALBSchemeInternetFacing, ListenerPort: entrypoint.HTTPSPort,
			ListenerProtocol: entrypoint.ListenerProtocolHTTPS, TLSPolicy: entrypoint.TLSPolicyTLS13_2021_06,
			IngressCIDRs: []string{"0.0.0.0/0"}, TargetProtocol: entrypoint.TargetProtocolHTTP, TargetPort: 8080,
			TargetSource: entrypoint.TargetSourceApprovedWorkerReadBack,
			PublicSubnets: []entrypoint.PublicSubnetScopeV1{
				{SubnetID: "subnet-1234567890abcdef0", VPCID: "vpc-0123456789abcdef0", AvailabilityZone: "us-west-2a", Public: true, ReadBackDigest: entryDigest("2"), ObservedAt: observedAt},
				{SubnetID: "subnet-2234567890abcdef0", VPCID: "vpc-0123456789abcdef0", AvailabilityZone: "us-west-2b", Public: true, ReadBackDigest: entryDigest("3"), ObservedAt: observedAt},
			},
		},
		Health:         entrypoint.HealthRouteScopeV1{Path: "/health/ready", ExpectedStatusCode: 200, EvidenceDigest: entryDigest("e"), NoCredentialRoute: true},
		Authentication: entrypoint.AuthenticationScopeV1{Required: true, ContractDigest: entryDigest("f")},
		Cost: entrypoint.EntryCostScopeV1{QuoteID: quoteID.String(), QuoteDigest: quoteDigest, Currency: "USD", QuotedAt: quotedAt, ValidUntil: validUntil,
			ALBHourlyEstimateMicros: 12000, LCUHourlyEstimateMicros: 9000, EstimatedLCUMilliUnits: 1000, EstimatedEgressMiB: 1024,
			TrafficEstimateMicros: 1000, MaximumLaunchAmountMicros: 30000, AssumptionsDigest: entryDigest("4")},
		Retention: entrypoint.RetentionScopeV1{Class: entrypoint.RetentionEphemeral, AutoDestroy: true, DestroyDeadline: destroyDeadline},
	}
}

func entryMutation(ownerID, label, idempotencyKey string) entrypoint.Mutation {
	return entrypoint.Mutation{Caller: task.MutationScope{ClientID: "entry-store-integration", CredentialID: uuid.NewString()},
		OwnerID: ownerID, IdempotencyKey: idempotencyKey, RequestHash: sha256.Sum256([]byte(label))}
}

func entrySignature(challenge entrypoint.ChallengeV1, signature []byte) entrypoint.SignatureV1 {
	return entrypoint.SignatureV1{ApprovalID: challenge.ApprovalID, ChallengeID: challenge.ChallengeID,
		EntryPlanID: challenge.EntryPlanID, EntryPlanRevision: challenge.EntryPlanRevision,
		PlanHash: challenge.PlanHash, ScopeDigest: challenge.ScopeDigest, SignerKeyID: challenge.SignerKeyID,
		ExpiresAt: challenge.ExpiresAt, Signature: signature}
}

func entryDigest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }
