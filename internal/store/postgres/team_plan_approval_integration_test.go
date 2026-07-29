package postgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamapproval"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestTeamPlanFactsAreImmutableScopedAndAtomicallyApproved(
	t *testing.T,
) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	mutationScope := task.MutationScope{
		ClientID:     "team-plan-integration",
		CredentialID: uuid.NewString(),
	}
	ownerID := "owner-team-plan"
	connectionID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO cloud_connections
		    (connection_id, agent_instance_id, owner_id, account_id, region,
		     control_role_arn, foundation_stack_id, credential_generation,
		     status, revision)
		VALUES ($1,$2,$3,'123456789012','us-east-1',
		        'arn:aws:iam::123456789012:role/test-control',
		        'test-foundation-stack',1,'active',1)`,
		connectionID,
		instanceID,
		ownerID,
	); err != nil {
		t.Fatal(err)
	}
	goal := "Implement and independently verify the approved change."
	createdTask, err := store.Create(
		ctx,
		mutationScope,
		task.CreateCommand{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        ownerID,
			Goal:           goal,
			Retention:      task.RetentionEphemeralAutoDestroy,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	snapshot := teamOfferSnapshotFixture(
		t,
		connectionID,
		now.Add(-time.Minute),
	)
	snapshotKey := uuid.NewString()
	snapshotRecord, err := store.CreateTeamOfferSnapshot(
		ctx,
		mutationScope,
		postgres.CreateTeamOfferSnapshotCommand{
			IdempotencyKey: snapshotKey,
			OwnerID:        ownerID,
			Snapshot:       snapshot,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	replayedSnapshot, err := store.CreateTeamOfferSnapshot(
		ctx,
		mutationScope,
		postgres.CreateTeamOfferSnapshotCommand{
			IdempotencyKey: snapshotKey,
			OwnerID:        ownerID,
			Snapshot:       snapshot,
		},
	)
	if err != nil ||
		replayedSnapshot.Digest != snapshotRecord.Digest {
		t.Fatalf("snapshot replay=%#v err=%v", replayedSnapshot, err)
	}
	plan := teamPlanFixture(
		t,
		snapshot,
		ownerID,
		goal,
		uuid.NewString(),
		1,
	)
	planKey := uuid.NewString()
	planRecord, err := store.CreateTeamPlan(
		ctx,
		mutationScope,
		postgres.CreateTeamPlanCommand{
			IdempotencyKey: planKey,
			TaskID:         createdTask.TaskID,
			Plan:           plan,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if planRecord.Status != postgres.TeamPlanReadyForConfirmation ||
		planRecord.RecordRevision != 1 ||
		planRecord.Plan.Revision != 1 {
		t.Fatalf("created Team Plan = %#v", planRecord)
	}
	var (
		beforeDigest string
		beforeJSON   string
		beforeCBOR   []byte
	)
	if err := pool.QueryRow(ctx, `
		SELECT plan_digest, plan_json::text, plan_cbor
		FROM team_plans
		WHERE plan_id=$1 AND plan_revision=1`,
		plan.PlanID,
	).Scan(&beforeDigest, &beforeJSON, &beforeCBOR); err != nil {
		t.Fatal(err)
	}

	seed := sha256.Sum256([]byte("Team Plan PostgreSQL approval device"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signerKeyID := "team-plan-device-1"
	if _, err := store.RegisterApprovalDevice(
		ctx,
		mutationScope,
		postgres.RegisterApprovalDeviceCommand{
			IdempotencyKey: uuid.NewString(),
			Device: cloudapproval.DeviceKeyV1{
				KeyID:           signerKeyID,
				AgentInstanceID: instanceID,
				OwnerID:         ownerID,
				Revision:        1,
				Status:          cloudapproval.DeviceKeyActive,
				PublicKey:       publicKey,
				NotBefore:       now.Add(-time.Hour),
				ExpiresAt:       now.Add(time.Hour),
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateTeamApprovalChallenge(
		ctx,
		mutationScope,
		postgres.CreateTeamApprovalChallengeCommand{
			IdempotencyKey:             uuid.NewString(),
			OwnerID:                    "other-owner",
			PlanID:                     plan.PlanID,
			PlanRevision:               plan.Revision,
			ExpectedPlanRecordRevision: planRecord.RecordRevision,
			ApprovalID:                 uuid.NewString(),
			ChallengeID:                uuid.NewString(),
			SignerKeyID:                signerKeyID,
		},
	); !errors.Is(err, postgres.ErrTeamFactScope) {
		t.Fatalf("cross-owner approval challenge error=%v", err)
	}
	challengeRecord, err := store.CreateTeamApprovalChallenge(
		ctx,
		mutationScope,
		postgres.CreateTeamApprovalChallengeCommand{
			IdempotencyKey:             uuid.NewString(),
			OwnerID:                    ownerID,
			PlanID:                     plan.PlanID,
			PlanRevision:               plan.Revision,
			ExpectedPlanRecordRevision: planRecord.RecordRevision,
			ApprovalID:                 uuid.NewString(),
			ChallengeID:                uuid.NewString(),
			SignerKeyID:                signerKeyID,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	signature := signTeamApproval(
		t,
		challengeRecord.Challenge,
		privateKey,
	)
	if _, err := store.ApproveTeamPlan(
		ctx,
		mutationScope,
		postgres.ApproveTeamPlanCommand{
			IdempotencyKey:                  uuid.NewString(),
			OwnerID:                         "other-owner",
			ExpectedPlanRecordRevision:      1,
			ExpectedChallengeRecordRevision: 1,
			Signature:                       signature,
		},
	); !errors.Is(err, postgres.ErrTeamFactScope) {
		t.Fatalf("cross-owner Team Plan approval error=%v", err)
	}
	approveKey := uuid.NewString()
	approved, err := store.ApproveTeamPlan(
		ctx,
		mutationScope,
		postgres.ApproveTeamPlanCommand{
			IdempotencyKey:                  approveKey,
			OwnerID:                         ownerID,
			ExpectedPlanRecordRevision:      1,
			ExpectedChallengeRecordRevision: 1,
			Signature:                       signature,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != postgres.TeamPlanApproved ||
		approved.RecordRevision != 2 ||
		approved.Plan.Revision != 1 ||
		approved.PlanDigest != beforeDigest {
		t.Fatalf("approved Team Plan = %#v", approved)
	}
	replayedApproval, err := store.ApproveTeamPlan(
		ctx,
		mutationScope,
		postgres.ApproveTeamPlanCommand{
			IdempotencyKey:                  approveKey,
			OwnerID:                         ownerID,
			ExpectedPlanRecordRevision:      1,
			ExpectedChallengeRecordRevision: 1,
			Signature:                       signature,
		},
	)
	if err != nil ||
		replayedApproval.Status != postgres.TeamPlanApproved ||
		replayedApproval.RecordRevision != 2 {
		t.Fatalf("approval replay=%#v err=%v", replayedApproval, err)
	}
	if _, err := store.ApproveTeamPlan(
		ctx,
		mutationScope,
		postgres.ApproveTeamPlanCommand{
			IdempotencyKey:                  uuid.NewString(),
			OwnerID:                         ownerID,
			ExpectedPlanRecordRevision:      2,
			ExpectedChallengeRecordRevision: 2,
			Signature:                       signature,
		},
	); !errors.Is(err, postgres.ErrTeamChallengeConsumed) {
		t.Fatalf("approval replay with new key error=%v", err)
	}
	storedApproval, err := store.GetTeamApproval(
		ctx,
		ownerID,
		signature.ApprovalID,
	)
	if err != nil ||
		storedApproval.Signature.SignatureBase64URL !=
			signature.SignatureBase64URL {
		t.Fatalf("stored approval=%#v err=%v", storedApproval, err)
	}
	boundApproval, err := store.GetTeamApprovalForPlan(
		ctx,
		ownerID,
		plan.PlanID,
		plan.Revision,
	)
	if err != nil ||
		boundApproval.Signature.ApprovalID != signature.ApprovalID ||
		boundApproval.Signature.PlanDigest != beforeDigest ||
		boundApproval.Signature.SignatureBase64URL !=
			signature.SignatureBase64URL {
		t.Fatalf("Plan-bound approval=%#v err=%v", boundApproval, err)
	}
	if _, err := store.GetTeamApprovalForPlan(
		ctx,
		"other-owner",
		plan.PlanID,
		plan.Revision,
	); !errors.Is(err, postgres.ErrTeamFactNotFound) {
		t.Fatalf("cross-owner Plan-bound approval read error=%v", err)
	}
	if _, err := store.GetTeamPlan(
		ctx,
		"other-owner",
		plan.PlanID,
		plan.Revision,
	); !errors.Is(err, postgres.ErrTeamFactScope) {
		t.Fatalf("cross-owner Team Plan read error=%v", err)
	}
	foreignStore, err := postgres.New(pool, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreignStore.GetTeamOfferSnapshot(
		ctx,
		ownerID,
		snapshot.SnapshotID(),
	); !errors.Is(err, postgres.ErrTeamFactNotFound) {
		t.Fatalf("cross-Agent Offer Snapshot read error=%v", err)
	}
	if _, err := foreignStore.GetTeamPlan(
		ctx,
		ownerID,
		plan.PlanID,
		plan.Revision,
	); !errors.Is(err, postgres.ErrTeamFactNotFound) {
		t.Fatalf("cross-Agent Team Plan read error=%v", err)
	}
	if _, err := foreignStore.GetTeamApprovalChallenge(
		ctx,
		ownerID,
		challengeRecord.Challenge.ChallengeID,
	); !errors.Is(err, postgres.ErrTeamFactNotFound) {
		t.Fatalf("cross-Agent approval challenge read error=%v", err)
	}
	if _, err := foreignStore.GetTeamApproval(
		ctx,
		ownerID,
		signature.ApprovalID,
	); !errors.Is(err, postgres.ErrTeamFactNotFound) {
		t.Fatalf("cross-Agent approval read error=%v", err)
	}
	if _, err := foreignStore.GetTeamApprovalForPlan(
		ctx,
		ownerID,
		plan.PlanID,
		plan.Revision,
	); !errors.Is(err, postgres.ErrTeamFactNotFound) {
		t.Fatalf("cross-Agent Plan-bound approval read error=%v", err)
	}
	var (
		afterDigest string
		afterJSON   string
		afterCBOR   []byte
	)
	if err := pool.QueryRow(ctx, `
		SELECT plan_digest, plan_json::text, plan_cbor
		FROM team_plans
		WHERE plan_id=$1 AND plan_revision=1`,
		plan.PlanID,
	).Scan(&afterDigest, &afterJSON, &afterCBOR); err != nil {
		t.Fatal(err)
	}
	if afterDigest != beforeDigest ||
		afterJSON != beforeJSON ||
		!bytes.Equal(afterCBOR, beforeCBOR) {
		t.Fatal("approval mutated signed Team Plan content")
	}
	assertTeamPlanDatabaseImmutability(
		t,
		ctx,
		pool,
		plan,
		snapshot,
		signature,
	)

	replanV1 := teamPlanFixture(
		t,
		snapshot,
		ownerID,
		goal,
		uuid.NewString(),
		1,
	)
	firstReplan, err := store.CreateTeamPlan(
		ctx,
		mutationScope,
		postgres.CreateTeamPlanCommand{
			IdempotencyKey: uuid.NewString(),
			Plan:           replanV1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	staleChallenge, err := store.CreateTeamApprovalChallenge(
		ctx,
		mutationScope,
		postgres.CreateTeamApprovalChallengeCommand{
			IdempotencyKey:             uuid.NewString(),
			OwnerID:                    ownerID,
			PlanID:                     replanV1.PlanID,
			PlanRevision:               1,
			ExpectedPlanRecordRevision: firstReplan.RecordRevision,
			ApprovalID:                 uuid.NewString(),
			ChallengeID:                uuid.NewString(),
			SignerKeyID:                signerKeyID,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	replanV2 := replanV1
	replanV2.Revision = 2
	secondReplan, err := store.CreateTeamPlan(
		ctx,
		mutationScope,
		postgres.CreateTeamPlanCommand{
			IdempotencyKey:           uuid.NewString(),
			ExpectedPreviousRevision: 1,
			Plan:                     replanV2,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	superseded, err := store.GetTeamPlan(
		ctx,
		ownerID,
		replanV1.PlanID,
		1,
	)
	if err != nil ||
		superseded.Status != postgres.TeamPlanSuperseded ||
		superseded.RecordRevision != 2 ||
		secondReplan.Status != postgres.TeamPlanReadyForConfirmation {
		t.Fatalf(
			"superseded=%#v current=%#v err=%v",
			superseded,
			secondReplan,
			err,
		)
	}
	if _, err := store.ApproveTeamPlan(
		ctx,
		mutationScope,
		postgres.ApproveTeamPlanCommand{
			IdempotencyKey:                  uuid.NewString(),
			OwnerID:                         ownerID,
			ExpectedPlanRecordRevision:      2,
			ExpectedChallengeRecordRevision: 1,
			Signature: signTeamApproval(
				t,
				staleChallenge.Challenge,
				privateKey,
			),
		},
	); !errors.Is(err, postgres.ErrTeamFactRevision) {
		t.Fatalf("superseded Plan approval error=%v", err)
	}

	racePlan := teamPlanFixture(
		t,
		snapshot,
		ownerID,
		goal,
		uuid.NewString(),
		1,
	)
	racePlanRecord, err := store.CreateTeamPlan(
		ctx,
		mutationScope,
		postgres.CreateTeamPlanCommand{
			IdempotencyKey: uuid.NewString(),
			Plan:           racePlan,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	raceChallenge, err := store.CreateTeamApprovalChallenge(
		ctx,
		mutationScope,
		postgres.CreateTeamApprovalChallengeCommand{
			IdempotencyKey:             uuid.NewString(),
			OwnerID:                    ownerID,
			PlanID:                     racePlan.PlanID,
			PlanRevision:               racePlan.Revision,
			ExpectedPlanRecordRevision: racePlanRecord.RecordRevision,
			ApprovalID:                 uuid.NewString(),
			ChallengeID:                uuid.NewString(),
			SignerKeyID:                signerKeyID,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	raceSignature := signTeamApproval(
		t,
		raceChallenge.Challenge,
		privateKey,
	)
	raceErrors := make([]error, 2)
	var waitGroup sync.WaitGroup
	for index := range raceErrors {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			_, raceErrors[index] = store.ApproveTeamPlan(
				ctx,
				mutationScope,
				postgres.ApproveTeamPlanCommand{
					IdempotencyKey:                  uuid.NewString(),
					OwnerID:                         ownerID,
					ExpectedPlanRecordRevision:      1,
					ExpectedChallengeRecordRevision: 1,
					Signature:                       raceSignature,
				},
			)
		}(index)
	}
	waitGroup.Wait()
	var approvedCount, consumedCount int
	for _, raceErr := range raceErrors {
		switch {
		case raceErr == nil:
			approvedCount++
		case errors.Is(raceErr, postgres.ErrTeamChallengeConsumed):
			consumedCount++
		default:
			t.Fatalf("unexpected concurrent approval error=%v", raceErr)
		}
	}
	if approvedCount != 1 || consumedCount != 1 {
		t.Fatalf(
			"concurrent approvals succeeded/consumed=%d/%d",
			approvedCount,
			consumedCount,
		)
	}

	expiringDocument := snapshot.Document()
	expiringDocument.SnapshotID = uuid.NewString()
	expiringDocument.ValidUntil = time.Now().UTC().
		Truncate(time.Microsecond).
		Add(2 * time.Second)
	expiringSnapshot, err := teamplan.NewOfferSnapshot(expiringDocument)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateTeamOfferSnapshot(
		ctx,
		mutationScope,
		postgres.CreateTeamOfferSnapshotCommand{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        ownerID,
			Snapshot:       expiringSnapshot,
		},
	); err != nil {
		t.Fatal(err)
	}
	expiringPlan := teamPlanFixture(
		t,
		expiringSnapshot,
		ownerID,
		goal,
		uuid.NewString(),
		1,
	)
	expiringPlanRecord, err := store.CreateTeamPlan(
		ctx,
		mutationScope,
		postgres.CreateTeamPlanCommand{
			IdempotencyKey: uuid.NewString(),
			Plan:           expiringPlan,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ExpireTeamPlan(
		ctx,
		mutationScope,
		postgres.ExpireTeamPlanCommand{
			IdempotencyKey:         uuid.NewString(),
			OwnerID:                "other-owner",
			PlanID:                 expiringPlan.PlanID,
			PlanRevision:           expiringPlan.Revision,
			ExpectedRecordRevision: expiringPlanRecord.RecordRevision,
		},
	); !errors.Is(err, postgres.ErrTeamFactScope) {
		t.Fatalf("cross-owner Team Plan expiry error=%v", err)
	}
	time.Sleep(time.Until(expiringPlan.ValidUntil) + 50*time.Millisecond)
	expiredPlan, err := store.ExpireTeamPlan(
		ctx,
		mutationScope,
		postgres.ExpireTeamPlanCommand{
			IdempotencyKey:         uuid.NewString(),
			OwnerID:                ownerID,
			PlanID:                 expiringPlan.PlanID,
			PlanRevision:           expiringPlan.Revision,
			ExpectedRecordRevision: expiringPlanRecord.RecordRevision,
		},
	)
	if err != nil ||
		expiredPlan.Status != postgres.TeamPlanExpired ||
		expiredPlan.RecordRevision != 2 {
		t.Fatalf("expired Team Plan=%#v err=%v", expiredPlan, err)
	}
	requotePlan := teamPlanFixture(
		t,
		snapshot,
		ownerID,
		goal,
		expiringPlan.PlanID,
		2,
	)
	if _, err := store.CreateTeamPlan(
		ctx,
		mutationScope,
		postgres.CreateTeamPlanCommand{
			IdempotencyKey:           uuid.NewString(),
			ExpectedPreviousRevision: 1,
			Plan:                     requotePlan,
		},
	); err != nil {
		t.Fatalf("create revision after expiry error=%v", err)
	}

	if _, err := pool.Exec(ctx, `
		UPDATE cloud_connections
		SET revision=2, updated_at=clock_timestamp()
		WHERE connection_id=$1`,
		connectionID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateTeamApprovalChallenge(
		ctx,
		mutationScope,
		postgres.CreateTeamApprovalChallengeCommand{
			IdempotencyKey:             uuid.NewString(),
			OwnerID:                    ownerID,
			PlanID:                     replanV2.PlanID,
			PlanRevision:               replanV2.Revision,
			ExpectedPlanRecordRevision: secondReplan.RecordRevision,
			ApprovalID:                 uuid.NewString(),
			ChallengeID:                uuid.NewString(),
			SignerKeyID:                signerKeyID,
		},
	); !errors.Is(err, postgres.ErrTeamFactScope) {
		t.Fatalf("connection revision drift challenge error=%v", err)
	}

	restarted, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	restartedPlan, err := restarted.GetTeamPlan(
		ctx,
		ownerID,
		plan.PlanID,
		plan.Revision,
	)
	if err != nil ||
		restartedPlan.Status != postgres.TeamPlanApproved ||
		restartedPlan.PlanDigest != planRecord.PlanDigest {
		t.Fatalf("restarted Team Plan=%#v err=%v", restartedPlan, err)
	}
}

func teamOfferSnapshotFixture(
	t *testing.T,
	connectionID string,
	capturedAt time.Time,
) *teamplan.OfferSnapshot {
	t.Helper()
	document := teamplan.OfferSnapshotDocument{
		SchemaVersion: teamplan.OfferSnapshotSchemaV1,
		SnapshotID:    uuid.NewString(),
		ProviderScope: teamplan.ProviderScope{
			Provider:           teamplan.CloudProviderAWS,
			ConnectionID:       connectionID,
			ConnectionRevision: 1,
			AccountID:          "123456789012",
		},
		Region:     "us-east-1",
		Currency:   "USD",
		CapturedAt: capturedAt,
		ValidUntil: capturedAt.Add(teamplan.OfferSnapshotValidity),
		Sources: []teamplan.OfferSourceReceipt{
			{
				Kind:       teamplan.OfferSourceModelPricing,
				SourceID:   "model-pricing-test",
				Digest:     "sha256:" + strings.Repeat("1", 64),
				CapturedAt: capturedAt.Add(-time.Hour),
			},
			{
				Kind:       teamplan.OfferSourceComputePricing,
				SourceID:   "aws-price-list-us-east-1",
				Digest:     "sha256:" + strings.Repeat("2", 64),
				CapturedAt: capturedAt,
			},
			{
				Kind:       teamplan.OfferSourceComputeCapacity,
				SourceID:   "aws-capacity-us-east-1",
				Digest:     "sha256:" + strings.Repeat("3", 64),
				CapturedAt: capturedAt,
			},
		},
		ModelOffers: []teamplan.ModelOffer{{
			ProfileID:              "model-balanced",
			Provider:               "openai",
			Model:                  "code-model",
			Interface:              teamplan.ModelOpenAIResponses,
			Quality:                teamplan.QualityBalanced,
			ContextTokens:          128_000,
			InputMicrosPerMillion:  1_000_000,
			OutputMicrosPerMillion: 2_000_000,
			CredentialRef:          "secret_ref:model/test",
			Enabled:                true,
			CredentialReady:        true,
		}},
		ComputeOffers: []teamplan.ComputeOffer{{
			OfferID:        uuid.NewString(),
			Region:         "us-east-1",
			InstanceType:   "m7i.large",
			Architecture:   recipe.ArchitectureAMD64,
			VCPU:           2,
			MemoryMiB:      8192,
			DiskGiB:        40,
			HourlyMicros:   3_600_000,
			PurchaseOption: "on_demand",
			CapacityPool:   "aws:ec2-quota:L-1216C47A",
			CapacityUnits:  2,
			AvailableUnits: 64,
			Available:      true,
		}},
	}
	snapshot, err := teamplan.NewOfferSnapshot(document)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func teamPlanFixture(
	t *testing.T,
	snapshot *teamplan.OfferSnapshot,
	ownerID,
	goal,
	planID string,
	revision uint64,
) teamplan.Plan {
	t.Helper()
	goalHash := sha256.Sum256([]byte(strings.TrimSpace(goal)))
	document := snapshot.Document()
	compute := document.ComputeOffers[0]
	model := document.ModelOffers[0]
	policyRevision, err := teamPlanPolicyFixture().Digest()
	if err != nil {
		t.Fatal(err)
	}
	assignment := teamplan.WorkerAssignment{
		RoleID:    "implementation",
		Title:     "Implementation",
		Objective: "worker-objective-private-marker",
		WorkClass: teamplan.WorkSoftwareImplementation,
		RequiredCapabilities: []teamplan.Capability{
			teamplan.CapabilityGit,
		},
		Workspace:          teamplan.WorkspaceIsolated,
		RuntimeReleaseID:   uuid.NewSHA1(uuid.MustParse(planID), []byte("runtime")).String(),
		RuntimeFamily:      teamplan.RuntimeCodex,
		RuntimeVersion:     "1.0.0",
		RuntimeImageDigest: "sha256:" + strings.Repeat("a", 64),
		RuntimeAdapter:     teamplan.AdapterCodexV1,
		ModelProfileID:     model.ProfileID,
		ModelProvider:      model.Provider,
		Model:              model.Model,
		ModelInterface:     model.Interface,
		ModelCredentialRef: model.CredentialRef,
		ComputeOfferID:     compute.OfferID,
		InstanceType:       compute.InstanceType,
		Resources: teamplan.ResourceEnvelope{
			VCPU:      compute.VCPU,
			MemoryMiB: compute.MemoryMiB,
			DiskGiB:   compute.DiskGiB,
			Arch:      compute.Architecture,
		},
		Duration: teamplan.DurationEstimate{
			Minimum:  time.Minute,
			Expected: 2 * time.Minute,
			Maximum:  3 * time.Minute,
		},
		Tokens: teamplan.TokenEstimate{
			InputMinimum:   1_000,
			InputExpected:  2_000,
			InputMaximum:   3_000,
			OutputMinimum:  100,
			OutputExpected: 200,
			OutputMaximum:  300,
		},
	}
	return teamplan.Plan{
		SchemaVersion:         teamplan.SchemaV1,
		PlanID:                planID,
		Revision:              revision,
		OwnerID:               ownerID,
		GoalDigest:            "sha256:" + hex.EncodeToString(goalHash[:]),
		ProviderScope:         document.ProviderScope,
		Region:                document.Region,
		CatalogRevision:       "sha256:" + strings.Repeat("b", 64),
		PolicyRevision:        policyRevision,
		PricingSnapshotID:     snapshot.SnapshotID(),
		PricingSnapshotDigest: snapshot.Digest(),
		QuotedAt:              snapshot.CapturedAt(),
		ValidUntil:            snapshot.ValidUntil(),
		ProposalConfidence:    90,
		ProposalRationale:     "One isolated implementation Worker is sufficient.",
		WorkerCount:           1,
		MaxConcurrentWorkers:  1,
		Assignments:           []teamplan.WorkerAssignment{assignment},
		Schedule: teamplan.ScheduleEstimate{
			MinimumWallTime:  time.Minute,
			ExpectedWallTime: 2 * time.Minute,
			MaximumWallTime:  3 * time.Minute,
		},
		Cost: teamplan.CostEstimate{
			Currency:         "USD",
			MinimumMicros:    71_200,
			ExpectedMicros:   132_400,
			MaximumMicros:    193_600,
			HardBudgetMicros: 232_320,
			Roles: []teamplan.RoleCostEstimate{{
				RoleID:                assignment.RoleID,
				ComputeMinimumMicros:  60_000,
				ComputeExpectedMicros: 120_000,
				ComputeMaximumMicros:  180_000,
				ModelMinimumMicros:    1_200,
				ModelExpectedMicros:   2_400,
				ModelMaximumMicros:    3_600,
				TotalMinimumMicros:    71_200,
				TotalExpectedMicros:   132_400,
				TotalMaximumMicros:    193_600,
			}},
			Assumptions: []string{
				"on_demand_compute",
				"remote_model_token_range",
				"workers_start_when_roles_are_ready",
			},
			Exclusions: []string{
				"excess_network_egress",
				"third_party_paid_tools",
				"unapproved_retries",
			},
		},
	}
}

func teamPlanPolicyFixture() teamplan.Policy {
	return teamplan.Policy{
		MaxWorkers:                1,
		MaxConcurrentWorkers:      1,
		MaxRoleDuration:           3 * time.Minute,
		MaxVCPUPerWorker:          2,
		MaxMemoryMiBPerWorker:     8192,
		MaxDiskGiBPerWorker:       40,
		MaxPlanCostMicros:         1_000_000,
		SafetyMarginBasisPoints:   2000,
		FixedWorkerOverheadMicros: 10_000,
		AllowedRuntimeFamilies: []teamplan.RuntimeFamily{
			teamplan.RuntimeCodex,
		},
	}
}

func signTeamApproval(
	t *testing.T,
	challenge teamapproval.ChallengeV1,
	privateKey ed25519.PrivateKey,
) teamapproval.SignatureV1 {
	t.Helper()
	payload, err := challenge.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	return teamapproval.SignatureV1{
		SchemaVersion: teamapproval.SignatureSchemaV1,
		ApprovalID:    challenge.ApprovalID,
		ChallengeID:   challenge.ChallengeID,
		PlanID:        challenge.PlanID,
		PlanRevision:  challenge.PlanRevision,
		PlanDigest:    challenge.PlanDigest,
		SignerKeyID:   challenge.SignerKeyID,
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(privateKey, payload),
		),
	}
}

func assertTeamPlanDatabaseImmutability(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	plan teamplan.Plan,
	snapshot *teamplan.OfferSnapshot,
	signature teamapproval.SignatureV1,
) {
	t.Helper()
	tests := []struct {
		name      string
		statement string
		arguments []any
	}{
		{
			name: "signed Plan",
			statement: `
				UPDATE team_plans
				SET plan_json=jsonb_set(
				        plan_json,
				        '{owner_id}',
				        '"tampered"'::jsonb
				    ),
				    status='failed',
				    record_revision=record_revision+1,
				    updated_at=clock_timestamp()
				WHERE plan_id=$1 AND plan_revision=$2`,
			arguments: []any{plan.PlanID, int64(plan.Revision)},
		},
		{
			name: "Offer Snapshot",
			statement: `
				UPDATE team_offer_snapshots
				SET owner_id=owner_id
				WHERE snapshot_id=$1`,
			arguments: []any{snapshot.SnapshotID()},
		},
		{
			name: "approval",
			statement: `
				UPDATE team_plan_approvals
				SET approved_at=approved_at
				WHERE approval_id=$1`,
			arguments: []any{signature.ApprovalID},
		},
		{
			name: "consumed challenge",
			statement: `
				UPDATE team_plan_approval_challenges
				SET record_revision=record_revision+1,
				    updated_at=clock_timestamp()
				WHERE challenge_id=$1`,
			arguments: []any{signature.ChallengeID},
		},
	}
	for _, test := range tests {
		if _, err := pool.Exec(
			ctx,
			test.statement,
			test.arguments...,
		); err == nil {
			t.Fatalf("%s database mutation unexpectedly succeeded", test.name)
		}
	}
	var leakedEventMarkers int
	if err := pool.QueryRow(ctx, `
		SELECT
		    (SELECT count(*) FROM task_events
		     WHERE summary_json::text LIKE '%worker-objective-private-marker%')
		    +
		    (SELECT count(*) FROM outbox_events
		     WHERE payload_json::text LIKE '%worker-objective-private-marker%')`,
	).Scan(&leakedEventMarkers); err != nil {
		t.Fatal(err)
	}
	if leakedEventMarkers != 0 {
		t.Fatalf(
			"Worker objective leaked into %d public event rows",
			leakedEventMarkers,
		)
	}
}
