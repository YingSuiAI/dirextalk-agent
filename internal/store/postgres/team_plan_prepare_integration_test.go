package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
)

func TestPrepareTeamPlanIsAtomicAndReplaysStableIntent(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	scope := task.MutationScope{
		ClientID:     "team-plan-prepare-integration",
		CredentialID: uuid.NewString(),
	}
	ownerID := "owner-team-plan-prepare"
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
	goal := "Prepare one immutable Team Plan atomically."
	createdTask, err := store.Create(
		ctx,
		scope,
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
	snapshot := shortLivedTeamOfferSnapshotFixture(
		t,
		connectionID,
		now,
	)
	plan := teamPlanFixture(
		t,
		snapshot,
		ownerID,
		goal,
		uuid.NewString(),
		1,
	)
	intent := teamPlanPreparationIntentFixture(plan, createdTask.TaskID)
	key := uuid.NewString()
	prepared, err := store.PrepareTeamPlan(
		ctx,
		scope,
		postgres.PrepareTeamPlanCommand{
			IdempotencyKey: key,
			Intent:         intent,
			Snapshot:       snapshot,
			Plan:           plan,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Replayed ||
		prepared.Offer.Digest != snapshot.Digest() ||
		prepared.Plan.PlanDigest == "" ||
		prepared.Plan.Status != postgres.TeamPlanReadyForConfirmation {
		t.Fatalf("prepared Team Plan = %#v", prepared)
	}
	replayed, found, err := store.FindPreparedTeamPlan(
		ctx,
		scope,
		postgres.FindPreparedTeamPlanCommand{
			IdempotencyKey: key,
			Intent:         intent,
		},
	)
	if err != nil || !found || !replayed.Replayed ||
		replayed.Offer.Digest != prepared.Offer.Digest ||
		replayed.Plan.PlanDigest != prepared.Plan.PlanDigest {
		t.Fatalf(
			"prepared Team Plan replay=%#v found=%v error=%v",
			replayed,
			found,
			err,
		)
	}
	changedIntent := intent
	changedIntent.Proposal.Rationale += " changed"
	if _, _, err := store.FindPreparedTeamPlan(
		ctx,
		scope,
		postgres.FindPreparedTeamPlanCommand{
			IdempotencyKey: key,
			Intent:         changedIntent,
		},
	); !errors.Is(err, idempotency.ErrConflict) {
		t.Fatalf("changed stable intent replay error=%v", err)
	}
	changedConnection := intent
	changedConnection.ConnectionID = uuid.NewString()
	if _, _, err := store.FindPreparedTeamPlan(
		ctx,
		scope,
		postgres.FindPreparedTeamPlanCommand{
			IdempotencyKey: key,
			Intent:         changedConnection,
		},
	); !errors.Is(err, idempotency.ErrConflict) {
		t.Fatalf("changed Cloud Connection replay error=%v", err)
	}
	otherScope := scope
	otherScope.CredentialID = uuid.NewString()
	if _, found, err := store.FindPreparedTeamPlan(
		ctx,
		otherScope,
		postgres.FindPreparedTeamPlanCommand{
			IdempotencyKey: key,
			Intent:         intent,
		},
	); err != nil || found {
		t.Fatalf("cross-caller replay found=%v error=%v", found, err)
	}
	foreignStore, err := postgres.New(pool, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := foreignStore.FindPreparedTeamPlan(
		ctx,
		scope,
		postgres.FindPreparedTeamPlanCommand{
			IdempotencyKey: key,
			Intent:         intent,
		},
	); err != nil || found {
		t.Fatalf("cross-Agent replay found=%v error=%v", found, err)
	}
	substitutedIntent := intent
	substitutedIntent.Proposal.Roles = append(
		[]teamplan.RoleProposal(nil),
		intent.Proposal.Roles...,
	)
	substitutedIntent.Proposal.Roles[0].Objective = "substituted objective"
	substitutedKey := uuid.NewString()
	if _, err := store.PrepareTeamPlan(
		ctx,
		scope,
		postgres.PrepareTeamPlanCommand{
			IdempotencyKey: substitutedKey,
			Intent:         substitutedIntent,
			Snapshot:       snapshot,
			Plan:           plan,
		},
	); !errors.Is(err, postgres.ErrTeamFactInvalid) {
		t.Fatalf("substituted stable intent error=%v", err)
	}
	if _, found, err := store.FindPreparedTeamPlan(
		ctx,
		scope,
		postgres.FindPreparedTeamPlanCommand{
			IdempotencyKey: substitutedKey,
			Intent:         substitutedIntent,
		},
	); err != nil || found {
		t.Fatalf("substituted preparation found=%v error=%v", found, err)
	}

	time.Sleep(time.Until(snapshot.ValidUntil()) + 50*time.Millisecond)
	expired, err := store.ExpireTeamPlan(
		ctx,
		scope,
		postgres.ExpireTeamPlanCommand{
			IdempotencyKey:         uuid.NewString(),
			OwnerID:                ownerID,
			PlanID:                 plan.PlanID,
			PlanRevision:           plan.Revision,
			ExpectedRecordRevision: prepared.Plan.RecordRevision,
		},
	)
	if err != nil ||
		expired.Status != postgres.TeamPlanExpired ||
		expired.RecordRevision != 2 {
		t.Fatalf("expired Team Plan=%#v error=%v", expired, err)
	}
	expiredReplay, found, err := store.FindPreparedTeamPlan(
		ctx,
		scope,
		postgres.FindPreparedTeamPlanCommand{
			IdempotencyKey: key,
			Intent:         intent,
		},
	)
	if err != nil || !found ||
		expiredReplay.Plan.PlanDigest != prepared.Plan.PlanDigest ||
		expiredReplay.Plan.Status != postgres.TeamPlanExpired ||
		expiredReplay.Plan.RecordRevision != expired.RecordRevision {
		t.Fatalf(
			"expired quote replay=%#v found=%v error=%v",
			expiredReplay,
			found,
			err,
		)
	}

	orphanSnapshot := teamOfferSnapshotFixture(
		t,
		connectionID,
		time.Now().UTC().Truncate(time.Microsecond),
	)
	orphanPlan := teamPlanFixture(
		t,
		orphanSnapshot,
		ownerID,
		goal,
		uuid.NewString(),
		1,
	)
	orphanIntent := teamPlanPreparationIntentFixture(
		orphanPlan,
		uuid.NewString(),
	)
	orphanKey := uuid.NewString()
	if _, err := store.PrepareTeamPlan(
		ctx,
		scope,
		postgres.PrepareTeamPlanCommand{
			IdempotencyKey: orphanKey,
			Intent:         orphanIntent,
			Snapshot:       orphanSnapshot,
			Plan:           orphanPlan,
		},
	); !errors.Is(err, postgres.ErrTeamFactScope) {
		t.Fatalf("failed atomic preparation error=%v", err)
	}
	if _, err := store.GetTeamOfferSnapshot(
		ctx,
		ownerID,
		orphanSnapshot.SnapshotID(),
	); !errors.Is(err, postgres.ErrTeamFactNotFound) {
		t.Fatalf("rolled-back Snapshot read error=%v", err)
	}
	if _, found, err := store.FindPreparedTeamPlan(
		ctx,
		scope,
		postgres.FindPreparedTeamPlanCommand{
			IdempotencyKey: orphanKey,
			Intent:         orphanIntent,
		},
	); err != nil || found {
		t.Fatalf("rolled-back preparation found=%v error=%v", found, err)
	}
}

func shortLivedTeamOfferSnapshotFixture(
	t *testing.T,
	connectionID string,
	now time.Time,
) *teamplan.OfferSnapshot {
	t.Helper()
	base := teamOfferSnapshotFixture(t, connectionID, now)
	document := base.Document()
	document.SnapshotID = uuid.NewString()
	document.CapturedAt = now
	document.ValidUntil = now.Add(2 * time.Second)
	for index := range document.Sources {
		if document.Sources[index].Kind != teamplan.OfferSourceModelPricing {
			document.Sources[index].CapturedAt = now
		}
	}
	snapshot, err := teamplan.NewOfferSnapshot(document)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func teamPlanPreparationIntentFixture(
	plan teamplan.Plan,
	taskID string,
) postgres.TeamPlanPreparationIntent {
	assignment := plan.Assignments[0]
	return postgres.TeamPlanPreparationIntent{
		OwnerID:      plan.OwnerID,
		TaskID:       taskID,
		ConnectionID: plan.ProviderScope.ConnectionID,
		PlanID:       plan.PlanID,
		Revision:     plan.Revision,
		GoalDigest:   plan.GoalDigest,
		Proposal: teamplan.TeamProposal{
			Confidence: plan.ProposalConfidence,
			Rationale:  plan.ProposalRationale,
			Roles: []teamplan.RoleProposal{{
				RoleID:               assignment.RoleID,
				Title:                assignment.Title,
				Objective:            assignment.Objective,
				WorkClass:            assignment.WorkClass,
				RequiredCapabilities: assignment.RequiredCapabilities,
				PreferredFamilies: []teamplan.RuntimeFamily{
					teamplan.RuntimeCodex,
				},
				Workspace:        assignment.Workspace,
				DependsOnRoleIDs: assignment.DependsOnRoleIDs,
				Duration:         assignment.Duration,
				Tokens:           assignment.Tokens,
				ModelNeed: teamplan.ModelNeed{
					MinimumQuality:       teamplan.QualityBalanced,
					MinimumContextTokens: 16_000,
				},
				MinimumResources: assignment.Resources,
			}},
		},
	}
}
