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
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/turncontrol"
	"github.com/google/uuid"
)

func TestTurnControllerPersistsApprovalAndCompletionGates(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	scope := task.MutationScope{
		ClientID:     "turn-controller-integration",
		CredentialID: uuid.NewString(),
	}
	ownerID := "owner-turn-controller"
	connectionID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO cloud_connections (
		    connection_id, agent_instance_id, owner_id, account_id, region,
		    control_role_arn, foundation_stack_id, credential_generation,
		    status, revision)
		VALUES (
		    $1,$2,$3,'123456789012','us-east-1',
		    'arn:aws:iam::123456789012:role/test-control',
		    'test-foundation-stack',1,'active',1)`,
		connectionID,
		instanceID,
		ownerID,
	); err != nil {
		t.Fatal(err)
	}
	goal := "Implement and independently verify the approved change."
	createdTask, err := store.Create(ctx, scope, task.CreateCommand{
		IdempotencyKey: uuid.NewString(),
		OwnerID:        ownerID,
		Goal:           goal,
		Retention:      task.RetentionEphemeralAutoDestroy,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	snapshot := teamOfferSnapshotFixture(t, connectionID, now)
	if _, err := store.CreateTeamOfferSnapshot(
		ctx,
		scope,
		postgres.CreateTeamOfferSnapshotCommand{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        ownerID,
			Snapshot:       snapshot,
		},
	); err != nil {
		t.Fatal(err)
	}
	plan := teamPlanFixture(
		t,
		snapshot,
		ownerID,
		goal,
		uuid.NewString(),
		1,
	)
	planRecord, err := store.CreateTeamPlan(
		ctx,
		scope,
		postgres.CreateTeamPlanCommand{
			IdempotencyKey: uuid.NewString(),
			TaskID:         createdTask.TaskID,
			Plan:           plan,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := turncontrol.NewDefaultService(store)
	if err != nil {
		t.Fatal(err)
	}
	goalDigest, err := turncontrol.GoalDigest(goal)
	if err != nil {
		t.Fatal(err)
	}
	turn, err := controller.Begin(ctx, scope, turncontrol.BeginRequest{
		IdempotencyKey: uuid.NewString(),
		RequestID:      uuid.NewString(),
		OwnerID:        ownerID,
		ConversationID: "conversation-turn-controller",
		GoalDigest:     goalDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	turn = advanceStoredTurn(t, ctx, controller, scope, turn,
		turncontrol.PhaseUnderstand,
		turncontrol.RouteUndecided,
		turncontrol.Artifact{
			Kind: turncontrol.ArtifactNone, Origin: turncontrol.OriginController,
		},
		turncontrol.PlanBinding{},
		turncontrol.ValidationUnspecified,
	)
	turn = advanceStoredTurn(t, ctx, controller, scope, turn,
		turncontrol.PhaseRetrieveMemory,
		turncontrol.RouteUndecided,
		storedTurnArtifact(
			turncontrol.ArtifactUnderstanding,
			turncontrol.OriginModelCandidate,
			"understanding",
			"1",
		),
		turncontrol.PlanBinding{},
		turncontrol.ValidationUnspecified,
	)
	turn = advanceStoredTurn(t, ctx, controller, scope, turn,
		turncontrol.PhaseDecideLocalOrDelegate,
		turncontrol.RouteUndecided,
		storedTurnArtifact(
			turncontrol.ArtifactMemorySnapshot,
			turncontrol.OriginMemory,
			"memory",
			"2",
		),
		turncontrol.PlanBinding{},
		turncontrol.ValidationUnspecified,
	)
	turn = advanceStoredTurn(t, ctx, controller, scope, turn,
		turncontrol.PhaseProposeTeam,
		turncontrol.RouteDelegate,
		storedTurnArtifact(
			turncontrol.ArtifactRouteDecision,
			turncontrol.OriginPolicy,
			"route",
			"3",
		),
		turncontrol.PlanBinding{},
		turncontrol.ValidationUnspecified,
	)
	turn = advanceStoredTurn(t, ctx, controller, scope, turn,
		turncontrol.PhaseCompileAndQuote,
		turncontrol.RouteUndecided,
		storedTurnArtifact(
			turncontrol.ArtifactTeamProposal,
			turncontrol.OriginModelCandidate,
			"proposal",
			"4",
		),
		turncontrol.PlanBinding{},
		turncontrol.ValidationUnspecified,
	)
	awaitKey := uuid.NewString()
	awaitRequest := turncontrol.AdvanceRequest{
		IdempotencyKey:   awaitKey,
		TurnID:           turn.TurnID,
		OwnerID:          turn.OwnerID,
		ExpectedRevision: turn.Revision,
		ExpectedPhase:    turn.Phase,
		NextPhase:        turncontrol.PhaseAwaitApproval,
		Route:            turncontrol.RouteUndecided,
		Artifact: storedTurnArtifact(
			turncontrol.ArtifactTeamPlan,
			turncontrol.OriginPolicy,
			"plan",
			"5",
		),
		Plan: turncontrol.PlanBinding{
			PlanID:       plan.PlanID,
			PlanRevision: plan.Revision,
			PlanDigest:   planRecord.PlanDigest,
			TaskID:       createdTask.TaskID,
		},
		Validation: turncontrol.ValidationUnspecified,
	}
	awaiting, err := controller.Advance(ctx, scope, awaitRequest)
	if err != nil {
		t.Fatal(err)
	}
	replayedAwaiting, err := controller.Advance(ctx, scope, awaitRequest)
	if err != nil ||
		replayedAwaiting.Revision != awaiting.Revision ||
		replayedAwaiting.Phase != turncontrol.PhaseAwaitApproval {
		t.Fatalf("await-approval replay=%#v error=%v", replayedAwaiting, err)
	}
	changedAwait := awaitRequest
	changedAwait.Plan.PlanDigest = storedTurnDigest("6")
	if _, err := controller.Advance(
		ctx,
		scope,
		changedAwait,
	); !errors.Is(err, turncontrol.ErrIdempotency) {
		t.Fatalf("changed Turn transition replay error=%v", err)
	}
	turn = awaiting
	resumeRequest := turncontrol.ResumeExecutionRequest{
		IdempotencyKey:   uuid.NewString(),
		TurnID:           turn.TurnID,
		OwnerID:          turn.OwnerID,
		ExpectedRevision: turn.Revision,
		ExpectedPhase:    turn.Phase,
		ApprovalID:       uuid.NewString(),
		Artifact: storedTurnArtifact(
			turncontrol.ArtifactApproval,
			turncontrol.OriginUser,
			"approval",
			"7",
		),
		Validation: turncontrol.ValidationUnspecified,
	}
	if _, err := controller.ResumeExecution(
		ctx,
		scope,
		resumeRequest,
	); !errors.Is(err, turncontrol.ErrApprovalRequired) {
		t.Fatalf("unsigned Turn execution error=%v", err)
	}

	seed := sha256.Sum256([]byte("Turn Controller approval device"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signerKeyID := "turn-controller-device"
	if _, err := store.RegisterApprovalDevice(
		ctx,
		scope,
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
	challenge, err := store.CreateTeamApprovalChallenge(
		ctx,
		scope,
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
	signature := signTeamApproval(t, challenge.Challenge, privateKey)
	if _, err := store.ApproveTeamPlan(
		ctx,
		scope,
		postgres.ApproveTeamPlanCommand{
			IdempotencyKey:                  uuid.NewString(),
			OwnerID:                         ownerID,
			ExpectedPlanRecordRevision:      1,
			ExpectedChallengeRecordRevision: 1,
			Signature:                       signature,
		},
	); err != nil {
		t.Fatal(err)
	}
	resumeRequest.IdempotencyKey = uuid.NewString()
	resumeRequest.ApprovalID = signature.ApprovalID
	turn, err = controller.ResumeExecution(ctx, scope, resumeRequest)
	if err != nil {
		t.Fatal(err)
	}
	otherScope := task.MutationScope{
		ClientID: scope.ClientID, CredentialID: uuid.NewString(),
	}
	if _, err := controller.Retry(ctx, otherScope, turncontrol.RetryRequest{
		IdempotencyKey:   uuid.NewString(),
		TurnID:           turn.TurnID,
		OwnerID:          turn.OwnerID,
		ExpectedRevision: turn.Revision,
		Phase:            turn.Phase,
		FailureCode:      "worker.unreachable",
	}); !errors.Is(err, turncontrol.ErrNotFound) {
		t.Fatalf("cross-caller Turn retry error=%v", err)
	}
	turn = advanceStoredTurn(t, ctx, controller, scope, turn,
		turncontrol.PhaseObserve,
		turncontrol.RouteUndecided,
		storedTurnArtifact(
			turncontrol.ArtifactTaskState,
			turncontrol.OriginTask,
			"task-running",
			"8",
		),
		turncontrol.PlanBinding{},
		turncontrol.ValidationUnspecified,
	)
	observeRequest := turncontrol.AdvanceRequest{
		IdempotencyKey:   uuid.NewString(),
		TurnID:           turn.TurnID,
		OwnerID:          turn.OwnerID,
		ExpectedRevision: turn.Revision,
		ExpectedPhase:    turn.Phase,
		NextPhase:        turncontrol.PhaseValidate,
		Route:            turncontrol.RouteUndecided,
		Artifact: storedTurnArtifact(
			turncontrol.ArtifactResult,
			turncontrol.OriginTask,
			"result",
			"9",
		),
		Validation: turncontrol.ValidationUnspecified,
	}
	if _, err := controller.Advance(
		ctx,
		scope,
		observeRequest,
	); !errors.Is(err, turncontrol.ErrArbitration) {
		t.Fatalf("unfinished Task result transition error=%v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE tasks
		SET execution_status='finished',
		    outcome_status='succeeded',
		    revision=revision+1,
		    updated_at=clock_timestamp()
		WHERE task_id=$1`,
		createdTask.TaskID,
	); err != nil {
		t.Fatal(err)
	}
	turn, err = controller.Advance(ctx, scope, observeRequest)
	if err != nil {
		t.Fatal(err)
	}
	turn = advanceStoredTurn(t, ctx, controller, scope, turn,
		turncontrol.PhaseSynthesize,
		turncontrol.RouteUndecided,
		storedTurnArtifact(
			turncontrol.ArtifactValidation,
			turncontrol.OriginValidator,
			"validation",
			"a",
		),
		turncontrol.PlanBinding{},
		turncontrol.ValidationPassed,
	)
	finalizeKey := uuid.NewString()
	finalizeRequest := turncontrol.FinalizeRequest{
		IdempotencyKey:   finalizeKey,
		TurnID:           turn.TurnID,
		OwnerID:          turn.OwnerID,
		ExpectedRevision: turn.Revision,
		Response: storedTurnArtifact(
			turncontrol.ArtifactResponse,
			turncontrol.OriginModelCandidate,
			"response",
			"b",
		),
	}
	if _, err := controller.Finalize(
		ctx,
		scope,
		finalizeRequest,
	); !errors.Is(err, turncontrol.ErrArbitration) {
		t.Fatalf("unfinished Team Plan finalization error=%v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE agent_turns
		SET phase='finalize',
		    status='completed',
		    phase_attempt=1,
		    phase_deadline=NULL,
		    response_ref='turn://artifact/bypass-response',
		    response_digest=$2,
		    revision=revision+1,
		    updated_at=clock_timestamp()
		WHERE turn_id=$1`,
		turn.TurnID,
		storedTurnDigest("c"),
	); err == nil {
		t.Fatal("database trigger accepted completion without Plan evidence")
	}
	if _, err := pool.Exec(ctx, `
		UPDATE team_plans
		SET status='executing',
		    record_revision=record_revision+1,
		    updated_at=clock_timestamp()
		WHERE plan_id=$1 AND plan_revision=$2 AND status='approved'`,
		plan.PlanID,
		int64(plan.Revision),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE team_plans
		SET status='completed',
		    record_revision=record_revision+1,
		    updated_at=clock_timestamp()
		WHERE plan_id=$1 AND plan_revision=$2 AND status='executing'`,
		plan.PlanID,
		int64(plan.Revision),
	); err != nil {
		t.Fatal(err)
	}
	completed, err := controller.Finalize(ctx, scope, finalizeRequest)
	if err != nil {
		t.Fatal(err)
	}
	replayedCompletion, err := controller.Finalize(
		ctx,
		scope,
		finalizeRequest,
	)
	if err != nil ||
		replayedCompletion.Revision != completed.Revision ||
		replayedCompletion.Status != turncontrol.StatusCompleted {
		t.Fatalf(
			"Turn completion replay=%#v error=%v",
			replayedCompletion,
			err,
		)
	}
	events, err := controller.Events(ctx, turncontrol.EventQuery{
		OwnerID: ownerID, TurnID: completed.TurnID, Limit: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 12 ||
		events[len(events)-1].Authority != turncontrol.AuthorityArbiter ||
		events[len(events)-1].Artifact.Kind != turncontrol.ArtifactResponse {
		t.Fatalf("persisted Turn events=%#v", events)
	}
	auditTurn, err := controller.Begin(ctx, scope, turncontrol.BeginRequest{
		IdempotencyKey: uuid.NewString(),
		RequestID:      uuid.NewString(),
		OwnerID:        ownerID,
		ConversationID: "conversation-turn-event-audit",
		GoalDigest:     goalDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	auditTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auditTx.Exec(ctx, `
		UPDATE agent_turns
		SET phase='understand',
		    phase_attempt=1,
		    phase_deadline=clock_timestamp() + interval '1 minute',
		    revision=revision+1,
		    updated_at=clock_timestamp()
		WHERE turn_id=$1`,
		auditTurn.TurnID,
	); err != nil {
		_ = auditTx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := auditTx.Exec(ctx, `
		INSERT INTO agent_turn_events (
		    turn_id, revision, from_phase, to_phase, authority,
		    artifact_kind, artifact_origin, validation_outcome)
		VALUES (
		    $1,2,'prepare','understand','approval',
		    'none','controller','unspecified')`,
		auditTurn.TurnID,
	); err == nil {
		_ = auditTx.Rollback(ctx)
		t.Fatal("database trigger accepted a false Turn event authority")
	}
	if err := auditTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	foreignStore, err := postgres.New(pool, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreignStore.GetTurn(
		ctx,
		ownerID,
		completed.TurnID,
	); !errors.Is(err, turncontrol.ErrNotFound) {
		t.Fatalf("cross-Agent Turn read error=%v", err)
	}
	var persistedRaw []byte
	if err := pool.QueryRow(ctx, `
		SELECT convert_to(
		    row_to_json(item)::text,
		    'UTF8'
		)
		FROM (
		    SELECT t.*, json_agg(e ORDER BY e.revision) AS events
		    FROM agent_turns t
		    JOIN agent_turn_events e ON e.turn_id=t.turn_id
		    WHERE t.turn_id=$1
		    GROUP BY t.turn_id
		) item`,
		completed.TurnID,
	).Scan(&persistedRaw); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		[]byte(goal),
		[]byte("worker-objective-private-marker"),
		privateKey,
	} {
		if bytes.Contains(persistedRaw, forbidden) {
			t.Fatal("Turn ledger persisted forbidden content")
		}
	}
}

func advanceStoredTurn(
	t *testing.T,
	ctx context.Context,
	controller *turncontrol.Service,
	scope task.MutationScope,
	current turncontrol.Turn,
	next turncontrol.Phase,
	route turncontrol.Route,
	artifact turncontrol.Artifact,
	plan turncontrol.PlanBinding,
	validation turncontrol.ValidationOutcome,
) turncontrol.Turn {
	t.Helper()
	advanced, err := controller.Advance(ctx, scope, turncontrol.AdvanceRequest{
		IdempotencyKey:   uuid.NewString(),
		TurnID:           current.TurnID,
		OwnerID:          current.OwnerID,
		ExpectedRevision: current.Revision,
		ExpectedPhase:    current.Phase,
		NextPhase:        next,
		Route:            route,
		Artifact:         artifact,
		Plan:             plan,
		Validation:       validation,
	})
	if err != nil {
		t.Fatal(err)
	}
	return advanced
}

func storedTurnArtifact(
	kind turncontrol.ArtifactKind,
	origin turncontrol.ArtifactOrigin,
	name,
	character string,
) turncontrol.Artifact {
	return turncontrol.Artifact{
		Kind: kind, Origin: origin,
		Ref: "turn://artifact/" + name, Digest: storedTurnDigest(character),
	}
}

func storedTurnDigest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}
