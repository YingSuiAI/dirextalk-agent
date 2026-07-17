package postgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCloudGoalSecretWaitPostgresPersistsFencesAndUploadAtomicallyWakes(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx := context.Background()
	ownerID, connectionID := "owner-secret-wait", uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO cloud_connections
		    (connection_id, agent_instance_id, owner_id, account_id, region, control_role_arn,
		     foundation_stack_id, credential_generation, status, revision)
		VALUES ($1,$2,$3,'123456789012','ap-northeast-1',
		        'arn:aws:iam::123456789012:role/dirextalk-control','foundation-secret-wait',1,'active',1)`,
		connectionID, instanceID, ownerID); err != nil {
		t.Fatal(err)
	}
	statuses, err := postgres.NewCloudStatusStore(store)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := planning.NewCloudSkillAdapter(store, store)
	if err != nil {
		t.Fatal(err)
	}
	service := rpcapi.NewCloudControlServiceWithGoals(nil, instanceID, statuses, nil, planner)
	credentialID := uuid.NewString()
	caller := task.MutationScope{ClientID: "message-server", CredentialID: credentialID}
	created, err := service.CreateCloudGoal(auth.ContextWithPrincipal(ctx, auth.Principal{ClientID: caller.ClientID, CredentialID: caller.CredentialID}), &agentv1.CreateCloudGoalRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: ownerID, CloudConnectionId: connectionID,
		Goal:            "Research and plan an official knowledge service with a user model credential.",
		RetentionPolicy: agentv1.RetentionPolicy_RETENTION_POLICY_EPHEMERAL_AUTO_DESTROY,
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatchable, err := store.ListDispatchableCloudGoals(ctx, 1)
	if err != nil || len(dispatchable) != 1 {
		t.Fatalf("load Cloud Goal dispatch=%d err=%v", len(dispatchable), err)
	}
	goal := dispatchable[0]
	if goal.Task.TaskID != created.GetTask().GetTaskId() || goal.Caller != caller {
		t.Fatalf("Cloud Goal caller/task drift: %#v", goal)
	}
	draftRecipe := integrationRecipe(goal.Session.Binding.RecipeID)
	draftRecipe.SecretSlots = []recipe.SecretSlotRequirementV1{{
		SlotID: "model-credential", Purpose: "model token", Delivery: recipe.SecretDeliveryEnvironment,
	}}
	draft, err := store.SaveRecipeDraft(ctx, caller, planning.SaveRecipeDraftCommand{
		IdempotencyKey: uuid.NewString(), Binding: goal.Session.Binding, Recipe: draftRecipe,
	})
	if err != nil {
		t.Fatalf("save durable recipe draft: %v", err)
	}

	finalLease := advanceCloudGoalToFinalLease(t, ctx, store, goal)
	command := task.SuspendStepForSecretsCommand{
		IdempotencyKey: uuid.NewString(), TaskID: finalLease.TaskID, StepID: finalLease.StepID,
		Attempt: finalLease.Attempt, LeaseEpoch: finalLease.LeaseEpoch, WorkerID: finalLease.WorkerID,
		ExpectedTaskRevision: finalLease.TaskRevision, ExpectedStepRevision: finalLease.StepRevision, ExpectedAttemptRevision: finalLease.Revision,
		AgentInstanceID: instanceID,
		Requirements:    []task.SecretWaitRequirement{{Purpose: "model token", RecipeDigest: draft.Digest}},
	}
	released, err := store.SuspendStepForSecrets(ctx, caller, command)
	if err != nil {
		t.Fatalf("suspend final stage: %v", err)
	}
	if released.ExecutionStatus != task.ExecutionFinished || released.OutcomeStatus != task.OutcomeInterrupted || !released.LeaseExpiresAt.IsZero() {
		t.Fatalf("released attempt=%#v", released)
	}
	replayed, err := store.SuspendStepForSecrets(ctx, caller, command)
	if err != nil || replayed.Revision != released.Revision || replayed.ExecutionStatus != task.ExecutionFinished {
		t.Fatalf("suspend replay=%#v err=%v", replayed, err)
	}
	assertCloudGoalWaitingState(t, ctx, pool, store, goal.Task.TaskID, finalLease.StepID, finalLease)
	// current_step_id is stored as uuid even though the durable command carries
	// the step ID as a Go string. This exercises the actual PostgreSQL cast path.
	var persistedCurrentStepID string
	if err := pool.QueryRow(ctx, `SELECT current_step_id::text FROM tasks WHERE task_id=$1`, goal.Task.TaskID).Scan(&persistedCurrentStepID); err != nil {
		t.Fatal(err)
	}
	if persistedCurrentStepID != finalLease.StepID {
		t.Fatalf("persisted waiting current_step_id=%q want %q", persistedCurrentStepID, finalLease.StepID)
	}
	if _, err := store.CompleteStep(ctx, caller, task.CompleteStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: finalLease.TaskID, StepID: finalLease.StepID,
		Attempt: finalLease.Attempt, LeaseEpoch: finalLease.LeaseEpoch, WorkerID: finalLease.WorkerID,
		Outcome: task.OutcomeSucceeded, ResultRef: "cloud://plan/" + uuid.NewString(),
	}); !errors.Is(err, task.ErrStaleLease) {
		t.Fatalf("late completion error=%v, want stale lease", err)
	}
	if queued, err := store.ListDispatchableCloudGoals(ctx, 8); err != nil || len(queued) != 0 {
		t.Fatalf("waiting Goal was redispatched count=%d err=%v", len(queued), err)
	}

	masterKey := bytes.Repeat([]byte{0x6a}, 32)
	secretStore, err := store.NewSecretBootstrapStore(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	manager, err := secretbootstrap.NewManager(secretStore, secretStore.KeyStore(), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	bootstrapScope := secretbootstrap.MutationScope{ClientID: caller.ClientID, CredentialID: caller.CredentialID}
	uploadUnexpectedBootstrap(t, ctx, manager, bootstrapScope, secretbootstrap.BindingV1{
		AgentInstanceID: instanceID, OwnerID: "different-owner", Purpose: "model token", TargetID: draft.Digest,
	})
	wrongDigest := "sha256:" + strings.Repeat("f", 64)
	uploadUnexpectedBootstrap(t, ctx, manager, bootstrapScope, secretbootstrap.BindingV1{
		AgentInstanceID: instanceID, OwnerID: ownerID, Purpose: "model token", TargetID: wrongDigest,
	})
	assertCloudGoalWaitingState(t, ctx, pool, store, goal.Task.TaskID, finalLease.StepID, finalLease)

	createdSession := createAndUploadBootstrap(t, ctx, manager, bootstrapScope, secretbootstrap.BindingV1{
		AgentInstanceID: instanceID, OwnerID: ownerID, Purpose: "model token", TargetID: draft.Digest,
	})
	current, err := store.Get(ctx, goal.Task.TaskID)
	if err != nil || current.ExecutionStatus != task.ExecutionQueued || current.OutcomeStatus != task.OutcomePending || current.CurrentStepID != "" {
		t.Fatalf("correct upload did not queue task=%#v err=%v", current, err)
	}
	steps, err := store.ListSteps(ctx, goal.Task.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	final := findCloudGoalStep(t, steps, "prepare_resource_candidates")
	if final.ExecutionStatus != task.ExecutionQueued || final.OutcomeStatus != task.OutcomePending || final.Attempt != finalLease.Attempt || final.LeaseEpoch != finalLease.LeaseEpoch {
		t.Fatalf("correct upload did not queue exact step=%#v", final)
	}
	var waits, eventRows, outboxRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM cloud_goal_secret_waits WHERE task_id=$1`, goal.Task.TaskID).Scan(&waits); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM task_events WHERE aggregate_id=$1`, goal.Task.TaskID).Scan(&eventRows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE event_seq IN (SELECT seq FROM task_events WHERE aggregate_id=$1)`, goal.Task.TaskID).Scan(&outboxRows); err != nil {
		t.Fatal(err)
	}
	if waits != 0 || eventRows != outboxRows || eventRows < 6 {
		t.Fatalf("wake persistence waits=%d task_events=%d outbox=%d", waits, eventRows, outboxRows)
	}
	queued, err := store.ListDispatchableCloudGoals(ctx, 8)
	if err != nil || len(queued) != 1 {
		t.Fatalf("secret-ready Goal was not schedulable count=%d err=%v", len(queued), err)
	}
	if ready, err := store.CloudGoalStageReady(ctx, goal.Task.TaskID, final.StepID, final.LeaseEpoch); err != nil || !ready {
		t.Fatalf("secret-ready final stage readiness=%t err=%v", ready, err)
	}

	// A restart and replayed UploadEncrypted response cannot emit a second wake
	// or leave the session ID/plaintext in event/outbox rows.
	restartedStore, err := postgres.NewSecretBootstrapStore(pool, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := secretbootstrap.NewManager(restartedStore, restartedStore.KeyStore(), rand.Reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := restarted.UploadIdempotent(ctx, createdSession.uploadScope, createdSession.uploadKey, createdSession.session.SessionID, createdSession.session.Revision, createdSession.token, createdSession.envelope); err != nil || replay.SessionID != createdSession.uploaded.SessionID {
		t.Fatalf("upload restart replay=%#v err=%v", replay, err)
	}
	var eventText, outboxText string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(string_agg(summary_json::text, E'\n'),'') FROM task_events WHERE aggregate_id=$1`, goal.Task.TaskID).Scan(&eventText); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT COALESCE(string_agg(payload_json::text, E'\n'),'') FROM outbox_events WHERE event_seq IN (SELECT seq FROM task_events WHERE aggregate_id=$1)`, goal.Task.TaskID).Scan(&outboxText); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(eventText, createdSession.session.SessionID) || strings.Contains(outboxText, createdSession.session.SessionID) ||
		strings.Contains(eventText, "test-upload-value") || strings.Contains(outboxText, "test-upload-value") {
		t.Fatal("secret bootstrap identity or plaintext reached task event/outbox")
	}
}

type uploadedBootstrap struct {
	session     secretbootstrap.SessionV1
	uploaded    secretbootstrap.SessionV1
	uploadKey   string
	token       string
	envelope    secretbootstrap.EnvelopeV1
	uploadScope secretbootstrap.MutationScope
}

func createAndUploadBootstrap(t *testing.T, ctx context.Context, manager *secretbootstrap.Manager, scope secretbootstrap.MutationScope, binding secretbootstrap.BindingV1) uploadedBootstrap {
	t.Helper()
	created, err := manager.CreateIdempotent(ctx, scope, uuid.NewString(), binding)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := secretbootstrap.Seal(created.Session, []byte("test-upload-value"), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := uuid.NewString()
	rotated := scope
	rotated.CredentialID = uuid.NewString()
	uploaded, err := manager.UploadIdempotent(ctx, rotated, key, created.Session.SessionID, created.Session.Revision, created.UploadToken.Reveal(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	return uploadedBootstrap{session: created.Session, uploaded: uploaded, uploadKey: key, token: created.UploadToken.Reveal(), envelope: envelope, uploadScope: rotated}
}

func uploadUnexpectedBootstrap(t *testing.T, ctx context.Context, manager *secretbootstrap.Manager, scope secretbootstrap.MutationScope, binding secretbootstrap.BindingV1) {
	t.Helper()
	_ = createAndUploadBootstrap(t, ctx, manager, scope, binding)
}

func advanceCloudGoalToFinalLease(t *testing.T, ctx context.Context, store *postgres.Store, goal planning.CloudGoalDispatch) task.Attempt {
	t.Helper()
	workerID := uuid.NewString()
	for _, name := range []string{"research_official_sources", "draft_recipe"} {
		steps, err := store.ListSteps(ctx, goal.Task.TaskID)
		if err != nil {
			t.Fatal(err)
		}
		step := findCloudGoalStep(t, steps, name)
		attempt, acquired, err := store.AcquireReadyStep(ctx, goal.Caller, task.AcquireReadyStepCommand{
			IdempotencyKey: uuid.NewString(), TaskID: goal.Task.TaskID, StepID: step.StepID, WorkerID: workerID,
			ExecutorKind: task.ExecutorControlPlane, LeaseDuration: time.Minute,
		})
		if err != nil || !acquired {
			t.Fatalf("acquire %s attempt=%#v acquired=%t err=%v", name, attempt, acquired, err)
		}
		if _, err := store.CompleteStep(ctx, goal.Caller, task.CompleteStepCommand{
			IdempotencyKey: uuid.NewString(), TaskID: attempt.TaskID, StepID: attempt.StepID, Attempt: attempt.Attempt,
			LeaseEpoch: attempt.LeaseEpoch, WorkerID: attempt.WorkerID, Outcome: task.OutcomeSucceeded,
			ResultRef: "planning://" + name + "/" + strings.Repeat("a", 64),
		}); err != nil {
			t.Fatalf("complete %s: %v", name, err)
		}
	}
	steps, err := store.ListSteps(ctx, goal.Task.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	step := findCloudGoalStep(t, steps, "prepare_resource_candidates")
	attempt, acquired, err := store.AcquireReadyStep(ctx, goal.Caller, task.AcquireReadyStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: goal.Task.TaskID, StepID: step.StepID, WorkerID: workerID,
		ExecutorKind: task.ExecutorControlPlane, LeaseDuration: time.Minute,
	})
	if err != nil || !acquired || attempt.TaskRevision < 1 || attempt.StepRevision < 1 || attempt.Revision < 1 {
		t.Fatalf("acquire final attempt=%#v acquired=%t err=%v", attempt, acquired, err)
	}
	return attempt
}

func findCloudGoalStep(t *testing.T, steps []task.Step, name string) task.Step {
	t.Helper()
	for _, step := range steps {
		if step.Name == name {
			return step
		}
	}
	t.Fatalf("missing Cloud Goal step %q", name)
	return task.Step{}
}

func assertCloudGoalWaitingState(t *testing.T, ctx context.Context, pool *pgxpool.Pool, store *postgres.Store, taskID, stepID string, attempt task.Attempt) {
	t.Helper()
	current, err := store.Get(ctx, taskID)
	if err != nil || current.ExecutionStatus != task.ExecutionWaitingUser || current.OutcomeStatus != task.OutcomePending || current.CurrentStepID != stepID {
		t.Fatalf("waiting task=%#v err=%v", current, err)
	}
	steps, err := store.ListSteps(ctx, taskID)
	if err != nil {
		t.Fatal(err)
	}
	step := findCloudGoalStep(t, steps, "prepare_resource_candidates")
	if step.ExecutionStatus != task.ExecutionWaitingUser || step.OutcomeStatus != task.OutcomePending || step.Attempt != attempt.Attempt || step.LeaseEpoch != attempt.LeaseEpoch {
		t.Fatalf("waiting step=%#v", step)
	}
	var attemptExecution, attemptOutcome string
	var leaseExpiry *time.Time
	var waits int
	if err := pool.QueryRow(ctx, `SELECT execution_status, outcome_status, lease_expires_at FROM task_attempts WHERE task_id=$1 AND step_id=$2 AND attempt=$3`, taskID, stepID, attempt.Attempt).Scan(&attemptExecution, &attemptOutcome, &leaseExpiry); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM cloud_goal_secret_waits WHERE task_id=$1 AND step_id=$2 AND attempt=$3`, taskID, stepID, attempt.Attempt).Scan(&waits); err != nil {
		t.Fatal(err)
	}
	if attemptExecution != string(task.ExecutionFinished) || attemptOutcome != string(task.OutcomeInterrupted) || leaseExpiry != nil || waits != 1 {
		t.Fatalf("waiting attempt execution=%q outcome=%q lease=%v waits=%d", attemptExecution, attemptOutcome, leaseExpiry, waits)
	}
}
