package postgres_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCloudGoalRPCPersistsOnePlanningTaskAndOutboxSequence(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx := context.Background()
	ownerID := "owner-cloud-goal"
	connectionID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO cloud_connections
		    (connection_id, agent_instance_id, owner_id, account_id, region, control_role_arn,
		     foundation_stack_id, credential_generation, status, revision)
		VALUES ($1,$2,$3,'123456789012','ap-northeast-1',
		        'arn:aws:iam::123456789012:role/dirextalk-control','foundation-cloud-goal',1,'active',1)`,
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
	principalContext := auth.ContextWithPrincipal(ctx, auth.Principal{ClientID: "message-server", CredentialID: credentialID})
	request := &agentv1.CreateCloudGoalRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: ownerID, CloudConnectionId: connectionID,
		Goal:            "Research and plan an official knowledge service.",
		RetentionPolicy: agentv1.RetentionPolicy_RETENTION_POLICY_EPHEMERAL_AUTO_DESTROY,
	}

	created, err := service.CreateCloudGoal(principalContext, request)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := service.CreateCloudGoal(principalContext, request)
	if err != nil || !reflect.DeepEqual(created, replayed) {
		t.Fatalf("exact PostgreSQL replay changed response: replay=%#v err=%v", replayed, err)
	}
	changed := &agentv1.CreateCloudGoalRequest{
		IdempotencyKey: request.GetIdempotencyKey(), OwnerId: request.GetOwnerId(), CloudConnectionId: request.GetCloudConnectionId(),
		Goal: "Research a different service.", RetentionPolicy: request.GetRetentionPolicy(), RecipeId: request.GetRecipeId(),
	}
	if _, err := service.CreateCloudGoal(principalContext, changed); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("conflicting PostgreSQL replay code=%s err=%v", status.Code(err), err)
	}

	var taskRows, sessionRows, eventRows, outboxRows int
	var persistedConnection, persistedTask string
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE owner_id=$1`, ownerID).Scan(&taskRows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*), COALESCE(max(connection_id::text),''), COALESCE(max(task_id::text),'')
		FROM planning_sessions WHERE owner_id=$1`, ownerID).Scan(&sessionRows, &persistedConnection, &persistedTask); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM task_events
		WHERE aggregate_id=$1 OR (aggregate_type='planning_session' AND summary_json->>'owner_id'=$2)`,
		created.GetTask().GetTaskId(), ownerID).Scan(&eventRows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM outbox_events
		WHERE event_seq IN (
			SELECT seq FROM task_events
			WHERE aggregate_id=$1 OR (aggregate_type='planning_session' AND summary_json->>'owner_id'=$2)
		)`, created.GetTask().GetTaskId(), ownerID).Scan(&outboxRows); err != nil {
		t.Fatal(err)
	}
	if taskRows != 1 || sessionRows != 1 || persistedConnection != connectionID || persistedTask != created.GetTask().GetTaskId() || eventRows != 4 || outboxRows != 4 {
		t.Fatalf("durable Goal facts task=%d session=%d connection=%q task_id=%q events=%d outbox=%d", taskRows, sessionRows, persistedConnection, persistedTask, eventRows, outboxRows)
	}
	dispatchable, err := store.ListDispatchableCloudGoals(ctx, 10)
	if err != nil || len(dispatchable) != 1 {
		t.Fatalf("dispatchable Cloud Goals=%d err=%v", len(dispatchable), err)
	}
	queued := dispatchable[0]
	if queued.Task.TaskID != created.GetTask().GetTaskId() || queued.Session.TaskID != queued.Task.TaskID ||
		queued.Session.Binding.RequestID != request.GetIdempotencyKey() || queued.Session.Binding.ConnectionID != connectionID ||
		queued.Caller.ClientID != "message-server" || queued.Caller.CredentialID != credentialID {
		t.Fatalf("dispatchable Cloud Goal lost durable caller/session binding: %#v", queued)
	}
	steps, err := store.ListSteps(ctx, queued.Task.TaskID)
	if err != nil || len(steps) != 3 {
		t.Fatalf("queued planning steps=%d err=%v", len(steps), err)
	}
	if ready, err := store.CloudGoalStageReady(ctx, queued.Task.TaskID, steps[0].StepID, steps[0].LeaseEpoch); err != nil || !ready {
		t.Fatalf("queued stage readiness=%t err=%v", ready, err)
	}
	leased, acquired, err := store.AcquireReadyStep(ctx, queued.Caller, task.AcquireReadyStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: queued.Task.TaskID, StepID: steps[0].StepID,
		WorkerID: uuid.NewString(), ExecutorKind: task.ExecutorControlPlane, LeaseDuration: time.Minute,
	})
	if err != nil || !acquired {
		t.Fatalf("lease queued Cloud Goal stage=%#v acquired=%t err=%v", leased, acquired, err)
	}
	if active, err := store.ListDispatchableCloudGoals(ctx, 10); err != nil || len(active) != 0 {
		t.Fatalf("active unexpired Goal was redispatched: count=%d err=%v", len(active), err)
	}
	if ready, err := store.CloudGoalStageReady(ctx, leased.TaskID, leased.StepID, leased.LeaseEpoch); err != nil || ready {
		t.Fatalf("active stage readiness=%t err=%v", ready, err)
	}
	goalDigest := sha256.Sum256([]byte(strings.TrimSpace(queued.Task.Goal)))
	identity := planning.CloudGoalStageIdentity{
		OutputIdempotencyKey: uuid.NewString(), Binding: queued.Session.Binding,
		TaskID: leased.TaskID, StepID: leased.StepID, StepName: steps[0].Name, GoalDigest: fmt.Sprintf("%x", goalDigest[:]),
	}
	stageOutput := planning.CloudGoalStageOutput{ResultRef: "planning://official-source-evidence/sha256:" + strings.Repeat("a", 64)}
	stageCommand := planning.SaveCloudGoalStageOutputCommand{Identity: identity, Attempt: leased, Output: stageOutput}
	savedOutput, err := store.SaveCloudGoalStageOutput(ctx, queued.Caller, stageCommand)
	if err != nil || savedOutput != stageOutput {
		t.Fatalf("save fenced stage output=%#v err=%v", savedOutput, err)
	}
	if replayed, err := store.SaveCloudGoalStageOutput(ctx, queued.Caller, stageCommand); err != nil || replayed != stageOutput {
		t.Fatalf("replay fenced stage output=%#v err=%v", replayed, err)
	}
	if loaded, found, err := store.GetCloudGoalStageOutput(ctx, queued.Caller, identity, leased); err != nil || !found || loaded != stageOutput {
		t.Fatalf("load fenced stage output=%#v found=%t err=%v", loaded, found, err)
	}
	conflictingStage := stageCommand
	conflictingStage.Output.ResultRef = "planning://official-source-evidence/sha256:" + strings.Repeat("b", 64)
	if _, err := store.SaveCloudGoalStageOutput(ctx, queued.Caller, conflictingStage); !errors.Is(err, task.ErrIdempotencyConflict) {
		t.Fatalf("conflicting stage output error=%v", err)
	}
	canary := "sk-" + strings.Repeat("Z", 40)
	secretStage := stageCommand
	secretStage.Identity.OutputIdempotencyKey = uuid.NewString()
	secretStage.Output.ResultRef = "planning://official-source-evidence/" + canary
	if _, err := store.SaveCloudGoalStageOutput(ctx, queued.Caller, secretStage); !errors.Is(err, planning.ErrCloudGoalOutputInvalid) {
		t.Fatalf("secret stage output error=%v", err)
	}
	var canaryRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM idempotency_records WHERE COALESCE(response_json::text,'') LIKE '%' || $1 || '%'`, canary).Scan(&canaryRows); err != nil || canaryRows != 0 {
		t.Fatalf("stage secret canary rows=%d err=%v", canaryRows, err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE task_attempts SET lease_expires_at=clock_timestamp()-interval '1 second'
		WHERE task_id=$1 AND step_id=$2 AND attempt=$3 AND lease_epoch=$4`,
		leased.TaskID, leased.StepID, leased.Attempt, leased.LeaseEpoch); err != nil {
		t.Fatal(err)
	}
	if expired, err := store.ListDispatchableCloudGoals(ctx, 10); err != nil || len(expired) != 1 {
		t.Fatalf("expired Goal was not recoverable: count=%d err=%v", len(expired), err)
	}
	if ready, err := store.CloudGoalStageReady(ctx, leased.TaskID, leased.StepID, leased.LeaseEpoch); err != nil || !ready {
		t.Fatalf("expired stage readiness=%t err=%v", ready, err)
	}
	staleStage := stageCommand
	staleStage.Identity.OutputIdempotencyKey = uuid.NewString()
	if _, err := store.SaveCloudGoalStageOutput(ctx, queued.Caller, staleStage); !errors.Is(err, task.ErrStaleLease) {
		t.Fatalf("expired lease stage output error=%v", err)
	}
	recoveredLease, acquired, err := store.AcquireReadyStep(ctx, queued.Caller, task.AcquireReadyStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: queued.Task.TaskID, StepID: steps[0].StepID,
		WorkerID: uuid.NewString(), ExecutorKind: task.ExecutorControlPlane, LeaseDuration: time.Minute,
	})
	if err != nil || !acquired || recoveredLease.LeaseEpoch != leased.LeaseEpoch+1 {
		t.Fatalf("recover expired stage lease=%#v acquired=%t err=%v", recoveredLease, acquired, err)
	}
	if replayed, found, err := store.GetCloudGoalStageOutput(ctx, queued.Caller, identity, recoveredLease); err != nil || !found || replayed != stageOutput {
		t.Fatalf("cross-lease stage replay=%#v found=%t err=%v", replayed, found, err)
	}
}
