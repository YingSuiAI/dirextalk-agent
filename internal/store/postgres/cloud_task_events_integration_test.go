package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

func TestCloudGoalTaskEventsAreProjectableAndIdempotent(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx := context.Background()
	ownerID, connectionID := "owner-cloud-task-events", uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO cloud_connections
		    (connection_id, agent_instance_id, owner_id, account_id, region, control_role_arn,
		     foundation_stack_id, credential_generation, status, revision)
		VALUES ($1,$2,$3,'123456789012','ap-northeast-1',
		        'arn:aws:iam::123456789012:role/dirextalk-control','foundation-cloud-task-events',1,'active',1)`,
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
	caller := auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()}
	requestID := uuid.NewString()
	promptCanary := "goal-prompt-canary-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	request := &agentv1.CreateCloudGoalRequest{
		IdempotencyKey: requestID, OwnerId: ownerID, CloudConnectionId: connectionID,
		Goal:            "Research the official knowledge service " + promptCanary + " at https://not-for-events.example/.",
		RetentionPolicy: agentv1.RetentionPolicy_RETENTION_POLICY_EPHEMERAL_AUTO_DESTROY,
	}
	principalContext := auth.ContextWithPrincipal(ctx, caller)
	created, err := service.CreateCloudGoal(principalContext, request)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := service.CreateCloudGoal(principalContext, request)
	if err != nil || !reflect.DeepEqual(created, replayed) {
		t.Fatalf("cloud Goal creation replay=%#v err=%v", replayed, err)
	}
	assertCloudTaskProjectionRows(t, ctx, pool, created.GetTask().GetTaskId(), ownerID, promptCanary, 1, 0)

	scope := task.MutationScope{ClientID: caller.ClientID, CredentialID: caller.CredentialID}
	steps, err := store.ListSteps(ctx, created.GetTask().GetTaskId())
	if err != nil || len(steps) != 3 {
		t.Fatalf("cloud Goal steps=%d err=%v", len(steps), err)
	}
	completeCloudPlanningStage(t, ctx, store, scope, created.GetTask().GetTaskId(), steps[0], "planning://official-source-evidence/sha256:"+strings.Repeat("a", 64), "")
	completeCloudPlanningStage(t, ctx, store, scope, created.GetTask().GetTaskId(), steps[1], "planning://recipe/sha256:"+strings.Repeat("b", 64), "")
	otherRequest := proto.Clone(request).(*agentv1.CreateCloudGoalRequest)
	otherRequest.IdempotencyKey, otherRequest.Goal = uuid.NewString(), "Research another official service."
	other, err := service.CreateCloudGoal(principalContext, otherRequest)
	if err != nil {
		t.Fatal(err)
	}
	foreignPlan := createReadyCloudTaskPlan(t, ctx, store, instanceID, ownerID, connectionID, other.GetTask().GetTaskId())
	plan := createReadyCloudTaskPlan(t, ctx, store, instanceID, ownerID, connectionID, created.GetTask().GetTaskId())
	finalAttempt := acquireCloudPlanningStage(t, ctx, store, scope, created.GetTask().GetTaskId(), steps[2])
	t.Run("rejects plan bound to another task", func(t *testing.T) {
		wrong := task.CompleteStepCommand{
			IdempotencyKey: uuid.NewString(), TaskID: finalAttempt.TaskID, StepID: finalAttempt.StepID,
			Attempt: finalAttempt.Attempt, LeaseEpoch: finalAttempt.LeaseEpoch, WorkerID: finalAttempt.WorkerID,
			Outcome: task.OutcomeSucceeded, ResultRef: "cloud://plan/" + foreignPlan.PlanID, RelatedPlanID: foreignPlan.PlanID,
		}
		if _, err := store.CompleteStep(ctx, scope, wrong); !errors.Is(err, task.ErrInvalid) {
			t.Fatalf("cross-task Plan completion error=%v, want task.ErrInvalid", err)
		}
		persisted, err := store.Get(ctx, created.GetTask().GetTaskId())
		if err != nil || persisted.ApprovedPlanID != "" || persisted.ExecutionStatus != task.ExecutionRunning || persisted.OutcomeStatus != task.OutcomePending {
			t.Fatalf("cross-task Plan changed Task=%#v err=%v", persisted, err)
		}
	})
	finalCommand := task.CompleteStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: finalAttempt.TaskID, StepID: finalAttempt.StepID,
		Attempt: finalAttempt.Attempt, LeaseEpoch: finalAttempt.LeaseEpoch, WorkerID: finalAttempt.WorkerID,
		Outcome: task.OutcomeSucceeded, ResultRef: "cloud://plan/" + plan.PlanID, RelatedPlanID: plan.PlanID,
	}
	completed, err := store.CompleteStep(ctx, scope, finalCommand)
	if err != nil || completed.OutcomeStatus != task.OutcomeSucceeded {
		t.Fatalf("final Cloud Goal completion=%#v err=%v", completed, err)
	}
	var beforeReplay int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM task_events WHERE event_type IN ('cloud.task.changed','cloud.step.changed')`).Scan(&beforeReplay); err != nil {
		t.Fatal(err)
	}
	replayedAttempt, err := store.CompleteStep(ctx, scope, finalCommand)
	if err != nil || !reflect.DeepEqual(completed, replayedAttempt) {
		t.Fatalf("final Cloud Goal replay=%#v err=%v", replayedAttempt, err)
	}
	var afterReplay int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM task_events WHERE event_type IN ('cloud.task.changed','cloud.step.changed')`).Scan(&afterReplay); err != nil {
		t.Fatal(err)
	}
	if afterReplay != beforeReplay {
		t.Fatalf("idempotent final completion duplicated Cloud events: before=%d after=%d", beforeReplay, afterReplay)
	}

	item, err := store.Get(ctx, created.GetTask().GetTaskId())
	if err != nil || item.ExecutionStatus != task.ExecutionFinished || item.OutcomeStatus != task.OutcomeSucceeded || item.ApprovedPlanID != plan.PlanID {
		t.Fatalf("final Cloud Goal Task=%#v err=%v", item, err)
	}
	assertCloudTaskProjectionRows(t, ctx, pool, created.GetTask().GetTaskId(), ownerID, promptCanary, 7, 6)
	assertCloudTaskPlanProjection(t, ctx, pool, created.GetTask().GetTaskId(), plan.PlanID)
}

func acquireCloudPlanningStage(t *testing.T, ctx context.Context, store *postgres.Store, scope task.MutationScope, taskID string, step task.Step) task.Attempt {
	t.Helper()
	attempt, acquired, err := store.AcquireReadyStep(ctx, scope, task.AcquireReadyStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: taskID, StepID: step.StepID, WorkerID: uuid.NewString(),
		ExecutorKind: task.ExecutorControlPlane, LeaseDuration: time.Minute,
	})
	if err != nil || !acquired || attempt.ExecutionStatus != task.ExecutionRunning || attempt.OutcomeStatus != task.OutcomePending {
		t.Fatalf("acquire Cloud planning stage=%#v acquired=%t err=%v", attempt, acquired, err)
	}
	return attempt
}

func completeCloudPlanningStage(t *testing.T, ctx context.Context, store *postgres.Store, scope task.MutationScope, taskID string, step task.Step, resultRef, relatedPlanID string) {
	t.Helper()
	attempt := acquireCloudPlanningStage(t, ctx, store, scope, taskID, step)
	completed, err := store.CompleteStep(ctx, scope, task.CompleteStepCommand{
		IdempotencyKey: uuid.NewString(), TaskID: attempt.TaskID, StepID: attempt.StepID, Attempt: attempt.Attempt,
		LeaseEpoch: attempt.LeaseEpoch, WorkerID: attempt.WorkerID, Outcome: task.OutcomeSucceeded,
		ResultRef: resultRef, RelatedPlanID: relatedPlanID,
	})
	if err != nil || completed.ExecutionStatus != task.ExecutionFinished || completed.OutcomeStatus != task.OutcomeSucceeded {
		t.Fatalf("complete Cloud planning stage=%#v err=%v", completed, err)
	}
}

func createReadyCloudTaskPlan(t *testing.T, ctx context.Context, store *postgres.Store, instanceID, ownerID, connectionID, taskID string) cloudapproval.PlanV1 {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	plan := cloudApprovalPlanFixture(instanceID)
	plan.PlanID, plan.OwnerID, plan.ConnectionID = uuid.NewString(), ownerID, connectionID
	quoted := cloudApprovalQuoteFixture(t, plan, uuid.NewString(), now)
	digest, err := quoted.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan.Quote.QuoteID, plan.Quote.Digest, plan.Quote.ValidUntil = quoted.QuoteID, digest, quoted.ValidUntil
	scope := task.MutationScope{ClientID: "cloud-task-event-plan", CredentialID: uuid.NewString()}
	if _, err := store.CreateQuote(ctx, scope, postgres.CreateQuoteCommand{IdempotencyKey: uuid.NewString(), Quote: quoted}); err != nil {
		t.Fatal(err)
	}
	created, err := store.CreatePlan(ctx, scope, postgres.CreatePlanCommand{IdempotencyKey: uuid.NewString(), TaskID: taskID, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func assertCloudTaskProjectionRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, taskID, ownerID, forbidden string, wantTasks, wantSteps int) {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT event.event_type, event.aggregate_type, event.aggregate_id::text, event.revision,
		       event.summary_json, outbox.topic, outbox.payload_json
		FROM task_events event
		JOIN outbox_events outbox ON outbox.event_seq=event.seq
		WHERE event.event_type IN ('cloud.task.changed','cloud.step.changed')
		  AND event.summary_json->>'task_id'=$1
		ORDER BY event.seq`, taskID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var taskCount, stepCount int
	for rows.Next() {
		var eventType, aggregateType, aggregateID, topic string
		var revision int64
		var summary, payload []byte
		if err := rows.Scan(&eventType, &aggregateType, &aggregateID, &revision, &summary, &topic, &payload); err != nil {
			t.Fatal(err)
		}
		if topic != eventType || revision < 1 {
			t.Fatalf("Cloud Task event/outbox metadata=%q/%q revision=%d", eventType, topic, revision)
		}
		assertCloudTaskSummary(t, summary, eventType, aggregateType, aggregateID, taskID, ownerID, revision)
		assertCloudTaskOutboxEnvelope(t, payload, summary, eventType, aggregateType, aggregateID, revision)
		if strings.Contains(string(summary), forbidden) || strings.Contains(string(payload), forbidden) ||
			strings.Contains(string(summary), "https://") || strings.Contains(string(payload), "https://") {
			t.Fatal("Cloud Task event/outbox leaked Goal text or URL")
		}
		switch eventType {
		case "cloud.task.changed":
			taskCount++
		case "cloud.step.changed":
			stepCount++
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if taskCount != wantTasks || stepCount != wantSteps {
		t.Fatalf("Cloud Task events task=%d step=%d want task=%d step=%d", taskCount, stepCount, wantTasks, wantSteps)
	}
}

func assertCloudTaskSummary(t *testing.T, encoded []byte, eventType, aggregateType, aggregateID, taskID, ownerID string, revision int64) {
	t.Helper()
	var summary map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &summary); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]struct{}{
		"schema_version": {}, "task_id": {}, "step_id": {}, "owner_id": {}, "execution_status": {}, "outcome_status": {},
		"current_stage": {}, "related_plan_id": {}, "error_code": {}, "revision": {}, "updated_at": {},
	}
	for key := range summary {
		if _, ok := allowed[key]; !ok {
			t.Fatalf("Cloud Task summary has unreviewed field %q: %s", key, encoded)
		}
	}
	if got := cloudTaskString(t, summary, "task_id"); got != taskID {
		t.Fatalf("summary task_id=%q want %q", got, taskID)
	}
	if got := cloudTaskString(t, summary, "owner_id"); got != ownerID {
		t.Fatalf("summary owner_id=%q want %q", got, ownerID)
	}
	if got := cloudTaskInt(t, summary, "schema_version"); got != 1 {
		t.Fatalf("summary schema_version=%d", got)
	}
	if got := cloudTaskInt(t, summary, "revision"); got != revision {
		t.Fatalf("summary revision=%d want %d", got, revision)
	}
	stage := cloudTaskString(t, summary, "current_stage")
	if stage != "research" && stage != "recipe" && stage != "quote" && stage != "waiting_user" && stage != "ready_for_confirmation" && stage != "finished" {
		t.Fatalf("summary current_stage=%q", stage)
	}
	if _, err := time.Parse(time.RFC3339Nano, cloudTaskString(t, summary, "updated_at")); err != nil {
		t.Fatalf("summary updated_at=%s", summary["updated_at"])
	}
	if eventType == "cloud.task.changed" && aggregateType != "cloud_task" {
		t.Fatalf("task aggregate_type=%q", aggregateType)
	}
	if eventType == "cloud.step.changed" {
		if aggregateType != "cloud_step" || cloudTaskString(t, summary, "step_id") != aggregateID {
			t.Fatalf("step aggregate/summary mismatch type=%q id=%q summary=%s", aggregateType, aggregateID, encoded)
		}
	}
	if eventType == "cloud.task.changed" && aggregateID != taskID {
		t.Fatalf("task aggregate_id=%q want %q", aggregateID, taskID)
	}
}

func assertCloudTaskOutboxEnvelope(t *testing.T, encoded, wantSummary []byte, eventType, aggregateType, aggregateID string, revision int64) {
	t.Helper()
	var payload struct {
		SchemaVersion int             `json:"schema_version"`
		EventType     string          `json:"event_type"`
		AggregateType string          `json:"aggregate_type"`
		AggregateID   string          `json:"aggregate_id"`
		Revision      int64           `json:"revision"`
		Summary       json.RawMessage `json:"summary"`
	}
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.SchemaVersion != 1 || payload.EventType != eventType || payload.AggregateType != aggregateType ||
		payload.AggregateID != aggregateID || payload.Revision != revision || !reflect.DeepEqual(payload.Summary, json.RawMessage(wantSummary)) {
		t.Fatalf("Cloud Task outbox payload=%s", encoded)
	}
}

func assertCloudTaskPlanProjection(t *testing.T, ctx context.Context, pool *pgxpool.Pool, taskID, planID string) {
	t.Helper()
	var summary []byte
	if err := pool.QueryRow(ctx, `
		SELECT summary_json FROM task_events
		WHERE event_type='cloud.task.changed' AND aggregate_id=$1
		ORDER BY seq DESC LIMIT 1`, taskID).Scan(&summary); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(summary, &decoded); err != nil {
		t.Fatal(err)
	}
	if cloudTaskString(t, decoded, "related_plan_id") != planID || cloudTaskString(t, decoded, "current_stage") != "ready_for_confirmation" {
		t.Fatalf("final Cloud Task projection=%s", summary)
	}
}

func cloudTaskString(t *testing.T, fields map[string]json.RawMessage, key string) string {
	t.Helper()
	var value string
	if raw, ok := fields[key]; !ok || json.Unmarshal(raw, &value) != nil {
		t.Fatalf("Cloud Task summary missing string %q: %#v", key, fields)
	}
	return value
}

func cloudTaskInt(t *testing.T, fields map[string]json.RawMessage, key string) int64 {
	t.Helper()
	var value int64
	if raw, ok := fields[key]; !ok || json.Unmarshal(raw, &value) != nil {
		t.Fatalf("Cloud Task summary missing integer %q: %#v", key, fields)
	}
	return value
}
