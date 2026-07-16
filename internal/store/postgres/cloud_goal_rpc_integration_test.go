package postgres_test

import (
	"context"
	"reflect"
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
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
	principalContext := auth.ContextWithPrincipal(ctx, auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
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
	changed := *request
	changed.Goal = "Research a different service."
	if _, err := service.CreateCloudGoal(principalContext, &changed); status.Code(err) != codes.AlreadyExists {
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
	if taskRows != 1 || sessionRows != 1 || persistedConnection != connectionID || persistedTask != created.GetTask().GetTaskId() || eventRows != 3 || outboxRows != 3 {
		t.Fatalf("durable Goal facts task=%d session=%d connection=%q task_id=%q events=%d outbox=%d", taskRows, sessionRows, persistedConnection, persistedTask, eventRows, outboxRows)
	}
}
