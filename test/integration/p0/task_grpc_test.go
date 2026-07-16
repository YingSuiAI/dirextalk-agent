package p0_test

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestTaskCreateReplayConflictAndCancelRevision(t *testing.T) {
	database := newMigratedDatabase(t)
	harness := newGRPCHarness(t, database.store, map[string][]string{
		"task-client": {"task.read", "task.write", "event.read"},
	})
	serviceKey := harness.keys["task-client"].value
	request := &agentv1.CreateTaskRequest{
		IdempotencyKey:  uuid.NewString(),
		OwnerId:         "owner-p0-task-flow",
		Goal:            "Compile the integration fixture and retain its evidence.",
		RetentionPolicy: agentv1.RetentionPolicy_RETENTION_POLICY_EPHEMERAL_AUTO_DESTROY,
	}

	ctx, cancel := rpcContext(serviceKey, 10*time.Second)
	created, err := harness.client.CreateTask(ctx, request)
	cancel()
	if err != nil {
		t.Fatalf("CreateTask failed: %v", status.Code(err))
	}
	if created.GetTask() == nil || created.GetTask().GetTaskId() == "" || created.GetTask().GetRevision() != 1 {
		t.Fatalf("CreateTask returned an incomplete task: %#v", created.GetTask())
	}
	if created.GetTask().GetExecutionStatus() != agentv1.ExecutionStatus_EXECUTION_STATUS_PLANNING ||
		created.GetTask().GetOutcomeStatus() != agentv1.OutcomeStatus_OUTCOME_STATUS_PENDING {
		t.Fatalf("CreateTask returned unexpected state: execution=%s outcome=%s", created.GetTask().GetExecutionStatus(), created.GetTask().GetOutcomeStatus())
	}

	ctx, cancel = rpcContext(serviceKey, 10*time.Second)
	replayed, err := harness.client.CreateTask(ctx, request)
	cancel()
	if err != nil {
		t.Fatalf("idempotent CreateTask replay failed: %v", status.Code(err))
	}
	if !proto.Equal(created.GetTask(), replayed.GetTask()) {
		t.Fatal("idempotent CreateTask replay did not return the original task")
	}

	conflicting := proto.Clone(request).(*agentv1.CreateTaskRequest)
	conflicting.Goal = "Use the same idempotency key for different input."
	ctx, cancel = rpcContext(serviceKey, 10*time.Second)
	_, err = harness.client.CreateTask(ctx, conflicting)
	cancel()
	assertCode(t, err, codes.AlreadyExists)

	ctx, cancel = rpcContext(serviceKey, 10*time.Second)
	read, err := harness.client.GetTask(ctx, &agentv1.GetTaskRequest{TaskId: created.GetTask().GetTaskId()})
	cancel()
	if err != nil || !proto.Equal(created.GetTask(), read.GetTask()) {
		t.Fatalf("GetTask did not return the persisted task: %v", status.Code(err))
	}
	ctx, cancel = rpcContext(serviceKey, 10*time.Second)
	listed, err := harness.client.ListTasks(ctx, &agentv1.ListTasksRequest{OwnerId: request.GetOwnerId(), PageSize: 10})
	cancel()
	if err != nil || len(listed.GetTasks()) != 1 || listed.GetTasks()[0].GetTaskId() != created.GetTask().GetTaskId() {
		t.Fatalf("ListTasks did not return the persisted owner task: code=%v count=%d", status.Code(err), len(listed.GetTasks()))
	}

	staleCancel := &agentv1.CancelTaskRequest{
		IdempotencyKey: uuid.NewString(), TaskId: created.GetTask().GetTaskId(),
		ExpectedRevision: created.GetTask().GetRevision() + 1, Reason: "stale caller revision",
	}
	ctx, cancel = rpcContext(serviceKey, 10*time.Second)
	_, err = harness.client.CancelTask(ctx, staleCancel)
	cancel()
	assertCode(t, err, codes.Aborted)

	validCancel := &agentv1.CancelTaskRequest{
		IdempotencyKey: uuid.NewString(), TaskId: created.GetTask().GetTaskId(),
		ExpectedRevision: created.GetTask().GetRevision(), Reason: "P0 integration test complete",
	}
	ctx, cancel = rpcContext(serviceKey, 10*time.Second)
	canceled, err := harness.client.CancelTask(ctx, validCancel)
	cancel()
	if err != nil {
		t.Fatalf("CancelTask failed: %v", status.Code(err))
	}
	if canceled.GetTask().GetRevision() != created.GetTask().GetRevision()+1 ||
		canceled.GetTask().GetExecutionStatus() != agentv1.ExecutionStatus_EXECUTION_STATUS_FINISHED ||
		canceled.GetTask().GetOutcomeStatus() != agentv1.OutcomeStatus_OUTCOME_STATUS_CANCELED {
		t.Fatalf("CancelTask returned unexpected terminal task: %#v", canceled.GetTask())
	}
	ctx, cancel = rpcContext(serviceKey, 10*time.Second)
	cancelReplay, err := harness.client.CancelTask(ctx, validCancel)
	cancel()
	if err != nil || !proto.Equal(canceled.GetTask(), cancelReplay.GetTask()) {
		t.Fatalf("idempotent CancelTask replay did not return the original result: %v", status.Code(err))
	}
	ctx, cancel = rpcContext(serviceKey, 10*time.Second)
	createReplayAfterMutation, err := harness.client.CreateTask(ctx, request)
	cancel()
	if err != nil || !proto.Equal(created.GetTask(), createReplayAfterMutation.GetTask()) {
		t.Fatalf("CreateTask replay returned mutated resource state instead of the original result: %v", status.Code(err))
	}
}

func TestWatchEventsResumesAfterPersistentCursor(t *testing.T) {
	database := newMigratedDatabase(t)
	harness := newGRPCHarness(t, database.store, map[string][]string{
		"event-client": {"task.write", "event.read"},
	})
	serviceKey := harness.keys["event-client"].value
	first := createTask(t, harness.client, serviceKey, "owner-p0-events", "Create first cursor event.")
	second := createTask(t, harness.client, serviceKey, "owner-p0-events", "Create second cursor event.")

	streamContext, stopStream := rpcContext(serviceKey, 10*time.Second)
	stream, err := harness.client.WatchEvents(streamContext, &agentv1.WatchEventsRequest{AfterSeq: 0})
	if err != nil {
		stopStream()
		t.Fatalf("open initial WatchEvents stream failed: %v", status.Code(err))
	}
	firstEvent, err := stream.Recv()
	if err != nil {
		stopStream()
		t.Fatalf("receive first event failed: %v", status.Code(err))
	}
	secondEvent, err := stream.Recv()
	stopStream()
	if err != nil {
		t.Fatalf("receive second event failed: %v", status.Code(err))
	}
	if firstEvent.GetEvent().GetAggregateId() != first.GetTask().GetTaskId() || secondEvent.GetEvent().GetAggregateId() != second.GetTask().GetTaskId() {
		t.Fatal("WatchEvents did not preserve committed task event order")
	}
	if firstEvent.GetEvent().GetSeq() <= 0 || secondEvent.GetEvent().GetSeq() <= firstEvent.GetEvent().GetSeq() {
		t.Fatal("WatchEvents sequence is not strictly monotonic")
	}

	third := createTask(t, harness.client, serviceKey, "owner-p0-events", "Create event after disconnect.")
	resumeContext, stopResume := rpcContext(serviceKey, 10*time.Second)
	resumed, err := harness.client.WatchEvents(resumeContext, &agentv1.WatchEventsRequest{AfterSeq: secondEvent.GetEvent().GetSeq()})
	if err != nil {
		stopResume()
		t.Fatalf("resume WatchEvents stream failed: %v", status.Code(err))
	}
	next, err := resumed.Recv()
	stopResume()
	if err != nil {
		t.Fatalf("receive resumed event failed: %v", status.Code(err))
	}
	if next.GetEvent().GetAggregateId() != third.GetTask().GetTaskId() || next.GetEvent().GetSeq() <= secondEvent.GetEvent().GetSeq() {
		t.Fatal("WatchEvents resume replayed an old event or skipped the next committed event")
	}
}

func TestServiceKeyScopesFailClosed(t *testing.T) {
	database := newMigratedDatabase(t)
	harness := newGRPCHarness(t, database.store, map[string][]string{
		"read":  {"task.read"},
		"write": {"task.write"},
		"event": {"event.read"},
	})
	request := &agentv1.CreateTaskRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: "owner-p0-auth", Goal: "Exercise scoped Service Keys.",
		RetentionPolicy: agentv1.RetentionPolicy_RETENTION_POLICY_EPHEMERAL_AUTO_DESTROY,
	}

	ctx, cancel := rpcContext("", 5*time.Second)
	_, err := harness.client.CreateTask(ctx, request)
	cancel()
	assertCode(t, err, codes.Unauthenticated)

	unknownKey := auth.FormatServiceKey("unknown-p0-key", make([]byte, 32))
	ctx, cancel = rpcContext(unknownKey, 5*time.Second)
	_, err = harness.client.CreateTask(ctx, request)
	cancel()
	assertCode(t, err, codes.Unauthenticated)

	ctx, cancel = rpcContext(harness.keys["read"].value, 5*time.Second)
	_, err = harness.client.CreateTask(ctx, request)
	cancel()
	assertCode(t, err, codes.PermissionDenied)

	ctx, cancel = rpcContext(harness.keys["write"].value, 10*time.Second)
	created, err := harness.client.CreateTask(ctx, request)
	cancel()
	if err != nil {
		t.Fatalf("task.write Service Key could not create task: %v", status.Code(err))
	}
	ctx, cancel = rpcContext(harness.keys["write"].value, 5*time.Second)
	_, err = harness.client.GetTask(ctx, &agentv1.GetTaskRequest{TaskId: created.GetTask().GetTaskId()})
	cancel()
	assertCode(t, err, codes.PermissionDenied)

	ctx, cancel = rpcContext(harness.keys["read"].value, 5*time.Second)
	read, err := harness.client.GetTask(ctx, &agentv1.GetTaskRequest{TaskId: created.GetTask().GetTaskId()})
	cancel()
	if err != nil || read.GetTask().GetTaskId() != created.GetTask().GetTaskId() {
		t.Fatalf("task.read Service Key could not read task: %v", status.Code(err))
	}

	streamContext, stopStream := rpcContext(harness.keys["read"].value, 5*time.Second)
	stream, streamErr := harness.client.WatchEvents(streamContext, &agentv1.WatchEventsRequest{})
	if streamErr == nil {
		_, streamErr = stream.Recv()
	}
	stopStream()
	assertCode(t, streamErr, codes.PermissionDenied)

	eventContext, stopEvent := rpcContext(harness.keys["event"].value, 5*time.Second)
	eventStream, err := harness.client.WatchEvents(eventContext, &agentv1.WatchEventsRequest{})
	if err != nil {
		stopEvent()
		t.Fatalf("event.read Service Key could not open WatchEvents: %v", status.Code(err))
	}
	event, err := eventStream.Recv()
	stopEvent()
	if err != nil || event.GetEvent().GetAggregateId() != created.GetTask().GetTaskId() {
		t.Fatalf("event.read Service Key could not receive event: %v", status.Code(err))
	}

	writeKey := harness.keys["write"]
	revokeContext, revokeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, err = database.store.RevokeCredential(revokeContext, auth.RevokeCredentialCommand{
		CallerCredentialID: writeKey.credential.CredentialID, CallerClientID: writeKey.credential.ClientID,
		IdempotencyKey: uuid.NewString(), CredentialID: writeKey.credential.CredentialID,
		ExpectedRevision: writeKey.credential.Revision,
	})
	revokeCancel()
	if err != nil {
		t.Fatalf("revoke test Service Key failed (%T)", err)
	}
	ctx, cancel = rpcContext(writeKey.value, 5*time.Second)
	_, err = harness.client.CreateTask(ctx, &agentv1.CreateTaskRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: request.GetOwnerId(), Goal: "Revoked key must fail closed.",
		RetentionPolicy: request.GetRetentionPolicy(),
	})
	cancel()
	assertCode(t, err, codes.Unauthenticated)
}

func createTask(t *testing.T, client agentv1.TaskServiceClient, serviceKey, ownerID, goal string) *agentv1.CreateTaskResponse {
	t.Helper()
	ctx, cancel := rpcContext(serviceKey, 10*time.Second)
	defer cancel()
	created, err := client.CreateTask(ctx, &agentv1.CreateTaskRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: ownerID, Goal: goal,
		RetentionPolicy: agentv1.RetentionPolicy_RETENTION_POLICY_EPHEMERAL_AUTO_DESTROY,
	})
	if err != nil {
		t.Fatalf("CreateTask fixture failed: %v", status.Code(err))
	}
	return created
}

func assertCode(t *testing.T, err error, expected codes.Code) {
	t.Helper()
	if status.Code(err) != expected {
		t.Fatalf("expected gRPC code %s, got %s", expected, status.Code(err))
	}
}
