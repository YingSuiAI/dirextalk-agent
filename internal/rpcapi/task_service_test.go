package rpcapi

import (
	"context"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type taskStoreStub struct {
	create      func(context.Context, task.MutationScope, task.CreateCommand) (task.Task, error)
	eventsAfter func(context.Context, int64, int) ([]task.Event, error)
}

func (store taskStoreStub) Create(ctx context.Context, scope task.MutationScope, command task.CreateCommand) (task.Task, error) {
	return store.create(ctx, scope, command)
}
func (taskStoreStub) Get(context.Context, string) (task.Task, error) {
	return task.Task{}, task.ErrNotFound
}
func (taskStoreStub) List(context.Context, task.ListQuery) (task.ListResult, error) {
	return task.ListResult{}, nil
}
func (taskStoreStub) Cancel(context.Context, task.MutationScope, task.CancelCommand) (task.Task, error) {
	return task.Task{}, task.ErrNotFound
}
func (taskStoreStub) ListSteps(context.Context, string) ([]task.Step, error) { return nil, nil }
func (store taskStoreStub) EventsAfter(ctx context.Context, after int64, limit int) ([]task.Event, error) {
	return store.eventsAfter(ctx, after, limit)
}
func (taskStoreStub) AcquireReadyStep(context.Context, task.MutationScope, task.AcquireReadyStepCommand) (task.Attempt, bool, error) {
	return task.Attempt{}, false, task.ErrNoReadyStep
}
func (taskStoreStub) RenewStepLease(context.Context, task.MutationScope, task.RenewStepLeaseCommand) (task.Attempt, error) {
	return task.Attempt{}, task.ErrAttemptNotFound
}
func (taskStoreStub) CheckpointStep(context.Context, task.MutationScope, task.CheckpointStepCommand) (task.Attempt, error) {
	return task.Attempt{}, task.ErrAttemptNotFound
}
func (taskStoreStub) CompleteStep(context.Context, task.MutationScope, task.CompleteStepCommand) (task.Attempt, error) {
	return task.Attempt{}, task.ErrAttemptNotFound
}

func TestCreateTaskRequiresRetentionAndMapsSafeErrors(t *testing.T) {
	t.Parallel()
	called := false
	service := NewTaskService(taskStoreStub{
		create: func(context.Context, task.MutationScope, task.CreateCommand) (task.Task, error) {
			called = true
			return task.Task{}, task.ErrRawSecret
		},
		eventsAfter: func(context.Context, int64, int) ([]task.Event, error) { return nil, nil },
	})
	ctx := authenticatedRPCContext()
	_, err := service.CreateTask(ctx, &agentv1.CreateTaskRequest{})
	if status.Code(err) != codes.InvalidArgument || called {
		t.Fatalf("missing retention = (%v, called=%v), want InvalidArgument before store", err, called)
	}
	_, err = service.CreateTask(ctx, &agentv1.CreateTaskRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: "owner", Goal: "sk-abcdefghijklmnopqrstuvwxyz",
		RetentionPolicy: agentv1.RetentionPolicy_RETENTION_POLICY_EPHEMERAL_AUTO_DESTROY,
	})
	if status.Code(err) != codes.InvalidArgument || !called {
		t.Fatalf("raw secret = (%v, called=%v), want InvalidArgument", err, called)
	}
}

func TestWatchEventsResumesStrictlyAfterCursor(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	stream := &watchEventsStreamStub{ctx: ctx, onSend: cancel}
	requestedAfter := int64(-1)
	service := NewTaskService(taskStoreStub{
		create: func(context.Context, task.MutationScope, task.CreateCommand) (task.Task, error) {
			return task.Task{}, errors.New("unused")
		},
		eventsAfter: func(_ context.Context, after int64, _ int) ([]task.Event, error) {
			requestedAfter = after
			return []task.Event{{Seq: 42, EventID: uuid.NewString(), EventType: "agent.task.changed", AggregateType: "task", AggregateID: uuid.NewString(), Revision: 2, SummaryJSON: []byte(`{"revision":2}`), OccurredAt: time.Now().UTC()}}, nil
		},
	})
	service.pollInterval = time.Millisecond
	err := service.WatchEvents(&agentv1.WatchEventsRequest{AfterSeq: 41}, stream)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WatchEvents() error = %v, want context canceled", err)
	}
	if requestedAfter != 41 || len(stream.sent) != 1 || stream.sent[0].GetEvent().GetSeq() != 42 {
		t.Fatalf("resume = after %d, sent %#v", requestedAfter, stream.sent)
	}
}

func authenticatedRPCContext() context.Context {
	return auth.ContextWithPrincipal(context.Background(), auth.Principal{
		CredentialID: uuid.NewString(), ClientID: "rpcapi-test", Scopes: map[string]struct{}{"task.write": {}},
	})
}

type watchEventsStreamStub struct {
	grpc.ServerStream
	ctx    context.Context
	onSend func()
	sent   []*agentv1.WatchEventsResponse
}

func (stream *watchEventsStreamStub) Context() context.Context { return stream.ctx }
func (stream *watchEventsStreamStub) Send(response *agentv1.WatchEventsResponse) error {
	stream.sent = append(stream.sent, response)
	stream.onSend()
	return nil
}
