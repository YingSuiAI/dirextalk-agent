package rpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type coreTaskStoreFake struct {
	coretask.Store
	created   coretask.CreateTaskCommand
	progress  []coretask.Progress
	canceled  coretask.Task
	getCalled bool
}

func (f *coreTaskStoreFake) CreateTask(_ context.Context, c coretask.CreateTaskCommand) (coretask.Task, error) {
	f.created = c
	now := time.Now().UTC()
	return coretask.Task{ID: uuid.NewString(), Spec: c.Spec, Status: coretask.StatusQueued, Revision: 1, CreatedAt: now, UpdatedAt: now, AvailableAt: now}, nil
}
func (f *coreTaskStoreFake) ListProgress(_ context.Context, _ string, after uint64, _ int) ([]coretask.Progress, string, error) {
	out := []coretask.Progress{}
	for _, p := range f.progress {
		if p.Sequence > after {
			out = append(out, p)
		}
	}
	return out, "", nil
}
func (f *coreTaskStoreFake) WatchProgress(ctx context.Context, _ string, after uint64) (<-chan coretask.Progress, error) {
	ch := make(chan coretask.Progress)
	go func() {
		defer close(ch)
		for _, p := range f.progress {
			if p.Sequence > after {
				select {
				case ch <- p:
				case <-ctx.Done():
					return
				}
			}
		}
		<-ctx.Done()
	}()
	return ch, nil
}
func (f *coreTaskStoreFake) CancelTask(context.Context, coretask.CancelCommand) (coretask.Task, error) {
	return f.canceled, nil
}
func (f *coreTaskStoreFake) GetTask(context.Context, string) (coretask.Task, error) {
	f.getCalled = true
	return coretask.Task{}, coretask.ErrNotFound
}

type taskEventStreamFake struct {
	grpc.ServerStream
	ctx  context.Context
	sent []*agentv1.TaskServiceWatchTaskEventsResponse
	done chan struct{}
}

func (s *taskEventStreamFake) Context() context.Context { return s.ctx }
func (s *taskEventStreamFake) Send(v *agentv1.TaskServiceWatchTaskEventsResponse) error {
	s.sent = append(s.sent, v)
	if s.done != nil {
		close(s.done)
	}
	return nil
}

func TestCoreTaskCreateComputesDigestServerSide(t *testing.T) {
	key := uuid.NewString()
	fake := &coreTaskStoreFake{}
	svc := NewCoreTaskService(fake)
	_, err := svc.CreateTask(context.Background(), &agentv1.TaskServiceCreateTaskRequest{IdempotencyKey: key, Goal: " do work ", ModelProfileId: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	if fake.created.Mutation.RequestDigest == "" || len(fake.created.Mutation.RequestDigest) != 64 {
		t.Fatalf("digest=%q", fake.created.Mutation.RequestDigest)
	}
	if fake.created.Spec.Goal != " do work " {
		t.Fatalf("goal changed unexpectedly: %q", fake.created.Spec.Goal)
	}
}

func TestCoreTaskWatchResumesAfterDurableSequence(t *testing.T) {
	id := uuid.NewString()
	now := time.Now().UTC()
	fake := &coreTaskStoreFake{progress: []coretask.Progress{{TaskID: id, Sequence: 2, At: now, Status: coretask.StatusQueued, Message: "queued"}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &taskEventStreamFake{ctx: ctx, done: make(chan struct{})}
	svc := NewCoreTaskService(fake)
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.WatchTaskEvents(&agentv1.TaskServiceWatchTaskEventsRequest{TaskId: id, AfterSequence: 1}, stream)
	}()
	<-stream.done
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("watch err=%v", err)
	}
	if len(stream.sent) != 1 || stream.sent[0].GetEvent().GetSequence() != 2 {
		t.Fatalf("events=%v", stream.sent)
	}
}

func TestCoreTaskCanonicalUUIDRejectsNonCanonical(t *testing.T) {
	if validCoreUUID(strings.ToUpper("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")) {
		t.Fatal("fixture unexpectedly canonical")
	}
	svc := NewCoreTaskService(&coreTaskStoreFake{})
	_, err := svc.GetTask(context.Background(), &agentv1.TaskServiceGetTaskRequest{TaskId: strings.ToUpper("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")})
	if err == nil {
		t.Fatal("non-canonical UUID accepted")
	}
}

func TestCancelReturnsDurableSnapshotWithoutCurrentRead(t *testing.T) {
	id, key := uuid.NewString(), uuid.NewString()
	now := time.Now().UTC()
	fake := &coreTaskStoreFake{canceled: coretask.Task{ID: id, Spec: coretask.TaskSpec{Goal: "cancelled", ModelProfileID: uuid.NewString(), IdempotencyKey: key}, Status: coretask.StatusCanceled, Revision: 9, CreatedAt: now, UpdatedAt: now, AvailableAt: now}}
	resp, err := NewCoreTaskService(fake).CancelTask(context.Background(), &agentv1.TaskServiceCancelTaskRequest{TaskId: id, IdempotencyKey: key, ExpectedRevision: 8, Reason: "user"})
	if err != nil || resp.GetTask().GetRevision() != 9 || fake.getCalled {
		t.Fatalf("cancel snapshot=%v err=%v get=%v", resp, err, fake.getCalled)
	}
}

type coreScheduleStoreFake struct {
	coretask.ScheduleStore
	trigger        func(context.Context, coretask.TriggerScheduleCommand) (coretask.Schedule, coretask.Occurrence, coretask.Task, error)
	getCalled      bool
	listCalled     bool
	lookupSnapshot coretask.Schedule
	lookupFound    bool
}

func (f *coreScheduleStoreFake) TriggerNow(ctx context.Context, c coretask.TriggerScheduleCommand) (coretask.Schedule, coretask.Occurrence, coretask.Task, error) {
	return f.trigger(ctx, c)
}
func (f *coreScheduleStoreFake) GetSchedule(context.Context, string) (coretask.Schedule, error) {
	f.getCalled = true
	return coretask.Schedule{}, coretask.ErrNotFound
}
func (f *coreScheduleStoreFake) ListSchedules(context.Context, string, int) ([]coretask.Schedule, string, error) {
	f.listCalled = true
	return nil, "", nil
}
func (f *coreScheduleStoreFake) LookupScheduleMutation(context.Context, string, string, string) (coretask.Schedule, bool, error) {
	return f.lookupSnapshot, f.lookupFound, nil
}

func TestTriggerNowUsesDurableScheduleSnapshot(t *testing.T) {
	scheduleID, occurrenceID, taskID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	now := time.Now().UTC()
	fake := &coreScheduleStoreFake{trigger: func(context.Context, coretask.TriggerScheduleCommand) (coretask.Schedule, coretask.Occurrence, coretask.Task, error) {
		return coretask.Schedule{ID: scheduleID, Name: "durable", Revision: 7, CreatedAt: now, UpdatedAt: now, Spec: coretask.TaskTemplate{Goal: "x", ModelProfileID: uuid.NewString()}, Cron: "0 0 * * *", Timezone: "UTC"}, coretask.Occurrence{ID: occurrenceID, ScheduleID: scheduleID, TaskID: taskID, ScheduledFor: now, CreatedAt: now}, coretask.Task{ID: taskID}, nil
	}}
	resp, err := NewCoreScheduleService(fake).TriggerNow(context.Background(), &agentv1.ScheduleServiceTriggerNowRequest{ScheduleId: scheduleID, IdempotencyKey: uuid.NewString()})
	if err != nil || resp.GetSchedule().GetRevision() != 7 || resp.GetOccurrenceId() != occurrenceID || resp.GetTaskId() != taskID || fake.getCalled {
		t.Fatalf("snapshot=%v err=%v get=%v", resp, err, fake.getCalled)
	}
}

func TestScheduleUpdateReplaysSnapshotBeforeCurrentRead(t *testing.T) {
	scheduleID := uuid.NewString()
	now := time.Now().UTC()
	snapshot := coretask.Schedule{ID: scheduleID, Name: "old", Revision: 4, CreatedAt: now, UpdatedAt: now, Spec: coretask.TaskTemplate{Goal: "x", ModelProfileID: uuid.NewString()}, Cron: "0 0 * * *", Timezone: "UTC"}
	fake := &coreScheduleStoreFake{lookupSnapshot: snapshot, lookupFound: true}
	resp, err := NewCoreScheduleService(fake).Update(context.Background(), &agentv1.ScheduleServiceUpdateRequest{ScheduleId: scheduleID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 3})
	if err != nil || resp.GetSchedule().GetRevision() != 4 || fake.getCalled {
		t.Fatalf("update replay=%v err=%v get=%v", resp, err, fake.getCalled)
	}
}

func TestProgressProtoPreservesEventIDResultAndZeroTimestamp(t *testing.T) {
	id := uuid.NewString()
	p := coretask.Progress{EventID: id, TaskID: uuid.NewString(), Sequence: 4, ResultJSON: []byte(`{"answer":42}`)}
	e := progressProto(p)
	if e.GetEventId() != id || e.GetOccurredAt() != nil || e.GetResult().GetFields()["answer"].GetNumberValue() != 42 {
		t.Fatalf("event projection=%v", e)
	}
}

func TestScheduleCursorValidationIsInvalidArgument(t *testing.T) {
	fake := &coreScheduleStoreFake{}
	_, err := NewCoreScheduleService(fake).List(context.Background(), &agentv1.ScheduleServiceListRequest{PageToken: "not-base64"})
	if status.Code(err) != codes.InvalidArgument || fake.listCalled {
		t.Fatalf("cursor err=%v called=%v", err, fake.listCalled)
	}
}
