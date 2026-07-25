package rpcapi

import (
	"context"
	"errors"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type CoreScheduleService struct {
	agentv1.UnimplementedScheduleServiceServer
	store scheduleServiceStore
}

type scheduleServiceStore interface {
	CreateSchedule(context.Context, coretask.CreateScheduleCommand) (coretask.Schedule, error)
	GetSchedule(context.Context, string) (coretask.Schedule, error)
	ListSchedules(context.Context, string, int) ([]coretask.Schedule, string, error)
	UpdateSchedule(context.Context, coretask.UpdateScheduleCommand) (coretask.Schedule, error)
	PauseSchedule(context.Context, coretask.ScheduleMutationCommand) (coretask.Schedule, error)
	ResumeSchedule(context.Context, coretask.ScheduleMutationCommand) (coretask.Schedule, error)
	TriggerNow(context.Context, coretask.TriggerScheduleCommand) (coretask.Schedule, coretask.Occurrence, coretask.Task, error)
	DeleteSchedule(context.Context, coretask.ScheduleMutationCommand) (coretask.Schedule, error)
}

func NewCoreScheduleService(store scheduleServiceStore) *CoreScheduleService {
	return &CoreScheduleService{store: store}
}
func NewScheduleService(store scheduleServiceStore) *CoreScheduleService {
	return NewCoreScheduleService(store)
}

func (s *CoreScheduleService) Create(ctx context.Context, r *agentv1.ScheduleServiceCreateRequest) (*agentv1.ScheduleServiceCreateResponse, error) {
	if r == nil || !validCoreUUID(r.GetIdempotencyKey()) {
		return nil, status.Error(codes.InvalidArgument, "idempotency_key is invalid")
	}
	now := time.Now().UTC()
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("schedule:"+r.GetIdempotencyKey())).String()
	sched, err := scheduleFromProto(id, r.GetName(), r.GetTaskTemplate(), r.GetTrigger(), now)
	if err != nil {
		return nil, coreTaskRPCError(err)
	}
	digest, err := mutationDigest("create_schedule", r.GetName(), r.GetTaskTemplate(), r.GetTrigger())
	if err != nil {
		return nil, coreTaskRPCError(err)
	}
	out, err := s.store.CreateSchedule(ctx, coretask.CreateScheduleCommand{Schedule: sched, Mutation: coretask.MutationCommand{IdempotencyKey: r.GetIdempotencyKey(), RequestDigest: digest}})
	if err != nil {
		return nil, coreTaskRPCError(err)
	}
	return &agentv1.ScheduleServiceCreateResponse{Schedule: scheduleProto(out)}, nil
}
func (s *CoreScheduleService) Get(ctx context.Context, r *agentv1.ScheduleServiceGetRequest) (*agentv1.ScheduleServiceGetResponse, error) {
	if r == nil || !validCoreUUID(r.GetScheduleId()) {
		return nil, status.Error(codes.InvalidArgument, "schedule_id is invalid")
	}
	v, e := s.store.GetSchedule(ctx, r.GetScheduleId())
	if e != nil {
		return nil, coreTaskRPCError(e)
	}
	return &agentv1.ScheduleServiceGetResponse{Schedule: scheduleProto(v)}, nil
}
func (s *CoreScheduleService) List(ctx context.Context, r *agentv1.ScheduleServiceListRequest) (*agentv1.ScheduleServiceListResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := validateSchedulePageToken(r.GetPageToken()); err != nil {
		return nil, err
	}
	n, e := pageLimit(r.GetPageSize())
	if e != nil {
		return nil, e
	}
	vs, next, e := s.store.ListSchedules(ctx, r.GetPageToken(), n)
	if e != nil {
		return nil, coreTaskRPCError(e)
	}
	out := &agentv1.ScheduleServiceListResponse{NextPageToken: next, Schedules: make([]*agentv1.CoreSchedule, 0, len(vs))}
	for _, v := range vs {
		out.Schedules = append(out.Schedules, scheduleProto(v))
	}
	return out, nil
}
func (s *CoreScheduleService) Update(ctx context.Context, r *agentv1.ScheduleServiceUpdateRequest) (*agentv1.ScheduleServiceUpdateResponse, error) {
	if r == nil || !validCoreUUID(r.GetScheduleId()) || !validCoreUUID(r.GetIdempotencyKey()) || r.GetExpectedRevision() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid update request")
	}
	digest, er := mutationDigest("update_schedule", r.GetScheduleId(), r.GetName(), r.GetTaskTemplate(), r.GetTrigger(), r.GetExpectedRevision())
	if er != nil {
		return nil, coreTaskRPCError(er)
	}
	if replay, ok := s.store.(interface {
		LookupScheduleMutation(context.Context, string, string, string) (coretask.Schedule, bool, error)
	}); ok {
		if snapshot, found, lookupErr := replay.LookupScheduleMutation(ctx, "update", r.GetIdempotencyKey(), digest); lookupErr == nil && found {
			return &agentv1.ScheduleServiceUpdateResponse{Schedule: scheduleProto(snapshot)}, nil
		} else if lookupErr != nil && !errors.Is(lookupErr, coretask.ErrNotFound) {
			return nil, coreTaskRPCError(lookupErr)
		}
	}
	cur, e := s.store.GetSchedule(ctx, r.GetScheduleId())
	if e != nil {
		return nil, coreTaskRPCError(e)
	}
	if r.Name != nil {
		cur.Name = r.GetName()
	}
	if r.TaskTemplate != nil {
		tpl, er := templateFromProto(r.TaskTemplate)
		if er != nil {
			return nil, coreTaskRPCError(er)
		}
		cur.Spec = tpl
	}
	if r.Trigger != nil {
		run, cron, tz, er := triggerFromProto(r.Trigger)
		if er != nil {
			return nil, coreTaskRPCError(er)
		}
		cur.RunAt, cur.Cron, cur.Timezone = run, cron, tz
	}
	cur.UpdatedAt = time.Now().UTC()
	out, er := s.store.UpdateSchedule(ctx, coretask.UpdateScheduleCommand{Schedule: cur, Mutation: coretask.MutationCommand{IdempotencyKey: r.GetIdempotencyKey(), RequestDigest: digest, ExpectedRevision: uint64(r.GetExpectedRevision())}})
	if er != nil {
		return nil, coreTaskRPCError(er)
	}
	return &agentv1.ScheduleServiceUpdateResponse{Schedule: scheduleProto(out)}, nil
}
func (s *CoreScheduleService) Pause(ctx context.Context, r *agentv1.ScheduleServicePauseRequest) (*agentv1.ScheduleServicePauseResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	out, err := s.scheduleState(ctx, r.GetScheduleId(), r.GetIdempotencyKey(), r.GetExpectedRevision(), true)
	if err != nil {
		return nil, err
	}
	return &agentv1.ScheduleServicePauseResponse{Schedule: scheduleProto(out)}, nil
}
func (s *CoreScheduleService) Resume(ctx context.Context, r *agentv1.ScheduleServiceResumeRequest) (*agentv1.ScheduleServiceResumeResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	out, err := s.scheduleState(ctx, r.GetScheduleId(), r.GetIdempotencyKey(), r.GetExpectedRevision(), false)
	if err != nil {
		return nil, err
	}
	return &agentv1.ScheduleServiceResumeResponse{Schedule: scheduleProto(out)}, nil
}
func (s *CoreScheduleService) scheduleState(ctx context.Context, id, key string, rev int64, pause bool) (coretask.Schedule, error) {
	if !validCoreUUID(id) || !validCoreUUID(key) || rev <= 0 {
		return coretask.Schedule{}, status.Error(codes.InvalidArgument, "invalid schedule mutation")
	}
	digest, e := mutationDigest("schedule_state", id, rev, pause)
	if e != nil {
		return coretask.Schedule{}, coreTaskRPCError(e)
	}
	c := coretask.ScheduleMutationCommand{ScheduleID: id, At: time.Now().UTC(), Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest, ExpectedRevision: uint64(rev)}}
	var out coretask.Schedule
	if pause {
		out, e = s.store.PauseSchedule(ctx, c)
	} else {
		out, e = s.store.ResumeSchedule(ctx, c)
	}
	if e != nil {
		return coretask.Schedule{}, coreTaskRPCError(e)
	}
	return out, nil
}
func (s *CoreScheduleService) TriggerNow(ctx context.Context, r *agentv1.ScheduleServiceTriggerNowRequest) (*agentv1.ScheduleServiceTriggerNowResponse, error) {
	if r == nil || !validCoreUUID(r.GetScheduleId()) || !validCoreUUID(r.GetIdempotencyKey()) {
		return nil, status.Error(codes.InvalidArgument, "invalid trigger request")
	}
	digest, e := mutationDigest("trigger_now", r.GetScheduleId())
	if e != nil {
		return nil, coreTaskRPCError(e)
	}
	sch, occ, t, e := s.store.TriggerNow(ctx, coretask.TriggerScheduleCommand{ScheduleID: r.GetScheduleId(), At: time.Now().UTC(), Mutation: coretask.MutationCommand{IdempotencyKey: r.GetIdempotencyKey(), RequestDigest: digest}})
	if e != nil {
		return nil, coreTaskRPCError(e)
	}
	return &agentv1.ScheduleServiceTriggerNowResponse{Schedule: scheduleProto(sch), OccurrenceId: occ.ID, TaskId: t.ID}, nil
}
func (s *CoreScheduleService) Delete(ctx context.Context, r *agentv1.ScheduleServiceDeleteRequest) (*agentv1.ScheduleServiceDeleteResponse, error) {
	if r == nil || !validCoreUUID(r.GetScheduleId()) || !validCoreUUID(r.GetIdempotencyKey()) || r.GetExpectedRevision() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid schedule deletion")
	}
	digest, e := mutationDigest("delete_schedule", r.GetScheduleId(), r.GetExpectedRevision())
	if e != nil {
		return nil, coreTaskRPCError(e)
	}
	_, e = s.store.DeleteSchedule(ctx, coretask.ScheduleMutationCommand{ScheduleID: r.GetScheduleId(), At: time.Now().UTC(), Mutation: coretask.MutationCommand{IdempotencyKey: r.GetIdempotencyKey(), RequestDigest: digest, ExpectedRevision: uint64(r.GetExpectedRevision())}})
	if e != nil {
		return nil, coreTaskRPCError(e)
	}
	return &agentv1.ScheduleServiceDeleteResponse{}, nil
}
